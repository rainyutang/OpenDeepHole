"""Scan lifetime model counters, partitioned by Agent process accumulator."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.models import OpenCodePoolModelStats, OpenCodePoolStatus

from .history import canonical_json, utc_now


MODEL_USAGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_opencode_pool_sources (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    agent_session_id TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(scan_id, agent_session_id)
);
CREATE TABLE IF NOT EXISTS scan_opencode_model_usage (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    agent_session_id TEXT NOT NULL,
    model_id TEXT NOT NULL,
    total BIGINT NOT NULL DEFAULT 0,
    success BIGINT NOT NULL DEFAULT 0,
    failure BIGINT NOT NULL DEFAULT 0,
    timeout BIGINT NOT NULL DEFAULT 0,
    cancelled BIGINT NOT NULL DEFAULT 0,
    total_duration_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
    model_json TEXT NOT NULL,
    PRIMARY KEY(scan_id, agent_session_id, model_id)
);
"""

COUNTERS = ("total", "success", "failure", "timeout", "cancelled")
OUTCOMES = COUNTERS[1:]


def _timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except (ValueError, TypeError):
        return None


def _historical_model(model: OpenCodePoolModelStats) -> OpenCodePoolModelStats:
    """Historical configuration must never recreate capacity or health state."""
    return model.model_copy(update={
        "running": 0, "queued": 0, "active_tasks": [],
        "enabled": False, "available": False,
        "effective_weight": model.weight, "health_penalty_level": 0,
        "last_health_failure_at": "", "last_health_failure_kind": "",
        "last_status": "" if model.last_status in {"running", "queued"} else model.last_status,
    })


class ScanModelUsageMixin:
    def _seed_model_usage_locked(self, scan_id: str, pool: OpenCodePoolStatus) -> None:
        # Existing snapshots predate this ledger. Attribute the baseline to its
        # original process before resume replaces the pool's execution identity.
        if not pool.models or self._conn.execute(
            "SELECT 1 FROM scan_opencode_pool_sources WHERE scan_id = ? LIMIT 1", (scan_id,),
        ).fetchone():
            return
        self._record_model_usage_locked(scan_id, pool)

    def _model_usage_execution_matches_locked(self, scan_id, status, row) -> bool:
        owner = status.execution_owner
        if owner is not None:
            if owner.kind == "scan" and owner.id != scan_id:
                return False
            if owner.kind == "fp_review":
                review = self._conn.execute(
                    "SELECT scan_id FROM fp_review_jobs WHERE review_id = ?", (owner.id,),
                ).fetchone()
                if review is None or review["scan_id"] != scan_id:
                    return False
            return self.execution_matches(
                owner.kind, owner.id, None, agent_session_id=status.agent_session_id,
                execution_revision=owner.revision,
            )
        if status.execution_revision > 0:
            return self.execution_matches(
                "scan", scan_id, None, agent_session_id=status.agent_session_id,
                execution_revision=status.execution_revision,
            )
        return int(row["execution_revision"] or 0) <= 0

    def _record_model_usage_locked(self, scan_id: str, status: OpenCodePoolStatus) -> bool:
        """Accept a monotonic raw process snapshot; never add it to itself."""
        session = status.agent_session_id or ""
        source = self._conn.execute(
            "SELECT updated_at FROM scan_opencode_pool_sources WHERE scan_id = ? AND agent_session_id = ?",
            (scan_id, session),
        ).fetchone()
        if source is not None:
            previous_stamp, incoming_stamp = _timestamp(source["updated_at"]), _timestamp(status.updated_at)
            if previous_stamp is not None and (incoming_stamp is None or incoming_stamp < previous_stamp):
                return False
        previous = {row["model_id"]: row for row in self._conn.execute(
            "SELECT * FROM scan_opencode_model_usage WHERE scan_id = ? AND agent_session_id = ?",
            (scan_id, session),
        ).fetchall()}
        rows = []
        for model in status.models:
            counters = [max(0, getattr(model, field)) for field in COUNTERS]
            duration = max(0.0, model.avg_duration_seconds) * sum(counters[1:])
            old = previous.get(model.id)
            if old is not None:
                if any(value < old[field] for field, value in zip(COUNTERS, counters)):
                    return False
                # Reconstructing a sum from an average can introduce roundoff.
                if duration + 1e-7 < old["total_duration_seconds"]:
                    return False
                duration = max(duration, old["total_duration_seconds"])
            metadata = _historical_model(model).model_dump(exclude=set(COUNTERS) | {"avg_duration_seconds"})
            values = (*counters, duration, canonical_json(metadata))
            if old is None or values != tuple(old[key] for key in (*COUNTERS, "total_duration_seconds", "model_json")):
                rows.append((scan_id, session, model.id, *values))
        self._conn.execute(
            "INSERT INTO scan_opencode_pool_sources (scan_id, agent_session_id, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(scan_id, agent_session_id) DO UPDATE SET updated_at = excluded.updated_at "
            "WHERE scan_opencode_pool_sources.updated_at <> excluded.updated_at",
            (scan_id, session, status.updated_at),
        )
        if rows:
            columns = ("scan_id", "agent_session_id", "model_id", *COUNTERS, "total_duration_seconds", "model_json")
            self._conn.executemany(
                f"INSERT INTO scan_opencode_model_usage ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)}) "
                "ON CONFLICT(scan_id, agent_session_id, model_id) DO UPDATE SET "
                + ", ".join(f"{key} = excluded.{key}" for key in columns[3:]),
                rows,
            )
        # Omitted rows remain historical usage, including an empty startup snapshot.
        return True

    def _aggregate_model_usage_locked(self, scan_id, status, previous):
        historical = {model.id: model for model in previous.models}
        current = {model.id: model.model_copy(deep=True) for model in status.models}
        totals = {}
        for row in self._conn.execute(
            "SELECT * FROM scan_opencode_model_usage WHERE scan_id = ? ORDER BY model_id, agent_session_id",
            (scan_id,),
        ).fetchall():
            model_id = row["model_id"]
            if model_id not in current:
                saved = historical.get(model_id) or OpenCodePoolModelStats.model_validate_json(row["model_json"])
                current[model_id] = _historical_model(saved)
            total = totals.setdefault(model_id, dict.fromkeys((*COUNTERS, "total_duration_seconds"), 0))
            for key in total:
                total[key] += row[key]
        for model_id, model in current.items():
            old = historical.get(model_id)
            if old is not None:
                if not model.last_started_at:
                    model.last_started_at = old.last_started_at
                if not model.last_finished_at:
                    model.last_finished_at = old.last_finished_at
                if not model.last_status:
                    model.last_status = _historical_model(old).last_status
            total = totals.get(model_id)
            if total is not None:
                for key in COUNTERS:
                    setattr(model, key, total[key])
                completed = sum(total[key] for key in OUTCOMES)
                model.avg_duration_seconds = total["total_duration_seconds"] / completed if completed else 0.0
        status.models = [current[key] for key in sorted(current)]
        return status

    @staticmethod
    def _stamp_pool_projection(status: OpenCodePoolStatus, previous: OpenCodePoolStatus) -> None:
        if status.model_dump(exclude={"updated_at"}) == previous.model_dump(exclude={"updated_at"}):
            status.updated_at = previous.updated_at
            return
        now = _timestamp(utc_now())
        old = _timestamp(previous.updated_at)
        # Browsers compare Date timestamps at millisecond precision. Guarantee
        # that changes in one fast transaction burst can still replace each other.
        if old is not None:
            now = max(now, old + timedelta(milliseconds=1))
        status.updated_at = now.isoformat()
