import asyncio
import sqlite3
from pathlib import Path
from unittest.mock import patch

from backend.api import agent as agent_api
from backend.models import AgentInfo, OpenCodePoolModelStats, OpenCodePoolStatus, User
from backend.store.sqlite import SqliteScanStore


def _pool_status(
    *,
    session_id: str,
    effective_weight: float,
    penalty_level: int,
    failure_at: str = "",
    failure_kind: str = "",
    success: int = 0,
    failure: int = 0,
) -> OpenCodePoolStatus:
    return OpenCodePoolStatus(
        agent_session_id=session_id,
        updated_at=f"2026-07-30T00:00:0{success + failure}+00:00",
        models=[
            OpenCodePoolModelStats(
                id="primary",
                model="provider/model",
                weight=4.0,
                effective_weight=effective_weight,
                health_penalty_level=penalty_level,
                last_health_failure_at=failure_at,
                last_health_failure_kind=failure_kind,
                total=success + failure,
                success=success,
                failure=failure,
            )
        ],
    )


def test_legacy_pool_model_snapshot_defaults_effective_weight_to_weight() -> None:
    model = OpenCodePoolModelStats.model_validate({
        "id": "legacy",
        "weight": 3.5,
    })

    assert model.weight == 3.5
    assert model.effective_weight == 3.5
    assert model.health_penalty_level == 0
    assert model.last_health_failure_at == ""
    assert model.last_health_failure_kind == ""


def test_agent_pool_uses_health_from_current_session_only(tmp_path: Path) -> None:
    store = SqliteScanStore(tmp_path / "pool.db")
    store.upsert_agent_opencode_pool_status(
        agent_name="stable-agent",
        user_id="owner",
        agent_session_id="old-session",
        status=_pool_status(
            session_id="old-session",
            effective_weight=1.0,
            penalty_level=2,
            failure_at="2026-07-30T00:00:01+00:00",
            failure_kind="timeout",
            failure=1,
        ),
    )
    store.upsert_agent_opencode_pool_status(
        agent_name="stable-agent",
        user_id="owner",
        agent_session_id="current-session",
        status=_pool_status(
            session_id="current-session",
            effective_weight=2.0,
            penalty_level=1,
            failure_at="2026-07-30T00:00:02+00:00",
            failure_kind="failure",
            success=1,
        ),
    )

    current = store.get_agent_opencode_pool_status(
        agent_name="stable-agent",
        user_id="owner",
        agent_session_id="current-session",
        online=True,
    )
    assert len(current.models) == 1
    model = current.models[0]
    assert model.total == 2
    assert model.success == 1
    assert model.failure == 1
    assert model.weight == 4.0
    assert model.effective_weight == 2.0
    assert model.health_penalty_level == 1
    assert model.last_health_failure_at == "2026-07-30T00:00:02+00:00"
    assert model.last_health_failure_kind == "failure"

    restarted = store.get_agent_opencode_pool_status(
        agent_name="stable-agent",
        user_id="owner",
        agent_session_id="new-session",
        online=True,
    )
    restarted_model = restarted.models[0]
    assert restarted_model.effective_weight == restarted_model.weight == 4.0
    assert restarted_model.health_penalty_level == 0
    assert restarted_model.last_health_failure_at == ""
    assert restarted_model.last_health_failure_kind == ""


def test_complete_snapshot_removes_stale_health_from_omitted_model(
    tmp_path: Path,
) -> None:
    store = SqliteScanStore(tmp_path / "pool.db")
    store.upsert_agent_opencode_pool_status(
        agent_name="stable-agent",
        user_id="owner",
        agent_session_id="current-session",
        status=_pool_status(
            session_id="current-session",
            effective_weight=1.0,
            penalty_level=2,
            failure_at="2026-07-30T00:00:01+00:00",
            failure_kind="timeout",
            failure=1,
        ),
    )
    store.upsert_agent_opencode_pool_status(
        agent_name="stable-agent",
        user_id="owner",
        agent_session_id="current-session",
        status=OpenCodePoolStatus(
            agent_session_id="current-session",
            updated_at="2026-07-30T00:00:02+00:00",
            models=[],
        ),
    )

    current = store.get_agent_opencode_pool_status(
        agent_name="stable-agent",
        user_id="owner",
        agent_session_id="current-session",
        online=True,
    )
    model = current.models[0]
    assert model.enabled is False
    assert model.effective_weight == model.weight == 4.0
    assert model.health_penalty_level == 0
    assert model.last_health_failure_at == ""
    assert model.last_health_failure_kind == ""


def test_live_complete_snapshot_clears_omitted_model_health_overlay(
    tmp_path: Path,
) -> None:
    store = SqliteScanStore(tmp_path / "pool.db")
    store.upsert_agent_opencode_pool_status(
        agent_name="stable-agent",
        user_id="owner",
        agent_session_id="current-session",
        status=_pool_status(
            session_id="current-session",
            effective_weight=1.0,
            penalty_level=2,
            failure_at="2026-07-30T00:00:01+00:00",
            failure_kind="timeout",
            failure=1,
        ),
    )
    agent = AgentInfo(
        agent_id="agent-id",
        agent_key="stable-agent",
        name="stable-agent",
        ip="127.0.0.1",
        last_seen="2026-07-30T00:00:00+00:00",
        user_id="owner",
        agent_session_id="current-session",
    )
    user = User(user_id="owner", username="owner", role="user")
    agent_api._registered_agents["agent-id"] = agent
    agent_api._agent_opencode_pool_latest["agent-id"] = OpenCodePoolStatus(
        agent_session_id="current-session",
        updated_at="2026-07-30T00:00:02+00:00",
        models=[],
    )
    try:
        with (
            patch("backend.api.agent.get_scan_store", return_value=store),
            patch("backend.api.agent._is_agent_online", return_value=True),
        ):
            current = asyncio.run(
                agent_api.get_agent_opencode_pool("agent-id", current_user=user)
            )
    finally:
        agent_api._registered_agents.clear()
        agent_api._agent_opencode_pool_latest.clear()

    model = current.models[0]
    assert model.enabled is False
    assert model.effective_weight == model.weight == 4.0
    assert model.health_penalty_level == 0
    assert model.last_health_failure_at == ""
    assert model.last_health_failure_kind == ""


def test_pool_table_migration_sets_legacy_effective_weight_from_weight(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "legacy-pool.db"
    connection = sqlite3.connect(db_path)
    connection.executescript(
        """\
        CREATE TABLE agent_opencode_pool_models (
            agent_name TEXT NOT NULL,
            user_id TEXT NOT NULL DEFAULT '',
            agent_session_id TEXT NOT NULL,
            model_id TEXT NOT NULL,
            model TEXT NOT NULL DEFAULT '',
            use_default_model INTEGER NOT NULL DEFAULT 0,
            capability TEXT NOT NULL DEFAULT '',
            weight REAL NOT NULL DEFAULT 1.0,
            max_concurrency INTEGER NOT NULL DEFAULT 1,
            enabled INTEGER NOT NULL DEFAULT 1,
            available INTEGER NOT NULL DEFAULT 1,
            time_windows TEXT NOT NULL DEFAULT '[]',
            running INTEGER NOT NULL DEFAULT 0,
            queued INTEGER NOT NULL DEFAULT 0,
            total INTEGER NOT NULL DEFAULT 0,
            success INTEGER NOT NULL DEFAULT 0,
            failure INTEGER NOT NULL DEFAULT 0,
            timeout INTEGER NOT NULL DEFAULT 0,
            cancelled INTEGER NOT NULL DEFAULT 0,
            total_duration_seconds REAL NOT NULL DEFAULT 0.0,
            last_status TEXT NOT NULL DEFAULT '',
            last_started_at TEXT NOT NULL DEFAULT '',
            last_finished_at TEXT NOT NULL DEFAULT '',
            active_tasks TEXT NOT NULL DEFAULT '[]',
            updated_at TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(agent_name, user_id, agent_session_id, model_id)
        );
        INSERT INTO agent_opencode_pool_models (
            agent_name, user_id, agent_session_id, model_id, model, weight
        ) VALUES ('stable-agent', 'owner', 'current-session', 'primary',
                  'provider/model', 3.0);
        """
    )
    connection.commit()
    connection.close()

    store = SqliteScanStore(db_path)
    status = store.get_agent_opencode_pool_status(
        agent_name="stable-agent",
        user_id="owner",
        agent_session_id="current-session",
        online=True,
    )

    assert status.models[0].weight == 3.0
    assert status.models[0].effective_weight == 3.0
    assert status.models[0].health_penalty_level == 0
