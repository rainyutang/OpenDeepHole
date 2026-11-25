"""Platform-level settings and versioned per-scan knowledge-base MCP storage."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable

from backend.models import AgentMcpConfig


PLATFORM_SETTINGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS platform_settings (
    setting_key TEXT PRIMARY KEY,
    value_json  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class KnowledgeBaseStoreMixin:
    """Persist platform settings and versioned desired scan knowledge-base configs."""

    def get_platform_setting(self, setting_key: str) -> dict[str, Any] | None:
        key = str(setting_key or "").strip()
        if not key:
            return None
        row = self._conn.execute(
            "SELECT value_json, updated_at FROM platform_settings WHERE setting_key = ?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row["value_json"] or "{}")
        except Exception:
            value = {}
        if not isinstance(value, dict):
            value = {}
        return {
            "value": value,
            "updated_at": str(row["updated_at"] or ""),
        }

    def upsert_platform_setting(
        self,
        setting_key: str,
        value: dict[str, Any],
        *,
        increment_revision: bool = True,
    ) -> dict[str, Any]:
        key = str(setting_key or "").strip()
        if not key:
            raise ValueError("setting_key is required")
        now = _utc_now()
        with self._lock:
            existing_row = self._conn.execute(
                "SELECT value_json FROM platform_settings WHERE setting_key = ?",
                (key,),
            ).fetchone()
            previous_revision = 0
            if existing_row is not None:
                try:
                    prev_value = json.loads(existing_row["value_json"] or "{}")
                    if isinstance(prev_value, dict):
                        previous_revision = max(0, int(prev_value.get("revision") or 0))
                except Exception:
                    previous_revision = 0
            stored = dict(value)
            if increment_revision:
                stored["revision"] = previous_revision + 1
            else:
                stored.setdefault("revision", previous_revision)
            payload_json = json.dumps(stored, ensure_ascii=False, sort_keys=True)
            self._conn.execute(
                """\
                INSERT INTO platform_settings (setting_key, value_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at = excluded.updated_at
                """,
                (key, payload_json, now),
            )
            self._conn.commit()
            return {"value": stored, "updated_at": now}

    def update_scan_knowledge_base(
        self,
        scan_id: str,
        *,
        enabled: bool,
        project_id: str | None,
        build_config: Callable[[bool, str], AgentMcpConfig],
    ):
        with self._lock:
            # Start a write transaction / lock the row before reading its config.
            self._conn.execute("UPDATE scans SET scan_id = scan_id WHERE scan_id = ?", (scan_id,))
            row = self._conn.execute(
                "SELECT * FROM scans WHERE scan_id = ? AND NOT EXISTS "
                "(SELECT 1 FROM scan_deletions d WHERE d.scan_id = scans.scan_id)",
                (scan_id,),
            ).fetchone()
            if row is None:
                self._conn.commit()
                return None
            meta = self._row_to_meta(row)
            if enabled and meta.scan_mode == "multi_version":
                raise ValueError("多版本比对扫描不支持知识库")
            existing = meta.knowledge_base_mcp
            target_project_id = (
                str(project_id).strip()
                if project_id is not None
                else (str(existing.project_id or "").strip() if existing is not None else "")
            )
            if enabled:
                if not target_project_id:
                    raise ValueError("启用知识库必须填写 Project ID")
                new_config = build_config(True, target_project_id)
                if (
                    meta.code_graph_mcp is not None
                    and meta.code_graph_mcp.enabled
                    and new_config.name.strip().casefold()
                    == meta.code_graph_mcp.name.strip().casefold()
                ):
                    raise ValueError("代码图谱 MCP 与知识库 MCP 名称不能相同")
            else:
                if existing is not None:
                    new_config = existing.model_copy(
                        update={"enabled": False, "project_id": target_project_id},
                        deep=True,
                    )
                elif target_project_id:
                    new_config = AgentMcpConfig(
                        enabled=False,
                        name="knowledge-base",
                        transport="remote",
                        project_id=target_project_id,
                    )
                else:
                    new_config = None

            was_enabled = bool(
                meta.knowledge_base_enabled
                and existing is not None
                and existing.enabled
            )
            old_project_id = str(existing.project_id or "").strip() if existing is not None else ""
            old_dump = existing.model_dump_json() if existing is not None else None
            new_dump = new_config.model_dump_json() if new_config is not None else None
            if (
                bool(enabled) != was_enabled
                or target_project_id != old_project_id
                or new_dump != old_dump
            ):
                self._conn.execute(
                    "UPDATE scans SET knowledge_base_enabled = ?, "
                    "knowledge_base_mcp_json = ?, "
                    "knowledge_base_mcp_revision = knowledge_base_mcp_revision + 1 "
                    "WHERE scan_id = ?",
                    (int(bool(enabled)), new_dump, scan_id),
                )
            row = self._conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            self._conn.commit()
            return self._row_to_meta(row)

    def acknowledge_scan_knowledge_base(
        self,
        scan_id: str,
        revision: int,
        agent_key: str = "",
    ) -> bool:
        if type(revision) is not int or revision < 0:
            return False
        with self._lock:
            result = self._conn.execute(
                "UPDATE scans SET knowledge_base_mcp_applied_revision = ? WHERE scan_id = ? "
                "AND knowledge_base_mcp_applied_revision < ? AND knowledge_base_mcp_revision >= ? "
                "AND (? = '' OR agent_key = ?) AND NOT EXISTS "
                "(SELECT 1 FROM scan_deletions d WHERE d.scan_id = scans.scan_id)",
                (revision, scan_id, revision, revision, agent_key, agent_key),
            )
            self._conn.commit()
            return bool(result.rowcount)

    def list_agent_knowledge_base_configs(self, agent_key: str) -> list[tuple[str, object]]:
        rows = self._conn.execute(
            "SELECT * FROM scans WHERE agent_key = ? AND knowledge_base_mcp_revision > 0 "
            "AND NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = scans.scan_id) "
            "ORDER BY scan_id",
            (agent_key,),
        ).fetchall()
        return [(row["scan_id"], self._row_to_meta(row)) for row in rows]
