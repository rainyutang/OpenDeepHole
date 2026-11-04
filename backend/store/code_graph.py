"""Versioned desired CodeGraph configuration and Agent acknowledgements."""

from backend.models import AgentMcpConfig


class ScanCodeGraphStoreMixin:
    def update_scan_code_graph(self, scan_id: str, enabled: bool, default_config: AgentMcpConfig):
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
                raise ValueError("多版本比对扫描不支持 CodeGraph")
            config = meta.code_graph_mcp
            was_enabled = config is not None and config.enabled
            if bool(enabled) != was_enabled:
                config = (config or default_config).model_copy(update={"enabled": bool(enabled)}, deep=True)
                if (enabled and meta.knowledge_base_mcp is not None
                        and config.name.strip().casefold() == meta.knowledge_base_mcp.name.strip().casefold()):
                    raise ValueError("代码图谱 MCP 与知识库 MCP 名称不能相同")
                self._conn.execute(
                    "UPDATE scans SET code_graph_mcp_json = ?, "
                    "code_graph_mcp_revision = code_graph_mcp_revision + 1 WHERE scan_id = ?",
                    (config.model_dump_json(), scan_id),
                )
            row = self._conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            self._conn.commit()
            return self._row_to_meta(row)

    def acknowledge_scan_code_graph(self, scan_id: str, revision: int, agent_key: str = "") -> bool:
        if type(revision) is not int or revision < 0:
            return False
        with self._lock:
            result = self._conn.execute(
                "UPDATE scans SET code_graph_mcp_applied_revision = ? WHERE scan_id = ? "
                "AND code_graph_mcp_applied_revision < ? AND code_graph_mcp_revision >= ? "
                "AND (? = '' OR agent_key = ?) AND NOT EXISTS "
                "(SELECT 1 FROM scan_deletions d WHERE d.scan_id = scans.scan_id)",
                (revision, scan_id, revision, revision, agent_key, agent_key),
            )
            self._conn.commit()
            return bool(result.rowcount)

    def list_agent_code_graph_configs(self, agent_key: str) -> list[tuple[str, object]]:
        rows = self._conn.execute(
            "SELECT * FROM scans WHERE agent_key = ? AND code_graph_mcp_revision > 0 "
            "AND NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = scans.scan_id) "
            "ORDER BY scan_id", (agent_key,),
        ).fetchall()
        return [(row["scan_id"], self._row_to_meta(row)) for row in rows]
