"""SQL-scoped dashboard summaries and independent cursor drilldowns."""

from .summaries import METRICS, fact_select


class DashboardStoreMixin:
    def _dashboard_scope(self, user_id=None, product=None):
        where = ["NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = s.scan_id)"]
        params = []
        if user_id is not None:
            where.append("s.user_id = ?")
            params.append(user_id)
        if product == "__unconfigured__":
            where.append("COALESCE(s.product, '') = ''")
        elif product:
            where.append("s.product = ?")
            params.append(product)
        return " AND ".join(where), params

    def _dashboard_cte(self, user_id=None, product=None):
        where, params = self._dashboard_scope(user_id, product)
        choice = "choice.checker" if getattr(self, "distributed", False) else "choice.value"
        expand = "jsonb_array_elements_text(s.scan_items::jsonb) AS choice(checker)" if getattr(self, "distributed", False) else "json_each(s.scan_items) choice"
        fallback = fact_select("v.scan_id IN (SELECT s.scan_id FROM visible s LEFT JOIN scan_summary_state st ON st.scan_id = s.scan_id WHERE COALESCE(st.ready, 0) = 0)")
        cte = f"""WITH visible AS (
            SELECT s.scan_id, s.project_id, s.scan_name, s.project_path, s.product, s.status, s.created_at, s.user_id, s.agent_name, s.scan_items
            FROM scans s WHERE {where}
        ), members AS (
            SELECT DISTINCT s.scan_id, {choice} AS checker FROM visible s CROSS JOIN {expand}
        ), legacy_facts AS ({fallback}), totals AS (
            SELECT t.scan_id, t.checker, {', '.join('t.' + key for key in METRICS)} FROM scan_checker_totals t
            JOIN scan_summary_state st ON st.scan_id = t.scan_id AND st.ready = 1 JOIN visible s ON s.scan_id = t.scan_id
            UNION ALL SELECT scan_id, checker, {', '.join('SUM(' + key + ')' for key in METRICS)} FROM legacy_facts GROUP BY scan_id, checker
        ), tickets AS (
            SELECT f.source_scan_id AS scan_id, f.vuln_type AS checker, COUNT(*) AS ticket_submitted_count FROM feedback_entries f
            JOIN visible s ON s.scan_id = f.source_scan_id WHERE f.ticket_submitted = 1 GROUP BY f.source_scan_id, f.vuln_type
        ), per_scan AS (
            SELECT s.*, m.checker, {', '.join('COALESCE(t.' + key + ', 0) AS ' + key for key in METRICS)},
            COALESCE(k.ticket_submitted_count, 0) AS ticket_submitted_count
            FROM members m JOIN visible s ON s.scan_id = m.scan_id
            LEFT JOIN totals t ON t.scan_id = m.scan_id AND t.checker = m.checker
            LEFT JOIN tickets k ON k.scan_id = m.scan_id AND k.checker = m.checker
        ) """
        return cte, params

    def get_checker_dashboard_aggregates(self, *, user_id=None, product=None):
        cte, params = self._dashboard_cte(user_id, product)
        rows = self._conn.execute(cte + "SELECT checker, COUNT(*) AS scan_count, COUNT(DISTINCT COALESCE(NULLIF(scan_name, ''), project_id)) AS project_count, "
            + ", ".join(f"SUM({key}) AS {key}" for key in (*METRICS, "ticket_submitted_count"))
            + " FROM per_scan GROUP BY checker", params).fetchall()
        where, count_params = self._dashboard_scope(user_id, product)
        counts = self._conn.execute("SELECT COUNT(*) AS scan_count, COUNT(DISTINCT COALESCE(NULLIF(s.scan_name, ''), s.project_id)) AS project_count FROM scans s WHERE " + where, count_params).fetchone()
        where, product_params = self._dashboard_scope(user_id)
        products = self._conn.execute("SELECT DISTINCT COALESCE(s.product, '') AS product FROM scans s WHERE " + where + " ORDER BY product", product_params).fetchall()
        return {"checkers": [dict(row) for row in rows], "counts": dict(counts), "products": [row["product"] for row in products]}

    def list_checker_scans_page(self, checker: str, *, user_id=None, product=None, before_created_at=None, before_scan_id=None, limit=50):
        cte, params = self._dashboard_cte(user_id, product)
        where = "p.checker = ?"
        params.append(checker)
        if before_created_at is not None and before_scan_id is not None:
            where += " AND (p.created_at < ? OR (p.created_at = ? AND p.scan_id < ?))"
            params.extend([before_created_at, before_created_at, before_scan_id])
        params.append(max(1, min(101, limit)))
        rows = self._conn.execute(cte + "SELECT p.*, COALESCE(u.username, '') AS username FROM per_scan p LEFT JOIN users u ON u.user_id = p.user_id WHERE "
            + where + " ORDER BY p.created_at DESC, p.scan_id DESC LIMIT ?", params).fetchall()
        return [dict(row) for row in rows]

    def dashboard_token_aggregates(self, *, user_id=None):
        where, params = self._dashboard_scope(user_id)
        counters = ("input_tokens", "output_tokens", "reasoning_tokens", "cache_read_tokens", "cache_write_tokens")
        # Group identity retains owner separation for historical unnamed Agents.
        identity = "COALESCE(s.agent_key, ''), COALESCE(s.user_id, ''), CASE WHEN COALESCE(s.agent_key, '') = '' THEN COALESCE(s.agent_name, '') ELSE '' END"
        select_identity = "COALESCE(s.agent_key, '') AS agent_key, COALESCE(s.user_id, '') AS user_id, CASE WHEN COALESCE(s.agent_key, '') = '' THEN COALESCE(s.agent_name, '') ELSE '' END AS legacy_name"
        groups = self._conn.execute(
            f"SELECT {select_identity}, MIN(COALESCE(NULLIF(s.agent_name, ''), a.display_name, '未知 Agent')) AS agent_name, MIN(COALESCE(a.machine_name, '')) AS machine_name, "
            "MIN(COALESCE(a.ip, '')) AS ip, MIN(COALESCE(u.username, '')) AS username, COUNT(*) AS scan_count, "
            "SUM(CASE WHEN EXISTS (SELECT 1 FROM scan_opencode_token_usage t WHERE t.scan_id = s.scan_id) THEN 1 ELSE 0 END) AS tracked_scan_count "
            "FROM scans s LEFT JOIN agents a ON a.agent_key = s.agent_key LEFT JOIN users u ON u.user_id = s.user_id WHERE " + where + " GROUP BY " + identity, params,
        ).fetchall()
        usage = self._conn.execute(f"SELECT {select_identity}, t.model, MIN(t.complete) AS complete, " + ", ".join(f"SUM(t.{key}) AS {key}" for key in counters)
            + " FROM scans s JOIN scan_opencode_token_usage t ON t.scan_id = s.scan_id WHERE " + where + " GROUP BY " + identity + ", t.model", params).fetchall()
        return {"groups": [dict(row) for row in groups], "usage": [dict(row) for row in usage]}
