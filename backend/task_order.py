"""Execution-time ordering shared by task history queries and their cursors."""

from __future__ import annotations

import re
from datetime import datetime, timezone


# Restrict parsing to the ISO timestamps emitted by Agents. In particular,
# PostgreSQL's relative dates ("now", "today") must never move a page boundary.
TASK_TIME_PATTERN = (
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-5][0-9]"
    r"([.][0-9]{1,6})?(Z|[+-][0-9]{2}:[0-9]{2})?"
)
MISSING_TASK_TIME = "-"


def task_sort_time(finished_at: object, started_at: object = None) -> str:
    """Return fixed-width UTC microseconds, or a key older than valid times."""
    for value in (finished_at, started_at):
        if not isinstance(value, str) or not re.fullmatch(TASK_TIME_PATTERN, value):
            continue
        try:
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        except (ValueError, OverflowError):
            continue
    return MISSING_TASK_TIME


def task_sort_time_sql(*, postgres: bool) -> str:
    if not postgres:
        return "task_sort_time(json_extract(v.metadata_json, '$.finished_at'), json_extract(v.metadata_json, '$.started_at'))"
    times = []
    for field in ("finished_at", "started_at"):
        value = f"(CAST(v.metadata_json AS jsonb) ->> '{field}')"
        zoned = f"(CASE WHEN {value} ~ '(Z|[+-][0-9]{{2}}:[0-9]{{2}})$' THEN {value} ELSE {value} || '+00:00' END)"
        times.append(
            f"CASE WHEN {value} ~ '^{TASK_TIME_PATTERN}$' "
            f"AND substring({value}, 12, 2) < '24' "
            f"AND pg_input_is_valid({zoned}, 'timestamp with time zone') "
            f"THEN to_char(CAST({zoned} AS timestamp with time zone) AT TIME ZONE 'UTC', "
            "'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') END"
        )
    return f"COALESCE({', '.join(times)}, '{MISSING_TASK_TIME}')"
