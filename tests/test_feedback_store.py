import tempfile
import unittest
from pathlib import Path

from backend.models import FeedbackEntry
from backend.store.sqlite import SqliteScanStore


def make_feedback(entry_id: str, verdict: str, reason: str) -> FeedbackEntry:
    return FeedbackEntry(
        id=entry_id,
        project_id="project-1",
        vuln_type="npd",
        verdict=verdict,
        file="src/a.c",
        line=42,
        function="parse",
        description="possible null dereference",
        reason=reason,
        source_scan_id="scan-1",
        created_at="2026-01-01T00:00:00+00:00",
        updated_at="2026-01-01T00:00:00+00:00",
    )


class FeedbackStoreTests(unittest.TestCase):
    def test_upsert_feedback_for_report_updates_existing_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")

            first = store.upsert_feedback_for_report(
                make_feedback("first", "false_positive", "old reason")
            )
            second = make_feedback("second", "confirmed", "new reason")
            second.updated_at = "2026-01-02T00:00:00+00:00"
            updated = store.upsert_feedback_for_report(second)

            self.assertEqual(first.id, "first")
            self.assertEqual(updated.id, "first")
            self.assertEqual(updated.verdict, "confirmed")
            self.assertEqual(updated.reason, "new reason")
            self.assertEqual(updated.updated_at, "2026-01-02T00:00:00+00:00")

            entries = store.list_feedback_by_scan("scan-1")
            self.assertEqual([entry.id for entry in entries], ["first"])

    def test_upsert_feedback_for_report_removes_old_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            first = make_feedback("first", "false_positive", "old reason")
            duplicate = make_feedback("duplicate", "false_positive", "duplicate reason")
            duplicate.created_at = "2026-01-02T00:00:00+00:00"
            duplicate.updated_at = "2026-01-02T00:00:00+00:00"
            store.add_feedback(first)
            store.add_feedback(duplicate)

            updated = store.upsert_feedback_for_report(
                make_feedback("new", "false_positive", "replacement reason")
            )

            self.assertEqual(updated.id, "first")
            self.assertEqual(updated.reason, "replacement reason")
            entries = store.list_feedback_by_scan("scan-1")
            self.assertEqual([entry.id for entry in entries], ["first"])


if __name__ == "__main__":
    unittest.main()
