import tempfile
import unittest
from pathlib import Path

from backend.models import FpReviewResult
from backend.store.sqlite import SqliteScanStore


class FpReviewStoreTests(unittest.TestCase):
    def test_lists_results_for_scan_oldest_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.create_fp_review_job("old", "scan-1", 1, "2026-01-01T00:00:00+00:00")
            store.create_fp_review_job("new", "scan-1", 1, "2026-01-02T00:00:00+00:00")
            store.add_fp_review_result(
                "old",
                FpReviewResult(
                    vuln_index=0,
                    verdict="fp",
                    reason="old false positive",
                    created_at="2026-01-01T00:01:00+00:00",
                ),
            )
            store.add_fp_review_result(
                "new",
                FpReviewResult(
                    vuln_index=0,
                    verdict="tp",
                    reason="new true positive",
                    created_at="2026-01-02T00:01:00+00:00",
                ),
            )

            results = store.list_fp_review_results_by_scan("scan-1")

            self.assertEqual([r.reason for r in results], ["old false positive", "new true positive"])


if __name__ == "__main__":
    unittest.main()
