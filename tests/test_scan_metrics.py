import unittest

from backend.models import FpReviewResult, Vulnerability
from backend.scan_metrics import calculate_issue_metrics, is_effective_fp_review_result


class ScanMetricsTests(unittest.TestCase):
    def test_effective_fp_result_requires_a_final_conclusion(self) -> None:
        base = {
            "vuln_index": 0,
            "verdict": "tp",
            "severity": "high",
            "created_at": "2026-08-04T00:00:00+00:00",
        }

        self.assertFalse(is_effective_fp_review_result(FpReviewResult(
            **base,
            reason="",
        )))
        self.assertFalse(is_effective_fp_review_result(FpReviewResult(
            **base,
            reason="Review incomplete: no result",
        )))
        self.assertTrue(is_effective_fp_review_result(FpReviewResult(
            **base,
            reason="reachable",
        )))

    def test_pending_analysis_is_not_counted_as_human_verdict(self) -> None:
        metrics = calculate_issue_metrics(
            [
                Vulnerability(
                    file="pending.c",
                    line=1,
                    function="pending",
                    vuln_type="npd",
                    severity="high",
                    description="pending",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="pending_analysis",
                ),
                Vulnerability(
                    file="confirmed.c",
                    line=2,
                    function="confirmed",
                    vuln_type="npd",
                    severity="high",
                    description="confirmed",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="confirmed",
                ),
                Vulnerability(
                    file="fp.c",
                    line=3,
                    function="fp",
                    vuln_type="npd",
                    severity="high",
                    description="fp",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="false_positive",
                ),
            ],
            {},
        )

        self.assertEqual(metrics.human_confirmed_count, 1)
        self.assertEqual(metrics.human_false_positive_count, 1)
        self.assertEqual(metrics.accuracy_basis_count, 3)
        self.assertEqual(metrics.accuracy, 0.3333)


if __name__ == "__main__":
    unittest.main()
