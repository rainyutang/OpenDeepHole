import unittest

from backend.models import FpReviewResult, Vulnerability
from backend.scan_metrics import (
    calculate_issue_metrics,
    calculate_validated_issue_count,
    is_effective_fp_review_result,
    latest_fp_review_result_map,
)


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
        self.assertEqual(metrics.suspected_issue_count, 1)
        self.assertEqual(metrics.accuracy_basis_count, 3)
        self.assertEqual(metrics.accuracy, 0.3333)

    def test_suspected_count_excludes_effective_fp_review_false_positives(self) -> None:
        vulnerability = Vulnerability(
            file="fp.c",
            line=3,
            function="fp",
            vuln_type="npd",
            severity="high",
            description="fp",
            ai_analysis="analysis",
            confirmed=True,
            ai_verdict="confirmed",
        )
        fp_results = latest_fp_review_result_map([
            FpReviewResult(
                vuln_index=0,
                verdict="fp",
                severity="low",
                reason="false positive",
                created_at="2026-08-05T00:00:00+00:00",
            ),
        ])

        metrics = calculate_issue_metrics([vulnerability], fp_results)

        self.assertEqual(metrics.effective_issue_count, 0)
        self.assertEqual(metrics.suspected_issue_count, 0)

    def test_validated_issue_count_excludes_fp_nonissues_and_running_validations(self) -> None:
        vulnerabilities = [
            Vulnerability(
                file=f"issue-{index}.c",
                line=index + 1,
                function=f"issue_{index}",
                vuln_type="npd",
                severity="high",
                description="issue",
                ai_analysis="analysis",
                confirmed=index != 2,
                ai_verdict="confirmed" if index != 2 else "not_confirmed",
            )
            for index in range(4)
        ]
        fp_results = latest_fp_review_result_map([
            FpReviewResult(
                vuln_index=1,
                verdict="fp",
                severity="low",
                reason="false positive",
                created_at="2026-08-05T00:00:00+00:00",
            ),
        ])

        count = calculate_validated_issue_count(
            vulnerabilities,
            fp_results,
            {
                0: ("verified", False),
                1: ("success", False),
                2: ("success", False),
                3: ("running", True),
            },
        )

        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
