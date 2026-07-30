import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from deephole_client.fp_check_review import run_fp_check_review


GATES_PASS = {
    "process": True,
    "reachability": True,
    "real_impact": True,
    "poc_validation": True,
    "math_bounds": True,
    "environment": True,
}
STANDARD_COMPLETE = {
    "claim_restatement": True,
    "data_flow": True,
    "escalation_checkpoint_one": True,
    "exploitability": True,
    "impact": True,
    "escalation_checkpoint_two": True,
    "poc": True,
    "devil_advocate": True,
    "gate_review": True,
}
DEEP_COMPLETE = {
    "data_flow": {
        "phase_1_1": True,
        "phase_1_2": True,
        "phase_1_3": True,
        "phase_1_4": True,
    },
    "exploitability": {
        "phase_2_1": True,
        "phase_2_2": True,
        "phase_2_3": True,
        "phase_2_4": True,
    },
    "impact": {
        "confidentiality": True,
        "integrity": True,
        "availability": True,
        "authentication": True,
        "authorization": True,
        "primary_vs_defense_in_depth": True,
    },
    "poc": {
        "phase_4_1": True,
        "phase_4_2": True,
        "phase_4_3": True,
        "phase_4_4": True,
        "phase_4_5": True,
    },
    "devil_advocate": {
        f"challenge_{index}": True
        for index in range(1, 14)
    },
}


def _result(structured: dict, *, status: str = "success") -> SimpleNamespace:
    return SimpleNamespace(
        status=status,
        text="" if status == "success" else "stage failed",
        structured=structured if status == "success" else None,
        output_source={"model": "provider/model", "session_id": "ses-test"},
    )


def _vulnerability(index: int) -> dict:
    return {
        "index": index,
        "file": f"src/{index}.c",
        "line": 10 + index,
        "function": f"handler_{index}",
        "vuln_type": "out_of_bounds",
        "severity": "high",
        "description": f"finding {index}",
        "ai_analysis": "analysis",
    }


def _claim(route: str) -> dict:
    return {
        "route": route,
        "claim": "attacker reaches an unsafe operation",
        "root_cause": "missing validation",
        "trigger": "crafted request",
        "claimed_impact": "availability and integrity",
        "threat_model": "unauthenticated remote attacker",
        "bug_class": "memory corruption",
        "stage_markdown": "# 主张与上下文",
    }


def _phase(stage: str) -> dict:
    value = {
        "complete": True,
        "reason": f"{stage} complete",
        "evidence": ["src/1.c:11"],
        "stage_markdown": f"# {stage}",
    }
    if stage in DEEP_COMPLETE:
        value["completeness"] = DEEP_COMPLETE[stage]
    return value


class FpCheckReviewTests(unittest.IsolatedAsyncioTestCase):
    async def test_item_operation_runs_standard_or_deep_stages(self) -> None:
        calls: list[str] = []

        async def invoke(**kwargs):
            name = kwargs["task_name"]
            calls.append(name)
            if name.endswith("-1-claim_context"):
                return _result(_claim("standard"))
            if name.endswith("-2-claim_context"):
                return _result(_claim("deep"))
            if name.endswith("-1-standard_verification"):
                gates = {**GATES_PASS, "reachability": False}
                return _result({
                    "decision": "verdict",
                    "reason": "caller rejects the crafted length",
                    "evidence": ["src/1.c:11"],
                    "gates": gates,
                    "completeness": STANDARD_COMPLETE,
                    "stage_markdown": "# 标准验证",
                })
            if name.endswith("-2-gate_review"):
                return _result({
                    **_phase("gate_review"),
                    "gates": GATES_PASS,
                })
            return _result(_phase(name.rsplit("-", 1)[-1]))

        with tempfile.TemporaryDirectory() as tmp, patch(
            "deephole_client.fp_check_review.runner.run_opencode_task",
            new=invoke,
        ):
            standard_result = await run_fp_check_review(
                operation="item",
                project_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-1",
                vulnerabilities=[_vulnerability(1)],
            )
            deep_result = await run_fp_check_review(
                operation="item",
                project_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-1",
                vulnerabilities=[_vulnerability(2)],
            )

        self.assertEqual(
            standard_result["results"][0]["verdict"],
            "false_positive",
        )
        self.assertEqual(
            deep_result["results"][0]["verdict"],
            "true_positive",
        )
        deep_stages = [
            "data_flow",
            "exploitability",
            "impact",
            "poc",
            "devil_advocate",
            "gate_review",
        ]
        self.assertEqual(
            [
                name.rsplit("-", 1)[-1]
                for name in calls
                if any(name.endswith(f"-{stage}") for stage in deep_stages)
            ],
            deep_stages,
        )

    async def test_incomplete_stage_never_generates_binary_verdict(self) -> None:
        async def invoke(**kwargs):
            name = kwargs["task_name"]
            if name.endswith("-claim_context"):
                return _result(_claim("deep"))
            if name.endswith("-data_flow"):
                return _result({}, status="failure")
            if name.endswith("-exploit-chain"):
                return _result({
                    "complete": True,
                    "chains": [],
                    "summary_markdown": "",
                })
            return _result(_phase(name.rsplit("-", 1)[-1]))

        with tempfile.TemporaryDirectory() as tmp, patch(
            "deephole_client.fp_check_review.runner.run_opencode_task",
            new=invoke,
        ):
            result = await run_fp_check_review(
                operation="item",
                project_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-2",
                vulnerabilities=[_vulnerability(4)],
            )

        self.assertEqual(result["results"], [])
        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["unresolved_indices"], [4])
        self.assertEqual(result["status"], "error")
        self.assertIn("stage failed", result["error_message"])
        self.assertEqual(result["summary_markdown"], "")

    async def test_valid_exploit_chain_is_summary_only(self) -> None:
        async def invoke(**kwargs):
            return _result({
                "complete": True,
                "chains": [{
                    "title": "combined authorization bypass",
                    "member_indices": [7, 8],
                    "reason": "the first issue supplies the second precondition",
                    "gates": GATES_PASS,
                }],
                "summary_markdown": "# 有效攻击链",
            })

        with tempfile.TemporaryDirectory() as tmp, patch(
            "deephole_client.fp_check_review.runner.run_opencode_task",
            new=invoke,
        ):
            result = await run_fp_check_review(
                operation="summary",
                project_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-3",
                vulnerabilities=[_vulnerability(7), _vulnerability(8)],
                individual_results=[
                    {
                        "vuln_index": 7,
                        "verdict": "fp",
                        "reason": "individually blocked",
                    },
                    {
                        "vuln_index": 8,
                        "verdict": "fp",
                        "reason": "individually blocked",
                    },
                ],
                unresolved_indices=[],
            )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["chains"][0]["member_indices"], [7, 8])
        self.assertIn("漏洞 #7、漏洞 #8", result["summary_markdown"])
        self.assertNotIn("results", result)

    async def test_item_uses_tolerant_schema_retry_and_inherited_output(self) -> None:
        calls: list[dict] = []

        async def invoke(**kwargs):
            calls.append(kwargs)
            if kwargs["task_name"].endswith("-claim_context"):
                return _result(_claim("standard"))
            return _result({
                "decision": "verdict",
                "reason": "validated",
                "evidence": ["src/1.c:11"],
                "gates": GATES_PASS,
                "completeness": STANDARD_COMPLETE,
                "stage_markdown": "# 标准验证",
            })

        with tempfile.TemporaryDirectory() as tmp, patch(
            "deephole_client.fp_check_review.runner.run_opencode_task",
            new=invoke,
        ):
            result = await run_fp_check_review(
                operation="item",
                project_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-4",
                vulnerabilities=[_vulnerability(1)],
            )

        self.assertEqual(result["status"], "success")
        self.assertTrue(all(
            call["output_schema"]["additionalProperties"]
            for call in calls
        ))
        self.assertTrue(all(
            "invalid_json_retry_prompt" in call
            for call in calls
        ))
        self.assertTrue(all("output" not in call for call in calls))
