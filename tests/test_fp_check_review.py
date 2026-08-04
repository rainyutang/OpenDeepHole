import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from deephole_client.fp_review import run_fp_review


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
    "data_flow": {f"phase_1_{index}": True for index in range(1, 5)},
    "exploitability": {f"phase_2_{index}": True for index in range(1, 5)},
    "impact": {
        "confidentiality": True,
        "integrity": True,
        "availability": True,
        "authentication": True,
        "authorization": True,
        "primary_vs_defense_in_depth": True,
    },
    "poc": {f"phase_4_{index}": True for index in range(1, 6)},
    "devil_advocate": {
        f"challenge_{index}": True for index in range(1, 14)
    },
}


def _task_result(structured: dict, *, status: str = "success") -> SimpleNamespace:
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
        "vulnerability_report": "# original report",
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


def _standard(*, gates: dict | None = None) -> dict:
    return {
        "decision": "verdict",
        "reason": "standard path complete",
        "evidence": ["src/1.c:11"],
        "gates": gates or GATES_PASS,
        "completeness": STANDARD_COMPLETE,
        "stage_markdown": "# 标准验证",
    }


def _deep_stage(stage: str) -> dict:
    value = {
        "complete": True,
        "reason": f"{stage} complete",
        "evidence": ["src/2.c:12"],
        "stage_markdown": f"# {stage}",
    }
    if stage in DEEP_COMPLETE:
        value["completeness"] = DEEP_COMPLETE[stage]
    if stage == "gate_review":
        value["gates"] = GATES_PASS
    return value


async def _run(tmp: str, index: int, output=None):
    return await run_fp_review(
        method_id="fp_check",
        project_path=tmp,
        code_scan_path=tmp,
        work_dir=Path(tmp) / "review" / str(index),
        scan_id="scan-1",
        review_id="review-1",
        vuln_index=index,
        vulnerability=_vulnerability(index),
        required_capability="high",
        output=output,
    )


class FpCheckReviewTests(unittest.IsolatedAsyncioTestCase):
    async def test_standard_path_returns_one_binary_vulnerability_result(self) -> None:
        calls: list[str] = []

        async def invoke(**kwargs):
            calls.append(kwargs["task_name"])
            if kwargs["task_name"].endswith("-claim_context"):
                return _task_result(_claim("standard"))
            return _task_result(_standard())

        events: list[dict] = []
        with tempfile.TemporaryDirectory() as tmp, patch(
            "task_agent.run_opencode_task",
            new=invoke,
        ):
            result = await _run(tmp, 3, events.append)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["verdict"], "true_positive")
        self.assertEqual(
            set(result["stage_outputs"]),
            {"claim_context", "standard_verification"},
        )
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(event["data"].get("vuln_index") == 3 for event in events))

    async def test_deep_path_runs_declared_stages_and_writes_per_vulnerability_artifacts(self) -> None:
        async def invoke(**kwargs):
            stage = kwargs["task_name"].rsplit("-", 1)[-1]
            if kwargs["task_name"].endswith("-claim_context"):
                return _task_result(_claim("deep"))
            return _task_result(_deep_stage(stage))

        with tempfile.TemporaryDirectory() as tmp, patch(
            "task_agent.run_opencode_task",
            new=invoke,
        ):
            result = await _run(tmp, 4)
            artifacts = Path(tmp) / "review" / "4" / "artifacts"
            gate_artifact_exists = (artifacts / "gate_review.json").is_file()

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["verdict"], "true_positive")
        self.assertEqual(
            set(result["stage_outputs"]),
            {
                "claim_context",
                "data_flow",
                "exploitability",
                "impact",
                "poc",
                "devil_advocate",
                "gate_review",
            },
        )
        self.assertTrue(gate_artifact_exists)

    async def test_incomplete_stage_returns_error_without_batch_fields(self) -> None:
        async def invoke(**kwargs):
            if kwargs["task_name"].endswith("-claim_context"):
                return _task_result(_claim("standard"))
            return _task_result({}, status="failure")

        with tempfile.TemporaryDirectory() as tmp, patch(
            "task_agent.run_opencode_task",
            new=invoke,
        ):
            result = await _run(tmp, 5)

        self.assertEqual(result["status"], "error")
        self.assertEqual(
            set(result["stage_outputs"]),
            {"claim_context", "standard_verification"},
        )
        self.assertNotIn("results", result)
        self.assertNotIn("summary_markdown", result)
        self.assertNotIn("unresolved_indices", result)

    async def test_removed_batch_arguments_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(TypeError):
                await run_fp_review(
                    method_id="fp_check",
                    project_path=tmp,
                    code_scan_path=tmp,
                    work_dir=tmp,
                    scan_id="scan-1",
                    review_id="review-1",
                    vuln_index=0,
                    vulnerability=_vulnerability(0),
                    operation="summary",
                    vulnerabilities=[_vulnerability(0)],
                )
