from deephole_client.fp_review import run_fp_review
from deephole_client.vulnerability_mining.report_schema import (
    AUDIT_JSON_REPAIR_OUTPUT_PROMPT,
)
from pathlib import Path
from task_agent.llm_json import LLMJsonParseError, parse_llm_json_schema
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import json
import tempfile
import unittest


def _prompt_schema(prompt: str) -> dict:
    raw = prompt.rsplit("```json\n", 1)[1].split("\n```", 1)[0]
    return json.loads(raw)


def _debate_result(
    verdict: str,
    *,
    reason: str = "stage result",
    evidence: str = "- 关键源码论据：`src/proto/parser.c:44`",
) -> SimpleNamespace:
    return SimpleNamespace(
        status="success",
        text="",
        structured={
            "verdict": verdict,
            "reason": reason,
            "evidence": evidence,
        },
        output_source={"model": "provider/model", "session_id": "ses-test"},
    )


def _final_tp_payload(
    *,
    severity: str = "high",
    file: str = "src/proto/parser.c",
    line: int = 44,
    function: str = "CopyPayload",
    vuln_type: str = "缓冲区越界写",
    description: str = "最终裁决纠正后的成因与影响说明。",
) -> dict:
    return {
        "verdict": "true_positive",
        "severity": severity,
        "vuln_type": vuln_type,
        "file": file,
        "line": line,
        "function": function,
        "description": description,
        "call_chain": (
            "```text\n"
            "HandlePacket: src/proto/handler.c:22\n"
            "└── ParseCommand: src/proto/parser.c:38\n"
            "    └── CopyPayload: src/proto/parser.c:44\n"
            "```"
        ),
        "vulnerable_code": (
            "`src/proto/parser.c:42-45`\n\n"
            "```c\n"
            "42 | void CopyPayload(char *dst, const unsigned char *src, size_t len)\n"
            "43 | {\n"
            "44 |     memcpy(dst, src, len); //[deephole] SINK：未校验目标容量写入 dst。\n"
            "45 | }\n"
            "```"
        ),
        "remediation": "在调用 `CopyPayload()` 前校验 `len <= sizeof(buf)`。",
    }


def _final_result(
    verdict: str,
    *,
    severity: str = "high",
    description: str = "最终裁决结论说明。",
) -> SimpleNamespace:
    structured = (
        _final_tp_payload(severity=severity, description=description)
        if verdict == "true_positive"
        else {
            "verdict": verdict,
            "description": description,
        }
    )
    return SimpleNamespace(
        status="success",
        text="",
        structured=structured,
        output_source={"model": "provider/judge", "session_id": "ses-judge"},
    )


def _vulnerability() -> dict:
    return {
        "index": 3,
        "file": "a.c",
        "line": 10,
        "function": "f",
        "vuln_type": "npd",
        "severity": "medium",
        "description": "错误的挖掘阶段描述",
        "ai_analysis": "analysis",
        "vulnerability_report": "# 原始漏洞报告\n\n来自漏洞挖掘阶段、含行号偏差的旧报告。",
    }


class FpReviewerEarlyExitTests(unittest.IsolatedAsyncioTestCase):
    async def test_prove_bug_false_positive_skips_later_stages(self) -> None:
        invoke = AsyncMock(
            return_value=_debate_result(
                "false_positive",
                reason="属于预期设计且已有长度限制",
                evidence="- `a.c:8` 已检查输入边界，无非预期影响。",
            )
        )
        with tempfile.TemporaryDirectory() as tmp, patch(
            "task_agent.run_opencode_task",
            new=invoke,
        ):
            result = await run_fp_review(
                method_id="adversarial",
                project_path=tmp,
                code_scan_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-1",
                vuln_index=3,
                vulnerability=_vulnerability(),
            )

        self.assertEqual(invoke.await_count, 1)
        self.assertIn("prove_bug", invoke.await_args.kwargs["task_name"])
        prompt = invoke.await_args.kwargs["prompt"]
        self.assertTrue(prompt.startswith("/prove-bug\n\n任务："))
        self.assertIn("## 原始漏洞报告", prompt)
        self.assertIn("来自漏洞挖掘阶段、含行号偏差的旧报告。", prompt)
        self.assertNotIn('"index"', prompt)
        self.assertNotIn('"feedback_entries"', prompt)
        self.assertNotIn('"history"', prompt)
        self.assertNotIn('"prior_stages"', prompt)
        self.assertNotIn("# 漏洞成立论证", prompt)
        self.assertIn("## 输出 JSON Schema", prompt)
        self.assertIn('"verdict"', prompt)
        self.assertTrue(prompt.endswith("\n\n请使用中文输出"))
        self.assertEqual(prompt.count("请使用中文输出"), 1)
        self.assertNotIn("invalid_json_retry_prompt", invoke.await_args.kwargs)
        schema = invoke.await_args.kwargs["output_schema"]
        self.assertEqual(
            set(schema["properties"]),
            {"verdict", "reason", "evidence"},
        )
        self.assertEqual(schema["properties"]["evidence"]["type"], "string")
        self.assertEqual(_prompt_schema(prompt), schema)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["verdict"], "false_positive")
        self.assertEqual(result["revised_severity"], "low")
        self.assertEqual(result["vulnerability_report"], "")
        self.assertEqual(list(result["stage_outputs"]), ["prove_bug"])
        self.assertIn("a.c:8", result["stage_outputs"]["prove_bug"])

    async def test_prove_bug_non_fp_runs_the_full_debate_and_regenerates_report(self) -> None:
        invoke = AsyncMock(side_effect=[
            _debate_result(
                "true_positive",
                reason="正方确认越界写",
                evidence="- 正方论据：`CopyPayload` 未校验栈数组容量。",
            ),
            _debate_result(
                "uncertain",
                reason="反方未找到充分阻断条件",
                evidence="- 反方论据：`ParseCommand:34` 仅校验接收长度。",
            ),
            _final_result(
                "true_positive",
                severity="high",
                description="外部报文长度未校验 64 字节目标栈容量导致越界写。",
            ),
        ])
        with tempfile.TemporaryDirectory() as tmp, patch(
            "task_agent.run_opencode_task",
            new=invoke,
        ):
            result = await run_fp_review(
                method_id="adversarial",
                project_path=tmp,
                code_scan_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-2",
                vuln_index=3,
                vulnerability=_vulnerability(),
            )

        self.assertEqual(invoke.await_count, 3)
        self.assertEqual(
            [
                call.kwargs["task_name"].rsplit("-", 1)[-1]
                for call in invoke.await_args_list
            ],
            ["prove_bug", "prove_fp", "final_judge"],
        )
        self.assertEqual(result["verdict"], "true_positive")
        self.assertEqual(result["revised_severity"], "high")
        self.assertEqual(
            result["reason"],
            "外部报文长度未校验 64 字节目标栈容量导致越界写。",
        )
        self.assertTrue(
            result["vulnerability_report"].startswith("**漏洞类型**：缓冲区越界写")
        )
        self.assertIn("**漏洞位置**：`src/proto/parser.c:44`", result["vulnerability_report"])
        self.assertIn("**漏洞函数**：`CopyPayload`", result["vulnerability_report"])
        self.assertIn("//[deephole] SINK", result["vulnerability_report"])
        self.assertIn("**修复建议**：", result["vulnerability_report"])
        self.assertNotIn("含行号偏差的旧报告", result["vulnerability_report"])

        prove_bug_prompt = invoke.await_args_list[0].kwargs["prompt"]
        prove_fp_prompt = invoke.await_args_list[1].kwargs["prompt"]
        final_prompt = invoke.await_args_list[2].kwargs["prompt"]
        self.assertTrue(prove_bug_prompt.startswith("/prove-bug\n\n任务："))
        self.assertTrue(prove_fp_prompt.startswith("/prove-fp\n\n任务："))
        self.assertNotIn("正方论据", prove_fp_prompt)
        self.assertIn("来自漏洞挖掘阶段、含行号偏差的旧报告。", prove_fp_prompt)
        self.assertTrue(final_prompt.startswith("/final-judge\n\n任务："))
        self.assertIn("## 原始漏洞报告", final_prompt)
        self.assertIn("## 正方论证报告", final_prompt)
        self.assertIn("正方论据", final_prompt)
        self.assertIn("## 反方论证报告", final_prompt)
        self.assertIn("反方论据", final_prompt)
        self.assertNotIn('"prior_stages"', final_prompt)
        self.assertEqual(
            invoke.await_args_list[2].kwargs["json_repair_output_prompt"],
            AUDIT_JSON_REPAIR_OUTPUT_PROMPT,
        )
        for call in invoke.await_args_list:
            self.assertTrue(call.kwargs["prompt"].endswith("\n\n请使用中文输出"))
            self.assertEqual(call.kwargs["prompt"].count("请使用中文输出"), 1)
            self.assertEqual(
                _prompt_schema(call.kwargs["prompt"]),
                call.kwargs["output_schema"],
            )

        for call in invoke.await_args_list[:2]:
            schema = call.kwargs["output_schema"]
            payload = _debate_result("uncertain").structured
            self.assertEqual(
                parse_llm_json_schema(json.dumps(payload), schema),
                payload,
            )
            with self.assertRaises(LLMJsonParseError):
                parse_llm_json_schema(
                    json.dumps({**payload, "stage_markdown": "extra"}),
                    schema,
                )

        final_schema = invoke.await_args_list[2].kwargs["output_schema"]
        self.assertEqual(
            final_schema["properties"]["verdict"]["enum"],
            ["true_positive", "false_positive"],
        )
        self.assertNotIn("stage_markdown", final_schema["properties"])
        self.assertNotIn("reason", final_schema["properties"])
        self.assertNotIn("report", final_schema["properties"])

        tp_payload = _final_tp_payload()
        self.assertEqual(
            parse_llm_json_schema(json.dumps(tp_payload), final_schema),
            tp_payload,
        )
        fp_payload = {
            "verdict": "false_positive",
            "description": "`src/proto/parser.c:34` 已校验容量上界，判定为误报。",
        }
        self.assertEqual(
            parse_llm_json_schema(json.dumps(fp_payload), final_schema),
            fp_payload,
        )

        # true_positive missing required report fields must fail schema validation
        with self.assertRaises(LLMJsonParseError) as missing_report:
            parse_llm_json_schema(
                json.dumps({"verdict": "true_positive", "description": "仅有描述"}),
                final_schema,
            )
        self.assertEqual(missing_report.exception.reason, "schema_mismatch")

        for verdict in ("uncertain", "", None, True, False, "tp", "fp"):
            with self.subTest(rejected_verdict=verdict):
                payload = {**tp_payload, "verdict": verdict}
                with self.assertRaises(LLMJsonParseError) as caught:
                    parse_llm_json_schema(json.dumps(payload), final_schema)
                self.assertEqual(caught.exception.reason, "schema_mismatch")

    async def test_final_judge_false_positive_and_failure_preserve_stage_reports(self) -> None:
        failed_stage = SimpleNamespace(
            status="failure",
            text="Final verdict still violates the JSON Schema after retries",
            structured=None,
            output_source={},
        )
        for final_stage in (
            _final_result("false_positive", description="已有完整容量校验"),
            failed_stage,
        ):
            with self.subTest(final_status=final_stage.status):
                invoke = AsyncMock(side_effect=[
                    _debate_result("true_positive", reason="正方报告", evidence="正方论据正文"),
                    _debate_result("uncertain", reason="反方报告", evidence="反方论据正文"),
                    final_stage,
                ])
                with tempfile.TemporaryDirectory() as tmp, patch(
                    "task_agent.run_opencode_task", new=invoke,
                ):
                    result = await run_fp_review(
                        method_id="adversarial",
                        project_path=tmp,
                        code_scan_path=tmp,
                        work_dir=Path(tmp) / "work",
                        scan_id="scan-1",
                        review_id="review-final",
                        vuln_index=3,
                        vulnerability=_vulnerability(),
                    )
                self.assertEqual(invoke.await_count, 3)
                self.assertEqual(
                    list(result["stage_outputs"]),
                    ["prove_bug", "prove_fp", "final_judge"],
                )
                self.assertIn("正方论据正文", result["stage_outputs"]["prove_bug"])
                self.assertIn("反方论据正文", result["stage_outputs"]["prove_fp"])
                if final_stage.status == "success":
                    self.assertEqual(result["status"], "success")
                    self.assertEqual(result["verdict"], "false_positive")
                    self.assertEqual(result["revised_severity"], "low")
                    self.assertEqual(result["vulnerability_report"], "")
                    self.assertEqual(result["reason"], "已有完整容量校验")
                else:
                    self.assertEqual(result["status"], "error")
                    self.assertNotIn("verdict", result)
                    self.assertEqual(result["error_message"], failed_stage.text)

    async def test_history_input_no_longer_adds_history_match_stage(self) -> None:
        invoke = AsyncMock(return_value=_debate_result("false_positive"))
        vulnerability = _vulnerability()
        vulnerability["variant_of"] = "legacy-history-pattern"
        with tempfile.TemporaryDirectory() as tmp, patch(
            "task_agent.run_opencode_task",
            new=invoke,
        ):
            result = await run_fp_review(
                method_id="adversarial",
                project_path=tmp,
                code_scan_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-3",
                vuln_index=3,
                vulnerability=vulnerability,
                history=[{"reference": "known issue"}],
            )

        self.assertEqual(invoke.await_count, 1)
        self.assertIn("prove_bug", invoke.await_args.kwargs["task_name"])
        self.assertNotIn("history_match", invoke.await_args.kwargs["task_name"])
        self.assertNotIn("known issue", invoke.await_args.kwargs["prompt"])
        self.assertNotIn("legacy-history-pattern", invoke.await_args.kwargs["prompt"])
        self.assertEqual(result["verdict"], "false_positive")
        self.assertEqual(result["revised_severity"], "low")
