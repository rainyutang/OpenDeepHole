"""Unit and integration tests for DeepHole网络安全红线排查引擎."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from backend.models import REDLINE_AUDIT_ENGINE_ID, REDLINE_AUDIT_ENGINE_LABEL, Vulnerability
from deephole_client.scan_paths import resolve_scan_scope
from deephole_client.vulnerability_mining.dedup import VulnerabilityDeduplicator
from deephole_client.vulnerability_mining.engines.redline_audit.engine import run as run_redline_engine
from deephole_client.vulnerability_mining.engines.redline_audit.prompt import (
    REDLINE_AUDIT_SCHEMA,
    build_redline_prompt,
)
from deephole_client.vulnerability_mining.engines.redline_audit.report import (
    build_redline_vulnerability_report,
    normalize_redline_vulnerability,
)
from deephole_client.vulnerability_mining.engines.redline_audit.validator import (
    normalize_redline_text,
    validate_redline_structured_result,
)
from deephole_client.vulnerability_mining.runtime import load_mining_engines
from task_agent.api import OpenCodeResult
from task_agent.llm_json import LLMJsonParseError, parse_llm_json_schema


SAMPLE_ITEM = {
    "item_id": "item-5-2-2",
    "code": "5.2.2",
    "security_attribute": "产品开发、发布和安装安全",
    "attribute_description": "禁止恶意软件。",
    "requirement": "产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。",
    "category": "A1",
    "guidance": "重点检查后台静默联网上报和广告拉取线程。",
    "remark": "核心合规项",
}


class RedlinePromptSchemaValidatorTests(unittest.TestCase):
    def test_engine_manifest_discovers_cleanly(self) -> None:
        registry = load_mining_engines()
        self.assertEqual(registry.errors, [])
        loaded = registry.get(REDLINE_AUDIT_ENGINE_ID)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.manifest.label, REDLINE_AUDIT_ENGINE_LABEL)
        self.assertFalse(loaded.manifest.fp_review)

    def test_normalize_redline_text_ignores_punctuation_and_whitespace(self) -> None:
        expected = "产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。"
        same_with_diff_punct = "  产品软件禁止存在发送恶意广告,吸费;恶意消耗流量等行为! "
        different_text = "产品软件禁止存在发送广告等行为。"
        with_code_prefix = "5.2.2 产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。"

        self.assertEqual(
            normalize_redline_text(expected),
            normalize_redline_text(same_with_diff_punct),
        )
        self.assertNotEqual(
            normalize_redline_text(expected),
            normalize_redline_text(different_text),
        )
        self.assertNotEqual(
            normalize_redline_text(expected),
            normalize_redline_text(with_code_prefix),
        )

    def test_prompt_excludes_code_and_expands_optional_fields(self) -> None:
        prompt = build_redline_prompt(
            security_attribute=SAMPLE_ITEM["security_attribute"],
            attribute_description=SAMPLE_ITEM["attribute_description"],
            requirement=SAMPLE_ITEM["requirement"],
            category=SAMPLE_ITEM["category"],
            guidance=SAMPLE_ITEM["guidance"],
            remark=SAMPLE_ITEM["remark"],
            project_path="/repo/demo",
            scan_paths="/repo/demo/src",
        )
        self.assertNotIn("5.2.2", prompt)
        self.assertNotIn("item-5-2-2", prompt)
        self.assertIn("- 安全属性：产品开发、发布和安装安全", prompt)
        self.assertIn("- 属性描述：禁止恶意软件。", prompt)
        self.assertIn("- 红线要求：产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。", prompt)
        self.assertIn("- 分类：A1", prompt)
        self.assertIn("- 解读及指导：重点检查后台静默联网上报和广告拉取线程。", prompt)
        self.assertIn("- 备注：核心合规项", prompt)

        minimal = build_redline_prompt(
            security_attribute=SAMPLE_ITEM["security_attribute"],
            attribute_description=SAMPLE_ITEM["attribute_description"],
            requirement=SAMPLE_ITEM["requirement"],
            category="",
            guidance="",
            remark="",
            project_path="/repo/demo",
            scan_paths="/repo/demo/src",
        )
        self.assertNotIn("- 分类：", minimal)
        self.assertNotIn("- 解读及指导：", minimal)
        self.assertNotIn("- 备注：", minimal)

    def test_schema_accepts_minimal_false_and_full_true(self) -> None:
        parsed_false = parse_llm_json_schema('{"found": false}', REDLINE_AUDIT_SCHEMA)
        self.assertEqual(parsed_false, {"found": False})

        payload_true = {
            "found": True,
            "redline_requirement": SAMPLE_ITEM["requirement"],
            "file": "src/bg.c",
            "line": 12,
            "function": "SendAd",
            "description": "后台发送未授权广告请求。",
            "evidence": "`src/bg.c:12`\n\n```c\n12 | HttpPost();\n```",
            "remediation": "移除未授权广告上报。",
        }
        parsed_true = parse_llm_json_schema(
            json.dumps(payload_true, ensure_ascii=False),
            REDLINE_AUDIT_SCHEMA,
        )
        self.assertEqual(parsed_true["file"], "src/bg.c")

        with self.assertRaises(LLMJsonParseError):
            parse_llm_json_schema('{"found": true, "file": "src/bg.c"}', REDLINE_AUDIT_SCHEMA)

    def test_semantic_validation_checks_text_path_line_and_previous_locations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "repo"
            src = project / "src"
            other = project / "other"
            src.mkdir(parents=True)
            other.mkdir(parents=True)
            target_file = src / "bg.c"
            target_file.write_text("line1\nline2\nline3\n", encoding="utf-8")
            outside_file = other / "skip.c"
            outside_file.write_text("line1\n", encoding="utf-8")
            scope = resolve_scan_scope(project, src, [src])

            base_payload = {
                "found": True,
                "redline_requirement": "产品软件禁止存在发送恶意广告,吸费,恶意消耗流量等行为",
                "file": "src/bg.c",
                "line": 2,
                "function": "SendAd",
                "description": "静默广告上报",
                "evidence": "`src/bg.c:2`\n```c\n2 | line2\n```",
                "remediation": "移除广告逻辑",
            }
            ok = validate_redline_structured_result(
                base_payload,
                expected_requirement=SAMPLE_ITEM["requirement"],
                scan_scope=scope,
            )
            self.assertTrue(ok.ok)
            self.assertEqual(ok.canonical_file, "src/bg.c")
            self.assertEqual(ok.line, 2)

            mismatch = validate_redline_structured_result(
                {**base_payload, "redline_requirement": "完全不同的红线"},
                expected_requirement=SAMPLE_ITEM["requirement"],
                scan_scope=scope,
            )
            self.assertFalse(mismatch.ok)
            self.assertTrue(mismatch.requirement_mismatch)

            out_of_scope = validate_redline_structured_result(
                {**base_payload, "file": "other/skip.c", "line": 1},
                expected_requirement=SAMPLE_ITEM["requirement"],
                scan_scope=scope,
            )
            self.assertFalse(out_of_scope.ok)

            out_of_range = validate_redline_structured_result(
                {**base_payload, "line": 99},
                expected_requirement=SAMPLE_ITEM["requirement"],
                scan_scope=scope,
            )
            self.assertFalse(out_of_range.ok)

            dup_prev = validate_redline_structured_result(
                base_payload,
                expected_requirement=SAMPLE_ITEM["requirement"],
                scan_scope=scope,
                previous_locations={("src/bg.c", 2)},
            )
            self.assertFalse(dup_prev.ok)

            # Subdirectory-relative path, backtick wrapper, and :line suffix normalize cleanly
            sub_relative = validate_redline_structured_result(
                {**base_payload, "file": "bg.c"},
                expected_requirement=SAMPLE_ITEM["requirement"],
                scan_scope=scope,
            )
            self.assertTrue(sub_relative.ok)
            self.assertEqual(sub_relative.canonical_file, "src/bg.c")

            wrapped_with_line = validate_redline_structured_result(
                {**base_payload, "file": "`src/bg.c:2`"},
                expected_requirement=SAMPLE_ITEM["requirement"],
                scan_scope=scope,
            )
            self.assertTrue(wrapped_with_line.ok)
            self.assertEqual(wrapped_with_line.canonical_file, "src/bg.c")

    def test_final_report_field_order_and_vulnerability_fields(self) -> None:
        report = build_redline_vulnerability_report(
            SAMPLE_ITEM,
            file="src/bg.c",
            line=84,
            function="SendHiddenAdLoop",
            description="后台静默发起广告请求。",
            evidence="`src/bg.c:84`\n\n```c\n84 | HttpPost();\n```",
            remediation="移除未授权广告逻辑。",
        )
        code_pos = report.index("**编号**：5.2.2")
        req_pos = report.index("**红线要求**：产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。")
        attr_pos = report.index("**安全属性**：产品开发、发布和安装安全")
        desc_pos = report.index("**属性描述**：禁止恶意软件。")
        cat_pos = report.index("**分类**：A1")
        loc_pos = report.index("**违规位置**：`src/bg.c:84`")
        self.assertTrue(code_pos < req_pos < attr_pos < desc_pos < cat_pos < loc_pos)

        vuln = normalize_redline_vulnerability(
            SAMPLE_ITEM,
            structured={
                "found": True,
                "redline_requirement": SAMPLE_ITEM["requirement"],
                "file": "src/bg.c",
                "line": 84,
                "function": "SendHiddenAdLoop",
                "description": "后台静默发起广告请求。",
                "evidence": "`src/bg.c:84`\n\n```c\n84 | HttpPost();\n```",
                "remediation": "移除未授权广告逻辑。",
            },
            canonical_file="src/bg.c",
            line=84,
            task_id="redline-audit-abc-round-1",
            output_source={"model": "demo/model"},
        )
        self.assertEqual(vuln["engine_id"], REDLINE_AUDIT_ENGINE_ID)
        self.assertEqual(vuln["engine_label"], REDLINE_AUDIT_ENGINE_LABEL)
        self.assertEqual(vuln["analysis_source"], REDLINE_AUDIT_ENGINE_ID)
        self.assertEqual(vuln["vuln_type"], "5.2.2 禁止恶意软件")
        self.assertTrue(vuln["confirmed"])
        self.assertEqual(vuln["ai_verdict"], "confirmed")


class RedlineEngineExecutionTests(unittest.IsolatedAsyncioTestCase):
    def _make_workspace(self, tmp: str) -> tuple[Path, Path, Path]:
        project = Path(tmp) / "project"
        src = project / "src"
        work = Path(tmp) / "work"
        src.mkdir(parents=True)
        work.mkdir(parents=True)
        (src / "bg.c").write_text("\n".join(f"int line_{i} = {i};" for i in range(1, 30)) + "\n", encoding="utf-8")
        return project, src, work

    def _config(self) -> SimpleNamespace:
        return SimpleNamespace(
            vulnerability_mining=SimpleNamespace(required_capability="high", concurrency=2),
            opencode=SimpleNamespace(concurrency=2),
        )

    async def test_found_false_skips_validation_and_stops_immediately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project, src, work = self._make_workspace(tmp)
            calls: list[dict] = []
            pushed_tasks = []

            class FakeReporter:
                async def get_redline_audit_tasks(self, scan_id: str):
                    return []

                async def push_redline_audit_task(self, scan_id: str, task):
                    pushed_tasks.append(task.model_copy(deep=True))
                    return task

            async def fake_run_opencode_task(**kwargs):
                calls.append(kwargs)
                return OpenCodeResult(
                    session_id="sess-false",
                    status="success",
                    text='{"found": false}',
                    structured={"found": False},
                    model="provider/model",
                    output_source={"serve_session_id": "sess-false"},
                )

            reported: list[dict] = []

            async def report_vulns(items):
                reported.extend(items)
                return [(item, {"index": idx}) for idx, item in enumerate(items)]

            with patch(
                "deephole_client.vulnerability_mining.engines.redline_audit.engine.run_opencode_task",
                new=AsyncMock(side_effect=fake_run_opencode_task),
            ):
                outcome = await run_redline_engine(
                    scan_id="scan-rl-1",
                    project_path=project,
                    code_scan_path=src,
                    code_scan_paths=[src],
                    work_dir=work,
                    config=self._config(),
                    reporter=FakeReporter(),
                    redline_items=[SAMPLE_ITEM],
                    is_resume=False,
                    output=AsyncMock(),
                    cancel_event=threading.Event(),
                    report_vulnerabilities=report_vulns,
                )

            self.assertEqual(outcome["status"], "success")
            self.assertEqual(outcome["processed_candidates"], 1)
            self.assertEqual(outcome["total_candidates"], 1)
            self.assertEqual(len(calls), 1)
            self.assertEqual(reported, [])
            completed = [t for t in pushed_tasks if t.status == "completed"]
            self.assertEqual(len(completed), 1)
            self.assertIs(completed[0].found, False)
            self.assertEqual(completed[0].stop_reason, "no_finding")

    async def test_same_session_retry_then_round2_receives_previous_finding_and_stops(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project, src, work = self._make_workspace(tmp)
            calls: list[dict] = []
            pushed_tasks = []

            class FakeReporter:
                async def get_redline_audit_tasks(self, scan_id: str):
                    return []

                async def push_redline_audit_task(self, scan_id: str, task):
                    pushed_tasks.append(task.model_copy(deep=True))
                    return task

            responses = [
                # Round 1 attempt 1: wrong redline_requirement
                OpenCodeResult(
                    session_id="sess-r1",
                    status="success",
                    text="{}",
                    structured={
                        "found": True,
                        "redline_requirement": "改写后的错误红线描述",
                        "file": "src/bg.c",
                        "line": 5,
                        "function": "SendAdA",
                        "description": "违规点A",
                        "evidence": "`src/bg.c:5`\n```c\n5 | int line_5 = 5;\n```",
                        "remediation": "修复A",
                    },
                    model="provider/model",
                    output_source={"serve_session_id": "sess-r1"},
                ),
                # Round 1 retry 1 on SAME session: fixed requirement (different punctuation allowed)
                OpenCodeResult(
                    session_id="sess-r1",
                    status="success",
                    text="{}",
                    structured={
                        "found": True,
                        "redline_requirement": "产品软件禁止存在发送恶意广告,吸费,恶意消耗流量等行为",
                        "file": "src/bg.c",
                        "line": 5,
                        "function": "SendAdA",
                        "description": "违规点A",
                        "evidence": "`src/bg.c:5`\n```c\n5 | int line_5 = 5;\n```",
                        "remediation": "修复A",
                    },
                    model="provider/model",
                    output_source={"serve_session_id": "sess-r1"},
                ),
                # Round 2: no more findings
                OpenCodeResult(
                    session_id="sess-r2",
                    status="success",
                    text='{"found": false}',
                    structured={"found": False},
                    model="provider/model",
                    output_source={"serve_session_id": "sess-r2"},
                ),
            ]

            async def fake_run_opencode_task(**kwargs):
                calls.append(kwargs)
                return responses.pop(0)

            reported: list[dict] = []

            async def report_vulns(items):
                start = len(reported)
                reported.extend(items)
                return [(item, {"index": start + offset}) for offset, item in enumerate(items)]

            with patch(
                "deephole_client.vulnerability_mining.engines.redline_audit.engine.run_opencode_task",
                new=AsyncMock(side_effect=fake_run_opencode_task),
            ):
                outcome = await run_redline_engine(
                    scan_id="scan-rl-2",
                    project_path=project,
                    code_scan_path=src,
                    code_scan_paths=[src],
                    work_dir=work,
                    config=self._config(),
                    reporter=FakeReporter(),
                    redline_items=[SAMPLE_ITEM],
                    is_resume=False,
                    output=AsyncMock(),
                    cancel_event=threading.Event(),
                    report_vulnerabilities=report_vulns,
                )

            self.assertEqual(outcome["status"], "success")
            self.assertEqual(len(calls), 3)
            # Retry 1 reuses exact same session_id
            self.assertNotIn("session_id", calls[0])
            self.assertEqual(calls[1]["session_id"], "sess-r1")
            self.assertIn("第 1/2 次纠正", calls[1]["prompt"])
            # Round 2 injects Round 1 finding and starts a fresh session
            self.assertNotIn("session_id", calls[2])
            self.assertIn("src/bg.c:5", calls[2]["prompt"])
            self.assertIn("SendAdA", calls[2]["prompt"])
            self.assertEqual(len(reported), 1)
            self.assertIn("**编号**：5.2.2", reported[0]["vulnerability_report"])
            self.assertIn("**红线要求**：产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。", reported[0]["vulnerability_report"])
            round1_done = [t for t in pushed_tasks if t.iteration == 1 and t.status == "completed"][-1]
            self.assertEqual(round1_done.validation_retries, 1)
            self.assertEqual(round1_done.result_vuln_indexes, [0])

    async def test_validation_fails_after_max_two_same_session_retries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project, src, work = self._make_workspace(tmp)
            calls: list[dict] = []

            async def fake_run_opencode_task(**kwargs):
                calls.append(kwargs)
                return OpenCodeResult(
                    session_id="sess-bad",
                    status="success",
                    text="{}",
                    structured={
                        "found": True,
                        "redline_requirement": "始终不一致的红线要求",
                        "file": "src/bg.c",
                        "line": 3,
                        "function": "BadFn",
                        "description": "描述",
                        "evidence": "证据",
                        "remediation": "修复",
                    },
                    model="provider/model",
                    output_source={"serve_session_id": "sess-bad"},
                )

            with patch(
                "deephole_client.vulnerability_mining.engines.redline_audit.engine.run_opencode_task",
                new=AsyncMock(side_effect=fake_run_opencode_task),
            ):
                outcome = await run_redline_engine(
                    scan_id="scan-rl-3",
                    project_path=project,
                    code_scan_path=src,
                    code_scan_paths=[src],
                    work_dir=work,
                    config=self._config(),
                    reporter=None,
                    redline_items=[SAMPLE_ITEM],
                    is_resume=False,
                    output=AsyncMock(),
                    cancel_event=threading.Event(),
                    report_vulnerabilities=AsyncMock(return_value=[]),
                )

            self.assertEqual(outcome["status"], "error")
            # 1 initial + 2 same-session retries = 3 total calls
            self.assertEqual(len(calls), 3)
            self.assertEqual(calls[1]["session_id"], "sess-bad")
            self.assertEqual(calls[2]["session_id"], "sess-bad")

    async def test_caps_at_five_rounds_and_supports_resume_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project, src, work = self._make_workspace(tmp)
            round_counter = {"n": 0}
            reported: list[dict] = []

            async def fake_run_opencode_task(**kwargs):
                round_counter["n"] += 1
                line_num = round_counter["n"]
                return OpenCodeResult(
                    session_id=f"sess-{line_num}",
                    status="success",
                    text="{}",
                    structured={
                        "found": True,
                        "redline_requirement": SAMPLE_ITEM["requirement"],
                        "file": "src/bg.c",
                        "line": line_num,
                        "function": f"BadFn_{line_num}",
                        "description": f"第 {line_num} 个问题",
                        "evidence": f"`src/bg.c:{line_num}`",
                        "remediation": "修复",
                    },
                    model="provider/model",
                    output_source={"serve_session_id": f"sess-{line_num}"},
                )

            async def report_vulns(items):
                start = len(reported)
                reported.extend(items)
                return [(item, {"index": start + offset}) for offset, item in enumerate(items)]

            with patch(
                "deephole_client.vulnerability_mining.engines.redline_audit.engine.run_opencode_task",
                new=AsyncMock(side_effect=fake_run_opencode_task),
            ):
                outcome = await run_redline_engine(
                    scan_id="scan-rl-5",
                    project_path=project,
                    code_scan_path=src,
                    code_scan_paths=[src],
                    work_dir=work,
                    config=self._config(),
                    reporter=None,
                    redline_items=[SAMPLE_ITEM],
                    is_resume=False,
                    output=AsyncMock(),
                    cancel_event=threading.Event(),
                    report_vulnerabilities=report_vulns,
                )

            self.assertEqual(outcome["status"], "success")
            self.assertEqual(round_counter["n"], 5)
            self.assertEqual(len(reported), 5)

            # Resuming with all 5 checkpoints intact should make 0 new LLM calls
            resume_mock = AsyncMock(side_effect=AssertionError("should not invoke LLM when checkpoints are valid"))
            with patch(
                "deephole_client.vulnerability_mining.engines.redline_audit.engine.run_opencode_task",
                new=resume_mock,
            ):
                resumed = await run_redline_engine(
                    scan_id="scan-rl-5",
                    project_path=project,
                    code_scan_path=src,
                    code_scan_paths=[src],
                    work_dir=work,
                    config=self._config(),
                    reporter=None,
                    redline_items=[SAMPLE_ITEM],
                    is_resume=True,
                    output=AsyncMock(),
                    cancel_event=threading.Event(),
                    report_vulnerabilities=report_vulns,
                )
            self.assertEqual(resumed["status"], "success")
            resume_mock.assert_not_awaited()

    async def test_stop_and_resume_only_scans_unfinished_and_skips_duplicate_reporting(self) -> None:
        from backend.models import RedlineAuditTask
        from deephole_client.vulnerability_mining.engines.redline_audit.engine import _task_id

        with tempfile.TemporaryDirectory() as tmp:
            project, src, work = self._make_workspace(tmp)
            item_done = {**SAMPLE_ITEM, "item_id": "item-a", "code": "5.1.1", "requirement": "要求甲"}
            item_partial = {**SAMPLE_ITEM, "item_id": "item-b", "code": "5.1.2", "requirement": "要求乙"}
            item_todo = {**SAMPLE_ITEM, "item_id": "item-c", "code": "5.1.3", "requirement": "要求丙"}
            all_items = [item_done, item_partial, item_todo]
            scan_id = "scan-rl-stop-resume"

            # First run: complete item_done (found=False) and item_partial round 1 (found=True),
            # then cancel before item_partial round 2 and item_todo finish.
            cancel_first = threading.Event()
            server_tasks: dict[str, RedlineAuditTask] = {}
            reported_vulns: list[Vulnerability] = []

            class StatefulReporter:
                async def get_redline_audit_tasks(self, _scan_id: str):
                    return [t.model_copy(deep=True) for t in server_tasks.values()]

                async def push_redline_audit_task(self, _scan_id: str, task: RedlineAuditTask):
                    server_tasks[task.task_id] = task.model_copy(deep=True)
                    return task

                async def get_vulnerability_dedup_context(self, _scan_id: str):
                    return [v.model_copy(deep=True) for v in reported_vulns]

            async def report_vulns(items):
                out = []
                for item in items:
                    idx = len(reported_vulns)
                    v = Vulnerability.model_validate({**item, "vuln_index": idx})
                    reported_vulns.append(v)
                    out.append((item, {"index": idx}))
                return out

            async def first_run_llm(**kwargs):
                import asyncio

                name = kwargs["task_name"]
                if name == _task_id(scan_id, item_done, 1):
                    return OpenCodeResult(
                        session_id="s-done",
                        status="success",
                        text='{"found": false}',
                        structured={"found": False},
                        model="provider/model",
                        output_source={"serve_session_id": "s-done"},
                    )
                if name == _task_id(scan_id, item_partial, 1):
                    return OpenCodeResult(
                        session_id="s-p1",
                        status="success",
                        text="{}",
                        structured={
                            "found": True,
                            "redline_requirement": item_partial["requirement"],
                            "file": "src/bg.c",
                            "line": 10,
                            "function": "PartialFn",
                            "description": "第一轮违规",
                            "evidence": "`src/bg.c:10`",
                            "remediation": "修复一",
                        },
                        model="provider/model",
                        output_source={"serve_session_id": "s-p1"},
                    )
                # Wait until item_done and item_partial round 1 are persisted before user clicks stop
                for _ in range(50):
                    if (
                        len(reported_vulns) >= 1
                        and server_tasks.get(_task_id(scan_id, item_done, 1), RedlineAuditTask(task_id="x")).status == "completed"
                        and server_tasks.get(_task_id(scan_id, item_partial, 1), RedlineAuditTask(task_id="x")).status == "completed"
                    ):
                        break
                    await asyncio.sleep(0.01)
                cancel_first.set()
                return OpenCodeResult(
                    session_id="s-cancel",
                    status="failure",
                    text="",
                    structured=None,
                    model="provider/model",
                    output_source={"serve_session_id": "s-cancel"},
                )

            config_seq = SimpleNamespace(
                vulnerability_mining=SimpleNamespace(required_capability="high", concurrency=1),
                opencode=SimpleNamespace(concurrency=1),
            )
            with patch(
                "deephole_client.vulnerability_mining.engines.redline_audit.engine.run_opencode_task",
                new=AsyncMock(side_effect=first_run_llm),
            ):
                first_outcome = await run_redline_engine(
                    scan_id=scan_id,
                    project_path=project,
                    code_scan_path=src,
                    code_scan_paths=[src],
                    work_dir=work,
                    config=config_seq,
                    reporter=StatefulReporter(),
                    redline_items=all_items,
                    is_resume=False,
                    output=AsyncMock(),
                    cancel_event=cancel_first,
                    report_vulnerabilities=report_vulns,
                )
            self.assertEqual(first_outcome["status"], "cancelled")
            self.assertEqual(len(reported_vulns), 1)
            self.assertEqual(server_tasks[_task_id(scan_id, item_done, 1)].status, "completed")
            self.assertEqual(server_tasks[_task_id(scan_id, item_partial, 1)].status, "completed")
            self.assertEqual(server_tasks[_task_id(scan_id, item_partial, 1)].result_vuln_indexes, [0])

            # Resume WITH local checkpoints intact: item_done and item_partial round 1 must NOT re-run
            # and item_partial round 1 must NOT re-report its already-persisted vulnerability.
            resume_calls: list[dict] = []
            resume_reports: list[dict] = []

            async def resume_report_vulns(items):
                resume_reports.extend(items)
                return await report_vulns(items)

            async def resume_llm(**kwargs):
                resume_calls.append(kwargs)
                return OpenCodeResult(
                    session_id=f"s-res-{len(resume_calls)}",
                    status="success",
                    text='{"found": false}',
                    structured={"found": False},
                    model="provider/model",
                    output_source={"serve_session_id": f"s-res-{len(resume_calls)}"},
                )

            with patch(
                "deephole_client.vulnerability_mining.engines.redline_audit.engine.run_opencode_task",
                new=AsyncMock(side_effect=resume_llm),
            ):
                resumed = await run_redline_engine(
                    scan_id=scan_id,
                    project_path=project,
                    code_scan_path=src,
                    code_scan_paths=[src],
                    work_dir=work,
                    config=config_seq,
                    reporter=StatefulReporter(),
                    redline_items=all_items,
                    is_resume=True,
                    output=AsyncMock(),
                    cancel_event=threading.Event(),
                    report_vulnerabilities=resume_report_vulns,
                )
            self.assertEqual(resumed["status"], "success")
            self.assertEqual(resumed["processed_candidates"], 3)
            self.assertEqual(resumed["total_candidates"], 3)
            self.assertEqual(resume_reports, [])
            called_names = [call["task_name"] for call in resume_calls]
            self.assertEqual(
                set(called_names),
                {_task_id(scan_id, item_partial, 2), _task_id(scan_id, item_todo, 1)},
            )
            p2_call = next(c for c in resume_calls if c["task_name"] == _task_id(scan_id, item_partial, 2))
            self.assertIn("src/bg.c:10", p2_call["prompt"])

            # Now simulate resume WITHOUT local checkpoints (server still has item_done completed
            # and item_partial round 1 completed with persisted finding; reset item_partial r2 & item_todo to cancelled)
            for marker in (work / ".completed-tasks").glob("*.json"):
                marker.unlink()
            server_tasks[_task_id(scan_id, item_partial, 2)].status = "cancelled"
            server_tasks[_task_id(scan_id, item_todo, 1)].status = "cancelled"
            fallback_calls: list[dict] = []

            async def fallback_llm(**kwargs):
                fallback_calls.append(kwargs)
                return OpenCodeResult(
                    session_id=f"s-fb-{len(fallback_calls)}",
                    status="success",
                    text='{"found": false}',
                    structured={"found": False},
                    model="provider/model",
                    output_source={"serve_session_id": f"s-fb-{len(fallback_calls)}"},
                )

            with patch(
                "deephole_client.vulnerability_mining.engines.redline_audit.engine.run_opencode_task",
                new=AsyncMock(side_effect=fallback_llm),
            ):
                resumed_no_markers = await run_redline_engine(
                    scan_id=scan_id,
                    project_path=project,
                    code_scan_path=src,
                    code_scan_paths=[src],
                    work_dir=work,
                    config=config_seq,
                    reporter=StatefulReporter(),
                    redline_items=all_items,
                    is_resume=True,
                    output=AsyncMock(),
                    cancel_event=threading.Event(),
                    report_vulnerabilities=resume_report_vulns,
                )
            self.assertEqual(resumed_no_markers["status"], "success")
            self.assertEqual(
                {call["task_name"] for call in fallback_calls},
                {_task_id(scan_id, item_partial, 2), _task_id(scan_id, item_todo, 1)},
            )
            p2_fallback = next(c for c in fallback_calls if c["task_name"] == _task_id(scan_id, item_partial, 2))
            self.assertIn("src/bg.c:10", p2_fallback["prompt"])


class RedlineDedupIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def test_redline_isolated_from_general_engines_and_other_redlines(self) -> None:
        dedup = VulnerabilityDeduplicator(
            scan_id="scan-dedup",
            project_path="/repo",
            required_capability="high",
            output=AsyncMock(),
        )
        static_vuln = Vulnerability(
            file="src/net.c",
            line=20,
            function="send_packet",
            vuln_type="buffer_overflow",
            severity="high",
            description="overflow",
            confirmed=True,
            ai_verdict="confirmed",
            engine_id="static_candidate",
            analysis_source="static_candidate",
        )
        redline_a_r1 = Vulnerability(
            file="src/net.c",
            line=20,
            function="send_packet",
            vuln_type="5.2.2 禁止恶意软件",
            severity="high",
            description="广告流量",
            confirmed=True,
            ai_verdict="confirmed",
            engine_id=REDLINE_AUDIT_ENGINE_ID,
            analysis_source=REDLINE_AUDIT_ENGINE_ID,
            source_task_id="redline-audit-aaaa-round-1",
        )
        redline_b_r1 = Vulnerability(
            file="src/net.c",
            line=20,
            function="send_packet",
            vuln_type="6.1.1 加密传输",
            severity="high",
            description="明文传输",
            confirmed=True,
            ai_verdict="confirmed",
            engine_id=REDLINE_AUDIT_ENGINE_ID,
            analysis_source=REDLINE_AUDIT_ENGINE_ID,
            source_task_id="redline-audit-bbbb-round-1",
        )
        redline_a_r2_dup = redline_a_r1.model_copy(
            update={"source_task_id": "redline-audit-aaaa-round-2"}
        )

        with patch(
            "deephole_client.vulnerability_mining.dedup.run_opencode_task",
            new=AsyncMock(),
        ) as llm_task:
            self.assertTrue((await dedup.assess(static_vuln)).accepted)
            self.assertTrue((await dedup.assess(redline_a_r1)).accepted)
            self.assertTrue((await dedup.assess(redline_b_r1)).accepted)
            dup_decision = await dedup.assess(redline_a_r2_dup)
            self.assertFalse(dup_decision.accepted)
            self.assertEqual(dup_decision.method, "exact_location")
            llm_task.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
