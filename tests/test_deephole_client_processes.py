from __future__ import annotations

import asyncio
import inspect
import json
import tempfile
import threading
import time
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from deephole_client.code_graph_build.code_database import CodeDatabase
from task_agent import OpenCodeResult

from deephole_client.candidate_audit import run_candidate_audit
from deephole_client.candidate_audit.runner import _candidate_prompt
from deephole_client.code_graph_build import run_code_graph_build
from deephole_client.fp_review import run_fp_review
from deephole_client.fp_check_review import run_fp_check_review
from deephole_client.static_analysis import run_static_analysis
from deephole_client.static_analysis.base import BaseAnalyzer, Candidate
from deephole_client.threat_analysis_runner import run_threat_analysis
from deephole_client.threat_audit import run_threat_audit
from deephole_client.vulnerability_validation import run_vulnerability_validation


PROCESS_FUNCTIONS = (
    run_code_graph_build,
    run_threat_analysis,
    run_static_analysis,
    run_candidate_audit,
    run_threat_audit,
    run_fp_review,
    run_fp_check_review,
    run_vulnerability_validation,
)


def _task_result(structured: object) -> OpenCodeResult:
    return OpenCodeResult(
        session_id="session-1",
        status="success",
        text="{}",
        structured=structured,
        model="test/model",
        output_source={"model": "test/model", "serve_session_id": "session-1"},
    )


def _audit_item(
    *,
    confirmed: bool,
    file: str,
    line: int,
    function: str,
    description: str,
    vuln_type: str = "demo",
) -> dict:
    item = {
        "confirmed": confirmed,
        "severity": "high" if confirmed else "low",
        "file": file,
        "line": line,
        "function": function,
        "description": description,
    }
    if confirmed:
        item.update({
            "vuln_type": vuln_type,
            "impact": "机密性：无直接影响；完整性：无直接影响；可用性：进程崩溃",
            "vulnerable_code": f"{file}:{line} {function}\nunsafe();",
            "call_chain": [
                {"function": "entry", "file": "src/entry.c", "line": 1},
                {"function": function, "file": file, "line": line},
            ],
            "attack_entry": "外部请求由 entry 处理",
            "root_cause": "缺少必要校验",
            "trigger_conditions": "攻击者提交畸形输入",
        })
    return item


def _write_candidate_audit_rule(
    root: Path,
    *,
    checker_name: str = "demo",
    skill_name: str = "demo-audit",
) -> Path:
    checker = root / checker_name
    checker.mkdir(parents=True)
    (checker / "audit.yaml").write_text(
        f"name: {checker_name}\nlabel: Demo\nresult_mode: vulnerabilities\n",
        encoding="utf-8",
    )
    (checker / "SKILL.md").write_text(
        "---\n"
        f"name: {skill_name}\n"
        "description: Audit demo candidates\n"
        "---\n\n"
        "Audit the candidate.",
        encoding="utf-8",
    )
    return checker


def _write_threat_audit_inputs(
    root: Path,
    *,
    attack_patterns: list[dict],
) -> tuple[Path, Path, Path]:
    project = root / "project"
    project.mkdir()
    attack_tree_path = root / "attack-trees.json"
    high_risk_modules_path = root / "high-risk-modules.json"
    attack_tree_path.write_text(json.dumps({
        "attack_trees": [{
            "tree_id": "TREE-CALLBACK",
            "value_asset": {"asset_name": "service"},
            "nodes": [{
                "node_id": "NODE-CALLBACK",
                "node_type": "attack_surface",
                "node_name": "parser",
                "module_name": "parser",
                "description": "parses external requests",
                "external_exposure": True,
            }],
            "attack_paths": [{
                "path_id": "PATH-CALLBACK",
                "path_name": "remote parser path",
                "path_description": "socket input reaches parser",
                "node_ids": ["NODE-CALLBACK"],
                "related_high_risk_modules": [{
                    "module_name": "parser",
                    "node_id": "NODE-CALLBACK",
                    "association_description": "entry",
                }],
                "attack_patterns": attack_patterns,
            }],
        }],
    }), encoding="utf-8")
    high_risk_modules_path.write_text(json.dumps([{
        "模块名称": "parser",
        "代码目录": "src/parser.c",
        "面临威胁": "out of bounds",
    }]), encoding="utf-8")
    return project, attack_tree_path, high_risk_modules_path


def test_all_process_entries_are_async_and_reject_unknown_keys() -> None:
    for function in PROCESS_FUNCTIONS:
        assert inspect.iscoroutinefunction(function)
        try:
            asyncio.run(function(unknown_process_key=True))
        except TypeError as exc:
            assert "unexpected key" in str(exc)
        else:
            raise AssertionError(f"{function.__name__} accepted an unknown key")


def test_candidate_prompt_uses_existing_related_variables_without_clues() -> None:
    prompt = _candidate_prompt(
        {"skill_name": "oob-audit"},
        {
            "file": "src/copy.c",
            "line": 28,
            "function": "copy_payload",
            "vuln_type": "oob",
            "description": "do not include this candidate clue",
            "metadata": {
                "focus_variable": "length",
                "target_variable": "destination",
            },
        },
        "",
    )

    assert prompt == (
        "/oob-audit\n"
        "你是一个白盒审计专家，使用该skill审计文件src/copy.c中28行"
        "函数copy_payload变量length、destination是否存在oob问题，是否可以触发。\n"
        "输出的 `call_chain` 必须以外部入口函数为起点。"
    )


def test_threat_processes_run_with_task_agent_only() -> None:
    async def scenario(root: Path) -> None:
        project = root / "project"
        project.mkdir()
        events: list[dict] = []

        def native_threat_analysis(**kwargs):
            output_path = Path(kwargs["output_path"])
            value_assets = output_path / "value-assets.json"
            attack_trees = output_path / "attack-trees.json"
            high_risk_modules = output_path / "high-risk-modules.json"
            value_assets.write_text("[]", encoding="utf-8")
            attack_trees.write_text(json.dumps({
                "attack_trees": [{
                    "tree_id": "TREE-1",
                    "value_asset": {"asset_name": "service"},
                    "nodes": [],
                    "attack_paths": [{
                        "path_id": "AP-1",
                        "path_name": "remote parser path",
                        "path_description": "socket input reaches parser",
                        "related_high_risk_modules": [{
                            "module_name": "parser",
                            "node_id": "NODE-1",
                            "association_description": "entry",
                        }],
                        "attack_patterns": [{
                            "pattern_id": "PATTERN-1",
                            "pattern_name": "malformed packet",
                            "association_description": "length mismatch",
                        }],
                    }],
                }],
            }), encoding="utf-8")
            high_risk_modules.write_text(json.dumps([{
                "模块名称": "parser",
                "代码目录": "src/parser.c",
                "面临威胁": "out of bounds",
            }]), encoding="utf-8")
            return {
                "result": True,
                "value_asset_path": str(value_assets),
                "attack_tree_path": str(attack_trees),
                "high_risk_modules_path": str(high_risk_modules),
            }

        with patch(
            "deephole_client.threat_analysis_runner._load_implementation",
            return_value=SimpleNamespace(
                run_threat_analysis=native_threat_analysis,
            ),
        ):
            analysis = await run_threat_analysis(
                code_path=project,
                output_path=root / "threat",
                output=events.append,
            )
        assert analysis["result"] is True
        assert Path(analysis["attack_tree_path"]).is_file()
        assert events and all(event["process"] == "threat_analysis" for event in events)

        audit_task_result = _task_result([_audit_item(
            confirmed=True,
            file="src/parser.c",
            line=10,
            function="parse",
            description="bad length",
            vuln_type="oob",
        )])
        with patch(
            "deephole_client.threat_audit.runner.run_opencode_task",
            new=AsyncMock(return_value=audit_task_result),
        ) as run_task:
            audit_events: list[dict] = []
            audit = await run_threat_audit(
                project_path=project,
                work_dir=root / "audit",
                scan_id="scan-1",
                attack_tree_path=analysis["attack_tree_path"],
                high_risk_modules_path=analysis["high_risk_modules_path"],
                output=audit_events.append,
            )
        assert audit["status"] == "success"
        assert audit["vulnerabilities"][0]["analysis_source"] == "threat_audit"
        assert audit["vulnerabilities"][0]["confirmed"] is True
        assert audit["vulnerabilities"][0]["call_chain"][0] == {
            "function": "entry",
            "file": "src/entry.c",
            "line": 1,
        }
        assert "JSON Schema" in run_task.await_args.kwargs["prompt"]
        assert "裸 JSON List" in run_task.await_args.kwargs["prompt"]
        assert run_task.await_args.kwargs["output_schema"]["type"] == "array"
        assert run_task.await_args.kwargs["output_schema"]["minItems"] == 0
        assert (
            "confirmed"
            not in run_task.await_args.kwargs["output_schema"]["items"]["properties"]
        )
        assert "output" not in run_task.await_args.kwargs
        task_status_events = [
            event
            for event in audit_events
            if event["kind"] == "task_status"
        ]
        assert [
            event["data"]["task"]["status"]
            for event in task_status_events
        ] == ["pending", "running", "completed"]
        assert len({
            event["data"]["task"]["created_at"]
            for event in task_status_events
        }) == 1
        assert all(
            event["data"]["task"]["updated_at"]
            for event in task_status_events
        )
        assert (
            task_status_events[-1]["data"]["task"]["output_source"]["model"]
            == "test/model"
        )

        with patch(
            "deephole_client.threat_audit.runner.run_opencode_task",
            new=AsyncMock(return_value=_task_result([])),
        ):
            empty_audit = await run_threat_audit(
                project_path=project,
                work_dir=root / "empty-audit",
                scan_id="scan-empty",
                attack_tree_path=analysis["attack_tree_path"],
                high_risk_modules_path=analysis["high_risk_modules_path"],
            )
        assert empty_audit["status"] == "success"
        assert empty_audit["vulnerabilities"] == []
        assert empty_audit["tasks"][0]["status"] == "completed"
        assert empty_audit["tasks"][0]["result_count"] == 0

        with patch(
            "deephole_client.threat_audit.runner.run_opencode_task",
            new=AsyncMock(side_effect=RuntimeError("model unavailable")),
        ):
            failed_events: list[dict] = []
            failed_audit = await run_threat_audit(
                project_path=project,
                work_dir=root / "failed-audit",
                scan_id="scan-failed",
                attack_tree_path=analysis["attack_tree_path"],
                high_risk_modules_path=analysis["high_risk_modules_path"],
                output=failed_events.append,
            )
        assert failed_audit["tasks"][0]["status"] == "failed"
        assert failed_audit["tasks"][0]["failure_reason"] == "model unavailable"
        assert [
            event["data"]["task"]["status"]
            for event in failed_events
            if event["kind"] == "task_status"
        ] == ["pending", "running", "failed"]

        cancelled = threading.Event()
        cancelled.set()
        with patch(
            "deephole_client.threat_audit.runner.run_opencode_task",
            new=AsyncMock(),
        ) as cancelled_run_task:
            cancelled_events: list[dict] = []
            cancelled_audit = await run_threat_audit(
                project_path=project,
                work_dir=root / "cancelled-audit",
                scan_id="scan-cancelled",
                attack_tree_path=analysis["attack_tree_path"],
                high_risk_modules_path=analysis["high_risk_modules_path"],
                output=cancelled_events.append,
                cancel_event=cancelled,
            )
        assert cancelled_audit["status"] == "cancelled"
        assert cancelled_audit["tasks"][0]["status"] == "cancelled"
        assert [
            event["data"]["task"]["status"]
            for event in cancelled_events
            if event["kind"] == "task_status"
        ] == ["pending", "cancelled"]
        cancelled_run_task.assert_not_awaited()

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))


def test_threat_audit_calls_sync_callback_with_completed_task_result() -> None:
    async def scenario(root: Path) -> None:
        project, attack_tree_path, high_risk_modules_path = (
            _write_threat_audit_inputs(
                root,
                attack_patterns=[{
                    "pattern_id": "PATTERN-SYNC",
                    "pattern_name": "malformed packet",
                }],
            )
        )
        callback_results: list[dict] = []
        model_result = _task_result([_audit_item(
            confirmed=True,
            file="src/parser.c",
            line=10,
            function="parse",
            description="bad length",
            vuln_type="oob",
        )])

        with patch(
            "deephole_client.threat_audit.runner.run_opencode_task",
            new=AsyncMock(return_value=model_result),
        ):
            audited = await run_threat_audit(
                project_path=project,
                work_dir=root / "audit",
                scan_id="scan-sync-callback",
                attack_tree_path=attack_tree_path,
                high_risk_modules_path=high_risk_modules_path,
                on_task_result=callback_results.append,
            )

        assert audited["status"] == "success"
        assert len(callback_results) == 1
        callback_result = callback_results[0]
        assert set(callback_result) == {"task", "vulnerabilities"}
        assert callback_result["task"]["status"] == "completed"
        assert callback_result["task"]["result_count"] == 1
        assert callback_result["vulnerabilities"] == audited["vulnerabilities"]
        assert callback_result["vulnerabilities"][0]["analysis_source"] == "threat_audit"
        assert (
            callback_result["vulnerabilities"][0]["source_task_id"]
            == callback_result["task"]["task_id"]
        )

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))


def test_threat_audit_callback_failure_does_not_fail_completed_task() -> None:
    async def scenario(root: Path) -> None:
        project, attack_tree_path, high_risk_modules_path = (
            _write_threat_audit_inputs(
                root,
                attack_patterns=[{
                    "pattern_id": "PATTERN-CALLBACK-FAILURE",
                    "pattern_name": "malformed packet",
                }],
            )
        )
        events: list[dict] = []

        def failed_callback(_result: dict) -> None:
            raise RuntimeError("report transport unavailable")

        with patch(
            "deephole_client.threat_audit.runner.run_opencode_task",
            new=AsyncMock(return_value=_task_result([_audit_item(
                confirmed=True,
                file="src/parser.c",
                line=11,
                function="parse",
                description="bad length",
                vuln_type="oob",
            )])),
        ):
            audited = await run_threat_audit(
                project_path=project,
                work_dir=root / "audit",
                scan_id="scan-callback-failure",
                attack_tree_path=attack_tree_path,
                high_risk_modules_path=high_risk_modules_path,
                output=events.append,
                on_task_result=failed_callback,
            )

        assert audited["status"] == "success"
        assert audited["tasks"][0]["status"] == "completed"
        assert len(audited["vulnerabilities"]) == 1
        assert any(
            event["kind"] == "error"
            and "result callback failed" in event["message"]
            for event in events
        )
        assert any(
            event["kind"] == "task_status"
            and event["data"]["task"]["status"] == "completed"
            for event in events
        )

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))


def test_threat_audit_streams_async_task_results_before_batch_finishes() -> None:
    async def scenario(root: Path) -> None:
        project, attack_tree_path, high_risk_modules_path = (
            _write_threat_audit_inputs(
                root,
                attack_patterns=[
                    {
                        "pattern_id": "PATTERN-READY",
                        "pattern_name": "ready pattern",
                    },
                    {
                        "pattern_id": "PATTERN-BLOCKED",
                        "pattern_name": "blocked pattern",
                    },
                ],
            )
        )
        release_blocked = asyncio.Event()
        blocked_started = asyncio.Event()
        ready_reported = asyncio.Event()
        callback_results: list[dict] = []
        task_status_events: list[dict] = []
        completed_statuses_seen_by_callback: dict[str, bool] = {}

        async def run_task(**kwargs):
            if "blocked pattern" in kwargs["prompt"]:
                blocked_started.set()
                await release_blocked.wait()
                return _task_result([])
            return _task_result([_audit_item(
                confirmed=True,
                file="src/parser.c",
                line=20,
                function="parse_ready",
                description="ready issue",
                vuln_type="oob",
            )])

        def collect_event(event: dict) -> None:
            if event["kind"] == "task_status":
                task_status_events.append(event)

        async def on_task_result(result: dict) -> None:
            await asyncio.sleep(0)
            task = result["task"]
            completed_statuses_seen_by_callback[task["task_id"]] = any(
                event["data"]["task"]["task_id"] == task["task_id"]
                and event["data"]["task"]["status"] == "completed"
                for event in task_status_events
            )
            callback_results.append(result)
            if task["method_name"] == "ready pattern":
                ready_reported.set()

        with patch(
            "deephole_client.threat_audit.runner.run_opencode_task",
            side_effect=run_task,
        ):
            batch_task = asyncio.create_task(run_threat_audit(
                project_path=project,
                work_dir=root / "audit",
                scan_id="scan-async-callback",
                attack_tree_path=attack_tree_path,
                high_risk_modules_path=high_risk_modules_path,
                concurrency=2,
                output=collect_event,
                on_task_result=on_task_result,
            ))
            try:
                await asyncio.wait_for(blocked_started.wait(), timeout=1)
                await asyncio.wait_for(ready_reported.wait(), timeout=1)
                assert not batch_task.done()
                assert len(callback_results) == 1
                assert callback_results[0]["task"]["status"] == "completed"
                assert callback_results[0]["task"]["result_count"] == 1
                assert callback_results[0]["task"]["method_name"] == "ready pattern"
            finally:
                release_blocked.set()
            audited = await asyncio.wait_for(batch_task, timeout=1)

        assert audited["status"] == "success"
        assert [
            result["task"]["method_name"]
            for result in callback_results
        ] == ["ready pattern", "blocked pattern"]
        assert [
            result["task"]["result_count"]
            for result in callback_results
        ] == [1, 0]
        assert callback_results[1]["vulnerabilities"] == []
        assert completed_statuses_seen_by_callback == {
            result["task"]["task_id"]: False
            for result in callback_results
        }

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))


def test_static_and_candidate_audit_processes_form_a_minimal_pipeline() -> None:
    async def scenario(root: Path) -> None:
        project = root / "project"
        project.mkdir()
        source = project / "sample.c"
        source.write_text("int bad(void) { return 0; }\n", encoding="utf-8")
        index_path = project / "code_index.db"
        database = CodeDatabase(index_path)
        database.close()
        static_root = root / "static-rules"
        static_checker = static_root / "demo"
        static_checker.mkdir(parents=True)
        (static_checker / "checker.yaml").write_text(
            "name: demo\nlabel: Demo\nenabled: true\nmode: opencode\n",
            encoding="utf-8",
        )
        (static_checker / "analyzer.py").write_text(
            "from ...base import BaseAnalyzer, Candidate\n"
            "class Analyzer(BaseAnalyzer):\n"
            "    vuln_type = 'demo'\n"
            "    def find_candidates(self, project_path, db=None):\n"
            "        return [Candidate(file='sample.c', line=1, function='bad', "
            "description='candidate', vuln_type='demo')]\n",
            encoding="utf-8",
        )
        audit_root = root / "audit-rules"
        _write_candidate_audit_rule(audit_root)
        static = await asyncio.wait_for(run_static_analysis(
            project_path=project,
            work_dir=root / "static",
            index_db_path=index_path,
            checker_dirs=[static_root],
        ), timeout=5)
        assert static["status"] == "success"
        assert static["stats"]["total"] == 1

        model_result = _task_result(_audit_item(
            confirmed=False,
            file="sample.c",
            line=1,
            function="bad",
            description="candidate is guarded",
        ))
        candidate_results: list[dict] = []
        task_context = MagicMock(return_value=nullcontext())
        with (
            patch(
                "deephole_client.candidate_audit.runner.opencode_task_context",
                task_context,
            ),
            patch(
                "deephole_client.candidate_audit.runner.run_opencode_task",
                new=AsyncMock(return_value=model_result),
            ) as run_task,
        ):
            audited = await asyncio.wait_for(run_candidate_audit(
                project_path=project,
                work_dir=root / "candidate-audit",
                scan_id="scan-1",
                candidates=static["candidates"],
                checker_dirs=[audit_root],
                index_db_path=index_path,
                product_mcp="product-info",
                on_candidate_result=candidate_results.append,
            ), timeout=5)
        assert audited["status"] == "success"
        assert audited["vulnerabilities"][0]["ai_verdict"] == "not_confirmed"
        prompt = run_task.await_args.kwargs["prompt"]
        assert prompt.startswith(
            "/demo-audit\n"
            "你是一个白盒审计专家，使用该skill审计文件sample.c中1行"
            "函数bad变量未指定是否存在demo问题，是否可以触发。"
        )
        assert "Audit the candidate." not in prompt
        assert "candidate" not in prompt
        assert "使用 `product-info` 提供的工具获取产品知识" in prompt
        assert "call_chain` 必须以外部入口函数为起点" in prompt
        assert "JSON Schema" in prompt
        assert '"vulnerable_code"' in prompt
        assert '"markdown_reports"' not in prompt
        assert run_task.await_args.kwargs["output_schema"]["type"] == "object"
        assert "output" not in run_task.await_args.kwargs
        assert task_context.call_args.kwargs["skill_paths"] == [
            audit_root.resolve(),
        ]
        assert candidate_results[0]["audit_index"] == 0
        assert candidate_results[0]["checker_name"] == "demo"
        assert candidate_results[0]["vulnerabilities"][0]["ai_verdict"] == "not_confirmed"
        assert audited["processed_keys"] == [{
            "file": "sample.c", "line": 1, "function": "bad", "vuln_type": "demo",
        }]

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))


def test_static_analysis_keeps_event_loop_responsive_during_blocking_checker() -> None:
    started = threading.Event()
    finished = threading.Event()
    release = threading.Event()

    class BlockingAnalyzer(BaseAnalyzer):
        vuln_type = "blocking"

        def find_candidates(self, project_path, db=None):
            started.set()
            release.wait(timeout=0.5)
            finished.set()
            return []

    async def scenario(root: Path) -> None:
        project = root / "project"
        project.mkdir()
        index_path = project / "code_index.db"
        database = CodeDatabase(index_path)
        database.close()
        analyzer = BlockingAnalyzer()
        checker = SimpleNamespace(
            name="blocking",
            label="Blocking checker",
            mode="opencode",
            analyzer=analyzer,
        )
        stop_ticker = asyncio.Event()
        ticks_while_blocked = 0
        events: list[dict] = []

        async def ticker() -> None:
            nonlocal ticks_while_blocked
            while not stop_ticker.is_set():
                if started.is_set() and not finished.is_set():
                    ticks_while_blocked += 1
                await asyncio.sleep(0.005)

        ticker_task = asyncio.create_task(ticker())
        with patch(
            "deephole_client.static_analysis.runner.discover_checkers",
            return_value={"blocking": checker},
        ), patch(
            "deephole_client.static_analysis.runner._PROGRESS_HEARTBEAT_SECONDS",
            0.02,
        ):
            analysis_task = asyncio.create_task(run_static_analysis(
                project_path=project,
                work_dir=root / "static",
                index_db_path=index_path,
                output=events.append,
            ))
            try:
                for _ in range(100):
                    if started.is_set():
                        break
                    await asyncio.sleep(0.005)
                deadline = asyncio.get_running_loop().time() + 0.5
                while (
                    ticks_while_blocked < 3
                    or not any(
                        event["kind"] == "checker_progress"
                        and "still running" in event["message"]
                        for event in events
                    )
                ):
                    if asyncio.get_running_loop().time() >= deadline:
                        break
                    await asyncio.sleep(0.005)
                task_was_still_running = not analysis_task.done()
                observed_ticks = ticks_while_blocked
            finally:
                release.set()
            result = await asyncio.wait_for(analysis_task, timeout=1)

        stop_ticker.set()
        await ticker_task
        assert started.is_set()
        assert task_was_still_running
        assert observed_ticks >= 3
        assert result["status"] == "success"
        assert analyzer.on_file_progress is None
        assert any(
            event["kind"] == "checker_progress"
            and "still running" in event["message"]
            and event["data"]["progress_current"] == 0
            and event["data"]["progress_total"] == 0
            for event in events
        )

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))


def test_static_analysis_emits_checker_lifecycle_and_candidate_counts() -> None:
    class FirstAnalyzer(BaseAnalyzer):
        vuln_type = "first"

        def find_candidates(self, project_path, db=None):
            assert self.on_file_progress is not None
            for current in (1, 10, 11, 12, 120, 120):
                self.on_file_progress(current, 100)
            return [
                Candidate(
                    file="first.c",
                    line=1,
                    function="first",
                    description="first candidate",
                    vuln_type="first",
                ),
                Candidate(
                    file="first.c",
                    line=2,
                    function="second",
                    description="second candidate",
                    vuln_type="first",
                ),
            ]

    class SecondAnalyzer(BaseAnalyzer):
        vuln_type = "second"

        def find_candidates(self, project_path, db=None):
            assert self.on_file_progress is not None
            self.on_file_progress(1, 1)
            return [
                Candidate(
                    file="second.c",
                    line=1,
                    function="third",
                    description="third candidate",
                    vuln_type="second",
                ),
            ]

    async def scenario(root: Path) -> None:
        project = root / "project"
        project.mkdir()
        (project / "first.c").write_text("int first;\n", encoding="utf-8")
        (project / "second.c").write_text("int second;\n", encoding="utf-8")
        index_path = project / "code_index.db"
        database = CodeDatabase(index_path)
        database.close()
        first = FirstAnalyzer()
        second = SecondAnalyzer()
        registry = {
            "first": SimpleNamespace(
                name="first",
                label="First checker",
                mode="opencode",
                analyzer=first,
            ),
            "second": SimpleNamespace(
                name="second",
                label="Second checker",
                mode="opencode",
                analyzer=second,
            ),
        }
        events: list[dict] = []

        async def collect_event(event: dict) -> None:
            await asyncio.sleep(0)
            events.append(event)

        with patch(
            "deephole_client.static_analysis.runner.discover_checkers",
            return_value=registry,
        ):
            result = await run_static_analysis(
                project_path=project,
                work_dir=root / "static",
                index_db_path=index_path,
                output=collect_event,
            )

        lifecycle = [
            event
            for event in events
            if event["kind"].startswith("checker_")
        ]
        assert [event["kind"] for event in lifecycle] == [
            "checker_start",
            "checker_progress",
            "checker_progress",
            "checker_progress",
            "checker_complete",
            "checker_start",
            "checker_progress",
            "checker_complete",
        ]
        assert [
            (
                event["data"]["checker_index"],
                event["data"]["checker_total"],
                event["data"]["checker_name"],
                event["data"]["checker_label"],
            )
            for event in lifecycle
        ] == (
            [(1, 2, "first", "First checker")] * 5
            + [(2, 2, "second", "Second checker")] * 3
        )
        assert [
            (
                event["data"]["progress_current"],
                event["data"]["progress_total"],
            )
            for event in lifecycle
            if event["kind"] == "checker_progress"
        ] == [(1, 100), (11, 100), (100, 100), (1, 1)]
        assert [
            event["data"]["checker_candidate_count"]
            for event in lifecycle
            if event["kind"] == "checker_complete"
        ] == [2, 1]
        final_event = events[-1]
        assert final_event["kind"] == "progress"
        assert final_event["data"]["candidate_count"] == 3
        assert events[0]["data"] == {"checker_total": 2}
        assert "current" not in final_event["data"]
        assert "total" not in final_event["data"]
        assert result["status"] == "success"
        assert result["stats"] == {
            "total": 3,
            "checkers": {"first": 2, "second": 1},
        }
        assert first.on_file_progress is None
        assert second.on_file_progress is None

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))


def test_static_analysis_external_cancellation_resets_file_progress_callback() -> None:
    cancel_event = threading.Event()
    started = threading.Event()

    class CancellableAnalyzer(BaseAnalyzer):
        vuln_type = "cancellable"

        def find_candidates(self, project_path, db=None):
            assert self.on_file_progress is not None
            self.on_file_progress(1, 10)
            started.set()
            deadline = time.monotonic() + 0.5
            while not cancel_event.is_set() and time.monotonic() < deadline:
                time.sleep(0.005)
            return []

    async def scenario(root: Path) -> None:
        project = root / "project"
        project.mkdir()
        index_path = project / "code_index.db"
        database = CodeDatabase(index_path)
        database.close()
        analyzer = CancellableAnalyzer()
        checker = SimpleNamespace(
            name="cancellable",
            label="Cancellable checker",
            mode="opencode",
            analyzer=analyzer,
        )
        events: list[dict] = []

        async def cancel_after_start() -> None:
            for _ in range(100):
                if started.is_set():
                    break
                await asyncio.sleep(0.005)
            assert started.is_set()
            cancel_event.set()

        with patch(
            "deephole_client.static_analysis.runner.discover_checkers",
            return_value={"cancellable": checker},
        ):
            cancel_task = asyncio.create_task(cancel_after_start())
            result = await asyncio.wait_for(run_static_analysis(
                project_path=project,
                work_dir=root / "static",
                index_db_path=index_path,
                cancel_event=cancel_event,
                output=events.append,
            ), timeout=1)
            await cancel_task

        assert result["status"] == "cancelled"
        assert result["stats"]["checkers"] == {}
        cancelled_event = next(
            event
            for event in events
            if event["kind"] == "checker_cancelled"
        )
        assert {
            key: cancelled_event["data"][key]
            for key in (
                "checker_index",
                "checker_total",
                "checker_name",
                "checker_label",
            )
        } == {
            "checker_index": 1,
            "checker_total": 1,
            "checker_name": "cancellable",
            "checker_label": "Cancellable checker",
        }
        assert analyzer.on_file_progress is None

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))


def test_static_analysis_task_cancellation_stops_bridge_and_cleans_callback() -> None:
    started = threading.Event()
    release = threading.Event()

    class BlockingAnalyzer(BaseAnalyzer):
        vuln_type = "task_cancel"

        def find_candidates(self, project_path, db=None):
            assert self.on_file_progress is not None
            self.on_file_progress(1, 10)
            started.set()
            release.wait(timeout=1)
            return []

    async def scenario(root: Path) -> None:
        project = root / "project"
        project.mkdir()
        index_path = project / "code_index.db"
        database = CodeDatabase(index_path)
        database.close()
        analyzer = BlockingAnalyzer()
        checker = SimpleNamespace(
            name="task_cancel",
            label="Task cancellation checker",
            mode="opencode",
            analyzer=analyzer,
        )
        events: list[dict] = []

        with patch(
            "deephole_client.static_analysis.runner.discover_checkers",
            return_value={"task_cancel": checker},
        ):
            analysis_task = asyncio.create_task(run_static_analysis(
                project_path=project,
                work_dir=root / "static",
                index_db_path=index_path,
                output=events.append,
            ))
            try:
                for _ in range(100):
                    if started.is_set():
                        break
                    await asyncio.sleep(0.005)
                assert started.is_set()
                analysis_task.cancel()
                try:
                    await asyncio.wait_for(analysis_task, timeout=0.2)
                except asyncio.CancelledError:
                    pass
                else:
                    raise AssertionError("static analysis task was not cancelled")
                event_count_after_cancel = len(events)
            finally:
                release.set()

            for _ in range(100):
                if analyzer.on_file_progress is None:
                    break
                await asyncio.sleep(0.005)

        assert analyzer.on_file_progress is None
        assert len(events) == event_count_after_cancel

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))


def test_static_analysis_resets_file_progress_callback_after_checker_error() -> None:
    class FailingAnalyzer(BaseAnalyzer):
        vuln_type = "failing"

        def find_candidates(self, project_path, db=None):
            assert self.on_file_progress is not None
            self.on_file_progress(1, 2)
            raise RuntimeError("checker failed")

    async def scenario(root: Path) -> None:
        project = root / "project"
        project.mkdir()
        index_path = project / "code_index.db"
        database = CodeDatabase(index_path)
        database.close()
        analyzer = FailingAnalyzer()
        checker = SimpleNamespace(
            name="failing",
            label="Failing checker",
            mode="opencode",
            analyzer=analyzer,
        )
        events: list[dict] = []

        with patch(
            "deephole_client.static_analysis.runner.discover_checkers",
            return_value={"failing": checker},
        ):
            try:
                await run_static_analysis(
                    project_path=project,
                    work_dir=root / "static",
                    index_db_path=index_path,
                    output=events.append,
                )
            except RuntimeError as exc:
                assert str(exc) == "checker failed"
            else:
                raise AssertionError("failing checker did not raise")

        error_event = next(
            event
            for event in events
            if event["kind"] == "checker_error"
        )
        assert {
            key: error_event["data"][key]
            for key in (
                "checker_index",
                "checker_total",
                "checker_name",
                "checker_label",
            )
        } == {
            "checker_index": 1,
            "checker_total": 1,
            "checker_name": "failing",
            "checker_label": "Failing checker",
        }
        assert analyzer.on_file_progress is None

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))


def test_candidate_audit_streams_results_before_the_batch_finishes() -> None:
    async def scenario(root: Path) -> None:
        project = root / "project"
        project.mkdir()
        index_path = project / "code_index.db"
        index_path.touch()
        audit_root = root / "audit-rules"
        _write_candidate_audit_rule(audit_root)
        release_second = asyncio.Event()
        second_started = asyncio.Event()
        first_reported = asyncio.Event()
        candidate_results: list[dict] = []

        async def run_task(**kwargs):
            audit_index = int(kwargs["task_name"].rsplit("-", 1)[-1])
            if audit_index == 1:
                second_started.set()
                await release_second.wait()
            return _task_result(_audit_item(
                confirmed=False,
                file=f"{'first' if audit_index == 0 else 'second'}.c",
                line=audit_index + 1,
                function="first" if audit_index == 0 else "second",
                description="candidate is guarded",
            ))

        async def on_candidate_result(result: dict) -> None:
            candidate_results.append(result)
            if result["audit_index"] == 0:
                first_reported.set()

        with patch(
            "deephole_client.candidate_audit.runner.run_opencode_task",
            side_effect=run_task,
        ):
            batch_task = asyncio.create_task(run_candidate_audit(
                project_path=project,
                work_dir=root / "candidate-audit",
                scan_id="scan-stream",
                candidates=[
                    {
                        "file": "first.c",
                        "line": 1,
                        "function": "first",
                        "description": "first candidate",
                        "vuln_type": "demo",
                    },
                    {
                        "file": "second.c",
                        "line": 2,
                        "function": "second",
                        "description": "second candidate",
                        "vuln_type": "demo",
                    },
                ],
                checker_dirs=[audit_root],
                index_db_path=index_path,
                concurrency=2,
                on_candidate_result=on_candidate_result,
            ))
            try:
                await asyncio.wait_for(second_started.wait(), timeout=1)
                await asyncio.wait_for(first_reported.wait(), timeout=1)
                assert not batch_task.done()
            finally:
                release_second.set()
            audited = await asyncio.wait_for(batch_task, timeout=1)

        assert audited["status"] == "success"
        assert [item["audit_index"] for item in candidate_results] == [0, 1]

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))


def test_candidate_result_callback_covers_all_terminal_outcomes() -> None:
    async def scenario(root: Path) -> None:
        project = root / "project"
        project.mkdir()
        index_path = project / "code_index.db"
        index_path.touch()
        audit_root = root / "audit-rules"
        _write_candidate_audit_rule(audit_root)
        candidate_results: list[dict] = []
        not_confirmed = _task_result(_audit_item(
            confirmed=False,
            file="same.c",
            line=1,
            function="same",
            description="same-pattern candidate is guarded",
        ))
        no_result = _task_result([])
        failure = OpenCodeResult(
            session_id="session-failed",
            status="failure",
            text="model failed",
            structured=None,
            model="test/model",
            output_source={
                "model": "test/model",
                "serve_session_id": "session-failed",
            },
        )
        project_result = _task_result([
            _audit_item(
                confirmed=True,
                file="project.c",
                line=9,
                function="project_issue",
                description="project-level issue",
            ),
            _audit_item(
                confirmed=True,
                file="other.c",
                line=12,
                function="other_issue",
                description="second project-level issue",
            ),
        ])
        candidates = [
            {
                "file": "same.c",
                "line": 1,
                "function": "same",
                "description": "first same-pattern candidate",
                "vuln_type": "demo",
            },
            {
                "file": "same.c",
                "line": 2,
                "function": "same",
                "description": "filtered same-pattern candidate",
                "vuln_type": "demo",
            },
            {
                "file": "empty.c",
                "line": 3,
                "function": "empty",
                "description": "empty model result",
                "vuln_type": "demo",
            },
            {
                "file": "failed.c",
                "line": 4,
                "function": "failed",
                "description": "failed model task",
                "vuln_type": "demo",
            },
            {
                "file": ".",
                "line": 1,
                "function": "__project__",
                "description": "report-only project audit",
                "vuln_type": "demo",
            },
        ]

        with patch(
            "deephole_client.candidate_audit.runner.run_opencode_task",
            new=AsyncMock(side_effect=[
                not_confirmed,
                no_result,
                failure,
                project_result,
            ]),
        ) as run_task:
            audited = await run_candidate_audit(
                project_path=project,
                work_dir=root / "candidate-audit",
                scan_id="scan-terminal",
                candidates=candidates,
                checker_dirs=[audit_root],
                index_db_path=index_path,
                concurrency=1,
                pattern_filter_enabled=True,
                pattern_filter_scope="function",
                on_candidate_result=candidate_results.append,
            )

        assert run_task.await_count == 4
        assert len(candidate_results) == 5
        by_index = {
            item["audit_index"]: item
            for item in candidate_results
        }
        assert by_index[0]["vulnerabilities"][0]["ai_verdict"] == "not_confirmed"
        assert by_index[1]["vulnerabilities"][0]["ai_verdict"] == "filtered_same_pattern"
        assert by_index[2]["vulnerabilities"][0]["ai_verdict"] == "no_result"
        assert by_index[3]["vulnerabilities"][0]["ai_verdict"] == "failed"
        assert len(by_index[4]["vulnerabilities"]) == 2
        assert all(
            item["ai_verdict"] == "confirmed"
            for item in by_index[4]["vulnerabilities"]
        )
        assert by_index[4]["skill_reports"] == []
        project_call = run_task.await_args_list[-1]
        assert project_call.kwargs["output_schema"]["type"] == "array"
        assert "裸 JSON List" in project_call.kwargs["prompt"]
        assert len(audited["processed_keys"]) == 5

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))


def test_fp_review_and_validation_processes_run_in_batches() -> None:
    async def scenario(root: Path) -> None:
        project = root / "project"
        project.mkdir()
        vulnerability = {
            "index": 7, "file": "sample.c", "line": 1, "function": "bad",
            "vuln_type": "oob", "severity": "high", "description": "candidate",
            "ai_analysis": "analysis",
            "vulnerability_report": "# OOB report",
            "confirmed": True,
        }
        with patch(
            "deephole_client.fp_review.runner.run_opencode_task",
            new=AsyncMock(return_value=_task_result({
                "verdict": "false_positive", "reason": "guarded", "evidence": ["check"],
                "revised_severity": "low",
            })),
        ) as run_task:
            reviewed = await run_fp_review(
                project_path=project,
                work_dir=root / "fp",
                scan_id="scan-1",
                review_id="review-1",
                vulnerabilities=[vulnerability],
            )
        assert reviewed["processed"] == 1
        assert reviewed["results"][0]["verdict"] == "false_positive"
        assert run_task.await_count > 0
        assert all(
            "JSON Schema" in call.kwargs["prompt"]
            and '"verdict"' in call.kwargs["prompt"]
            for call in run_task.await_args_list
        )

        validators = root / "validators"
        validator = validators / "demo"
        validator.mkdir(parents=True)
        (validator / "validator.yaml").write_text(
            "schema_version: 1\nproduct: Demo\nvalidation_environment: lab\n",
            encoding="utf-8",
        )
        (validator / "validator.py").write_text(
            "from ...sdk import ValidationResult\n"
            "async def validate(**kwargs):\n"
            "    await kwargs['emit_stdout']('validation', 'ran')\n"
            "    return ValidationResult(True, True, summary='verified')\n",
            encoding="utf-8",
        )
        validated = await run_vulnerability_validation(
            project_path=project,
            code_scan_path=project,
            work_dir=root / "validation",
            scan_id="scan-1",
            product="Demo",
            environment="lab",
            validation_items=[{"vuln_index": 7, "vulnerability": vulnerability}],
            validators_dir=validators,
            environment_config={},
            cancel_event=threading.Event(),
        )
        assert validated["status"] == "success"
        assert validated["validations"][0]["status"] == "verified"
        assert validated["validations"][0]["is_problem"] is True

    with tempfile.TemporaryDirectory() as temp:
        asyncio.run(scenario(Path(temp)))
