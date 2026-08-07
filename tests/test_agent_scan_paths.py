from __future__ import annotations

import asyncio
import tempfile
import threading
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from deephole_client.config import AgentConfig
from deephole_client.scanner import (
    SCAN_MODE_THREAT_ANALYSIS_ONLY,
    _event_candidate_index,
    _finish_scan,
    _format_process_console_line,
    _format_process_event_message,
    _report_process_vulnerabilities,
    _resolve_scan_paths,
    run_scan,
)
from deephole_client.task_manager import ScanCancellationEvent
from backend.models import MiningEngineSelection, Vulnerability
from deephole_client.vulnerability_mining import runtime as mining_runtime
from deephole_client.vulnerability_mining.engines.threat_audit import (
    engine as threat_audit_engine_module,
)
from deephole_client.vulnerability_mining.engines.threat_audit.engine import (
    run as run_threat_audit_engine,
)


def _reporter() -> SimpleNamespace:
    reporter = SimpleNamespace(
        send_event=AsyncMock(),
        finish_scan=AsyncMock(),
        send_index_status=AsyncMock(),
        publish_opencode_pool_until=AsyncMock(),
        send_static_progress=AsyncMock(),
        report_candidates=AsyncMock(),
        get_processed_keys=AsyncMock(return_value=set()),
        replace_skill_reports=AsyncMock(),
        report_vulnerability=AsyncMock(return_value={"index": 0}),
        report_processed_key=AsyncMock(),
        get_threat_audit_tasks=AsyncMock(return_value=[]),
        push_threat_analysis=AsyncMock(),
        report_threat_analysis_run=AsyncMock(),
        push_threat_audit_task=AsyncMock(),
        report_mining_engine_run=AsyncMock(),
    )
    return reporter


def _vulnerability() -> dict:
    return {
        "file": "src/a.c",
        "line": 10,
        "function": "parse",
        "call_chain": [],
        "vuln_type": "npd",
        "severity": "high",
        "description": "null dereference",
        "ai_analysis": "confirmed from source",
        "vulnerability_report": "# Null dereference report",
        "confirmed": True,
        "ai_verdict": "confirmed",
        "audit_index": 0,
    }


def _threat_vulnerability() -> dict:
    return {
        "file": "src/threat.c",
        "line": 42,
        "function": "handle_packet",
        "call_chain": [],
        "vuln_type": "out_of_bounds",
        "severity": "critical",
        "description": "threat-derived out-of-bounds write",
        "confirmed": True,
        "ai_verdict": "confirmed",
        "analysis_source": "threat_audit",
        "source_task_id": "threat-task-1",
        "threat_surface_node_id": "TREE-1:NODE-1",
        "threat_method_node_id": "PATTERN-1",
    }


class AgentScanPathTests(unittest.IsolatedAsyncioTestCase):
    async def test_replaced_attempt_suppresses_stale_terminal_report(self) -> None:
        reporter = _reporter()
        cancel_event = ScanCancellationEvent()
        cancel_event.suppress_terminal_report = True

        await _finish_scan(
            reporter,
            "scan-replaced",
            status="cancelled",
            vulnerabilities=[],
            total=0,
            processed=0,
            cancel_event=cancel_event,
        )

        reporter.finish_scan.assert_not_awaited()

    async def test_reported_fp_check_item_keeps_selected_method(self) -> None:
        reporter = _reporter()
        reporter.report_vulnerability.return_value = {
            "index": 0,
            "fp_review": {
                "review_id": "review-1",
                "method": "fp_check",
                "vuln_index": 0,
                "queued": True,
                "processed": 0,
            },
        }
        config = AgentConfig()
        config.vulnerability_validation.enabled = False
        enqueue = AsyncMock(side_effect=RuntimeError("queue unavailable"))
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch(
                "deephole_client.server.enqueue_fp_review",
                enqueue,
            ),
        ):
            project = Path(tmp)
            reported = await _report_process_vulnerabilities(
                reporter=reporter,
                config=config,
                scan_id="scan-1",
                project_path=project,
                code_scan_path=project,
                product="",
                validation_environment="",
                feedback_entries=[],
                code_graph_mcp=None,
                engine=MiningEngineSelection(
                    engine_id="static_candidate",
                    engine_label="Static",
                    enabled=True,
                ),
                values=[_vulnerability()],
            )

        self.assertEqual(enqueue.await_args.kwargs["method"], "fp_check")
        self.assertEqual(len(reported), 1)
        self.assertEqual(reported[0][1]["index"], 0)

    def test_structured_task_output_does_not_repeat_process_prefix(self) -> None:
        line = "[threat_analysis][ses-1][tool] name=read"

        self.assertEqual(
            _format_process_console_line("threat_analysis", line),
            line,
        )
        self.assertEqual(
            _format_process_console_line(
                "threat_analysis",
                "Threat analysis started",
            ),
            "[threat_analysis] Threat analysis started",
        )

    def test_code_graph_progress_message_includes_percentage(self) -> None:
        event = {
            "process": "code_graph_build",
            "kind": "progress",
            "message": "tree-sitter refs",
            "data": {"current": 3200, "total": 12840},
        }

        self.assertEqual(
            _format_process_event_message(event, event["message"]),
            "tree-sitter refs: 3200/12840 (24.9%)",
        )

    def test_static_analysis_phase_counts_are_not_candidate_indexes(self) -> None:
        for data in (
            {"checker_index": 2, "checker_total": 8},
            {"progress_current": 30, "progress_total": 100},
            {"current": 4, "total": 9},
        ):
            with self.subTest(data=data):
                self.assertIsNone(_event_candidate_index({
                    "process": "static_analysis",
                    "kind": "progress",
                    "data": data,
                }))

        self.assertEqual(
            _event_candidate_index({
                "process": "static_analysis",
                "kind": "progress",
                "data": {"candidate_count": 3},
            }),
            3,
        )

    def test_scan_path_must_stay_inside_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            source = project / "src"
            outside = root / "outside"
            source.mkdir(parents=True)
            outside.mkdir()

            resolved_project, resolved_source = _resolve_scan_paths(
                project,
                source,
            )
            self.assertEqual(resolved_project, project.resolve())
            self.assertEqual(resolved_source, source.resolve())
            with self.assertRaisesRegex(ValueError, "inside project_path"):
                _resolve_scan_paths(project, outside)

    async def test_full_scan_coordinates_graph_static_and_audit_processes(self) -> None:
        calls: list[str] = []
        reporter = _reporter()
        config = AgentConfig()
        config.threat_analysis.enabled = False
        config.vulnerability_validation.enabled = False
        config.product_info.enabled = True
        config.product_info.name = "product-knowledge"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            source = project / "src"
            source.mkdir(parents=True)
            index_path = root / "index.db"
            index_path.touch()

            async def graph(**kwargs):
                calls.append("code_graph_build")
                self.assertEqual(kwargs["project_path"], project.resolve())
                self.assertEqual(kwargs["code_scan_path"], source.resolve())
                return {
                    "status": "success",
                    "index_db_path": str(index_path),
                    "stats": {"files": 1},
                }

            async def static(**kwargs):
                calls.append("static_analysis")
                self.assertEqual(kwargs["index_db_path"], index_path)
                self.assertIn("static_candidate/rules", kwargs["checker_dirs"][0].as_posix())
                return {
                    "status": "success",
                    "candidates": [{
                        "file": "src/a.c",
                        "line": 10,
                        "function": "parse",
                        "description": "candidate",
                        "vuln_type": "npd",
                    }],
                }

            async def audit(**kwargs):
                calls.append("candidate_audit")
                self.assertEqual(kwargs["index_db_path"], index_path)
                self.assertIn("static_candidate/rules", kwargs["checker_dirs"][0].as_posix())
                self.assertEqual(kwargs["product_mcp"], "product-info")
                processed_key = {
                    "file": "src/a.c",
                    "line": 10,
                    "function": "parse",
                    "vuln_type": "npd",
                }
                await kwargs["on_candidate_result"]({
                    "audit_index": 0,
                    "checker_name": "npd",
                    "candidate": {
                        **processed_key,
                        "description": "candidate",
                    },
                    "vulnerabilities": [_vulnerability()],
                    "skill_reports": [],
                    "processed_key": processed_key,
                })
                self.assertEqual(
                    reporter.report_vulnerability.await_count,
                    1,
                )
                self.assertEqual(
                    reporter.report_processed_key.await_count,
                    1,
                )
                return {
                    "status": "success",
                    "vulnerabilities": [_vulnerability()],
                    "skill_reports": {},
                    "processed_keys": [processed_key],
                }

            task_context = MagicMock(return_value=nullcontext())
            with (
                patch("deephole_client.scanner.Path.home", return_value=root),
                patch("deephole_client.scanner.configure_platform_runtime"),
                patch(
                    "deephole_client.scanner.opencode_task_context",
                    task_context,
                ),
                patch(
                    "deephole_client.scanner.run_code_graph_build",
                    side_effect=graph,
                ),
                patch(
                    "deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.run_static_analysis",
                    side_effect=static,
                ),
                patch(
                    "deephole_client.vulnerability_mining.engines.static_candidate.candidate_audit.run_candidate_audit",
                    side_effect=audit,
                ),
            ):
                await run_scan(
                    config=config,
                    project_path=project,
                    code_scan_path=source,
                    reporter=reporter,
                    scan_name="demo",
                    product="",
                    validation_environment="",
                    checker_names=["npd"],
                    scan_id="scan-1",
                    cancel_event=threading.Event(),
                    knowledge_base_mcp={
                        "enabled": True,
                        "name": "product-info",
                        "transport": "remote",
                        "timeout_seconds": 300,
                        "local": {"executable": "", "args": [], "environment": {}},
                        "remote": {"url": "http://knowledge.test/mcp", "headers": {}},
                    },
                    mining_engines=[{
                        "engine_id": "static_candidate",
                        "engine_label": "静态规则扫描 + 候选点审计",
                        "enabled": True,
                    }],
                )

        self.assertEqual(
            calls,
            ["code_graph_build", "static_analysis", "candidate_audit"],
        )
        reporter.report_candidates.assert_awaited_once()
        reported_candidates = reporter.report_candidates.await_args.args[1]
        self.assertEqual(len(reported_candidates), 1)
        self.assertEqual(reported_candidates[0].file, "src/a.c")
        reporter.send_static_progress.assert_awaited_once_with(
            "scan-1",
            0,
            0,
            done=True,
        )
        reporter.report_vulnerability.assert_awaited_once()
        reporter.report_processed_key.assert_awaited_once()
        reporter.finish_scan.assert_awaited_once()
        self.assertEqual(
            reporter.finish_scan.await_args.args[3],
            1,
        )
        self.assertEqual(
            reporter.finish_scan.await_args.args[2],
            "complete",
        )
        self.assertIsNone(task_context.call_args.kwargs["code_graph_mcp"])
        self.assertEqual(
            task_context.call_args.kwargs["knowledge_base_mcp"]["name"],
            "product-info",
        )
        self.assertTrue(any(
            call.args[1].message
            == "Code graph MCP is not enabled; model tasks will use file tools only"
            for call in reporter.send_event.await_args_list
        ))

    async def test_code_graph_stage_progress_keeps_source_file_counts(self) -> None:
        reporter = _reporter()
        config = AgentConfig()
        task_log = "[threat_analysis][session-1][tool] name=read path=src/a.c"
        validation_log = "explicit validation output"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()

            async def graph(**kwargs):
                await kwargs["output"]({
                    "process": "threat_analysis",
                    "kind": "log",
                    "message": task_log,
                    "data": {},
                })
                await kwargs["output"]({
                    "process": "vulnerability_validation",
                    "kind": "log",
                    "message": validation_log,
                    "data": {"title": "验证过程"},
                })
                await kwargs["output"]({
                    "process": "code_graph_build",
                    "kind": "progress",
                    "message": "Indexing source files",
                    "data": {"current": 5, "total": 10},
                })
                await kwargs["output"]({
                    "process": "code_graph_build",
                    "kind": "progress",
                    "message": "tree-sitter refs",
                    "data": {"current": 400, "total": 800},
                })
                return {
                    "status": "cancelled",
                    "index_db_path": "",
                    "stats": {},
                }

            with (
                patch("deephole_client.scanner.Path.home", return_value=root),
                patch("deephole_client.scanner.configure_platform_runtime"),
                patch(
                    "deephole_client.scanner.run_code_graph_build",
                    side_effect=graph,
                ),
                patch("deephole_client.scanner.print") as console_print,
            ):
                await run_scan(
                    config=config,
                    project_path=project,
                    code_scan_path=project,
                    reporter=reporter,
                    scan_name="progress",
                    product="",
                    validation_environment="",
                    checker_names=[],
                    scan_id="scan-progress",
                    cancel_event=threading.Event(),
                    mining_engines=[{
                        "engine_id": "static_candidate",
                        "engine_label": "Static",
                        "enabled": True,
                    }],
                )

        source_status, stage_status = (
            reporter.send_index_status.await_args_list
        )
        self.assertEqual(source_status.args, ("scan-progress", "parsing", 5, 10))
        self.assertEqual(source_status.kwargs["stage"], "")
        self.assertEqual(stage_status.args, ("scan-progress", "parsing", 5, 10))
        self.assertEqual(stage_status.kwargs["stage"], "tree-sitter refs")
        self.assertEqual(stage_status.kwargs["stage_current"], 400)
        self.assertEqual(stage_status.kwargs["stage_total"], 800)
        messages = [
            call.args[1].message
            for call in reporter.send_event.await_args_list
        ]
        self.assertNotIn("Indexing source files: 5/10 (50.0%)", messages)
        self.assertNotIn("tree-sitter refs: 400/800 (50.0%)", messages)
        self.assertNotIn(task_log, messages)
        self.assertIn(validation_log, messages)
        self.assertTrue(any(
            call.args and call.args[0] == task_log
            for call in console_print.call_args_list
        ))
        self.assertEqual(reporter.finish_scan.await_args.args[2], "cancelled")

    async def test_code_graph_exception_finishes_scan_as_error(self) -> None:
        reporter = _reporter()
        config = AgentConfig()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()

            with (
                patch("deephole_client.scanner.Path.home", return_value=root),
                patch("deephole_client.scanner.configure_platform_runtime"),
                patch(
                    "deephole_client.scanner.run_code_graph_build",
                    new=AsyncMock(
                        side_effect=OSError("cross-device publish failed"),
                    ),
                ),
            ):
                await run_scan(
                    config=config,
                    project_path=project,
                    code_scan_path=project,
                    reporter=reporter,
                    scan_name="failure",
                    product="",
                    validation_environment="",
                    checker_names=[],
                    scan_id="scan-failure",
                    cancel_event=threading.Event(),
                    mining_engines=[{
                        "engine_id": "static_candidate",
                        "engine_label": "Static",
                        "enabled": True,
                    }],
                )

        error_status = reporter.send_index_status.await_args
        self.assertEqual(error_status.args, ("scan-failure", "error", 0, 0))
        self.assertEqual(
            error_status.kwargs["error"],
            "OSError: cross-device publish failed",
        )
        self.assertEqual(reporter.finish_scan.await_args.args[2], "error")
        self.assertEqual(
            reporter.finish_scan.await_args.kwargs["error_message"],
            "OSError: cross-device publish failed",
        )
        self.assertTrue(any(
            call.args[1].message
            == (
                "Code graph build failed: "
                "OSError: cross-device publish failed"
            )
            for call in reporter.send_event.await_args_list
        ))

    async def test_threat_analysis_can_run_without_mining_engine(self) -> None:
        reporter = _reporter()
        config = AgentConfig()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            index_path = root / "index.db"
            index_path.touch()
            analysis = AsyncMock(return_value={
                "result": True,
                "attack_tree_path": str(root / "attack-tree.json"),
                "high_risk_modules_path": str(root / "risk.json"),
            })
            mining = AsyncMock()
            with (
                patch("deephole_client.scanner.Path.home", return_value=root),
                patch("deephole_client.scanner.configure_platform_runtime"),
                patch(
                    "deephole_client.scanner.opencode_task_context",
                    return_value=nullcontext(),
                ),
                patch(
                    "deephole_client.scanner.run_code_graph_build",
                    new=AsyncMock(return_value={
                        "status": "success",
                        "index_db_path": str(index_path),
                        "stats": {"files": 0},
                    }),
                ),
                patch(
                    "deephole_client.scanner.run_threat_analysis",
                    new=analysis,
                ),
                patch(
                    "deephole_client.scanner.collect_json_artifacts",
                    return_value={"artifacts": {}},
                ),
                patch(
                    "deephole_client.scanner.run_mining_engine",
                    new=mining,
                ),
            ):
                await run_scan(
                    config=config,
                    project_path=project,
                    code_scan_path=project,
                    reporter=reporter,
                    scan_name="analysis-only",
                    product="",
                    validation_environment="",
                    checker_names=[],
                    scan_id="scan-analysis-only",
                    cancel_event=threading.Event(),
                    threat_analysis_enabled=True,
                    threat_analysis_method="custom_threat_analysis",
                    mining_engines=[],
                )

        analysis.assert_awaited_once()
        self.assertEqual(
            analysis.await_args.kwargs["method_id"],
            "custom_threat_analysis",
        )
        self.assertFalse(analysis.await_args.kwargs["is_resume"])
        mining.assert_not_awaited()
        reporter.push_threat_analysis.assert_awaited_once()
        self.assertEqual(
            [
                call.args[1].status
                for call in reporter.report_threat_analysis_run.await_args_list
            ],
            ["running", "success"],
        )
        self.assertEqual(reporter.finish_scan.await_args.args[2], "complete")

    async def test_threat_analysis_error_is_reported_and_kept_visible(self) -> None:
        reporter = _reporter()
        config = AgentConfig()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            index_path = root / "index.db"
            index_path.touch()
            with (
                patch("deephole_client.scanner.Path.home", return_value=root),
                patch("deephole_client.scanner.configure_platform_runtime"),
                patch(
                    "deephole_client.scanner.opencode_task_context",
                    return_value=nullcontext(),
                ),
                patch(
                    "deephole_client.scanner.run_code_graph_build",
                    new=AsyncMock(return_value={
                        "status": "success",
                        "index_db_path": str(index_path),
                        "stats": {"files": 0},
                    }),
                ),
                patch(
                    "deephole_client.scanner.run_threat_analysis",
                    new=AsyncMock(return_value={
                        "result": False,
                        "reason": "Threat model service unavailable",
                    }),
                ),
            ):
                await run_scan(
                    config=config,
                    project_path=project,
                    code_scan_path=project,
                    reporter=reporter,
                    scan_name="analysis-error",
                    product="",
                    validation_environment="",
                    checker_names=[],
                    scan_id="scan-analysis-error",
                    cancel_event=threading.Event(),
                    threat_analysis_enabled=True,
                    mining_engines=[],
                )

        reported_runs = [
            call.args[1]
            for call in reporter.report_threat_analysis_run.await_args_list
        ]
        self.assertEqual([run.status for run in reported_runs], ["running", "error"])
        self.assertEqual(
            reported_runs[-1].error_message,
            "Threat model service unavailable",
        )
        self.assertEqual(reporter.finish_scan.await_args.args[2], "error")
        self.assertIn(
            "Threat model service unavailable",
            reporter.finish_scan.await_args.kwargs["error_message"],
        )

    async def test_threat_analysis_failure_only_blocks_dependent_engine(
        self,
    ) -> None:
        reporter = _reporter()
        started: list[str] = []
        manifests = [
            SimpleNamespace(
                engine_id="independent",
                label="Independent engine",
                fp_review=False,
            ),
            SimpleNamespace(
                engine_id="threat_audit",
                label="Threat audit",
                fp_review=False,
            ),
        ]
        loaded = {
            item.engine_id: SimpleNamespace(manifest=item)
            for item in manifests
        }
        registry = SimpleNamespace(
            errors=[],
            manifests=lambda: manifests,
            get=lambda engine_id: loaded.get(engine_id),
        )

        async def run_engine(engine, **_kwargs):
            started.append(engine.manifest.engine_id)
            return {
                "status": "success",
                "vulnerabilities": [],
                "error_message": "",
                "total_candidates": 0,
                "processed_candidates": 0,
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            index_path = root / "index.db"
            index_path.touch()
            with (
                patch("deephole_client.scanner.Path.home", return_value=root),
                patch("deephole_client.scanner.configure_platform_runtime"),
                patch(
                    "deephole_client.scanner.opencode_task_context",
                    return_value=nullcontext(),
                ),
                patch(
                    "deephole_client.scanner.load_mining_engines",
                    return_value=registry,
                ),
                patch(
                    "deephole_client.scanner.run_mining_engine",
                    side_effect=run_engine,
                ),
                patch(
                    "deephole_client.scanner.run_code_graph_build",
                    new=AsyncMock(return_value={
                        "status": "success",
                        "index_db_path": str(index_path),
                        "stats": {"files": 0},
                    }),
                ),
                patch(
                    "deephole_client.scanner.run_threat_analysis",
                    new=AsyncMock(return_value={
                        "result": False,
                        "reason": "Threat model service unavailable",
                    }),
                ),
            ):
                await run_scan(
                    config=AgentConfig(),
                    project_path=project,
                    code_scan_path=project,
                    reporter=reporter,
                    scan_name="independent-engine",
                    product="",
                    validation_environment="",
                    checker_names=[],
                    scan_id="scan-independent-engine",
                    cancel_event=threading.Event(),
                    threat_analysis_enabled=True,
                    mining_engines=[
                        {
                            "engine_id": item.engine_id,
                            "engine_label": item.label,
                            "enabled": True,
                        }
                        for item in manifests
                    ],
                )

        final_runs = {
            call.args[1]["engine_id"]: call.args[1]
            for call in reporter.report_mining_engine_run.await_args_list
        }
        self.assertEqual(started, ["independent"])
        self.assertEqual(final_runs["independent"]["status"], "success")
        self.assertEqual(final_runs["threat_audit"]["status"], "skipped")
        self.assertIn(
            "Blocked because threat analysis failed",
            final_runs["threat_audit"]["error_message"],
        )
        self.assertEqual(reporter.finish_scan.await_args.args[2], "complete")
        self.assertIn(
            "Threat model service unavailable",
            reporter.finish_scan.await_args.kwargs["error_message"],
        )

    async def test_threat_analysis_resume_falls_back_once_from_clean_artifacts(
        self,
    ) -> None:
        reporter = _reporter()
        config = AgentConfig()
        attempts: list[bool] = []

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            index_path = root / "index.db"
            index_path.touch()

            async def run_analysis(**kwargs):
                attempts.append(bool(kwargs["is_resume"]))
                output_path = Path(kwargs["output_path"])
                output_path.mkdir(parents=True, exist_ok=True)
                if len(attempts) == 1:
                    (output_path / "poisoned.json").write_text(
                        '{"cached": true}',
                        encoding="utf-8",
                    )
                    return {
                        "result": False,
                        "reason": "cached semantic mismatch",
                    }
                return {
                    "result": True,
                    "attack_tree_path": str(root / "attack-tree.json"),
                    "high_risk_modules_path": str(root / "risk.json"),
                }

            with (
                patch("deephole_client.scanner.Path.home", return_value=root),
                patch("deephole_client.scanner.configure_platform_runtime"),
                patch(
                    "deephole_client.scanner.opencode_task_context",
                    return_value=nullcontext(),
                ),
                patch(
                    "deephole_client.scanner.run_code_graph_build",
                    new=AsyncMock(return_value={
                        "status": "success",
                        "index_db_path": str(index_path),
                        "stats": {"files": 0},
                    }),
                ),
                patch(
                    "deephole_client.scanner.run_threat_analysis",
                    new=AsyncMock(side_effect=run_analysis),
                ),
                patch(
                    "deephole_client.scanner.collect_json_artifacts",
                    return_value={"artifacts": {}},
                ),
            ):
                await run_scan(
                    config=config,
                    project_path=project,
                    code_scan_path=project,
                    reporter=reporter,
                    scan_name="analysis-resume",
                    product="",
                    validation_environment="",
                    checker_names=[],
                    scan_id="scan-analysis-resume",
                    cancel_event=threading.Event(),
                    is_resume=True,
                    retry_total_candidates=7,
                    retry_processed_offset=5,
                    resume_threat_analysis=True,
                    threat_analysis_enabled=True,
                    mining_engines=[],
                )

            failed_root = (
                root
                / ".opendeephole"
                / "scans"
                / "scan-analysis-resume"
                / "threat_analysis_failed"
            )
            archives = list(failed_root.iterdir())
            self.assertEqual(attempts, [True, False])
            self.assertEqual(len(archives), 1)
            self.assertTrue((archives[0] / "poisoned.json").is_file())
            self.assertEqual(
                reporter.finish_scan.await_args.args[2],
                "complete",
            )
            self.assertEqual(reporter.finish_scan.await_args.args[3:5], (7, 5))

    async def test_threat_analysis_resume_clean_fallback_is_not_repeated(
        self,
    ) -> None:
        reporter = _reporter()
        attempts: list[bool] = []

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            index_path = root / "index.db"
            index_path.touch()

            async def run_analysis(**kwargs):
                attempts.append(bool(kwargs["is_resume"]))
                Path(kwargs["output_path"]).mkdir(
                    parents=True,
                    exist_ok=True,
                )
                return {
                    "result": False,
                    "reason": f"attempt {len(attempts)} failed",
                }

            with (
                patch("deephole_client.scanner.Path.home", return_value=root),
                patch("deephole_client.scanner.configure_platform_runtime"),
                patch(
                    "deephole_client.scanner.opencode_task_context",
                    return_value=nullcontext(),
                ),
                patch(
                    "deephole_client.scanner.run_code_graph_build",
                    new=AsyncMock(return_value={
                        "status": "success",
                        "index_db_path": str(index_path),
                        "stats": {"files": 0},
                    }),
                ),
                patch(
                    "deephole_client.scanner.run_threat_analysis",
                    new=AsyncMock(side_effect=run_analysis),
                ),
            ):
                await run_scan(
                    config=AgentConfig(),
                    project_path=project,
                    code_scan_path=project,
                    reporter=reporter,
                    scan_name="analysis-resume-double-failure",
                    product="",
                    validation_environment="",
                    checker_names=[],
                    scan_id="scan-analysis-resume-double-failure",
                    cancel_event=threading.Event(),
                    is_resume=True,
                    resume_threat_analysis=True,
                    threat_analysis_enabled=True,
                    mining_engines=[],
                )

        self.assertEqual(attempts, [True, False])
        self.assertEqual(reporter.finish_scan.await_args.args[2], "error")
        self.assertIn(
            "Incremental threat-analysis resume failed: attempt 1 failed; "
            "clean fallback failed: attempt 2 failed",
            reporter.finish_scan.await_args.kwargs["error_message"],
        )

    async def test_resume_runs_only_requested_failed_engine(self) -> None:
        reporter = _reporter()
        config = AgentConfig()
        started: list[str] = []
        manifests = [
            SimpleNamespace(engine_id="good", label="Good", fp_review=False),
            SimpleNamespace(engine_id="bad", label="Bad", fp_review=False),
        ]
        loaded = {
            item.engine_id: SimpleNamespace(manifest=item)
            for item in manifests
        }
        registry = SimpleNamespace(
            errors=[],
            manifests=lambda: manifests,
            get=lambda engine_id: loaded.get(engine_id),
        )

        async def run_engine(engine, **_kwargs):
            started.append(engine.manifest.engine_id)
            raise RuntimeError("retry still failed")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            index_path = root / "index.db"
            index_path.touch()
            with (
                patch("deephole_client.scanner.Path.home", return_value=root),
                patch("deephole_client.scanner.configure_platform_runtime"),
                patch(
                    "deephole_client.scanner.opencode_task_context",
                    return_value=nullcontext(),
                ),
                patch(
                    "deephole_client.scanner.load_mining_engines",
                    return_value=registry,
                ),
                patch(
                    "deephole_client.scanner.run_mining_engine",
                    side_effect=run_engine,
                ),
                patch(
                    "deephole_client.scanner.run_code_graph_build",
                    new=AsyncMock(return_value={
                        "status": "success",
                        "index_db_path": str(index_path),
                        "stats": {"files": 0},
                    }),
                ),
            ):
                await run_scan(
                    config=config,
                    project_path=project,
                    code_scan_path=project,
                    reporter=reporter,
                    scan_name="targeted-resume",
                    product="",
                    validation_environment="",
                    checker_names=[],
                    scan_id="scan-targeted-resume",
                    cancel_event=threading.Event(),
                    is_resume=True,
                    retry_mining_engine_ids=["bad"],
                    mining_engines=[
                        {
                            "engine_id": "good",
                            "engine_label": "Good",
                            "enabled": True,
                        },
                        {
                            "engine_id": "bad",
                            "engine_label": "Bad",
                            "enabled": True,
                        },
                    ],
                )

        self.assertEqual(started, ["bad"])
        self.assertEqual(reporter.finish_scan.await_args.args[2], "complete")
        self.assertIn(
            "Bad: retry still failed",
            reporter.finish_scan.await_args.kwargs["error_message"],
        )

    async def test_threat_only_mode_does_not_start_static_processes(self) -> None:
        reporter = _reporter()
        reported_indexes: list[int] = []

        async def report_vulnerability(
            _scan_id,
            vulnerability,
        ):
            index = len(reported_indexes)
            reported_indexes.append(index)
            vulnerability.output_source.agent_session_id = "agent-session-1"
            return {"index": index}

        reporter.report_vulnerability.side_effect = report_vulnerability
        config = AgentConfig()
        config.threat_analysis.enabled = True
        static = AsyncMock()
        audit = AsyncMock()
        first_threat_result_reported = asyncio.Event()
        release_threat_batch = asyncio.Event()
        threat_vulnerabilities = [
            _threat_vulnerability(),
            {
                **_threat_vulnerability(),
                "file": "src/threat_second.c",
                "line": 84,
                "function": "handle_second_packet",
                "description": "second threat-derived issue",
                "vuln_type": "integer_overflow",
            },
        ]
        threat_task = {
            "task_id": "threat-task-1",
            "scan_id": "scan-threat",
            "status": "running",
            "surface_node_id": "TREE-1:NODE-1",
            "surface_name": "parser",
            "method_node_id": "PATTERN-1",
            "method_name": "malformed packet",
            "created_at": "2026-07-30T00:00:00+00:00",
            "started_at": "2026-07-30T00:00:01+00:00",
            "updated_at": "2026-07-30T00:00:01+00:00",
        }

        async def threat_audit_run(**kwargs):
            await kwargs["output"]({
                "process": "threat_audit",
                "kind": "task_status",
                "message": "pending",
                "data": {
                    "task": {
                        **threat_task,
                        "status": "pending",
                        "started_at": "",
                        "updated_at": "2026-07-30T00:00:00+00:00",
                    },
                },
            })
            await kwargs["output"]({
                "process": "threat_audit",
                "kind": "task_status",
                "message": "running",
                "data": {"task": threat_task},
            })
            completed_task = {
                **threat_task,
                "status": "completed",
                "finished_at": "2026-07-30T00:00:02+00:00",
                "updated_at": "2026-07-30T00:00:02+00:00",
            }
            await kwargs["on_task_result"]({
                "task": completed_task,
                "vulnerabilities": threat_vulnerabilities,
            })
            await kwargs["output"]({
                "process": "threat_audit",
                "kind": "task_status",
                "message": "completed",
                "data": {"task": completed_task},
            })
            first_threat_result_reported.set()
            await release_threat_batch.wait()
            return {
                "status": "success",
                "tasks": [completed_task],
                "vulnerabilities": threat_vulnerabilities,
            }

        original_load_module = mining_runtime._load_module

        def load_engine_module(manifest):
            if manifest.engine_id == "threat_audit":
                return threat_audit_engine_module
            return original_load_module(manifest)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            index_path = root / "index.db"
            index_path.touch()
            (root / "attack-tree.json").write_text("{}", encoding="utf-8")
            (root / "risk.json").write_text("{}", encoding="utf-8")
            with (
                patch("deephole_client.scanner.Path.home", return_value=root),
                patch("deephole_client.scanner.configure_platform_runtime"),
                patch(
                    "deephole_client.scanner.opencode_task_context",
                    return_value=nullcontext(),
                ),
                patch(
                    "deephole_client.scanner.run_code_graph_build",
                    new=AsyncMock(return_value={
                        "status": "success",
                        "index_db_path": str(index_path),
                        "stats": {"files": 0},
                    }),
                ),
                patch(
                    "deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.run_static_analysis",
                    new=static,
                ),
                patch(
                    "deephole_client.vulnerability_mining.engines.static_candidate.candidate_audit.run_candidate_audit",
                    new=audit,
                ),
                patch(
                    "deephole_client.scanner.run_threat_analysis",
                    new=AsyncMock(return_value={
                        "result": True,
                        "attack_tree_path": str(root / "attack-tree.json"),
                        "high_risk_modules_path": str(root / "risk.json"),
                    }),
                ) as threat,
                patch(
                    "deephole_client.scanner.collect_json_artifacts",
                    return_value={"artifacts": {}},
                ),
                patch(
                    "deephole_client.vulnerability_mining.runtime._load_module",
                    side_effect=load_engine_module,
                ),
                patch(
                    "deephole_client.vulnerability_mining.engines.threat_audit.engine.run_threat_audit",
                    new=AsyncMock(side_effect=threat_audit_run),
                ),
            ):
                scan_task = asyncio.create_task(run_scan(
                    config=config,
                    project_path=project,
                    code_scan_path=project,
                    reporter=reporter,
                    scan_name="threat",
                    product="LTE",
                    validation_environment="",
                    checker_names=[],
                    scan_id="scan-threat",
                    cancel_event=threading.Event(),
                    scan_mode=SCAN_MODE_THREAT_ANALYSIS_ONLY,
                ))
                try:
                    await asyncio.wait_for(
                        first_threat_result_reported.wait(),
                        timeout=1,
                    )
                    self.assertEqual(
                        reporter.report_vulnerability.await_count,
                        2,
                    )
                    reporter.finish_scan.assert_not_awaited()
                    self.assertFalse(scan_task.done())
                    live_task = (
                        reporter.push_threat_audit_task.await_args.args[1]
                    )
                    self.assertEqual(live_task.status, "completed")
                    self.assertEqual(live_task.result_vuln_indexes, [0, 1])
                finally:
                    release_threat_batch.set()
                await asyncio.wait_for(scan_task, timeout=1)

        threat.assert_awaited_once()
        static.assert_not_awaited()
        audit.assert_not_awaited()
        reporter.send_static_progress.assert_awaited_once_with(
            "scan-threat",
            0,
            0,
            done=True,
        )
        finish_args = reporter.finish_scan.await_args.args
        self.assertEqual(finish_args[2], "complete")
        self.assertEqual(len(finish_args[1]), 2)
        self.assertEqual(
            finish_args[1][0].analysis_source,
            "threat_audit",
        )
        self.assertEqual(
            [
                call.args[1].status
                for call in reporter.push_threat_audit_task.await_args_list
            ][:3],
            ["pending", "running", "completed"],
        )
        self.assertEqual(reporter.report_vulnerability.await_count, 2)
        self.assertTrue(
            all(
                vulnerability.output_source.agent_session_id
                == "agent-session-1"
                for vulnerability in finish_args[1]
            ),
        )

    async def test_threat_engine_retries_each_unreported_finding(self) -> None:
        for failure_mode in (
            "empty_response",
            "exception",
            "legacy_runner_empty_response",
        ):
            with self.subTest(failure_mode=failure_mode):
                reporter = _reporter()
                config = AgentConfig()
                attempts: list[str] = []
                threat_vulnerabilities = [
                    _threat_vulnerability(),
                    {
                        **_threat_vulnerability(),
                        "file": "src/threat_retry.c",
                        "line": 99,
                        "function": "retry_issue",
                        "description": "finding requiring report retry",
                    },
                ]
                completed_task = {
                    "task_id": "threat-task-1",
                    "scan_id": "scan-threat-retry",
                    "status": "completed",
                    "surface_node_id": "TREE-1:NODE-1",
                    "surface_name": "parser",
                    "method_node_id": "PATTERN-1",
                    "method_name": "malformed packet",
                    "finished_at": "2026-07-30T00:00:02+00:00",
                    "updated_at": "2026-07-30T00:00:02+00:00",
                }

                async def report_values(values):
                    self.assertEqual(len(values), 1)
                    vulnerability = (
                        values[0]
                        if isinstance(values[0], Vulnerability)
                        else Vulnerability.model_validate(values[0])
                    )
                    attempts.append(vulnerability.file)
                    if (
                        vulnerability.file == "src/threat_retry.c"
                        and attempts.count("src/threat_retry.c") == 1
                    ):
                        if failure_mode == "exception":
                            raise RuntimeError("temporary report failure")
                        vulnerability.output_source.agent_session_id = (
                            "agent-session-retry"
                        )
                        return [(vulnerability, None)]
                    vulnerability.output_source.agent_session_id = (
                        "agent-session-retry"
                    )
                    index = (
                        4
                        if vulnerability.file == "src/threat.c"
                        else 5
                    )
                    return [(vulnerability, {"index": index})]

                async def run_audit(**kwargs):
                    if failure_mode != "legacy_runner_empty_response":
                        await kwargs["on_task_result"]({
                            "task": completed_task,
                            "vulnerabilities": threat_vulnerabilities,
                        })
                    await kwargs["output"]({
                        "process": "threat_audit",
                        "kind": "task_status",
                        "message": "completed",
                        "data": {"task": completed_task},
                    })
                    return {
                        "status": "success",
                        "tasks": [completed_task],
                        "vulnerabilities": threat_vulnerabilities,
                    }

                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    project = root / "project"
                    project.mkdir()
                    attack_tree_path = root / "attack-tree.json"
                    high_risk_modules_path = root / "risk.json"
                    attack_tree_path.write_text("{}", encoding="utf-8")
                    high_risk_modules_path.write_text("{}", encoding="utf-8")
                    with (
                        patch(
                            "deephole_client.vulnerability_mining.engines."
                            "threat_audit.engine.run_threat_audit",
                            new=AsyncMock(side_effect=run_audit),
                        ),
                    ):
                        result = await run_threat_audit_engine(
                            project_path=project,
                            code_scan_path=project,
                            work_dir=root / "work",
                            scan_id="scan-threat-retry",
                            config=config,
                            reporter=reporter,
                            output=AsyncMock(),
                            cancel_event=threading.Event(),
                            retry_threat_audit_task_ids=None,
                            threat_analysis_result={
                                "result": True,
                                "attack_tree_path": str(attack_tree_path),
                                "high_risk_modules_path": str(
                                    high_risk_modules_path
                                ),
                            },
                            report_vulnerabilities=report_values,
                        )

                self.assertEqual(result["status"], "success")
                self.assertEqual(
                    attempts,
                    [
                        "src/threat.c",
                        "src/threat_retry.c",
                        "src/threat_retry.c",
                    ],
                )
                self.assertEqual(len(result["vulnerabilities"]), 2)
                self.assertTrue(all(
                    vulnerability["output_source"]["agent_session_id"]
                    == "agent-session-retry"
                    for vulnerability in result["vulnerabilities"]
                ))
                pushed_tasks = [
                    call.args[1]
                    for call in reporter.push_threat_audit_task.await_args_list
                ]
                self.assertEqual(
                    pushed_tasks[0].result_vuln_indexes,
                    (
                        []
                        if failure_mode == "legacy_runner_empty_response"
                        else [4]
                    ),
                )
                self.assertEqual(
                    pushed_tasks[-1].result_vuln_indexes,
                    [4, 5],
                )

    async def test_custom_scan_graph_is_prepared_and_enters_task_context(
        self,
    ) -> None:
        reporter = _reporter()
        config = AgentConfig()
        config.threat_analysis.enabled = False
        config.vulnerability_validation.enabled = False
        graph_config = {
            "enabled": True,
            "name": "scan-graph",
            "transport": "remote",
            "timeout_seconds": 30,
            "remote": {
                "url": "http://127.0.0.1:9010/mcp",
                "headers": {"Authorization": "Bearer scan-secret"},
            },
            "local": {"executable": "", "args": [], "environment": {}},
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            index_path = root / "index.db"
            index_path.touch()
            task_context = MagicMock(return_value=nullcontext())

            with (
                patch("deephole_client.scanner.Path.home", return_value=root),
                patch("deephole_client.scanner.configure_platform_runtime"),
                patch(
                    "deephole_client.scanner.opencode_task_context",
                    task_context,
                ),
                patch(
                    "deephole_client.codegraph.prepare_scan_codegraph",
                    new=AsyncMock(return_value=True),
                ) as prepare,
                patch(
                    "deephole_client.scanner.run_code_graph_build",
                    new=AsyncMock(return_value={
                        "status": "success",
                        "index_db_path": str(index_path),
                        "stats": {"files": 0},
                    }),
                ),
                patch(
                    "deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.run_static_analysis",
                    new=AsyncMock(return_value={
                        "status": "success",
                        "candidates": [],
                    }),
                ),
                patch(
                    "deephole_client.vulnerability_mining.engines.static_candidate.candidate_audit.run_candidate_audit",
                    new=AsyncMock(return_value={
                        "status": "success",
                        "vulnerabilities": [],
                        "skill_reports": {},
                        "processed_keys": [],
                    }),
                ),
            ):
                await run_scan(
                    config=config,
                    project_path=project,
                    code_scan_path=project,
                    reporter=reporter,
                    scan_name="custom graph",
                    product="",
                    validation_environment="",
                    checker_names=["npd"],
                    scan_id="scan-custom",
                    cancel_event=threading.Event(),
                    code_graph_mcp=graph_config,
                    mining_engines=[{
                        "engine_id": "static_candidate",
                        "engine_label": "静态规则扫描 + 候选点审计",
                        "enabled": True,
                    }],
                )

        prepare.assert_awaited_once()
        self.assertEqual(
            task_context.call_args.kwargs["code_graph_mcp"],
            graph_config,
        )

    async def test_engine_failure_is_isolated_when_another_engine_succeeds(
        self,
    ) -> None:
        reporter = _reporter()
        config = AgentConfig()
        started: set[str] = set()
        both_started = asyncio.Event()
        manifests = [
            SimpleNamespace(
                engine_id="good",
                label="Good engine",
                fp_review=True,
            ),
            SimpleNamespace(
                engine_id="bad",
                label="Bad engine",
                fp_review=False,
            ),
        ]
        loaded = {
            item.engine_id: SimpleNamespace(manifest=item)
            for item in manifests
        }
        registry = SimpleNamespace(
            errors=[],
            manifests=lambda: manifests,
            get=lambda engine_id: loaded.get(engine_id),
        )
        received_keys: set[str] = set()

        async def run_engine(engine, **engine_kwargs):
            received_keys.update(engine_kwargs)
            started.add(engine.manifest.engine_id)
            if len(started) == 2:
                both_started.set()
            await asyncio.wait_for(both_started.wait(), timeout=1)
            if engine.manifest.engine_id == "bad":
                raise RuntimeError("adapter exploded")
            return {
                "status": "success",
                "vulnerabilities": [
                    Vulnerability.model_validate(_vulnerability()),
                ],
                "error_message": "",
                "total_candidates": 1,
                "processed_candidates": 1,
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            index_path = root / "index.db"
            index_path.touch()
            with (
                patch(
                    "deephole_client.scanner.Path.home",
                    return_value=root,
                ),
                patch(
                    "deephole_client.scanner.configure_platform_runtime",
                ),
                patch(
                    "deephole_client.scanner.opencode_task_context",
                    return_value=nullcontext(),
                ),
                patch(
                    "deephole_client.scanner.load_mining_engines",
                    return_value=registry,
                ),
                patch(
                    "deephole_client.scanner.run_mining_engine",
                    side_effect=run_engine,
                ),
                patch(
                    "deephole_client.scanner.run_code_graph_build",
                    new=AsyncMock(return_value={
                        "status": "success",
                        "index_db_path": str(index_path),
                        "stats": {"files": 0},
                    }),
                ),
            ):
                await run_scan(
                    config=config,
                    project_path=project,
                    code_scan_path=project,
                    reporter=reporter,
                    scan_name="isolated",
                    product="",
                    validation_environment="",
                    checker_names=[],
                    scan_id="scan-isolated",
                    cancel_event=threading.Event(),
                    mining_engines=[
                        {
                            "engine_id": "good",
                            "engine_label": "Good engine",
                            "enabled": True,
                        },
                        {
                            "engine_id": "bad",
                            "engine_label": "Bad engine",
                            "enabled": True,
                        },
                        {
                            "engine_id": "missing",
                            "engine_label": "Missing engine",
                            "enabled": True,
                        },
                    ],
                )

        self.assertEqual(started, {"good", "bad"})
        self.assertEqual(
            received_keys,
            {
                "engine_id",
                "engine_label",
                "scan_id",
                "project_path",
                "code_scan_path",
                "scan_dir",
                "work_dir",
                "index_db_path",
                "config",
                "reporter",
                "checker_names",
                "checker_packages",
                "product",
                "validation_environment",
                "vulnerability_validation",
                "feedback_entries",
                "code_graph_mcp",
                "knowledge_base_mcp",
                "product_mcp",
                "is_resume",
                "retry_candidates",
                "retry_total_candidates",
                "retry_processed_offset",
                "resume_threat_analysis",
                "retry_threat_audit_task_ids",
                "output",
                "cancel_event",
                "report_vulnerabilities",
            },
        )
        finish = reporter.finish_scan.await_args
        self.assertEqual(finish.args[2], "complete")
        self.assertEqual(len(finish.args[1]), 1)
        reporter.report_vulnerability.assert_awaited_once()
        reported_vulnerability = (
            reporter.report_vulnerability.await_args.args[1]
        )
        self.assertEqual(reported_vulnerability.engine_id, "good")
        self.assertEqual(
            reported_vulnerability.engine_label,
            "Good engine",
        )
        self.assertFalse(
            hasattr(reported_vulnerability, "fp_review_eligible")
        )
        self.assertIn(
            "Bad engine: adapter exploded",
            finish.kwargs["error_message"],
        )
        self.assertIn(
            "Missing engine: Engine adapter is unavailable",
            finish.kwargs["error_message"],
        )
        run_states = [
            call.args[1]["status"]
            for call in reporter.report_mining_engine_run.await_args_list
        ]
        self.assertIn("success", run_states)
        self.assertIn("error", run_states)
        self.assertEqual(run_states.count("error"), 2)

    async def test_live_report_provenance_does_not_trigger_final_replay(
        self,
    ) -> None:
        reporter = _reporter()
        config = AgentConfig()
        manifest = SimpleNamespace(
            engine_id="good",
            label="Good engine",
            fp_review=True,
        )
        loaded = SimpleNamespace(manifest=manifest)
        registry = SimpleNamespace(
            errors=[],
            manifests=lambda: [manifest],
            get=lambda engine_id: loaded if engine_id == "good" else None,
        )

        async def report_vulnerability(_scan_id, vulnerability):
            vulnerability.output_source.agent_session_id = "agent-session-1"
            return {"index": 0}

        reporter.report_vulnerability.side_effect = report_vulnerability

        async def run_engine(_engine, **engine_kwargs):
            await engine_kwargs["report_vulnerabilities"]([_vulnerability()])
            return {
                "status": "success",
                "vulnerabilities": [
                    Vulnerability.model_validate(_vulnerability()).model_copy(
                        update={
                            "engine_id": "good",
                            "engine_label": "Good engine",
                            "analysis_source": "good",
                        },
                    ),
                ],
                "error_message": "",
                "total_candidates": 1,
                "processed_candidates": 1,
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            index_path = root / "index.db"
            index_path.touch()
            with (
                patch("deephole_client.scanner.Path.home", return_value=root),
                patch("deephole_client.scanner.configure_platform_runtime"),
                patch(
                    "deephole_client.scanner.opencode_task_context",
                    return_value=nullcontext(),
                ),
                patch(
                    "deephole_client.scanner.load_mining_engines",
                    return_value=registry,
                ),
                patch(
                    "deephole_client.scanner.run_mining_engine",
                    side_effect=run_engine,
                ),
                patch(
                    "deephole_client.scanner.run_code_graph_build",
                    new=AsyncMock(return_value={
                        "status": "success",
                        "index_db_path": str(index_path),
                        "stats": {"files": 0},
                    }),
                ),
            ):
                await run_scan(
                    config=config,
                    project_path=project,
                    code_scan_path=project,
                    reporter=reporter,
                    scan_name="live-report-idempotency",
                    product="",
                    validation_environment="",
                    checker_names=[],
                    scan_id="scan-live-report-idempotency",
                    cancel_event=threading.Event(),
                    mining_engines=[{
                        "engine_id": "good",
                        "engine_label": "Good engine",
                        "enabled": True,
                    }],
                )

        reporter.report_vulnerability.assert_awaited_once()
        final_vulnerabilities = reporter.finish_scan.await_args.args[1]
        self.assertEqual(len(final_vulnerabilities), 1)
        self.assertEqual(
            final_vulnerabilities[0].output_source.agent_session_id,
            "",
        )

    async def test_scan_errors_when_all_enabled_engines_fail(self) -> None:
        reporter = _reporter()
        config = AgentConfig()
        registry = SimpleNamespace(
            errors=["missing: invalid adapter"],
            manifests=lambda: [],
            get=lambda _engine_id: None,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            index_path = root / "index.db"
            index_path.touch()
            with (
                patch(
                    "deephole_client.scanner.Path.home",
                    return_value=root,
                ),
                patch(
                    "deephole_client.scanner.configure_platform_runtime",
                ),
                patch(
                    "deephole_client.scanner.opencode_task_context",
                    return_value=nullcontext(),
                ),
                patch(
                    "deephole_client.scanner.load_mining_engines",
                    return_value=registry,
                ),
                patch(
                    "deephole_client.scanner.run_code_graph_build",
                    new=AsyncMock(return_value={
                        "status": "success",
                        "index_db_path": str(index_path),
                        "stats": {"files": 0},
                    }),
                ),
            ):
                await run_scan(
                    config=config,
                    project_path=project,
                    code_scan_path=project,
                    reporter=reporter,
                    scan_name="all failed",
                    product="",
                    validation_environment="",
                    checker_names=[],
                    scan_id="scan-all-failed",
                    cancel_event=threading.Event(),
                    mining_engines=[{
                        "engine_id": "missing",
                        "engine_label": "Missing engine",
                        "enabled": True,
                    }],
                )

        finish = reporter.finish_scan.await_args
        self.assertEqual(finish.args[2], "error")
        self.assertIn(
            "Missing engine: Engine adapter is unavailable",
            finish.kwargs["error_message"],
        )
