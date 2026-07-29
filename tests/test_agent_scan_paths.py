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
    _format_process_console_line,
    _resolve_scan_paths,
    run_scan,
)
from deephole_client.vulnerability_mining import MiningEngineOutput


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
        "vulnerability_report": "",
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
                self.assertIn("static_analysis/rules", kwargs["checker_dirs"][0].as_posix())
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
                self.assertIn("candidate_audit/rules", kwargs["checker_dirs"][0].as_posix())
                self.assertEqual(kwargs["product_mcp"], "product-knowledge")
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
                    "deephole_client.static_analysis.run_static_analysis",
                    side_effect=static,
                ),
                patch(
                    "deephole_client.candidate_audit.run_candidate_audit",
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
                )

        self.assertEqual(
            calls,
            ["code_graph_build", "static_analysis", "candidate_audit"],
        )
        reporter.report_candidates.assert_awaited_once()
        reporter.report_vulnerability.assert_awaited_once()
        reporter.report_processed_key.assert_awaited_once()
        reporter.finish_scan.assert_awaited_once()
        self.assertEqual(
            reporter.finish_scan.await_args.args[2],
            "complete",
        )
        self.assertIsNone(task_context.call_args.kwargs["code_graph_mcp"])
        self.assertTrue(any(
            call.args[1].message
            == "Code graph MCP is not enabled; model tasks will use file tools only"
            for call in reporter.send_event.await_args_list
        ))

    async def test_threat_only_mode_does_not_start_static_processes(self) -> None:
        reporter = _reporter()
        config = AgentConfig()
        config.threat_analysis.enabled = True
        static = AsyncMock()
        audit = AsyncMock()

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
                    "deephole_client.static_analysis.run_static_analysis",
                    new=static,
                ),
                patch(
                    "deephole_client.candidate_audit.run_candidate_audit",
                    new=audit,
                ),
                patch(
                    "deephole_client.threat_analysis_runner.run_threat_analysis",
                    new=AsyncMock(return_value={
                        "result": True,
                        "attack_tree_path": str(root / "attack-tree.json"),
                        "high_risk_modules_path": str(root / "risk.json"),
                    }),
                ) as threat,
                patch(
                    "deephole_client.process_artifacts.collect_json_artifacts",
                    return_value={"artifacts": {}},
                ),
                patch(
                    "deephole_client.threat_audit.run_threat_audit",
                    new=AsyncMock(return_value={
                        "status": "success",
                        "tasks": [],
                        "vulnerabilities": [_threat_vulnerability()],
                    }),
                ),
            ):
                await run_scan(
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
                )

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
        self.assertEqual(len(finish_args[1]), 1)
        self.assertEqual(
            finish_args[1][0].analysis_source,
            "threat_audit",
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
                    "deephole_client.static_analysis.run_static_analysis",
                    new=AsyncMock(return_value={
                        "status": "success",
                        "candidates": [],
                    }),
                ),
                patch(
                    "deephole_client.candidate_audit.run_candidate_audit",
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
                default_enabled=True,
                default_fp_review_enabled=True,
            ),
            SimpleNamespace(
                engine_id="bad",
                label="Bad engine",
                default_enabled=True,
                default_fp_review_enabled=True,
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

        async def run_engine(engine, _context):
            started.add(engine.manifest.engine_id)
            if len(started) == 2:
                both_started.set()
            await asyncio.wait_for(both_started.wait(), timeout=1)
            if engine.manifest.engine_id == "bad":
                raise RuntimeError("adapter exploded")
            return MiningEngineOutput(
                vulnerabilities=[_vulnerability()],
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
                            "fp_review_enabled": True,
                        },
                        {
                            "engine_id": "bad",
                            "engine_label": "Bad engine",
                            "enabled": True,
                            "fp_review_enabled": True,
                        },
                        {
                            "engine_id": "missing",
                            "engine_label": "Missing engine",
                            "enabled": True,
                            "fp_review_enabled": False,
                        },
                    ],
                )

        self.assertEqual(started, {"good", "bad"})
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
        self.assertTrue(reported_vulnerability.fp_review_eligible)
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
                        "fp_review_enabled": False,
                    }],
                )

        finish = reporter.finish_scan.await_args
        self.assertEqual(finish.args[2], "error")
        self.assertIn(
            "Missing engine: Engine adapter is unavailable",
            finish.kwargs["error_message"],
        )
