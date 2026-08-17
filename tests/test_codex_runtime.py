from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import deephole_client.main as agent_main
from deephole_client import codex_runtime
from deephole_client.codex_profiles import CodexProfileSyncResult


class CodexRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        codex_runtime._reset_codex_runtime_state_for_tests()
        self.profile_sync_patcher = patch.object(
            codex_runtime,
            "sync_codex_profiles",
            return_value=CodexProfileSyncResult(),
        )
        self.profile_sync = self.profile_sync_patcher.start()
        self.addCleanup(self.profile_sync_patcher.stop)

    def tearDown(self) -> None:
        codex_runtime._reset_codex_runtime_state_for_tests()

    def test_existing_codex_is_probed_without_touching_npm(self) -> None:
        runner = AsyncMock(return_value=codex_runtime._ProcessResult(
            returncode=0,
            stdout="codex-cli 1.2.3\n",
            stderr="",
        ))

        with (
            patch.object(
                codex_runtime.shutil,
                "which",
                side_effect=lambda name: (
                    "/opt/bin/codex" if name == "codex" else None
                ),
            ) as which,
            patch.object(codex_runtime, "_run_process", new=runner),
            patch("builtins.print"),
        ):
            state = asyncio.run(
                codex_runtime.initialize_codex_runtime(),
            )

        self.assertTrue(state.available)
        self.assertEqual(state.command, ("/opt/bin/codex",))
        self.assertEqual(state.version, "codex-cli 1.2.3")
        self.assertEqual(
            runner.await_args.args[0],
            ("/opt/bin/codex", "--version"),
        )
        self.assertEqual(runner.await_count, 1)
        self.assertEqual(
            [call.args[0] for call in which.call_args_list],
            ["codex"],
        )
        self.profile_sync.assert_called_once_with(
            codex_version="codex-cli 1.2.3",
        )

    def test_missing_npm_is_non_fatal_and_cached_for_this_process(self) -> None:
        with (
            patch.object(codex_runtime.shutil, "which", return_value=None),
            patch.object(
                codex_runtime,
                "_run_process",
                new=AsyncMock(),
            ) as runner,
            patch("builtins.print") as output,
        ):
            first = asyncio.run(
                codex_runtime.initialize_codex_runtime(),
            )
            second = asyncio.run(
                codex_runtime.initialize_codex_runtime(),
            )

        self.assertIs(first, second)
        self.assertFalse(first.available)
        self.assertIn("npm was not found", first.error)
        runner.assert_not_awaited()
        self.assertTrue(any(
            "Agent startup will continue" in str(call)
            for call in output.call_args_list
        ))

    def test_model_sync_failure_keeps_ready_cli_and_default_fallback(
        self,
    ) -> None:
        self.profile_sync.return_value = CodexProfileSyncResult(
            error="profile directory denied",
        )
        ready = codex_runtime.CodexRuntimeState(
            available=True,
            command=("/opt/bin/codex",),
            executable="/opt/bin/codex",
            version="codex-cli 0.146.1",
        )

        with patch("builtins.print") as output:
            state = codex_runtime._sync_runtime_models(ready)

        self.assertTrue(state.available)
        self.assertEqual(state.command, ("/opt/bin/codex",))
        self.assertEqual(state.models, ())
        self.assertEqual(
            state.model_config_error,
            "profile directory denied",
        )
        self.assertTrue(any(
            "user's default Codex configuration" in str(call)
            and "Agent startup will continue" in str(call)
            for call in output.call_args_list
        ))

    def test_install_runs_exact_steps_and_adds_global_bin_to_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp) / "npm-global"
            bin_dir = prefix / "bin"
            bin_dir.mkdir(parents=True)
            installed_codex = bin_dir / "codex"
            installed_codex.touch()
            codex_lookups = iter([None, str(installed_codex)])

            def which(name: str):
                if name == "codex":
                    return next(codex_lookups)
                if name == "npm":
                    return "/opt/node/bin/npm"
                return None

            results = [
                codex_runtime._ProcessResult(0, "", ""),
                codex_runtime._ProcessResult(0, "", ""),
                codex_runtime._ProcessResult(0, "", ""),
                codex_runtime._ProcessResult(0, "installed\n", ""),
                codex_runtime._ProcessResult(0, f"{prefix}\n", ""),
                codex_runtime._ProcessResult(
                    0,
                    "codex-cli 9.9.9\n",
                    "",
                ),
            ]
            runner = AsyncMock(side_effect=results)
            with (
                patch.object(codex_runtime.shutil, "which", side_effect=which),
                patch.object(codex_runtime, "_run_process", new=runner),
                patch.dict(os.environ, {"PATH": "/usr/bin"}),
                patch("builtins.print"),
            ):
                state = asyncio.run(
                    codex_runtime.initialize_codex_runtime(),
                )
                resulting_path = os.environ["PATH"]

        self.assertTrue(state.available)
        self.assertEqual(state.version, "codex-cli 9.9.9")
        self.assertEqual(state.command, (str(installed_codex),))
        commands = [call.args[0] for call in runner.await_args_list]
        self.assertEqual(commands, [
            ("/opt/node/bin/npm", "set", "strict-ssl", "false"),
            (
                "/opt/node/bin/npm",
                "config",
                "set",
                "registry",
                "https://mirrors.tools.huawei.com/npm/",
            ),
            ("/opt/node/bin/npm", "cache", "clean", "-f"),
            (
                "/opt/node/bin/npm",
                "install",
                "-g",
                "@openai/codex",
            ),
            ("/opt/node/bin/npm", "prefix", "--global"),
            (str(installed_codex), "--version"),
        ])
        self.assertEqual(
            resulting_path.split(os.pathsep)[0],
            str(bin_dir),
        )
        self.assertTrue(all(
            0 < call.kwargs["timeout"] <= 120
            for call in runner.await_args_list
        ))
        timeouts = [
            call.kwargs["timeout"]
            for call in runner.await_args_list
        ]
        self.assertEqual(timeouts, sorted(timeouts, reverse=True))

    def test_failed_setup_step_stops_install_and_does_not_retry(self) -> None:
        runner = AsyncMock(side_effect=[
            codex_runtime._ProcessResult(0, "", ""),
            codex_runtime._ProcessResult(1, "", "registry denied"),
        ])

        def which(name: str):
            return "/opt/bin/npm" if name == "npm" else None

        with (
            patch.object(codex_runtime.shutil, "which", side_effect=which),
            patch.object(codex_runtime, "_run_process", new=runner),
            patch("builtins.print"),
        ):
            first = asyncio.run(
                codex_runtime.initialize_codex_runtime(),
            )
            second = asyncio.run(
                codex_runtime.initialize_codex_runtime(),
            )

        self.assertIs(first, second)
        self.assertFalse(first.available)
        self.assertIn("npm config set registry failed", first.error)
        self.assertIn("registry denied", first.error)
        self.assertEqual(runner.await_count, 2)

    def test_timeout_is_non_fatal(self) -> None:
        runner = AsyncMock(side_effect=asyncio.TimeoutError)

        def which(name: str):
            return "/opt/bin/npm" if name == "npm" else None

        with (
            patch.object(codex_runtime.shutil, "which", side_effect=which),
            patch.object(codex_runtime, "_run_process", new=runner),
            patch("builtins.print"),
        ):
            state = asyncio.run(
                codex_runtime.initialize_codex_runtime(
                    timeout_seconds=120,
                ),
            )

        self.assertFalse(state.available)
        self.assertIn("timed out during npm set strict-ssl false", state.error)
        self.assertEqual(runner.await_count, 1)

    def test_process_timeout_terminates_owned_child(self) -> None:
        async def exercise() -> None:
            with self.assertRaises(asyncio.TimeoutError):
                await codex_runtime._run_process(
                    (
                        sys.executable,
                        "-c",
                        "import time; time.sleep(30)",
                    ),
                    timeout=0.05,
                )

        asyncio.run(exercise())

    def test_successful_npm_without_resolvable_codex_is_unavailable(self) -> None:
        runner = AsyncMock(side_effect=[
            codex_runtime._ProcessResult(0, "", ""),
            codex_runtime._ProcessResult(0, "", ""),
            codex_runtime._ProcessResult(0, "", ""),
            codex_runtime._ProcessResult(0, "", ""),
            codex_runtime._ProcessResult(0, "/opt/npm\n", ""),
        ])
        codex_lookups = iter([None, None])

        def which(name: str):
            if name == "codex":
                return next(codex_lookups)
            if name == "npm":
                return "/opt/bin/npm"
            return None

        with (
            patch.object(codex_runtime.shutil, "which", side_effect=which),
            patch.object(codex_runtime, "_run_process", new=runner),
            patch.dict(os.environ, {"PATH": "/usr/bin"}),
            patch("builtins.print"),
        ):
            state = asyncio.run(
                codex_runtime.initialize_codex_runtime(),
            )

        self.assertFalse(state.available)
        self.assertIn("still not available in PATH", state.error)

    def test_windows_npm_shim_exposes_node_argv_prefix_to_engines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp)
            shim = prefix / "codex.cmd"
            shim.touch()
            launcher = (
                prefix
                / "node_modules"
                / "@openai"
                / "codex"
                / "bin"
                / "codex.js"
            )
            launcher.parent.mkdir(parents=True)
            launcher.touch()
            with (
                patch.object(codex_runtime, "_is_windows", return_value=True),
                patch.object(
                    codex_runtime.shutil,
                    "which",
                    return_value="C:/Program Files/nodejs/node.exe",
                ),
            ):
                command = codex_runtime._codex_command(str(shim))

        self.assertEqual(command, (
            "C:/Program Files/nodejs/node.exe",
            str(launcher),
        ))

    def test_agent_prepares_codex_before_connecting(self) -> None:
        order: list[str] = []
        config = SimpleNamespace(
            server_url="http://server.example",
            agent_name="agent-1",
        )
        reporter = SimpleNamespace(
            set_agent_name=MagicMock(),
            close=AsyncMock(),
        )

        async def prepare():
            order.append("codex")
            return codex_runtime.CodexRuntimeState(available=False)

        async def connect(*_args):
            order.append("connect")

        with (
            patch.object(
                agent_main,
                "_parse_args",
                return_value=SimpleNamespace(
                    config=None,
                    server=None,
                    name=None,
                ),
            ),
            patch(
                "deephole_client.config.load_config",
                return_value=config,
            ),
            patch("deephole_client.config.apply_network_env"),
            patch(
                "deephole_client.opencode_integration."
                "configure_opencode_component",
            ),
            patch(
                "deephole_client.codex_runtime.initialize_codex_runtime",
                new=prepare,
            ),
            patch(
                "deephole_client.reporter.Reporter",
                return_value=reporter,
            ),
            patch(
                "deephole_client.task_manager.TaskManager",
                return_value=MagicMock(),
            ),
            patch.object(agent_main, "_ws_loop", new=connect),
            patch("task_agent.shutdown_opencode", new=AsyncMock()),
            patch("builtins.print"),
        ):
            asyncio.run(agent_main._main())

        self.assertEqual(order, ["codex", "connect"])
        reporter.close.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
