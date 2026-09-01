from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from deephole_client import codex_profiles, codex_scan_config
from deephole_client.codex_profiles import sync_codex_trusted_projects


def _local_mcp(
    *,
    executable: str = "codegraph",
    args: list[str] | None = None,
    environment: dict[str, str] | None = None,
) -> dict:
    return {
        "enabled": True,
        "name": "codegraph",
        "transport": "local",
        "timeout_seconds": 300,
        "local": {
            "executable": executable,
            "args": list(args or ["serve", "--mcp"]),
            "environment": dict(environment or {
                "CODEGRAPH_MCP_TOOLS": "explore,node,search",
            }),
        },
        "remote": {"url": "", "headers": {}},
    }


class _AppServer:
    def __init__(self, *, codex_home: Path, cwd: Path) -> None:
        environment = os.environ.copy()
        environment["CODEX_HOME"] = str(codex_home)
        self._process = subprocess.Popen(
            [
                shutil.which("codex") or "codex",
                "app-server",
                "--listen",
                "stdio://",
            ],
            cwd=cwd,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self._messages: queue.Queue[dict] = queue.Queue()
        self._stderr: list[str] = []
        self._stdout_thread = threading.Thread(
            target=self._read_stdout,
            daemon=True,
        )
        self._stderr_thread = threading.Thread(
            target=self._read_stderr,
            daemon=True,
        )
        self._stdout_thread.start()
        self._stderr_thread.start()
        self._next_id = 1
        self.request(
            "initialize",
            {
                "clientInfo": {
                    "name": "opendeephole-test",
                    "version": "1",
                },
                "capabilities": {"experimentalApi": True},
            },
        )
        self.notify("initialized", {})

    def _read_stdout(self) -> None:
        assert self._process.stdout is not None
        for line in self._process.stdout:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                self._messages.put(value)

    def _read_stderr(self) -> None:
        assert self._process.stderr is not None
        self._stderr.extend(self._process.stderr)

    def notify(self, method: str, params: dict) -> None:
        assert self._process.stdin is not None
        self._process.stdin.write(json.dumps({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }) + "\n")
        self._process.stdin.flush()

    def request(
        self,
        method: str,
        params: dict,
        *,
        timeout: float = 20.0,
    ) -> dict:
        request_id = self._next_id
        self._next_id += 1
        assert self._process.stdin is not None
        self._process.stdin.write(json.dumps({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }) + "\n")
        self._process.stdin.flush()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                message = self._messages.get(
                    timeout=max(0.01, deadline - time.monotonic()),
                )
            except queue.Empty:
                break
            if message.get("id") != request_id:
                continue
            if "error" in message:
                raise AssertionError(
                    f"{method} failed: {message['error']}\n"
                    + "".join(self._stderr)
                )
            result = message.get("result")
            if not isinstance(result, dict):
                raise AssertionError(f"{method} returned no result: {message}")
            return result
        raise AssertionError(
            f"timed out waiting for {method}\n" + "".join(self._stderr)
        )

    def close(self) -> None:
        if self._process.poll() is not None:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=5)

    def __enter__(self) -> _AppServer:
        return self

    def __exit__(self, *_args) -> None:
        self.close()


class ScanCodexConfigTests(unittest.TestCase):
    def test_access_trusts_project_storage_workspace_and_runtime_references(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            app_home = root / "home" / ".opendeephole"
            scan_dir = app_home / "scans" / "scan-1"
            scan_dir.mkdir(parents=True)
            codex_home = root / "codex-home"
            runtime_references = root / "runtime" / "codex-goal"
            runtime_references.mkdir(parents=True)

            with patch.object(
                codex_scan_config,
                "codex_runtime_reference_root",
                return_value=runtime_references,
            ):
                result = codex_scan_config.prepare_scan_codex_access(
                    project_path=project,
                    scan_dir=scan_dir,
                    codex_home=codex_home,
                )

            workspace = scan_dir / "threat_analysis"
            self.assertEqual(result.error, "")
            self.assertTrue(workspace.is_dir())
            self.assertEqual(set(result.trusted_paths), {
                str(project.resolve()),
                str(app_home.resolve()),
                str(workspace.resolve()),
                str(runtime_references.resolve()),
            })
            parsed = codex_scan_config.tomllib.loads(
                (codex_home / "config.toml").read_text(encoding="utf-8")
            )
            self.assertEqual(set(parsed["projects"]), set(result.trusted_paths))
            self.assertNotIn("sandbox_permissions", parsed)

    def test_windows_access_adds_global_full_read_sandbox_permission(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            app_home = root / "home" / ".opendeephole"
            scan_dir = app_home / "scans" / "scan-1"
            scan_dir.mkdir(parents=True)
            codex_home = root / "codex-home"
            runtime_references = root / "runtime" / "codex-goal"
            runtime_references.mkdir(parents=True)

            with patch.object(
                codex_scan_config,
                "codex_runtime_reference_root",
                return_value=runtime_references,
            ):
                result = codex_scan_config.prepare_scan_codex_access(
                    project_path=project,
                    scan_dir=scan_dir,
                    codex_home=codex_home,
                    platform="win32",
                )

            config_text = (
                codex_home / "config.toml"
            ).read_text(encoding="utf-8")
            parsed = codex_scan_config.tomllib.loads(config_text)
            self.assertEqual(result.error, "")
            self.assertEqual(
                parsed["sandbox_permissions"],
                ["disk-full-read-access"],
            )
            self.assertIn(
                codex_profiles._ACCESS_CONFIG_BEGIN,
                config_text,
            )
            self.assertEqual(set(parsed["projects"]), set(result.trusted_paths))

    def test_local_mcp_is_private_idempotent_and_removed_when_disabled(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            scan_dir = root / ".opendeephole" / "scans" / "scan-1"
            project.mkdir()
            scan_dir.mkdir(parents=True)
            with patch.object(
                codex_scan_config.shutil,
                "which",
                return_value="/opt/codegraph/bin/codegraph",
            ):
                first = codex_scan_config.sync_scan_codex_mcp(
                    scan_dir=scan_dir,
                    project_path=project,
                    code_graph_mcp=_local_mcp(),
                )
            config_path = (
                scan_dir / "threat_analysis" / ".codex" / "config.toml"
            )
            parsed = codex_scan_config.tomllib.loads(
                config_path.read_text(encoding="utf-8")
            )
            mcp = parsed["mcp_servers"]["codegraph"]

            self.assertEqual(first.error, "")
            self.assertTrue(first.mcp_configured)
            self.assertEqual(mcp["command"], "/opt/codegraph/bin/codegraph")
            self.assertEqual(mcp["args"], ["serve", "--mcp"])
            self.assertEqual(mcp["cwd"], str(project.resolve()))
            self.assertTrue(mcp["enabled"])
            self.assertFalse(mcp["required"])
            self.assertEqual(mcp["startup_timeout_sec"], 300)
            self.assertEqual(mcp["tool_timeout_sec"], 300)
            self.assertEqual(
                mcp["env"]["CODEGRAPH_MCP_TOOLS"],
                "explore,node,search",
            )
            if os.name != "nt":
                self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)

            with (
                patch.object(
                    codex_scan_config.shutil,
                    "which",
                    return_value="/opt/codegraph/bin/codegraph",
                ),
                patch.object(codex_scan_config, "_stage_file") as stage,
            ):
                repeated = codex_scan_config.sync_scan_codex_mcp(
                    scan_dir=scan_dir,
                    project_path=project,
                    code_graph_mcp=_local_mcp(),
                )
            self.assertTrue(repeated.mcp_configured)
            stage.assert_not_called()

            disabled = codex_scan_config.sync_scan_codex_mcp(
                scan_dir=scan_dir,
                project_path=project,
                code_graph_mcp=None,
            )
            self.assertEqual(disabled.error, "")
            self.assertFalse(config_path.exists())

    def test_windows_batch_mcp_uses_cmd_with_separate_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            scan_dir = root / ".opendeephole" / "scans" / "scan-1"
            project.mkdir()
            scan_dir.mkdir(parents=True)
            executable = r"C:\Program Files\CodeGraph\codegraph.CMD"

            result = codex_scan_config.sync_scan_codex_mcp(
                scan_dir=scan_dir,
                project_path=project,
                code_graph_mcp=_local_mcp(executable=executable),
                env={"COMSPEC": r"C:\Windows\System32\cmd.exe"},
                platform="win32",
            )

            self.assertEqual(result.error, "")
            parsed = codex_scan_config.tomllib.loads((
                scan_dir / "threat_analysis" / ".codex" / "config.toml"
            ).read_text(encoding="utf-8"))
            mcp = parsed["mcp_servers"]["codegraph"]
            self.assertEqual(mcp["command"], r"C:\Windows\System32\cmd.exe")
            self.assertEqual(
                mcp["args"],
                ["/d", "/c", "call", executable, "serve", "--mcp"],
            )

    def test_remote_headers_are_mapped_and_foreign_config_is_preserved(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            scan_dir = root / ".opendeephole" / "scans" / "scan-1"
            project.mkdir()
            scan_dir.mkdir(parents=True)
            remote = {
                "enabled": True,
                "name": "codegraph",
                "transport": "remote",
                "timeout_seconds": 15,
                "local": {},
                "remote": {
                    "url": "https://mcp.example.test/api",
                    "headers": {"Authorization": "Bearer scan-secret"},
                },
            }
            result = codex_scan_config.sync_scan_codex_mcp(
                scan_dir=scan_dir,
                project_path=project,
                code_graph_mcp=remote,
            )
            config_path = (
                scan_dir / "threat_analysis" / ".codex" / "config.toml"
            )
            parsed = codex_scan_config.tomllib.loads(
                config_path.read_text(encoding="utf-8")
            )
            mcp = parsed["mcp_servers"]["codegraph"]
            self.assertEqual(result.error, "")
            self.assertEqual(mcp["url"], "https://mcp.example.test/api")
            self.assertEqual(mcp["tool_timeout_sec"], 15)
            self.assertEqual(
                mcp["http_headers"]["Authorization"],
                "Bearer scan-secret",
            )

            config_path.write_text('model = "foreign"\n', encoding="utf-8")
            foreign = codex_scan_config.sync_scan_codex_mcp(
                scan_dir=scan_dir,
                project_path=project,
                code_graph_mcp=None,
            )
            self.assertIn("foreign", foreign.error)
            self.assertEqual(
                config_path.read_text(encoding="utf-8"),
                'model = "foreign"\n',
            )

            if os.name != "nt":
                blocked_scan = root / ".opendeephole" / "scans" / "scan-2"
                blocked_scan.mkdir(parents=True)
                outside = root / "outside"
                outside.mkdir()
                (blocked_scan / "threat_analysis").symlink_to(
                    outside,
                    target_is_directory=True,
                )
                symlinked = codex_scan_config.sync_scan_codex_mcp(
                    scan_dir=blocked_scan,
                    project_path=project,
                    code_graph_mcp=remote,
                )
                self.assertIn("symlinked Codex workspace", symlinked.error)
                self.assertFalse((outside / ".codex").exists())

    @unittest.skipUnless(shutil.which("codex"), "codex is not installed")
    def test_real_app_server_loads_scan_mcp_only_with_exact_trust(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            app_home = root / "home" / ".opendeephole"
            scan_dir = app_home / "scans" / "scan-1"
            scan_dir.mkdir(parents=True)
            workspace = codex_scan_config.scan_codex_workspace(scan_dir)
            fixture = Path(__file__).parent / "fixtures" / "mcp_probe_server.py"
            mcp = _local_mcp(
                executable=sys.executable,
                args=[str(fixture)],
                environment={"PROBE_TOOL_NAME": "scan_codegraph_loaded"},
            )

            parent_home = root / "codex-parent-only"
            parent_trust = sync_codex_trusted_projects(
                (app_home.resolve(),),
                codex_home=parent_home,
            )
            self.assertEqual(parent_trust.error, "")
            local = codex_scan_config.sync_scan_codex_mcp(
                scan_dir=scan_dir,
                project_path=project,
                code_graph_mcp=mcp,
            )
            self.assertEqual(local.error, "")
            with _AppServer(codex_home=parent_home, cwd=workspace) as server:
                disabled = server.request(
                    "config/read",
                    {"cwd": str(workspace), "includeLayers": True},
                )
            project_layers = [
                layer
                for layer in disabled.get("layers", [])
                if layer.get("name", {}).get("type") == "project"
            ]
            self.assertEqual(len(project_layers), 1)
            self.assertTrue(project_layers[0].get("disabledReason"))
            self.assertNotIn(
                "codegraph",
                disabled.get("config", {}).get("mcp_servers", {}),
            )

            exact_home = root / "codex-exact"
            access = codex_scan_config.prepare_scan_codex_access(
                project_path=project,
                scan_dir=scan_dir,
                codex_home=exact_home,
            )
            self.assertEqual(access.error, "")
            with _AppServer(codex_home=exact_home, cwd=workspace) as server:
                loaded = server.request(
                    "config/read",
                    {"cwd": str(workspace), "includeLayers": True},
                )
                loaded_mcp = loaded["config"]["mcp_servers"]["codegraph"]
                self.assertEqual(loaded_mcp["command"], sys.executable)
                self.assertEqual(loaded_mcp["args"], [str(fixture)])
                self.assertEqual(loaded_mcp["cwd"], str(project.resolve()))
                self.assertEqual(
                    loaded_mcp["env"]["PROBE_TOOL_NAME"],
                    "scan_codegraph_loaded",
                )
                self.assertTrue(loaded_mcp["enabled"])


if __name__ == "__main__":
    unittest.main()
