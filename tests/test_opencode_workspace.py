import json
import os
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from unittest.mock import patch

from deephole_client import codegraph as codegraph_runtime
from deephole_client.opencode_integration import (
    _resolved_serve_port,
    _runtime_environment,
    build_opencode_config,
    configure_opencode_component,
    get_global_opencode_workspace,
    managed_opencode_config_path,
    refresh_global_opencode_config,
    writable_edit_patterns,
)


def assert_opencode_read_permissions(
    testcase: unittest.TestCase,
    config: dict,
    workspace: Path,
) -> None:
    permission = config.get("permission", {})
    for key in ("read", "list", "glob", "grep"):
        testcase.assertEqual(permission.get(key, {}).get("*"), "allow")
    testcase.assertEqual(
        permission.get("external_directory", {}).get("*"),
        "deny",
    )
    testcase.assertEqual(permission.get("edit", {}).get("*"), "deny")
    testcase.assertEqual(permission.get("bash"), {"*": "deny"})
    testcase.assertEqual(permission.get("skill"), {"*": "allow"})

    read = permission["read"]
    external = permission["external_directory"]
    edit = permission["edit"]
    for root in (
        "~/.opendeephole/opencode_workspace/.opencode",
        workspace / ".opencode",
        workspace / ".opencode" / "skills",
    ):
        for pattern in writable_edit_patterns(root):
            testcase.assertEqual(read.get(pattern), "allow")
            testcase.assertEqual(external.get(pattern), "allow")
            testcase.assertNotEqual(edit.get(pattern), "allow")

    home_root = Path.home() / ".opendeephole"
    for name in (
        "scans",
        "fp_reviews",
        "vulnerability_validation",
        "skill_create",
    ):
        for root in (
            f"~/.opendeephole/{name}",
            (home_root / name).resolve(),
        ):
            for pattern in writable_edit_patterns(root):
                testcase.assertEqual(read.get(pattern), "allow")
                testcase.assertEqual(external.get(pattern), "allow")
                testcase.assertEqual(edit.get(pattern), "allow")


class OpencodeWorkspaceTests(unittest.TestCase):
    def test_agent_host_binding_exposes_entire_scans_root_as_writable(
        self,
    ) -> None:
        with patch("task_agent.configure_opencode") as configure:
            configure_opencode_component()

        bindings = configure.call_args.args[0]
        self.assertEqual(
            bindings.writable_roots(),
            tuple(
                (Path.home() / ".opendeephole" / name).resolve()
                for name in (
                    "scans",
                    "fp_reviews",
                    "vulnerability_validation",
                    "skill_create",
                )
            ),
        )

    def test_runtime_environment_only_adds_no_proxy(self) -> None:
        system_proxies = {
            "HTTP_PROXY": "http://system.example:8080",
            "HTTPS_PROXY": "http://system.example:8080",
            "http_proxy": "http://system.example:8080",
            "https_proxy": "http://system.example:8080",
            "ALL_PROXY": "socks5://system.example:1080",
            "all_proxy": "socks5://system.example:1080",
        }
        with patch.dict(os.environ, system_proxies, clear=True):
            env = _runtime_environment({
                "proxy_url": "http://configured.example:8080",
                "no_proxy": "127.0.0.1,localhost",
            })

        self.assertEqual(env, {
            "NODE_TLS_REJECT_UNAUTHORIZED": "0",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        })

    def test_agent_serve_port_precedence_and_auto_port_reuse(self) -> None:
        with patch.dict(os.environ, {"OPENCODE_SERVE_PORT": "4100"}, clear=False):
            self.assertEqual(_resolved_serve_port(4200), 4200)
            self.assertEqual(_resolved_serve_port(None), 4100)

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("deephole_client.opencode_integration._auto_serve_port", None),
            patch("deephole_client.opencode_integration.socket.socket") as socket_factory,
        ):
            socket_factory.return_value.__enter__.return_value.getsockname.return_value = (
                "127.0.0.1",
                43123,
            )
            first = _resolved_serve_port(None)
            second = _resolved_serve_port(None)

        self.assertGreaterEqual(first, 1)
        self.assertLessEqual(first, 65535)
        self.assertEqual(second, first)

    def test_writable_edit_patterns_include_windows_slash_variants(self) -> None:
        path = PureWindowsPath(
            "C:/Users/demo/.opendeephole/fp_reviews/review/artifacts/1"
        )
        patterns = writable_edit_patterns(path)
        self.assertIn(
            r"C:\Users\demo\.opendeephole\fp_reviews\review\artifacts\1",
            patterns,
        )
        self.assertIn(
            r"C:\Users\demo\.opendeephole\fp_reviews\review\artifacts\1\**",
            patterns,
        )
        self.assertIn(
            "C:/Users/demo/.opendeephole/fp_reviews/review/artifacts/1/**",
            patterns,
        )

    def test_build_opencode_config_allows_explicit_writable_path(self) -> None:
        path = PureWindowsPath(
            "C:/Users/demo/.opendeephole/work/review"
        )
        fake_config = SimpleNamespace(
            code_graph=SimpleNamespace(enabled=False, name="codegraph"),
            product_info=SimpleNamespace(enabled=False, name="product-info"),
        )
        with patch(
            "deephole_client.opencode_integration.get_config",
            return_value=fake_config,
        ):
            config = build_opencode_config(
                writable_paths=[str(path)],
            )
        edit = config["permission"]["edit"]
        self.assertEqual(edit["*"], "deny")
        self.assertEqual(
            edit["C:/Users/demo/.opendeephole/work/review/**"],
            "allow",
        )
        self.assertGreater(
            list(edit).index("C:/Users/demo/.opendeephole/work/review/**"),
            list(edit).index("~/.opendeephole/scans/**"),
        )

    def test_build_opencode_config_keeps_product_mcp_global_but_not_code_graph(self) -> None:
        fake_config = SimpleNamespace(
            code_graph=SimpleNamespace(
                enabled=True,
                name="codegraph",
                transport="local",
                timeout_seconds=45,
                local=SimpleNamespace(
                    executable="codegraph",
                    args=["serve", "--mcp"],
                    environment={"CODEGRAPH_MCP_TOOLS": "explore,node"},
                ),
            ),
            product_info=SimpleNamespace(
                enabled=True,
                name="product-info",
                transport="remote",
                timeout_seconds=12,
                remote=SimpleNamespace(
                    url="http://10.0.0.8:9000/mcp",
                    headers={"Authorization": "Bearer token"},
                ),
            ),
        )
        with (
            patch(
                "deephole_client.opencode_integration.get_config",
                return_value=fake_config,
            ),
            patch(
                "deephole_client.opencode_integration.shutil.which",
                return_value="/usr/bin/codegraph",
            ),
        ):
            config = build_opencode_config()

        self.assertNotIn("codegraph", config["mcp"])
        self.assertNotIn("deephole-code", config["mcp"])
        self.assertEqual(config["mcp"]["product-info"]["type"], "remote")
        self.assertIs(config["mcp"]["product-info"]["oauth"], False)

    def test_codegraph_readiness_survives_restart_and_subdirectories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            nested = root / "src" / "module"
            nested.mkdir(parents=True)
            database = root / ".codegraph" / "codegraph.db"
            database.parent.mkdir()
            database.write_bytes(b"sqlite")
            codegraph_runtime._ready_projects.clear()

            self.assertTrue(codegraph_runtime.is_codegraph_ready(nested))
            self.assertIn(root.resolve(), codegraph_runtime._ready_projects)

    def test_global_workspace_does_not_inject_threat_analysis_method_skills(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace_path = Path(tmp) / "opencode_workspace"
            fake_config = SimpleNamespace(
                code_graph=SimpleNamespace(enabled=False, name="codegraph"),
                product_info=SimpleNamespace(
                    enabled=False,
                    name="product-info",
                ),
            )
            with (
                patch(
                    "deephole_client.opencode_integration._GLOBAL_WORKSPACE",
                    workspace_path,
                ),
                patch(
                    "deephole_client.opencode_integration.get_config",
                    return_value=fake_config,
                ),
            ):
                workspace = get_global_opencode_workspace()

            config = json.loads(
                managed_opencode_config_path(workspace).read_text(
                    encoding="utf-8"
                )
            )
            self.assertNotIn("deephole-code", config["mcp"])
            assert_opencode_read_permissions(self, config, workspace)
            self.assertNotIn("agent", config)
            skills_dir = workspace / ".opencode" / "skills"
            for name in (
                "value-asset-map",
                "high-risk-module-map",
                "high-risk-module-merge",
                "attack-tree-by-asset",
            ):
                installed = skills_dir / name
                self.assertFalse(installed.exists())

    def test_global_workspace_removes_legacy_managed_skill_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace_path = Path(tmp) / "opencode_workspace"
            skills_dir = workspace_path / ".opencode" / "skills"
            managed = skills_dir / "attack-tree-by-asset"
            unrelated = skills_dir / "user-owned-skill"
            managed.mkdir(parents=True)
            unrelated.mkdir()
            (managed / "stale.txt").write_text("stale", encoding="utf-8")
            (managed / "stale-empty-directory").mkdir()
            (unrelated / "SKILL.md").write_text("user-owned", encoding="utf-8")
            fake_config = SimpleNamespace(
                code_graph=SimpleNamespace(enabled=False, name="codegraph"),
                product_info=SimpleNamespace(
                    enabled=False,
                    name="product-info",
                ),
            )
            with (
                patch(
                    "deephole_client.opencode_integration._GLOBAL_WORKSPACE",
                    workspace_path,
                ),
                patch(
                    "deephole_client.opencode_integration.get_config",
                    return_value=fake_config,
                ),
            ):
                get_global_opencode_workspace()

            self.assertFalse((managed / "stale.txt").exists())
            self.assertFalse((managed / "stale-empty-directory").exists())
            self.assertFalse(managed.exists())
            self.assertEqual(
                (unrelated / "SKILL.md").read_text(encoding="utf-8"),
                "user-owned",
            )

    def test_stale_permissions_are_refreshed_and_obsolete_builtin_mcp_is_removed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace_path = Path(tmp) / "opencode_workspace"
            workspace_path.mkdir()
            config_path = managed_opencode_config_path(workspace_path)
            config_path.write_text(
                json.dumps({
                    "mcp": {
                        "deephole-code": {
                            "type": "remote",
                            "url": "http://127.0.0.1:58507/mcp",
                            "enabled": True,
                        },
                    },
                    "permission": {
                        "external_directory": {
                            "*": "deny",
                            "~/.opendeephole/scans": "allow",
                            "~/.opendeephole/scans/**": "allow",
                        },
                        "edit": {
                            "*": "deny",
                            "~/.opendeephole/scans": "deny",
                            "~/.opendeephole/scans/**": "deny",
                        },
                    },
                }),
                encoding="utf-8",
            )
            fake_config = SimpleNamespace(
                code_graph=SimpleNamespace(enabled=False, name="codegraph"),
                product_info=SimpleNamespace(
                    enabled=False,
                    name="product-info",
                ),
            )
            with (
                patch(
                    "deephole_client.opencode_integration._GLOBAL_WORKSPACE",
                    workspace_path,
                ),
                patch(
                    "deephole_client.opencode_integration.get_config",
                    return_value=fake_config,
                ),
            ):
                workspace = get_global_opencode_workspace()

            config = json.loads(
                managed_opencode_config_path(workspace).read_text(
                    encoding="utf-8"
                )
            )
            self.assertNotIn("deephole-code", config["mcp"])
            assert_opencode_read_permissions(self, config, workspace)

    def test_obsolete_builtin_mcp_alone_triggers_managed_config_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace_path = Path(tmp) / "opencode_workspace"
            fake_config = SimpleNamespace(
                code_graph=SimpleNamespace(enabled=False, name="codegraph"),
                product_info=SimpleNamespace(
                    enabled=False,
                    name="product-info",
                ),
            )
            with (
                patch(
                    "deephole_client.opencode_integration._GLOBAL_WORKSPACE",
                    workspace_path,
                ),
                patch(
                    "deephole_client.opencode_integration.get_config",
                    return_value=fake_config,
                ),
            ):
                workspace = get_global_opencode_workspace()
                config_path = managed_opencode_config_path(workspace)
                config = json.loads(config_path.read_text(encoding="utf-8"))
                config["mcp"]["deephole-code"] = {
                    "type": "remote",
                    "url": "http://127.0.0.1:8100/mcp",
                    "enabled": True,
                }
                config_path.write_text(json.dumps(config), encoding="utf-8")

                get_global_opencode_workspace()

            refreshed = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertNotIn("deephole-code", refreshed["mcp"])

    def test_global_refresh_does_not_overwrite_live_runtime_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace_path = Path(tmp) / "opencode_workspace"
            fake_config = SimpleNamespace(
                code_graph=SimpleNamespace(enabled=False, name="codegraph"),
                product_info=SimpleNamespace(
                    enabled=False,
                    name="product-info",
                ),
            )
            with (
                patch(
                    "deephole_client.opencode_integration._GLOBAL_WORKSPACE",
                    workspace_path,
                ),
                patch(
                    "deephole_client.opencode_integration.get_config",
                    return_value=fake_config,
                ),
            ):
                workspace = get_global_opencode_workspace()
                live_path = workspace / "opencode.json"
                live_path.write_text('{"sentinel": true}', encoding="utf-8")
                refresh_global_opencode_config()

            self.assertEqual(
                live_path.read_text(encoding="utf-8"),
                '{"sentinel": true}',
            )
