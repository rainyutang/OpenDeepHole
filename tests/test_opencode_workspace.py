import json
import os
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from unittest.mock import patch

from deephole_client import codegraph as codegraph_runtime
from deephole_client.opencode_integration import (
    _config_home_candidates,
    _opencode_executable_alias,
    _resolve_serve_port,
    _resolved_serve_port,
    _runtime_config_content,
    _runtime_environment,
    build_opencode_session_runtime,
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
            self.assertFalse(_resolve_serve_port(4200).auto_selected)
            self.assertFalse(_resolve_serve_port(None).auto_selected)

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
            resolved = _resolve_serve_port(None)

        self.assertGreaterEqual(first, 1)
        self.assertLessEqual(first, 65535)
        self.assertEqual(second, first)
        self.assertEqual(resolved.port, first)
        self.assertTrue(resolved.auto_selected)

    def test_runtime_config_discovery_is_controlled_and_managed_fields_win(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            executable_dir = root / "portable"
            project = root / "project"
            configured_dir = root / "configured"
            env_dir = root / "env-dir"
            workspace = root / "workspace"
            for path in (
                home / ".config" / "opencode",
                executable_dir / ".opencode",
                project / ".opencode",
                configured_dir,
                env_dir,
                workspace,
            ):
                path.mkdir(parents=True, exist_ok=True)

            (home / ".config" / "opencode" / "config.json").write_text(
                json.dumps({
                    "provider": {"corp": {"options": {"legacy_global": True}}},
                }),
                encoding="utf-8",
            )
            (home / ".config" / "opencode" / "opencode.json").write_text(
                json.dumps({
                    "model": "global/model",
                    "provider": {"corp": {"options": {"global": True}}},
                }),
                encoding="utf-8",
            )
            (executable_dir / "config.json").write_text(
                json.dumps({"env": {"APP_MODE": "portable"}, "version": 2}),
                encoding="utf-8",
            )
            (executable_dir / ".opencode" / "config.json").write_text(
                json.dumps({"env": {"NESTED_MODE": "portable"}, "version": 3}),
                encoding="utf-8",
            )
            (executable_dir / ".opencode" / "opencode.json").write_text(
                json.dumps({
                    "model": "executable/model",
                    "provider": {"corp": {"options": {"portable": True}}},
                }),
                encoding="utf-8",
            )
            (project / "opencode.jsonc").write_text(
                '{"model": "project/model", "mcp": {"user": {"enabled": false}}}',
                encoding="utf-8",
            )
            (project / "config.json").write_text(
                json.dumps({"env": {"PROJECT_MODE": "test"}, "version": 3}),
                encoding="utf-8",
            )
            (configured_dir / "opencode.json").write_text(
                json.dumps({"model": "configured/model"}),
                encoding="utf-8",
            )
            env_path = root / "from-env.json"
            env_path.write_text(json.dumps({"model": "env-path/model"}), encoding="utf-8")
            official_path = root / "official.json"
            official_path.write_text(json.dumps({"model": "official/model"}), encoding="utf-8")
            (env_dir / "opencode.json").write_text(
                json.dumps({
                    "model": "env-dir/model",
                    "permission": {"bash": "allow"},
                    "skills": {"paths": ["user-skill"]},
                    "mcp": {"managed": {"enabled": False}},
                }),
                encoding="utf-8",
            )
            managed_opencode_config_path(workspace).write_text(
                json.dumps({
                    "$schema": "https://opencode.ai/config.json",
                    "permission": {"bash": "deny"},
                    "skills": {"paths": ["managed-skill"]},
                    "mcp": {"managed": {"enabled": True}},
                }),
                encoding="utf-8",
            )
            effective = {
                "tool": "opencode",
                "executable": str(executable_dir / "opencode.exe"),
                "config_paths": [str(configured_dir)],
            }
            with patch.dict(os.environ, {
                "HOME": str(home),
                "OPENCODE_CONFIG_PATH": str(env_path),
                "OPENCODE_CONFIG": str(official_path),
                "OPENCODE_CONFIG_DIR": str(env_dir),
            }, clear=True):
                config = json.loads(
                    _runtime_config_content(workspace, effective, project)
                )

            self.assertEqual(config["model"], "env-dir/model")
            self.assertNotIn("env", config)
            self.assertNotIn("version", config)
            self.assertEqual(config["provider"]["corp"]["options"], {
                "legacy_global": True,
                "global": True,
                "portable": True,
            })
            self.assertIn("user", config["mcp"])
            self.assertEqual(config["mcp"]["managed"], {"enabled": True})
            self.assertEqual(config["permission"], {"bash": "deny"})
            self.assertEqual(config["skills"], {"paths": ["managed-skill"]})

    def test_invalid_ambient_config_is_ignored_before_runtime_file_generation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            global_dir = root / "home" / ".config" / "opencode"
            workspace = root / "workspace"
            project = root / "project"
            global_dir.mkdir(parents=True)
            workspace.mkdir()
            project.mkdir()
            (global_dir / "opencode.json").write_text("{ broken", encoding="utf-8")
            managed_opencode_config_path(workspace).write_text(
                json.dumps({"permission": {"bash": "deny"}}),
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"HOME": str(root / "home")}, clear=True):
                config = json.loads(_runtime_config_content(
                    workspace,
                    {"tool": "opencode", "executable": ""},
                    project,
                ))

            self.assertEqual(config, {"permission": {"bash": "deny"}})

    def test_nga_executable_discovers_legacy_nga_config_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            project = root / "project"
            workspace = root / "workspace"
            nga_config = home / ".config" / "nga"
            for path in (project, workspace, nga_config):
                path.mkdir(parents=True)
            (nga_config / "opencode.json").write_text(
                json.dumps({"model": "nga/default", "provider": {"nga": {}}}),
                encoding="utf-8",
            )
            managed_opencode_config_path(workspace).write_text("{}", encoding="utf-8")

            with patch.dict(os.environ, {"HOME": str(home)}, clear=True):
                config = json.loads(_runtime_config_content(
                    workspace,
                    {"tool": "opencode", "executable": "/usr/local/bin/nga"},
                    project,
                ))

            self.assertEqual(config["model"], "nga/default")
            self.assertEqual(config["provider"], {"nga": {}})

    def test_session_runtime_uses_global_executable_and_ignores_model_override(
        self,
    ) -> None:
        cli_config = SimpleNamespace(
            tool="opencode",
            executable="nga",
            model="",
            config_paths=[],
            no_proxy="",
            proxy_url="",
            serve_port=4317,
        )
        model = SimpleNamespace(
            model="provider/model",
            executable="opencode",
            tool="nga",
            use_default_model=False,
        )
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("deephole_client.opencode_integration.shutil.which") as which,
            patch(
                "deephole_client.opencode_integration.get_global_opencode_workspace",
                return_value=Path(tmp),
            ),
            patch(
                "deephole_client.opencode_integration._runtime_config_content",
                return_value="{}",
            ),
        ):
            which.side_effect = lambda executable: {
                "opencode": "/usr/bin/opencode",
                "nga": "/usr/local/bin/nga",
            }.get(executable)
            runtime = build_opencode_session_runtime(
                cli_config,
                model,
                Path(tmp),
            )

        self.assertEqual(runtime.tool, "opencode")
        self.assertEqual(runtime.executable, "/usr/local/bin/nga")
        self.assertEqual(runtime.model, "provider/model")

    def test_windows_config_home_candidates_include_userprofile_and_appdata(
        self,
    ) -> None:
        with patch("deephole_client.opencode_integration.sys.platform", "win32"):
            candidates = _config_home_candidates({
                "USERPROFILE": r"C:\Users\demo",
                "APPDATA": r"C:\Users\demo\AppData\Roaming",
            })

        self.assertIn(Path(r"C:\Users\demo") / ".config", candidates)
        self.assertIn(Path(r"C:\Users\demo\AppData\Roaming"), candidates)

    def test_executable_alias_handles_posix_and_windows_paths(self) -> None:
        self.assertEqual(_opencode_executable_alias("nga"), "nga")
        self.assertEqual(_opencode_executable_alias("/opt/nga/bin/nga"), "nga")
        self.assertEqual(_opencode_executable_alias(r"C:\Tools\nga.exe"), "nga")
        self.assertEqual(_opencode_executable_alias(r"C:\Tools\OPENCODE.CMD"), "opencode")
        self.assertEqual(_opencode_executable_alias("/opt/custom/compatible"), "")

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

    def test_build_opencode_config_keeps_scan_owned_mcps_out_of_global_config(self) -> None:
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
        self.assertNotIn("product-info", config["mcp"])

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
