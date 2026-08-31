from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deephole_client import codex_profiles


def _effective_config() -> dict:
    return {
        "provider": {
            "literal": {
                "name": "Literal Provider",
                "options": {
                    "baseURL": "https://literal.example/v1",
                    "apiKey": "literal-secret-value",
                },
                "models": {
                    "beta/model": {"limit": {"context": 65536}},
                    "unused": {},
                },
            },
            "env": {
                "options": {
                    "baseURL": "https://env.example/v1",
                    "apiKey": "{env:ENV_PROVIDER_TOKEN}",
                },
                "models": {"alpha": {}},
            },
        },
    }


class CodexConfigSyncTests(unittest.TestCase):
    def _sync(
        self,
        codex_home: Path,
        config: dict,
        model_ids: list[str],
        *,
        version: str = "codex-cli 0.149.1",
        platform: str = "linux",
        no_proxy_hosts: tuple[str, ...] = (),
    ) -> codex_profiles.CodexConfigSyncResult:
        return codex_profiles.sync_codex_config(
            codex_version=version,
            opencode_config=config,
            selected_model_ids=model_ids,
            env={"CODEX_HOME": str(codex_home)},
            platform=platform,
            no_proxy_hosts=no_proxy_hosts,
        )

    def test_base_url_is_normalized_for_v1_responses(self) -> None:
        self.assertEqual(
            codex_profiles.normalize_codex_base_url("https://api.example"),
            "https://api.example/v1",
        )
        self.assertEqual(
            codex_profiles.normalize_codex_base_url(
                "https://api.example/root/v1/responses"
            ),
            "https://api.example/root/v1",
        )
        self.assertEqual(
            codex_profiles.normalize_codex_base_url(
                "https://api.example/v1?unsafe=true"
            ),
            "",
        )

    def test_user_default_inspection_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            codex_home.mkdir()
            config_path = codex_home / "config.toml"
            original = (
                b'model = "personal"\n'
                b'model_provider = "private"\n'
                b'[features]\nmemories = true\n'
            )
            config_path.write_bytes(original)

            with patch.object(codex_profiles, "_stage_file") as stage:
                result = codex_profiles.inspect_codex_user_default(
                    codex_home=codex_home,
                )

            self.assertEqual(result.error, "")
            self.assertTrue(result.user_default_preserved)
            self.assertEqual(result.models[0].id, "private/personal")
            self.assertEqual(config_path.read_bytes(), original)
            stage.assert_not_called()

    def test_selected_model_host_is_managed_in_both_dotenv_variables(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            codex_home.mkdir()
            env_path = codex_home / ".env"
            original = (
                b"# User-owned values stay unchanged.\n"
                b"NO_PROXY=localhost,shared.local\n"
                b"no_proxy=corp.local\n"
                b"PROVIDER_SECRET=keep-me"
            )
            env_path.write_bytes(original)

            first = self._sync(
                codex_home,
                _effective_config(),
                ["literal/beta/model"],
                no_proxy_hosts=("10.20.30.40", "shared.local"),
            )
            first_text = env_path.read_text(encoding="utf-8")
            second = self._sync(
                codex_home,
                _effective_config(),
                ["env/alpha"],
                no_proxy_hosts=("env.example",),
            )
            second_text = env_path.read_text(encoding="utf-8")
            empty = self._sync(codex_home, {}, [], no_proxy_hosts=())

            self.assertEqual(first.error, "")
            self.assertEqual(second.error, "")
            self.assertEqual(empty.error, "")
            self.assertTrue(first_text.startswith(original.decode("utf-8")))
            self.assertIn(
                "NO_PROXY=localhost,shared.local,10.20.30.40",
                first_text,
            )
            self.assertIn(
                "no_proxy=corp.local,10.20.30.40,shared.local",
                first_text,
            )
            self.assertTrue(second_text.startswith(original.decode("utf-8")))
            self.assertIn(
                "NO_PROXY=localhost,shared.local,env.example",
                second_text,
            )
            self.assertNotIn("10.20.30.40", second_text)
            self.assertEqual(env_path.read_bytes(), original)

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics differ")
    def test_symlinked_or_malformed_dotenv_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            codex_home = root / "codex"
            codex_home.mkdir()
            target = root / "personal.env"
            target.write_text("TOKEN=secret\n", encoding="utf-8")
            env_path = codex_home / ".env"
            env_path.symlink_to(target)

            symlink_error = codex_profiles._sync_codex_env(
                codex_home,
                ("127.0.0.1",),
            )
            env_path.unlink()
            malformed = (
                f"{codex_profiles._ENV_BEGIN}\nNO_PROXY=old\n"
            )
            env_path.write_text(malformed, encoding="utf-8")
            marker_error = codex_profiles._sync_codex_env(
                codex_home,
                ("127.0.0.1",),
            )

            self.assertIn("symlinked", symlink_error)
            self.assertEqual(target.read_text(encoding="utf-8"), "TOKEN=secret\n")
            self.assertIn("markers", marker_error)
            self.assertEqual(env_path.read_text(encoding="utf-8"), malformed)

    @unittest.skipIf(os.name == "nt", "POSIX permissions are unavailable")
    def test_new_codex_dotenv_is_private_and_does_not_mutate_process_env(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {"NO_PROXY": "process-upper", "no_proxy": "process-lower"},
            clear=False,
        ):
            codex_home = Path(tmp) / "codex"
            result = self._sync(
                codex_home,
                _effective_config(),
                ["literal/beta/model"],
                no_proxy_hosts=("::1",),
            )

            self.assertEqual(result.error, "")
            env_path = codex_home / ".env"
            self.assertEqual(env_path.stat().st_mode & 0o777, 0o600)
            text = env_path.read_text(encoding="utf-8")
            self.assertIn("NO_PROXY=::1", text)
            self.assertIn("no_proxy=::1", text)
            self.assertEqual(os.environ["NO_PROXY"], "process-upper")
            self.assertEqual(os.environ["no_proxy"], "process-lower")

    def test_user_default_wins_and_no_profile_files_are_generated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            codex_home.mkdir()
            user_config = codex_home / "config.toml"
            original = b'model = "personal-default"\n'
            user_config.write_bytes(original)
            legacy = codex_home / "opendeephole-old.config.toml"
            legacy.write_text(
                f"{codex_profiles._MANAGED_MARKER}\nmodel = \"old\"\n",
                encoding="utf-8",
            )

            first = self._sync(
                codex_home,
                _effective_config(),
                ["literal/beta/model", "env/alpha", "literal/beta/model"],
            )
            second = self._sync(
                codex_home,
                _effective_config(),
                ["literal/beta/model", "env/alpha"],
            )

            self.assertEqual(first.error, "")
            self.assertTrue(first.user_default_preserved)
            self.assertIsNone(first.managed_default_model)
            self.assertEqual(
                [item.id for item in first.models],
                ["openai/personal-default"],
            )
            self.assertEqual(first.models, second.models)
            self.assertEqual(user_config.read_bytes(), original)
            self.assertFalse(legacy.exists())
            self.assertEqual(
                first.models[0].engine_value(("/opt/bin/codex",)),
                {
                    "id": "openai/personal-default",
                    "provider_id": "openai",
                    "model_id": "personal-default",
                    "command": ["/opt/bin/codex"],
                },
            )

    def test_missing_default_uses_first_platform_model_and_preserves_user_bytes(
        self,
    ) -> None:
        config = {
            "provider": {
                "a": {
                    "options": {"baseURL": "https://a.example/v1"},
                    "models": {"first": {}},
                },
                "z": {
                    "options": {"baseURL": "https://z.example/v1"},
                    "models": {"last": {}},
                },
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            codex_home.mkdir()
            config_path = codex_home / "config.toml"
            original = (
                b"# Personal settings stay byte-for-byte intact.\r\n"
                b"[features]\r\nmemories = true\r\n"
            )
            config_path.write_bytes(original)
            if os.name != "nt":
                config_path.chmod(0o640)

            first = self._sync(codex_home, config, ["z/last", "a/first"])
            first_bytes = config_path.read_bytes()
            with patch.object(codex_profiles, "_stage_file") as stage:
                second = self._sync(
                    codex_home,
                    config,
                    ["z/last", "a/first"],
                )

            self.assertEqual(first.error, "")
            self.assertEqual(first.models, second.models)
            self.assertEqual(first.managed_default_model.id, "z/last")
            remainder, owned, marker_error = codex_profiles._split_managed_default(
                first_bytes.decode("utf-8")
            )
            self.assertTrue(owned)
            self.assertEqual(marker_error, "")
            self.assertEqual(remainder.encode("utf-8"), original)
            parsed = codex_profiles.tomllib.loads(first_bytes.decode("utf-8"))
            self.assertEqual(parsed["model"], "last")
            provider_key = parsed["model_provider"]
            self.assertEqual(
                parsed["model_providers"][provider_key]["base_url"],
                "https://z.example/v1",
            )
            self.assertTrue(parsed["features"]["memories"])
            stage.assert_not_called()
            self.assertEqual(config_path.read_bytes(), first_bytes)
            if os.name != "nt":
                self.assertEqual(config_path.stat().st_mode & 0o777, 0o640)

    def test_existing_user_default_is_never_overwritten(self) -> None:
        original = (
            b'model = "personal"\n'
            b'model_provider = "personal-provider"\n'
            b'# keep me\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            codex_home.mkdir()
            config_path = codex_home / "config.toml"
            config_path.write_bytes(original)

            result = self._sync(
                codex_home,
                _effective_config(),
                ["env/alpha"],
            )

            self.assertEqual(result.error, "")
            self.assertTrue(result.user_default_preserved)
            self.assertIsNone(result.managed_default_model)
            self.assertEqual(result.models[0].id, "personal-provider/personal")
            self.assertEqual(config_path.read_bytes(), original)
            self.assertEqual(
                list(codex_home.glob("opendeephole-*.config.toml")),
                [],
            )

    def test_profile_only_config_is_not_a_bare_default(self) -> None:
        original = b'profile = "personal-profile"\n# keep me\n'
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            codex_home.mkdir()
            config_path = codex_home / "config.toml"
            config_path.write_bytes(original)

            result = self._sync(codex_home, _effective_config(), ["env/alpha"])

            self.assertEqual(result.error, "")
            self.assertFalse(result.user_default_preserved)
            self.assertEqual(result.managed_default_model.id, "env/alpha")
            remainder, owned, error = codex_profiles._split_managed_default(
                config_path.read_text(encoding="utf-8")
            )
            self.assertTrue(owned)
            self.assertEqual(error, "")
            self.assertEqual(remainder.encode("utf-8"), original)

    def test_provider_without_model_is_preserved_and_rejected(self) -> None:
        original = (
            b'model_provider = "personal"\n'
            b'[model_providers.personal]\n'
            b'base_url = "https://personal.example/v1"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            codex_home.mkdir()
            config_path = codex_home / "config.toml"
            config_path.write_bytes(original)

            result = self._sync(codex_home, _effective_config(), ["env/alpha"])

            self.assertIn("model_provider", result.error)
            self.assertEqual(config_path.read_bytes(), original)

    @unittest.skipIf(os.name == "nt", "POSIX permissions are unavailable")
    def test_literal_default_credential_tightens_only_file_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            codex_home.mkdir()
            config_path = codex_home / "config.toml"
            original = b"# Existing user comment.\n"
            config_path.write_bytes(original)
            config_path.chmod(0o644)

            result = self._sync(
                codex_home,
                _effective_config(),
                ["literal/beta/model"],
            )

            self.assertEqual(result.error, "")
            remainder, owned, error = codex_profiles._split_managed_default(
                config_path.read_text(encoding="utf-8")
            )
            self.assertTrue(owned)
            self.assertEqual(error, "")
            self.assertEqual(remainder.encode("utf-8"), original)
            self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)

    def test_managed_default_retargets_then_yields_to_user_default(self) -> None:
        config = {
            "provider": {
                "p": {
                    "options": {"baseURL": "https://models.example/v1"},
                    "models": {"one": {}, "two": {}},
                },
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            legacy = codex_home / "opendeephole-old.config.toml"
            codex_home.mkdir()
            legacy.write_text(
                f"{codex_profiles._MANAGED_MARKER}\nmodel = \"old\"\n",
                encoding="utf-8",
            )
            first = self._sync(codex_home, config, ["p/two"])
            self.assertEqual(first.managed_default_model.id, "p/two")
            self.assertFalse(legacy.exists())

            second = self._sync(codex_home, config, ["p/one"])
            self.assertEqual(second.managed_default_model.id, "p/one")
            config_path = codex_home / "config.toml"
            current = config_path.read_bytes()
            user_addition = b'model = "personal-later"\n'
            config_path.write_bytes(current + user_addition)

            third = self._sync(codex_home, config, ["p/one"])

            self.assertTrue(third.user_default_preserved)
            self.assertIsNone(third.managed_default_model)
            self.assertEqual(config_path.read_bytes(), user_addition)
            self.assertEqual(
                codex_profiles.tomllib.loads(
                    config_path.read_text(encoding="utf-8")
                )["model"],
                "personal-later",
            )

    def test_empty_selection_removes_only_owned_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            first = self._sync(
                codex_home,
                _effective_config(),
                ["env/alpha"],
            )
            self.assertEqual(first.models[0].id, "env/alpha")
            owned = codex_home / "opendeephole-old.config.toml"
            owned.write_text(
                f"{codex_profiles._MANAGED_MARKER}\nmodel = \"old\"\n",
                encoding="utf-8",
            )
            foreign = codex_home / "personal.config.toml"
            foreign.write_text('model = "personal"\n', encoding="utf-8")

            empty = self._sync(codex_home, {}, [])

            self.assertEqual(empty.error, "")
            self.assertEqual(empty.models, ())
            self.assertFalse(owned.exists())
            self.assertEqual((codex_home / "config.toml").read_bytes(), b"")
            self.assertEqual(foreign.read_text(encoding="utf-8"), 'model = "personal"\n')

    def test_unresolved_model_is_all_or_nothing_and_redacts_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            first = self._sync(
                codex_home,
                _effective_config(),
                ["env/alpha"],
            )
            before = {
                path.name: path.read_bytes()
                for path in codex_home.iterdir()
                if path.is_file()
            }
            secret = "must-never-appear-in-errors"
            bad = _effective_config()
            bad["provider"]["bad"] = {
                "options": {"apiKey": secret},
                "models": {"model": {}},
            }

            result = self._sync(
                codex_home,
                bad,
                ["literal/beta/model", "bad/model"],
            )

            self.assertTrue(result.error)
            self.assertNotIn(secret, result.error)
            self.assertNotIn(secret, "\n".join(result.warnings))
            self.assertEqual(
                before,
                {
                    path.name: path.read_bytes()
                    for path in codex_home.iterdir()
                    if path.is_file()
                },
            )
            self.assertEqual(first.models[0].id, "env/alpha")

    def test_invalid_or_symlinked_user_config_keeps_owned_profiles(self) -> None:
        for symlinked in (False, True):
            if symlinked and os.name == "nt":
                continue
            with self.subTest(symlinked=symlinked), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                codex_home = root / "codex"
                codex_home.mkdir()
                stale = codex_home / "opendeephole-stale.config.toml"
                stale_content = (
                    f"{codex_profiles._MANAGED_MARKER}\nmodel = \"old\"\n"
                )
                stale.write_text(stale_content, encoding="utf-8")
                config_path = codex_home / "config.toml"
                if symlinked:
                    target = root / "personal.toml"
                    target.write_text('model = "personal"\n', encoding="utf-8")
                    config_path.symlink_to(target)
                    original = target.read_bytes()
                else:
                    config_path.write_bytes(b'model = "unterminated\nsecret-value')
                    original = config_path.read_bytes()

                result = self._sync(
                    codex_home,
                    _effective_config(),
                    ["env/alpha"],
                )

                self.assertTrue(result.error)
                self.assertEqual(stale.read_text(encoding="utf-8"), stale_content)
                if symlinked:
                    self.assertEqual(config_path.resolve().read_bytes(), original)
                else:
                    self.assertEqual(config_path.read_bytes(), original)

    def test_old_owned_profiles_are_removed_and_foreign_files_are_preserved(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            codex_home.mkdir()
            stale = codex_home / "opendeephole-stale.config.toml"
            stale_content = f"{codex_profiles._MANAGED_MARKER}\nmodel = \"old\"\n"
            stale.write_text(stale_content, encoding="utf-8")

            old = self._sync(
                codex_home,
                _effective_config(),
                ["env/alpha"],
                version="codex-cli 0.133.9",
            )
            self.assertEqual(old.error, "")
            self.assertFalse(stale.exists())

            foreign = codex_home / "opendeephole-foreign.config.toml"
            foreign_content = 'model = "foreign"\n'
            foreign.write_text(foreign_content, encoding="utf-8")
            second = self._sync(
                codex_home,
                _effective_config(),
                ["env/alpha"],
            )
            self.assertEqual(second.error, "")
            self.assertEqual(foreign.read_text(encoding="utf-8"), foreign_content)

    def test_write_failure_keeps_stale_profiles_and_cleans_staging_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            codex_home.mkdir()
            stale = codex_home / "opendeephole-stale.config.toml"
            stale_content = f"{codex_profiles._MANAGED_MARKER}\nmodel = \"old\"\n"
            stale.write_text(stale_content, encoding="utf-8")

            with patch.object(codex_profiles.os, "replace", side_effect=PermissionError):
                result = self._sync(
                    codex_home,
                    _effective_config(),
                    ["env/alpha"],
                )

            self.assertTrue(result.error)
            self.assertEqual(stale.read_text(encoding="utf-8"), stale_content)
            self.assertEqual(list(codex_home.glob(".*.tmp")), [])

    def test_trusted_projects_are_cumulative_and_preserve_model_and_user_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            codex_home.mkdir()
            config_path = codex_home / "config.toml"
            user_content = (
                b"# Personal settings stay byte-for-byte intact.\r\n"
                b"[features]\r\nmemories = true\r\n"
            )
            config_path.write_bytes(user_content)

            first = codex_profiles.sync_codex_trusted_projects(
                ("/repo/one", "/home/user/.opendeephole"),
                codex_home=codex_home,
            )
            model = self._sync(
                codex_home,
                _effective_config(),
                ["env/alpha"],
            )
            second = codex_profiles.sync_codex_trusted_projects(
                ("/repo/two", "/repo/one"),
                codex_home=codex_home,
            )
            content = config_path.read_bytes().decode("utf-8")
            remainder, has_default, default_error = (
                codex_profiles._split_managed_default(content)
            )
            restored, managed, has_trust, trust_error = (
                codex_profiles._split_managed_trust(remainder)
            )

            self.assertEqual(first.error, "")
            self.assertEqual(model.error, "")
            self.assertEqual(second.error, "")
            self.assertTrue(has_default)
            self.assertTrue(has_trust)
            self.assertEqual(default_error, "")
            self.assertEqual(trust_error, "")
            self.assertEqual(restored.encode("utf-8"), user_content)
            self.assertEqual(
                set(managed),
                {"/repo/one", "/repo/two", "/home/user/.opendeephole"},
            )
            parsed = codex_profiles.tomllib.loads(content)
            self.assertEqual(parsed["model"], "alpha")
            self.assertTrue(parsed["features"]["memories"])
            self.assertTrue(all(
                parsed["projects"][path]["trust_level"] == "trusted"
                for path in managed
            ))

            with patch.object(codex_profiles, "_stage_file") as stage:
                repeated = codex_profiles.sync_codex_trusted_projects(
                    ("/repo/two",),
                    codex_home=codex_home,
                )
            self.assertEqual(repeated.error, "")
            stage.assert_not_called()

            removed_model = self._sync(codex_home, {}, [])
            self.assertEqual(removed_model.error, "")
            parsed_without_model = codex_profiles.tomllib.loads(
                config_path.read_text(encoding="utf-8")
            )
            self.assertNotIn("model", parsed_without_model)
            self.assertEqual(set(parsed_without_model["projects"]), set(managed))

    def test_user_owned_project_trust_is_reused_and_untrusted_is_respected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            codex_home.mkdir()
            config_path = codex_home / "config.toml"
            original = (
                b'[projects."/already"]\ntrust_level = "trusted"\n\n'
                b'[projects."/blocked"]\ntrust_level = "untrusted"\n'
            )
            config_path.write_bytes(original)

            trusted = codex_profiles.sync_codex_trusted_projects(
                ("/already",),
                codex_home=codex_home,
            )
            blocked = codex_profiles.sync_codex_trusted_projects(
                ("/blocked",),
                codex_home=codex_home,
            )

            self.assertEqual(trusted.error, "")
            self.assertEqual(trusted.trusted_paths, ("/already",))
            self.assertIn("not trusted", blocked.error)
            self.assertEqual(config_path.read_bytes(), original)

    def test_windows_and_unc_trusted_paths_round_trip_through_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            paths = (
                r"C:\Users\Alice Smith\project",
                r"C:\Users\Alice Smith\.opendeephole",
                r"\\server\share\scan",
            )

            result = codex_profiles.sync_codex_trusted_projects(
                paths,
                codex_home=codex_home,
                platform="win32",
            )

            self.assertEqual(result.error, "")
            parsed = codex_profiles.tomllib.loads(
                (codex_home / "config.toml").read_text(encoding="utf-8")
            )
            self.assertEqual(set(parsed["projects"]), set(paths))
            self.assertIn(r"C:\\Users\\Alice Smith", (
                codex_home / "config.toml"
            ).read_text(encoding="utf-8"))

    def test_malformed_trust_markers_and_symlink_are_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            codex_home = root / "codex"
            codex_home.mkdir()
            config_path = codex_home / "config.toml"
            malformed = (
                f"{codex_profiles._TRUST_CONFIG_BEGIN}\n"
                '[projects."/old"]\ntrust_level = "trusted"\n'
            ).encode("utf-8")
            config_path.write_bytes(malformed)

            invalid = codex_profiles.sync_codex_trusted_projects(
                ("/new",),
                codex_home=codex_home,
            )

            self.assertIn("markers", invalid.error)
            self.assertEqual(config_path.read_bytes(), malformed)
            if os.name != "nt":
                config_path.unlink()
                target = root / "personal.toml"
                target.write_text('model = "personal"\n', encoding="utf-8")
                config_path.symlink_to(target)
                symlinked = codex_profiles.sync_codex_trusted_projects(
                    ("/new",),
                    codex_home=codex_home,
                )
                self.assertIn("symlinked", symlinked.error)
                self.assertEqual(
                    target.read_text(encoding="utf-8"),
                    'model = "personal"\n',
                )

    def test_windows_codex_home_fallback_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            userprofile = Path(tmp) / "user"
            result = codex_profiles.sync_codex_config(
                codex_version="codex-cli 0.149.1",
                opencode_config=_effective_config(),
                selected_model_ids=["env/alpha"],
                env={"USERPROFILE": str(userprofile)},
                platform="win32",
            )

            self.assertEqual(result.error, "")
            self.assertTrue((userprofile / ".codex" / "config.toml").is_file())


if __name__ == "__main__":
    unittest.main()
