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


class CodexProfileSyncTests(unittest.TestCase):
    def _sync(
        self,
        codex_home: Path,
        config: dict,
        model_ids: list[str],
        *,
        version: str = "codex-cli 0.149.1",
        platform: str = "linux",
    ) -> codex_profiles.CodexProfileSyncResult:
        return codex_profiles.sync_codex_profiles(
            codex_version=version,
            opencode_config=config,
            selected_model_ids=model_ids,
            env={"CODEX_HOME": str(codex_home)},
            platform=platform,
        )

    def test_syncs_only_selected_models_in_platform_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "codex"
            codex_home.mkdir()
            user_config = codex_home / "config.toml"
            original = b'model = "personal-default"\n'
            user_config.write_bytes(original)

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
                ["literal/beta/model", "env/alpha"],
            )
            self.assertEqual(first.models, second.models)
            self.assertEqual(user_config.read_bytes(), original)

            by_id = {item.id: item for item in first.models}
            literal_path = codex_home / (
                f"{by_id['literal/beta/model'].profile}.config.toml"
            )
            env_path = codex_home / f"{by_id['env/alpha'].profile}.config.toml"
            literal_text = literal_path.read_text(encoding="utf-8")
            env_text = env_path.read_text(encoding="utf-8")
            self.assertIn('model = "beta/model"', literal_text)
            self.assertIn("model_context_window = 65536", literal_text)
            self.assertIn(
                'experimental_bearer_token = "literal-secret-value"',
                literal_text,
            )
            self.assertIn('env_key = "ENV_PROVIDER_TOKEN"', env_text)
            self.assertFalse(any("unused" in path.name for path in codex_home.iterdir()))
            if os.name != "nt":
                self.assertEqual(literal_path.stat().st_mode & 0o777, 0o600)

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

    def test_existing_user_model_profile_and_provider_are_never_overwritten(
        self,
    ) -> None:
        variants = (
            b'model = "personal"\n# keep me\n',
            b'profile = "personal-profile"\n# keep me\n',
            (
                b'model_provider = "personal"\n'
                b'[model_providers.personal]\n'
                b'base_url = "https://personal.example/v1"\n'
            ),
        )
        for original in variants:
            with self.subTest(original=original), tempfile.TemporaryDirectory() as tmp:
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
                self.assertEqual(config_path.read_bytes(), original)
                self.assertTrue(
                    (codex_home / f"{result.models[0].profile}.config.toml").is_file()
                )

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
            first = self._sync(codex_home, config, ["p/two"])
            first_path = codex_home / f"{first.models[0].profile}.config.toml"
            self.assertEqual(first.managed_default_model.id, "p/two")

            second = self._sync(codex_home, config, ["p/one"])
            self.assertEqual(second.managed_default_model.id, "p/one")
            self.assertFalse(first_path.exists())
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
            owned = codex_home / f"{first.models[0].profile}.config.toml"
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
            self.assertTrue(
                (codex_home / f"{first.models[0].profile}.config.toml").exists()
            )

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

    def test_old_codex_and_foreign_collision_preserve_existing_files(self) -> None:
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
            self.assertTrue(old.error)
            self.assertEqual(stale.read_text(encoding="utf-8"), stale_content)

            profile = codex_profiles._profile_name("env", "alpha")
            foreign = codex_home / f"{profile}.config.toml"
            foreign_content = 'model = "foreign"\n'
            foreign.write_text(foreign_content, encoding="utf-8")
            collision = self._sync(
                codex_home,
                _effective_config(),
                ["env/alpha"],
            )
            self.assertIn("refused to overwrite", collision.error)
            self.assertEqual(foreign.read_text(encoding="utf-8"), foreign_content)
            self.assertEqual(stale.read_text(encoding="utf-8"), stale_content)

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

    def test_windows_codex_home_fallback_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            userprofile = Path(tmp) / "user"
            result = codex_profiles.sync_codex_profiles(
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
