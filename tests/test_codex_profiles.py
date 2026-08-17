from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deephole_client import codex_profiles


class CodexProfileSyncTests(unittest.TestCase):
    @staticmethod
    def _config_dir(root: Path) -> Path:
        directory = root / "opencode"
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_syncs_json_and_jsonc_models_with_credentials_and_context(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            xdg = root / "xdg"
            codex_home = root / "codex"
            config_dir = self._config_dir(xdg)
            literal_secret = "literal-secret-value"
            self._write_json(config_dir / "opencode.json", {
                "provider": {
                    "literal": {
                        "name": "Literal Provider",
                        "options": {
                            "baseURL": "https://initial.example/v1",
                            "apiKey": literal_secret,
                        },
                        "models": {"beta/model": {}},
                    },
                    "env": {
                        "options": {
                            "baseURL": "https://env.example/v1",
                            "apiKey": "{env:ENV_PROVIDER_TOKEN}",
                        },
                        "models": {"alpha": {}},
                    },
                },
            })
            (config_dir / "opencode.jsonc").write_text(
                """
                {
                  // JSONC has higher precedence than opencode.json.
                  "provider": {
                    "literal": {
                      "options": {
                        "baseURL": "https://override.example/v1",
                      },
                      "models": {
                        "beta/model": {
                          "limit": {"context": 65536,},
                        },
                      },
                    },
                  },
                }
                """,
                encoding="utf-8",
            )
            codex_home.mkdir()
            user_config = codex_home / "config.toml"
            user_config.write_text(
                'model = "personal-default"\n',
                encoding="utf-8",
            )
            env = {
                "HOME": str(home),
                "XDG_CONFIG_HOME": str(xdg),
                "CODEX_HOME": str(codex_home),
            }

            first = codex_profiles.sync_codex_profiles(
                codex_version="codex-cli 0.146.1",
                env=env,
                platform="linux",
            )
            second = codex_profiles.sync_codex_profiles(
                codex_version="codex-cli 0.146.1",
                env=env,
                platform="linux",
            )

            self.assertEqual(first.error, "")
            self.assertEqual(
                [item.id for item in first.models],
                ["env/alpha", "literal/beta/model"],
            )
            self.assertEqual(
                [item.profile for item in first.models],
                [item.profile for item in second.models],
            )
            by_id = {item.id: item for item in first.models}
            env_profile_path = (
                codex_home
                / f"{by_id['env/alpha'].profile}.config.toml"
            )
            literal_profile_path = (
                codex_home
                / f"{by_id['literal/beta/model'].profile}.config.toml"
            )
            env_text = env_profile_path.read_text(encoding="utf-8")
            literal_text = literal_profile_path.read_text(encoding="utf-8")

            self.assertIn('model = "alpha"', env_text)
            self.assertIn(
                'env_key = "ENV_PROVIDER_TOKEN"',
                env_text,
            )
            self.assertNotIn("experimental_bearer_token", env_text)
            self.assertIn('model = "beta/model"', literal_text)
            self.assertIn("model_context_window = 65536", literal_text)
            self.assertIn(
                'base_url = "https://override.example/v1"',
                literal_text,
            )
            self.assertIn(
                f'experimental_bearer_token = "{literal_secret}"',
                literal_text,
            )
            self.assertIn('wire_api = "responses"', literal_text)
            self.assertEqual(
                user_config.read_text(encoding="utf-8"),
                'model = "personal-default"\n',
            )
            if os.name != "nt":
                self.assertEqual(
                    literal_profile_path.stat().st_mode & 0o777,
                    0o600,
                )

    def test_windows_appdata_is_used_and_non_global_scopes_are_ignored(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            appdata = root / "appdata"
            userprofile = root / "user"
            codex_home = root / "codex"
            config_dir = self._config_dir(appdata)
            self._write_json(config_dir / "opencode.json", {
                "provider": {
                    "appdata": {
                        "options": {
                            "baseURL": "https://appdata.example/v1",
                        },
                        "models": {"windows-model": {}},
                    },
                },
            })
            for directory in (
                root / "project",
                root / "bin" / ".opencode",
                root / "explicit",
            ):
                directory.mkdir(parents=True)
                self._write_json(directory / "opencode.json", {
                    "provider": {
                        "ignored": {
                            "options": {
                                "baseURL": "https://ignored.example/v1",
                            },
                            "models": {directory.name: {}},
                        },
                    },
                })
            env = {
                "USERPROFILE": str(userprofile),
                "APPDATA": str(appdata),
                "CODEX_HOME": str(codex_home),
                "OPENCODE_CONFIG_PATH": str(
                    root / "explicit" / "opencode.json"
                ),
            }

            result = codex_profiles.sync_codex_profiles(
                codex_version="codex-cli 0.146.1",
                env=env,
                platform="win32",
            )

            self.assertEqual(result.error, "")
            self.assertEqual(
                [item.id for item in result.models],
                ["appdata/windows-model"],
            )

    def test_invalid_source_and_old_codex_preserve_managed_profiles(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            config_dir = self._config_dir(home / ".config")
            codex_home = root / "codex"
            codex_home.mkdir()
            stale = codex_home / "opendeephole-stale.config.toml"
            stale_content = (
                f"{codex_profiles._MANAGED_MARKER}\n"
                'model = "old"\n'
            )
            stale.write_text(stale_content, encoding="utf-8")
            invalid_secret = "must-never-appear-in-errors"
            (config_dir / "opencode.json").write_text(
                '{"provider":{"secret":"'
                + invalid_secret
                + '"',
                encoding="utf-8",
            )
            env = {
                "HOME": str(home),
                "CODEX_HOME": str(codex_home),
            }

            invalid = codex_profiles.sync_codex_profiles(
                codex_version="codex-cli 0.146.1",
                env=env,
                platform="linux",
            )
            self.assertTrue(invalid.error)
            self.assertNotIn(invalid_secret, invalid.error)
            self.assertEqual(stale.read_text(encoding="utf-8"), stale_content)

            self._write_json(config_dir / "opencode.json", {
                "provider": {
                    "new": {
                        "options": {
                            "baseURL": "https://new.example/v1",
                        },
                        "models": {"model": {}},
                    },
                },
            })
            old_version = codex_profiles.sync_codex_profiles(
                codex_version="codex-cli 0.133.0",
                env=env,
                platform="linux",
            )
            self.assertIn("older than 0.134", old_version.error)
            self.assertEqual(stale.read_text(encoding="utf-8"), stale_content)

    def test_reconciles_only_owned_profiles_and_refuses_foreign_collision(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            codex_home = root / "codex"
            config_path = (
                self._config_dir(home / ".config") / "opencode.json"
            )
            env = {
                "HOME": str(home),
                "CODEX_HOME": str(codex_home),
            }
            provider = {
                "options": {"baseURL": "https://models.example/v1"},
                "models": {"one": {}, "two": {}},
            }
            self._write_json(config_path, {"provider": {"p": provider}})

            first = codex_profiles.sync_codex_profiles(
                codex_version="development-build",
                env=env,
                platform="linux",
            )
            self.assertEqual(len(first.models), 2)
            self.assertTrue(any(
                "could not be parsed" in item for item in first.warnings
            ))
            first_paths = {
                item.id: codex_home / f"{item.profile}.config.toml"
                for item in first.models
            }
            foreign = codex_home / "opendeephole-user.config.toml"
            foreign.write_text('model = "mine"\n', encoding="utf-8")

            provider["models"] = {"one": {}}
            self._write_json(config_path, {"provider": {"p": provider}})
            reconciled = codex_profiles.sync_codex_profiles(
                codex_version="codex-cli 0.146.1",
                env=env,
                platform="linux",
            )
            self.assertEqual([item.id for item in reconciled.models], ["p/one"])
            self.assertTrue(first_paths["p/one"].exists())
            self.assertFalse(first_paths["p/two"].exists())
            self.assertEqual(
                foreign.read_text(encoding="utf-8"),
                'model = "mine"\n',
            )

            collision = first_paths["p/one"]
            collision.write_text('model = "user-edited"\n', encoding="utf-8")
            refused = codex_profiles.sync_codex_profiles(
                codex_version="codex-cli 0.146.1",
                env=env,
                platform="linux",
            )
            self.assertIn("refused to overwrite", refused.error)
            self.assertEqual(
                collision.read_text(encoding="utf-8"),
                'model = "user-edited"\n',
            )

    def test_write_failure_keeps_stale_profiles_and_cleans_staging_files(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            codex_home = root / "codex"
            codex_home.mkdir()
            stale = codex_home / "opendeephole-old.config.toml"
            stale.write_text(
                f"{codex_profiles._MANAGED_MARKER}\nmodel = \"old\"\n",
                encoding="utf-8",
            )
            config_path = (
                self._config_dir(home / ".config") / "opencode.json"
            )
            self._write_json(config_path, {
                "provider": {
                    "p": {
                        "options": {
                            "baseURL": "https://models.example/v1",
                        },
                        "models": {"new": {}},
                    },
                },
            })
            env = {
                "HOME": str(home),
                "CODEX_HOME": str(codex_home),
            }

            with patch.object(
                codex_profiles.os,
                "replace",
                side_effect=PermissionError,
            ):
                result = codex_profiles.sync_codex_profiles(
                    codex_version="codex-cli 0.146.1",
                    env=env,
                    platform="linux",
                )

            self.assertIn("atomically write", result.error)
            self.assertTrue(stale.exists())
            self.assertEqual(
                list(codex_home.glob(".*.tmp")),
                [],
            )

    def test_missing_base_url_is_skipped_without_exposing_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            config_path = (
                self._config_dir(home / ".config") / "opencode.json"
            )
            secret = "skipped-provider-secret"
            self._write_json(config_path, {
                "provider": {
                    "bad": {
                        "options": {"apiKey": secret},
                        "models": {"model": {}},
                    },
                },
            })

            result = codex_profiles.sync_codex_profiles(
                codex_version="codex-cli 0.146.1",
                env={
                    "HOME": str(home),
                    "CODEX_HOME": str(root / "codex"),
                },
                platform="linux",
            )

            self.assertEqual(result.error, "")
            self.assertEqual(result.models, ())
            warning_text = "\n".join(result.warnings)
            self.assertIn("baseURL is missing or invalid", warning_text)
            self.assertNotIn(secret, warning_text)


if __name__ == "__main__":
    unittest.main()
