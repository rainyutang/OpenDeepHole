"""Unit tests for OpenCode ripgrep bundling and runtime provisioning."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from task_agent.ripgrep_runtime import (
    BUNDLED_RIPGREP_DIRNAME,
    bundled_ripgrep_executable,
    ensure_ripgrep_ready,
    is_working_ripgrep,
    prepend_dir_to_env_path,
)


VALID_RG_BYTES = b"MZ-valid-ripgrep-binary"


def _make_fake_repo(tmp_path: Path, content: bytes = VALID_RG_BYTES) -> Path:
    repo_root = tmp_path / "agent_root"
    bundled_dir = repo_root / BUNDLED_RIPGREP_DIRNAME
    bundled_dir.mkdir(parents=True, exist_ok=True)
    (bundled_dir / "rg.exe").write_bytes(content)
    return repo_root


def _bytes_probe(path: Path) -> bool:
    try:
        return path.is_file() and path.read_bytes() == VALID_RG_BYTES
    except OSError:
        return False


class RipgrepRuntimeTests(unittest.TestCase):
    def test_bundled_repo_ripgrep_binary_exists_and_is_valid_windows_pe(self) -> None:
        exe = bundled_ripgrep_executable()
        self.assertIsNotNone(exe)
        assert exe is not None
        self.assertTrue(exe.is_file())
        header = exe.read_bytes()[:64]
        self.assertEqual(header[:2], b"MZ")
        self.assertGreater(exe.stat().st_size, 1_000_000)

    def test_windows_missing_ripgrep_copies_to_opencode_bin_even_if_bundled_dir_in_path(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo_root = _make_fake_repo(tmp_path)
            bundled_dir = repo_root / BUNDLED_RIPGREP_DIRNAME
            user_home = tmp_path / "Users" / "tester"
            custom_xdg = tmp_path / "custom_xdg_data"

            # Simulate run_agent.bat already having prepended BUNDLED_RIPGREP_DIR to Path.
            env = {
                "USERPROFILE": str(user_home),
                "XDG_DATA_HOME": str(custom_xdg),
                "Path": f"{bundled_dir};{tmp_path / 'System32'}",
            }

            result = ensure_ripgrep_ready(
                env=env,
                executable="opencode",
                root=repo_root,
                platform="win32",
                probe_fn=_bytes_probe,
            )

            expected_user_rg = user_home / ".local" / "share" / "opencode" / "bin" / "rg.exe"
            expected_xdg_rg = custom_xdg / "opencode" / "bin" / "rg.exe"

            self.assertTrue(result.available)
            self.assertEqual(result.source, "bundled")
            self.assertEqual(expected_user_rg.read_bytes(), VALID_RG_BYTES)
            self.assertEqual(expected_xdg_rg.read_bytes(), VALID_RG_BYTES)
            self.assertEqual(
                set(result.copied_targets),
                {str(expected_user_rg), str(expected_xdg_rg)},
            )
            self.assertNotIn("Path", env)
            self.assertEqual(env["PATH"].split(";")[0], str(bundled_dir))

    def test_windows_corrupted_cached_ripgrep_is_repaired_even_when_system_rg_exists(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo_root = _make_fake_repo(tmp_path)
            user_home = tmp_path / "Users" / "tester"
            system_bin = tmp_path / "scoop" / "shims"
            system_bin.mkdir(parents=True)
            (system_bin / "rg.exe").write_bytes(VALID_RG_BYTES)

            cached_rg = user_home / ".local" / "share" / "opencode" / "bin" / "rg.exe"
            cached_rg.parent.mkdir(parents=True)
            cached_rg.write_bytes(b"")  # 0-byte leftover from failed download

            env = {
                "USERPROFILE": str(user_home),
                "PATH": str(system_bin),
            }

            result = ensure_ripgrep_ready(
                env=env,
                executable="opencode",
                root=repo_root,
                platform="win32",
                probe_fn=_bytes_probe,
            )

            self.assertTrue(result.available)
            self.assertEqual(result.source, "system_path")
            self.assertEqual(cached_rg.read_bytes(), VALID_RG_BYTES)
            self.assertIn(str(cached_rg), result.copied_targets)

    def test_windows_existing_healthy_cached_ripgrep_is_reused_without_copy(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo_root = _make_fake_repo(tmp_path)
            user_home = tmp_path / "Users" / "tester"
            cached_rg = user_home / ".local" / "share" / "opencode" / "bin" / "rg.exe"
            cached_rg.parent.mkdir(parents=True)
            cached_rg.write_bytes(VALID_RG_BYTES)

            env = {"USERPROFILE": str(user_home), "PATH": ""}
            result = ensure_ripgrep_ready(
                env=env,
                executable="opencode",
                root=repo_root,
                platform="win32",
                probe_fn=_bytes_probe,
            )

            self.assertTrue(result.available)
            self.assertEqual(result.copied_targets, ())
            self.assertEqual(result.reused_targets, (str(cached_rg),))

    def test_windows_nga_executable_provisions_both_opencode_and_nga_bins(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo_root = _make_fake_repo(tmp_path)
            user_home = tmp_path / "Users" / "tester"
            env = {"USERPROFILE": str(user_home), "PATH": ""}

            result = ensure_ripgrep_ready(
                env=env,
                executable=r"C:\Tools\nga.exe",
                root=repo_root,
                platform="win32",
                probe_fn=_bytes_probe,
            )

            opencode_rg = user_home / ".local" / "share" / "opencode" / "bin" / "rg.exe"
            nga_rg = user_home / ".local" / "share" / "nga" / "bin" / "rg.exe"
            self.assertTrue(result.available)
            self.assertEqual(opencode_rg.read_bytes(), VALID_RG_BYTES)
            self.assertEqual(nga_rg.read_bytes(), VALID_RG_BYTES)

    def test_windows_opencode_v2_isolated_data_home_is_seeded(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo_root = _make_fake_repo(tmp_path)
            user_home = tmp_path / "Users" / "tester"
            system_bin = tmp_path / "system_bin"
            system_bin.mkdir(parents=True)
            (system_bin / "rg.exe").write_bytes(VALID_RG_BYTES)

            isolated_data = tmp_path / "serve_cwd" / ".opendeephole-xdg-runtime" / "data"
            isolated_data.mkdir(parents=True)

            env = {
                "USERPROFILE": str(user_home),
                "XDG_DATA_HOME": str(isolated_data),
                "PATH": str(system_bin),
            }

            result = ensure_ripgrep_ready(
                env=env,
                executable="opencode",
                isolated_data_home=isolated_data,
                root=repo_root,
                platform="win32",
                probe_fn=_bytes_probe,
            )

            isolated_rg = isolated_data / "opencode" / "bin" / "rg.exe"
            self.assertTrue(result.available)
            self.assertEqual(isolated_rg.read_bytes(), VALID_RG_BYTES)
            self.assertIn(str(isolated_rg), result.copied_targets)

    def test_windows_copy_permission_error_degrades_gracefully_with_bundled_path(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo_root = _make_fake_repo(tmp_path)
            user_home = tmp_path / "Users" / "tester"
            env = {"USERPROFILE": str(user_home), "PATH": ""}

            with patch(
                "task_agent.ripgrep_runtime._atomic_copy_executable",
                side_effect=PermissionError("Access is denied"),
            ):
                result = ensure_ripgrep_ready(
                    env=env,
                    executable="opencode",
                    root=repo_root,
                    platform="win32",
                    probe_fn=_bytes_probe,
                )

            self.assertTrue(result.available)
            self.assertEqual(result.source, "bundled")
            self.assertEqual(result.copied_targets, ())
            self.assertTrue(any("Access is denied" in item for item in result.warnings))
            self.assertIn(str(repo_root / BUNDLED_RIPGREP_DIRNAME), env["PATH"])

    def test_posix_opencode_bin_fallback_prepends_path_when_system_rg_missing(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            user_home = tmp_path / "home" / "tester"
            cached_rg = user_home / ".local" / "share" / "opencode" / "bin" / "rg"
            cached_rg.parent.mkdir(parents=True)
            cached_rg.write_bytes(VALID_RG_BYTES)

            env = {"HOME": str(user_home), "PATH": "/usr/bin"}
            result = ensure_ripgrep_ready(
                env=env,
                executable="opencode",
                root=tmp_path,
                platform="linux",
                probe_fn=_bytes_probe,
            )

            self.assertTrue(result.available)
            self.assertEqual(result.source, "opencode_bin")
            self.assertEqual(env["PATH"].split(":")[0], str(cached_rg.parent))

    def test_prepend_dir_to_env_path_deduplicates_case_insensitively_on_windows(
        self,
    ) -> None:
        env = {"Path": r"C:\Windows\System32;C:\Tools\RipGrep;C:\Users\dev\bin"}
        updated = prepend_dir_to_env_path(env, r"c:\tools\ripgrep", platform="win32")
        self.assertNotIn("Path", env)
        self.assertEqual(updated, r"c:\tools\ripgrep;C:\Windows\System32;C:\Users\dev\bin")
        self.assertEqual(env["PATH"], updated)

    def test_is_working_ripgrep_checks_exit_code_and_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_rg = Path(tmp) / "rg"
            fake_rg.write_text("#!/bin/sh\n", encoding="utf-8")

            class _FakePopen:
                def __init__(self, returncode: int, stdout: bytes) -> None:
                    self.returncode = returncode
                    self._stdout = stdout

                def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
                    return (self._stdout, b"")

                def kill(self) -> None:
                    pass

            with patch(
                "task_agent.ripgrep_runtime._PROBE_CACHE",
                {},
            ), patch(
                "task_agent.ripgrep_runtime._ORIGINAL_POPEN",
                return_value=_FakePopen(0, b"ripgrep 15.1.0\n"),
            ):
                self.assertTrue(is_working_ripgrep(fake_rg))

            with patch(
                "task_agent.ripgrep_runtime._PROBE_CACHE",
                {},
            ), patch(
                "task_agent.ripgrep_runtime._ORIGINAL_POPEN",
                return_value=_FakePopen(1, b"error\n"),
            ):
                self.assertFalse(is_working_ripgrep(fake_rg))


if __name__ == "__main__":
    unittest.main()
