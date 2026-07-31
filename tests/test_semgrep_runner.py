import json
import shutil
import subprocess
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

import pytest

from deephole_client.static_analysis.semgrep_runner import (
    SEMGREP_INTERNAL_EXCLUDES,
    run_semgrep,
)


def test_semgrep_runner_sets_noninteractive_env(tmp_path: Path) -> None:
    rule_file = tmp_path / "rule.yml"
    rule_file.write_text("rules: []\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        assert cmd[:2] == ["semgrep", "scan"]
        assert "--metrics=off" in cmd
        assert "--disable-version-check" in cmd
        assert "--no-autofix" in cmd
        assert "--x-ignore-semgrepignore-files" in cmd
        exclude_values = [
            cmd[index + 1]
            for index, value in enumerate(cmd)
            if value == "--exclude"
        ]
        assert exclude_values == list(SEMGREP_INTERNAL_EXCLUDES)
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["env"]["PYTHONUTF8"] == "1"
        assert kwargs["env"]["PYTHONIOENCODING"] == "utf-8"
        assert kwargs["env"]["SEMGREP_SEND_METRICS"] == "off"
        assert kwargs["env"]["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
        assert kwargs["env"]["SEMGREP_SETTINGS_FILE"].endswith("settings.yml")
        assert kwargs["env"]["SEMGREP_LOG_FILE"].endswith("semgrep.log")
        assert kwargs["env"]["XDG_CONFIG_HOME"].endswith("config")
        assert kwargs["env"]["XDG_CACHE_HOME"].endswith("cache")
        return CompletedProcess(cmd, 0, stdout='{"results":[]}', stderr="")

    with patch("deephole_client.static_analysis.semgrep_runner.subprocess.run", side_effect=fake_run):
        result = run_semgrep(tmp_path, rule_file=rule_file, checker_name="unit", timeout=3)

    assert result is not None
    assert result.returncode == 0
    assert result.stdout == '{"results":[]}'


@pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="semgrep CLI is not installed",
)
def test_semgrep_runner_ignores_invalid_project_semgrepignore(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".semgrepignore").write_text("\\\n", encoding="utf-8")
    (project / "sample.c").write_text(
        "int sample(void) { return 0; }\n",
        encoding="utf-8",
    )
    rule_file = tmp_path / "rule.yml"
    rule_file.write_text(
        """
rules:
  - id: test-return-zero
    languages: [c]
    severity: INFO
    message: test
    pattern: return 0;
""".lstrip(),
        encoding="utf-8",
    )

    result = run_semgrep(
        project,
        rule_file=rule_file,
        checker_name="unit",
        timeout=30,
    )

    assert result is not None
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["errors"] == []
    assert any(Path(path).name == "sample.c" for path in data["paths"]["scanned"])


def test_semgrep_runner_returns_none_when_timeout_has_no_json(tmp_path: Path) -> None:
    rule_file = tmp_path / "rule.yml"
    rule_file.write_text("rules: []\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        raise TimeoutExpired(cmd, kwargs["timeout"], output="", stderr="still running")

    with patch("deephole_client.static_analysis.semgrep_runner.subprocess.run", side_effect=fake_run):
        result = run_semgrep(tmp_path, rule_file=rule_file, checker_name="unit", timeout=1)

    assert result is None


def test_semgrep_runner_prints_heartbeat_when_enabled(tmp_path: Path, capsys) -> None:
    rule_file = tmp_path / "rule.yml"
    rule_file.write_text("rules: []\n", encoding="utf-8")

    class FakePopen:
        def __init__(self, cmd, **kwargs):
            assert "--x-ignore-semgrepignore-files" in cmd
            self.cmd = cmd
            self.returncode = 0
            self.calls = 0

        def communicate(self, timeout=None):
            self.calls += 1
            if self.calls == 1:
                raise TimeoutExpired(self.cmd, timeout, output="", stderr="")
            return '{"results":[]}', ""

        def kill(self):
            self.returncode = -9

    with (
        patch("deephole_client.static_analysis.semgrep_runner.subprocess.Popen", side_effect=FakePopen),
        patch("deephole_client.static_analysis.semgrep_runner.time.monotonic", side_effect=[0.0, 0.0, 0.2, 0.2]),
    ):
        result = run_semgrep(
            tmp_path,
            rule_file=rule_file,
            checker_name="unit",
            timeout=3,
            heartbeat_interval=0.1,
        )

    assert result is not None
    assert result.stdout == '{"results":[]}'
    captured = capsys.readouterr()
    assert "[semgrep] unit still running: 0s" in captured.out
