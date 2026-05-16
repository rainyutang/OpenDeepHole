from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from checkers.inf_loop.analyzer import Analyzer as InfLoopAnalyzer
from checkers.resleak import analyzer as resleak_analyzer


def test_inf_loop_semgrep_output_uses_utf8_replace(tmp_path: Path) -> None:
    def fake_run(cmd, **kwargs):
        assert kwargs["encoding"] == "utf-8"
        assert kwargs["errors"] == "replace"
        return CompletedProcess(cmd, 0, stdout='{"results":[]}', stderr="")

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("checkers.inf_loop.analyzer.subprocess.run", side_effect=fake_run),
    ):
        assert list(InfLoopAnalyzer().find_candidates(tmp_path)) == []


def test_resleak_cppcheck_output_uses_utf8_replace(tmp_path: Path) -> None:
    def fake_run(cmd, **kwargs):
        assert kwargs["encoding"] == "utf-8"
        assert kwargs["errors"] == "replace"
        return CompletedProcess(cmd, 0, stdout="", stderr="<results><errors /></results>")

    with patch("checkers.resleak.analyzer.subprocess.run", side_effect=fake_run):
        assert list(resleak_analyzer._run_cppcheck(tmp_path, "cppcheck")) == []
