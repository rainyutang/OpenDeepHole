from __future__ import annotations

import json
import subprocess
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

import yaml

from deephole_client.vulnerability_mining.engines.static_candidate.rules.loop_mut_idx_oob.analyzer import (
    Analyzer as LoopMutIdxOobAnalyzer,
)


RULE_FILE = Path(
    "deephole_client/vulnerability_mining/engines/static_candidate/rules/"
    "loop_mut_idx_oob/loop_mut_idx_oob_semgrep.yml"
)


class FakeDb:
    def get_function_by_location(self, file_path: str, line: int):
        if file_path == "sample.c" and line == 8:
            return {"name": "copy_loop"}
        if file_path == "derived.c" and line == 17:
            return {"name": "derived_loop"}
        return None


def test_loop_mut_idx_oob_skips_when_semgrep_missing(tmp_path: Path) -> None:
    with patch("shutil.which", return_value=None):
        assert list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path)) == []


def test_loop_mut_idx_oob_rule_yaml_is_valid() -> None:
    data = yaml.safe_load(RULE_FILE.read_text(encoding="utf-8"))
    assert len(data["rules"]) == 6
    rule_ids = {rule["id"] for rule in data["rules"]}
    assert "c.loop-mutated-index-array-access.broad" in rule_ids
    assert "c.loop-bound-unchecked-index-access.broad" not in rule_ids
    assert "c.loop-mutated-copy-from-user-sink.broad" in rule_ids
    assert "c.loop-mutated-index-pointer-access.broad" in rule_ids
    assert "c.loop-mutated-index-memory-call.broad" in rule_ids
    assert "c.loop-mutated-index-derived-pointer-sink.broad" in rule_ids
    assert "c.loop-mutated-pointer-cursor-access.broad" in rule_ids


def test_loop_mut_idx_oob_semgrep_runner_arguments(tmp_path: Path) -> None:
    def fake_run(cmd, **kwargs):
        assert kwargs["encoding"] == "utf-8"
        assert kwargs["errors"] == "replace"
        assert kwargs["timeout"] == 900
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert cmd[:2] == ["semgrep", "scan"]
        assert any(arg.startswith("--json-output=") for arg in cmd)
        assert "--metrics=off" in cmd
        assert "--disable-version-check" in cmd
        return CompletedProcess(cmd, 0, stdout='{"results":[]}', stderr="")

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.semgrep_runner.subprocess.run", side_effect=fake_run),
    ):
        assert list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path)) == []


def test_loop_mut_idx_oob_direct_result_uses_json_file_and_code_db(tmp_path: Path) -> None:
    file_output = _semgrep_output(
        path=str(tmp_path / "sample.c"),
        line=8,
        check_id="c.loop-mutated-index-array-access.broad",
        message="Possible unchecked loop index memory access.",
        metavars={
            "$IDX": {"abstract_content": "idx"},
            "$COND": {"abstract_content": "remain > 0"},
            "$STEP": {"abstract_content": "step"},
            "$BASE": {"abstract_content": "dst"},
        },
        metadata={"source_kind": "array", "recall": "high"},
        lines="dst[idx] = src[idx];",
    )

    def fake_run(cmd, **kwargs):
        output_arg = next(arg for arg in cmd if arg.startswith("--json-output="))
        Path(output_arg.split("=", 1)[1]).write_text(file_output.stdout, encoding="utf-8")
        return CompletedProcess(cmd, 0, stdout='{"results":[]}', stderr="")

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.semgrep_runner.subprocess.run", side_effect=fake_run),
    ):
        candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path, FakeDb()))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.file == "sample.c"
    assert candidate.line == 8
    assert candidate.function == "copy_loop"
    assert candidate.vuln_type == "loop_mut_idx_oob"
    assert "越界访问问题" in candidate.description
    assert "循环变化索引: idx" in candidate.description
    assert "循环条件: remain > 0" in candidate.description
    assert "内存访问: dst[idx]" in candidate.description
    assert "宽召回" not in candidate.description
    assert "匹配代码" not in candidate.description


def test_loop_mut_idx_oob_copy_from_user_result_names_focus_variable(tmp_path: Path) -> None:
    output = _semgrep_output(
        path=str(tmp_path / "copy.c"),
        line=19,
        check_id="c.loop-mutated-copy-from-user-sink.broad",
        message="Possible loop length copy_from_user overflow.",
        metavars={
            "$COPY": {"abstract_content": "bspkern_copy_from_user"},
            "$DST": {"abstract_content": "fragPayload"},
            "$LEN": {"abstract_content": "fragLen"},
            "$COND": {"abstract_content": "fragId < fragNum"},
        },
        metadata={"source_kind": "copy-from-user", "recall": "high"},
        lines="bspkern_copy_from_user(fragPayload, fragPayloadFromUser, fragLen)",
    )

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.semgrep_runner.subprocess.run", return_value=output),
    ):
        candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert "重点变量 `fragLen`" in candidate.description
    assert "目标 `fragPayload`" in candidate.description
    assert "copy_from_user调用: bspkern_copy_from_user" in candidate.description
    assert "重点变量/拷贝长度: fragLen" in candidate.description
    assert candidate.metadata == {
        "problem": "copy_from_user循环累加长度越界",
        "focus_variable": "fragLen",
        "target_variable": "fragPayload",
        "sink": "bspkern_copy_from_user",
    }
    assert "subject" not in candidate.metadata


def test_loop_mut_idx_oob_derived_pointer_result_and_dedup(tmp_path: Path) -> None:
    payload = {
        "results": [
            _match(
                path=str(tmp_path / "derived.c"),
                line=17,
                check_id="c.loop-mutated-index-derived-pointer-sink.broad",
                message="Possible unchecked loop-index-derived pointer reaches memory sink.",
                metavars={
                    "$IDX": {"abstract_content": "idx"},
                    "$COND": {"abstract_content": "remain"},
                    "$BASE": {"abstract_content": "base"},
                    "$P": {"abstract_content": "tmp"},
                },
                metadata={"source_kind": "derived-pointer", "recall": "high"},
                lines="*tmp = 0;",
            ),
            _match(
                path=str(tmp_path / "derived.c"),
                line=17,
                check_id="c.loop-mutated-index-derived-pointer-sink.broad",
                message="Possible unchecked loop-index-derived pointer reaches memory sink.",
                metavars={
                    "$IDX": {"abstract_content": "idx"},
                    "$COND": {"abstract_content": "remain"},
                    "$BASE": {"abstract_content": "base"},
                    "$P": {"abstract_content": "tmp"},
                },
                metadata={"source_kind": "derived-pointer", "recall": "high"},
                lines="*tmp = 0;",
            ),
        ],
    }

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.semgrep_runner.subprocess.run",
            return_value=CompletedProcess(["semgrep"], 1, stdout=json.dumps(payload), stderr=""),
        ),
    ):
        candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path, FakeDb()))

    assert len(candidates) == 1
    assert candidates[0].function == "derived_loop"
    assert "越界访问问题" in candidates[0].description
    assert "derived-pointer" not in candidates[0].description
    assert "循环条件: remain" in candidates[0].description


def test_loop_mut_idx_oob_timeout_uses_partial_json(tmp_path: Path) -> None:
    output = _semgrep_output(
        path=str(tmp_path / "sample.c"),
        line=8,
        check_id="c.loop-mutated-index-array-access.broad",
        message="Possible unchecked loop index memory access.",
        metavars={"$IDX": {"abstract_content": "idx"}, "$COND": {"abstract_content": "remain"}},
        metadata={"source_kind": "array", "recall": "high"},
    )

    def fake_run(cmd, **kwargs):
        output_arg = next(arg for arg in cmd if arg.startswith("--json-output="))
        Path(output_arg.split("=", 1)[1]).write_text(output.stdout, encoding="utf-8")
        raise TimeoutExpired(cmd, kwargs["timeout"], output="", stderr="still running")

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.semgrep_runner.subprocess.run", side_effect=fake_run),
    ):
        candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path, FakeDb()))

    assert len(candidates) == 1
    assert candidates[0].function == "copy_loop"


def test_loop_mut_idx_oob_skips_tool_errors_and_bad_json(tmp_path: Path) -> None:
    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.semgrep_runner.subprocess.run",
            return_value=CompletedProcess(["semgrep"], 2, stdout="", stderr="bad config"),
        ),
    ):
        assert list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path)) == []

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.semgrep_runner.subprocess.run",
            return_value=CompletedProcess(["semgrep"], 0, stdout="not-json", stderr=""),
        ),
    ):
        assert list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path)) == []


def test_member_message_fallback_uses_exact_utf8_access_and_deduplicates(tmp_path: Path) -> None:
    source = "// 中文注释影响字节偏移\nvoid f(State *ctx) {\nwhile (remain) {\n*(ctx->p++) = 0;\n}\n}\n"
    path = tmp_path / "member.c"
    path.write_text(source, encoding="utf-8")
    access = "*(ctx->p++)"
    offset = source.encode().index(access.encode())
    first = _match(
        path=str(path), line=4,
        check_id="c.loop-mutated-pointer-cursor-access.broad",
        message="Broad candidate: loop-updated expression `ctx->p` reaches a memory access. "
                "Loop condition `remain`; update step `$STEP`.",
        metavars={}, metadata={"source_kind": "pointer-cursor"},
        lines="requires login",
    )
    first["start"]["offset"] = offset
    first["end"] = {"offset": offset + len(access.encode())}
    second = dict(first, check_id="another-equivalent-cursor-pattern")
    result = CompletedProcess(["semgrep"], 0, stdout=json.dumps({"results": [first, second]}), stderr="")
    with (
        patch("shutil.which", return_value="semgrep"),
        patch("deephole_client.vulnerability_mining.engines.static_candidate.rules.loop_mut_idx_oob.analyzer.run_semgrep", return_value=result),
    ):
        candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path))
    assert len(candidates) == 1
    assert candidates[0].line == 4
    assert "循环变化指针: ctx->p" in candidates[0].description
    assert "循环条件: remain" in candidates[0].description
    assert "内存访问: *(ctx->p++)" in candidates[0].description
    assert "$STEP" not in candidates[0].description


def test_member_copy_fallback_preserves_paths_and_metadata(tmp_path: Path) -> None:
    output = _semgrep_output(
        path=str(tmp_path / "missing.c"), line=12,
        check_id="c.loop-mutated-copy-from-user-sink.broad",
        message="Broad candidate: copy_from_user-family sink `copy_from_user` uses destination "
                "variable `ctx->items[k].p` inside a loop while `ctx->items[k].p` is updated by "
                "length variable `ctx->items[k].len` in the same loop. Loop condition `$COND`.",
        metavars={}, metadata={"source_kind": "copy-from-user"},
    )
    with (
        patch("shutil.which", return_value="semgrep"),
        patch("deephole_client.vulnerability_mining.engines.static_candidate.rules.loop_mut_idx_oob.analyzer.run_semgrep", return_value=output),
    ):
        candidate, = LoopMutIdxOobAnalyzer().find_candidates(tmp_path)
    assert candidate.metadata["target_variable"] == "ctx->items[k].p"
    assert candidate.metadata["focus_variable"] == "ctx->items[k].len"
    assert "copy_from_user(ctx->items[k].p, ..., ctx->items[k].len)" in candidate.description
    assert "$COND" not in candidate.description


def _semgrep_output(
    *,
    path: str,
    line: int,
    check_id: str,
    message: str,
    metavars: dict,
    metadata: dict | None = None,
    lines: str = "",
) -> CompletedProcess:
    payload = {
        "results": [
            _match(
                path=path,
                line=line,
                check_id=check_id,
                message=message,
                metavars=metavars,
                metadata=metadata,
                lines=lines,
            )
        ]
    }
    return CompletedProcess(["semgrep"], 0, stdout=json.dumps(payload), stderr="")


def _match(
    *,
    path: str,
    line: int,
    check_id: str,
    message: str,
    metavars: dict,
    metadata: dict | None = None,
    lines: str = "",
) -> dict:
    return {
        "path": path,
        "start": {"line": line},
        "check_id": check_id,
        "extra": {
            "severity": "WARNING",
            "message": message,
            "metavars": metavars,
            "lines": lines,
            "metadata": metadata or {"llm_audit": True},
        },
    }
