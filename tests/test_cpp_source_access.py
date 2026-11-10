"""Source I/O failures and Ctags path compatibility must not hide coverage loss."""

import json
import subprocess
from pathlib import Path

import pytest

from deephole_client.code_graph_build import cpp_analyzer
from deephole_client.code_graph_build.code_database import CodeDatabase
from deephole_client.code_graph_build.cpp_analyzer import CodeIndexToolError, CppAnalyzer


@pytest.fixture
def indexer(tmp_path, monkeypatch):
    database = CodeDatabase(tmp_path / "code_index.db")
    analyzer = CppAnalyzer(database)
    monkeypatch.setattr(analyzer, "_ensure_tools_available", lambda: None)
    warnings = []
    analyzer.on_warning = lambda path, reason: warnings.append((path, reason))
    try:
        yield analyzer, database, warnings
    finally:
        database.close()


def _tag(path, name="good", line=1):
    return {
        "_type": "tag", "path": path, "name": name, "kind": "function",
        "line": line, "end": line, "signature": "(void)",
    }


def _completed(cmd, tags=(), stderr=""):
    return subprocess.CompletedProcess(
        cmd, 0, stdout="\n".join(json.dumps(tag) for tag in tags), stderr=stderr,
    )


@pytest.mark.parametrize("failure", ["disappeared", "broken_link", "permission"])
def test_unreadable_source_is_reported_and_excluded(tmp_path, monkeypatch, indexer, failure):
    analyzer, database, warnings = indexer
    good = tmp_path / "good.c"
    good.write_text("int good(void) { return 0; }\n", encoding="utf-8")
    bad = tmp_path / "bad.h"
    if failure == "broken_link":
        try:
            bad.symlink_to(tmp_path / "missing.h")
        except OSError:
            pytest.skip("Creating symlinks requires platform privileges")
    else:
        bad.write_text("int missing(void);\n", encoding="utf-8")
    if failure == "disappeared":
        collect = analyzer._collect_source_files

        def collect_then_delete(root):
            files = collect(root)
            bad.unlink()
            return files

        monkeypatch.setattr(analyzer, "_collect_source_files", collect_then_delete)
    if failure == "permission":
        read_text = Path.read_text

        def deny_read(path, *args, **kwargs):
            if path.name == bad.name:
                raise PermissionError(13, "Permission denied", str(path))
            return read_text(path, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", deny_read)
    seen = []

    def ctags(root, files, work):
        assert analyzer._source_texts == {}
        seen.extend(path.name for path in files)
        return [_tag("good.c")]

    monkeypatch.setattr(analyzer, "_run_ctags_json", ctags)
    progress = []
    analyzer.analyze_directory(tmp_path, on_progress=lambda n, total: progress.append((n, total)))
    assert seen == ["good.c"]
    assert database.get_index_stats()["files"] == 1
    assert database.get_functions_by_name("good")[0]["file_path"] == "good.c"
    assert analyzer.skipped_files == {"bad.h"}
    assert analyzer.coverage_complete is False
    assert warnings[0][0] == "bad.h"
    assert progress[-1] == (2, 2)


def test_all_discovered_sources_unreadable_is_error(tmp_path, monkeypatch, indexer):
    analyzer, database, warnings = indexer
    monkeypatch.setattr(analyzer, "_collect_source_files", lambda root: [root / "missing.h"])
    with pytest.raises(CodeIndexToolError, match="均无法读取"):
        analyzer.analyze_directory(tmp_path)
    assert database.get_index_stats()["files"] == 0
    assert analyzer.skipped_files == {"missing.h"}
    assert warnings


def test_empty_source_directory_remains_successful(tmp_path, indexer):
    analyzer, database, warnings = indexer
    analyzer.analyze_directory(tmp_path)
    assert database.get_index_stats()["files"] == 0
    assert analyzer.coverage_complete is True
    assert not warnings


def test_walk_failure_marks_coverage_incomplete(tmp_path, monkeypatch, indexer):
    analyzer, database, warnings = indexer
    good = tmp_path / "good.c"
    good.write_text("int good(void) { return 0; }\n", encoding="utf-8")

    def walk(root, extensions, *, on_error, **kwargs):
        on_error(PermissionError(13, "Permission denied", str(root / "unreadable")))
        yield good

    monkeypatch.setattr(cpp_analyzer, "iter_source_files", walk)
    monkeypatch.setattr(analyzer, "_run_ctags_json", lambda *args: [_tag("good.c")])
    analyzer.analyze_directory(tmp_path)
    assert database.get_index_stats()["files"] == 1
    assert analyzer.coverage_complete is False
    assert analyzer.skipped_files == set()
    assert warnings[0][0].endswith("unreadable")


def test_zero_exit_ctags_input_error_excludes_failed_file(tmp_path, monkeypatch, indexer):
    analyzer, database, warnings = indexer
    for name in ("good", "gone"):
        (tmp_path / f"{name}.c").write_text(f"int {name}(void) {{ return 0; }}\n", encoding="utf-8")
    monkeypatch.setattr(
        subprocess, "run", lambda cmd, **kwargs: _completed(
            cmd, [_tag("good.c"), _tag("gone.c", "gone")],
            'ctags: Warning: cannot open input file "gone.c" : No such file or directory\n',
        ),
    )
    analyzer.analyze_directory(tmp_path)
    assert database.get_index_stats()["files"] == 1
    assert database.get_functions_by_name("good")
    assert not database.get_functions_by_name("gone")
    assert analyzer.skipped_files == {"gone.c"}
    assert analyzer.coverage_complete is False
    assert warnings[0][0] == "gone.c"


@pytest.mark.parametrize("fallback", [False, True])
def test_long_source_snapshot_preserves_original_path_and_text(tmp_path, monkeypatch, indexer, fallback):
    analyzer, database, warnings = indexer
    source = tmp_path / "oh_modules" / "deep" / "original.hpp"
    source.parent.mkdir(parents=True)
    raw = "\n\nint long_function(void) { return 7; }\n// form feed stays here\f\n"
    source.write_text(raw, encoding="utf-8")
    (tmp_path / "good.c").write_text("int good(void) { return 0; }\n", encoding="utf-8")
    monkeypatch.setattr(
        cpp_analyzer, "needs_short_tool_path",
        lambda path: (tmp_path in Path(path).parents) if fallback else "oh_modules" in Path(path).parts,
    )
    workdirs = []

    def ctags(cmd, **kwargs):
        root = Path(kwargs["cwd"])
        file_list = root / cmd[cmd.index("-L") + 1]
        workdirs.append(file_list.parent)
        assert (root == tmp_path) is not fallback
        inputs = file_list.read_text(encoding="utf-8").splitlines()
        assert len(inputs) == 2
        aliases = [name for name in inputs if name.endswith(".hpp")]
        assert len(aliases) == 1
        alias = aliases[0]
        assert "oh_modules" not in alias
        assert (root / alias).read_text(encoding="utf-8") == raw
        # The original file may disappear after Python has read it. Ctags must
        # consume the already-read snapshot instead of reopening that file.
        source.unlink()
        good_path = next(name for name in inputs if name.endswith(".c"))
        output_path = str(root / alias) if fallback else alias
        return _completed(cmd, [_tag(output_path, "long_function", 3), _tag(good_path)])

    monkeypatch.setattr(subprocess, "run", ctags)
    analyzer.analyze_directory(tmp_path)
    row = database.get_functions_by_name("long_function")[0]
    assert row["file_path"] == "oh_modules/deep/original.hpp"
    assert row["start_line"] == 3
    assert "return 7" in row["body"]
    assert database.get_index_stats()["files"] == 2
    assert analyzer.coverage_complete is True
    assert analyzer.skipped_files == set()
    assert not warnings
    assert all(not directory.exists() for directory in workdirs)


def test_ctags_cannot_read_long_path_snapshot_is_error(tmp_path, monkeypatch, indexer):
    analyzer, database, warnings = indexer
    source = tmp_path / "oh_modules" / "long.h"
    source.parent.mkdir()
    source.write_text("int good(void) { return 0; }\n", encoding="utf-8")
    monkeypatch.setattr(cpp_analyzer, "needs_short_tool_path", lambda p: "oh_modules" in Path(p).parts)
    workdirs = []

    def ctags(cmd, **kwargs):
        file_list = Path(kwargs["cwd"]) / cmd[cmd.index("-L") + 1]
        workdirs.append(file_list.parent)
        alias = file_list.read_text(encoding="utf-8").strip()
        return _completed(cmd, stderr=f'ctags: Warning: cannot open input file "{alias}" : error')

    monkeypatch.setattr(subprocess, "run", ctags)
    with pytest.raises(CodeIndexToolError, match="cannot open input file"):
        analyzer.analyze_directory(tmp_path)
    assert analyzer.skipped_files == set()
    assert database.get_index_stats()["files"] == 0
    assert not warnings
    assert all(not directory.exists() for directory in workdirs)


def test_no_short_temporary_path_is_explicit_error(tmp_path, monkeypatch, indexer):
    analyzer, database, _ = indexer
    (tmp_path / "good.c").write_text("int good(void) { return 0; }\n", encoding="utf-8")
    monkeypatch.setattr(cpp_analyzer, "needs_short_tool_path", lambda p: True)
    with pytest.raises(CodeIndexToolError, match="足够短"):
        analyzer.analyze_directory(tmp_path)
    assert database.get_index_stats()["files"] == 0
    assert analyzer.skipped_files == set()


def test_ctags_rejects_every_input_without_publishing_empty_index(tmp_path, monkeypatch, indexer):
    analyzer, database, warnings = indexer
    (tmp_path / "gone.c").write_text("int gone(void) { return 0; }\n", encoding="utf-8")
    monkeypatch.setattr(
        subprocess, "run", lambda cmd, **kwargs: _completed(
            cmd, stderr='ctags: Warning: cannot open input file "gone.c" : error',
        ),
    )
    with pytest.raises(CodeIndexToolError, match="均无法读取"):
        analyzer.analyze_directory(tmp_path)
    assert database.get_index_stats()["files"] == 0
    assert analyzer.skipped_files == {"gone.c"}
    assert analyzer.coverage_complete is False
    assert warnings


def test_unmapped_ctags_input_error_is_not_silently_successful(tmp_path, monkeypatch, indexer):
    analyzer, database, _ = indexer
    (tmp_path / "good.c").write_text("int good(void) { return 0; }\n", encoding="utf-8")
    monkeypatch.setattr(
        subprocess, "run", lambda cmd, **kwargs: _completed(
            cmd, stderr='ctags: Warning: cannot open input file "unknown.c" : error',
        ),
    )
    with pytest.raises(CodeIndexToolError, match="cannot open input file"):
        analyzer.analyze_directory(tmp_path)
    assert database.get_index_stats()["files"] == 0
