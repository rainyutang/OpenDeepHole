from pathlib import Path

import pytest

from deephole_client.code_graph_build import path_access
from deephole_client.code_graph_build.source_filter import iter_source_files


@pytest.mark.parametrize("normal,extended", [
    (r"D:\source\file.h", r"\\?\D:\source\file.h"),
    (r"\\server\share\source\file.h", r"\\?\UNC\server\share\source\file.h"),
    (r"D:\source\nested\..\file.h", r"\\?\D:\source\file.h"),
    ("D:/source/file.h", r"\\?\D:\source\file.h"),
])
def test_extended_windows_paths_preserve_file_identity(normal, extended):
    assert path_access._extended_windows_path(normal) == extended
    assert path_access._extended_windows_path(extended) == extended
    assert path_access._extended_windows_path(path_access._display_path(extended)) == extended


def test_windows_tool_length_counts_utf16_units(monkeypatch):
    monkeypatch.setattr(path_access, "is_windows", lambda: True)
    short = "D:\\" + "x" * 255
    assert not path_access.needs_short_tool_path(short)
    assert path_access.needs_short_tool_path(short + "xx")
    assert path_access.needs_short_tool_path(short + "😀")
    assert not path_access.needs_short_tool_path("\\\\?\\" + short)


@pytest.mark.skipif(path_access.is_windows(), reason="POSIX paths")
def test_posix_paths_are_not_rewritten(tmp_path):
    assert path_access.io_path(tmp_path) == tmp_path
    assert not path_access.needs_short_tool_path(tmp_path / ("x" * 300))
    assert path_access.resolved_path(tmp_path / "a" / "..") == tmp_path


@pytest.mark.skipif(not path_access.is_windows(), reason="Requires actual Windows filesystem")
def test_windows_long_source_is_discovered_and_read(tmp_path):
    target = tmp_path
    for _ in range(7):
        target /= "deep_oh_modules_中文_" + "x" * 28
    target /= "log print_default.h"
    expected = "int long_path_function(void) { return 1; }\n"
    path_access.io_path(target.parent).mkdir(parents=True)
    path_access.io_path(target).write_text(expected, encoding="utf-8")
    try:
        assert path_access.needs_short_tool_path(target)
        assert list(iter_source_files(tmp_path, {".h"})) == [target]
        assert path_access.io_path(target).read_text(encoding="utf-8") == expected
        assert path_access.resolved_path(target) == target.resolve()
        assert not str(path_access.display_path(path_access.io_path(target))).startswith("\\\\?\\")
    finally:
        path_access.io_path(target).unlink()
        parent = target.parent
        while parent != tmp_path:
            path_access.io_path(parent).rmdir()
            parent = parent.parent
