from pathlib import Path

from checkers.memleak.analyzer import Analyzer


def _write_source(tmp_path: Path, content: str) -> None:
    (tmp_path / "sample.c").write_text(content, encoding="utf-8")


def test_memleak_candidates_are_grouped_by_function(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
void grouped(int mode) {
    char *p = malloc(8);
    char *q = malloc(16);
    if (mode == 1) {
        return;
    }
    if (mode == 2) {
        return;
    }
    release_buffer(p);
    destroy_buffer(q);
}
""",
    )

    candidates = list(Analyzer().find_candidates(tmp_path))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.file == "sample.c"
    assert candidate.function == "grouped"
    assert candidate.vuln_type == "memleak"
    assert candidate.description.count("疑似内存泄漏点") == 1
    assert "发现 2 个疑似内存泄漏点" in candidate.description
    assert "1. 第" in candidate.description
    assert "2. 第" in candidate.description
    assert "release_buffer" in candidate.related_functions
    assert "destroy_buffer" in candidate.related_functions


def test_memleak_candidates_keep_different_functions_separate(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
void first(int flag) {
    char *p = malloc(8);
    if (flag) {
        return;
    }
    free(p);
}

void second(int flag) {
    char *q = malloc(16);
    if (flag) {
        return;
    }
    free(q);
}
""",
    )

    candidates = list(Analyzer().find_candidates(tmp_path))

    assert len(candidates) == 2
    assert [candidate.function for candidate in candidates] == ["first", "second"]
    assert all("发现 1 个疑似内存泄漏点" in c.description for c in candidates)
