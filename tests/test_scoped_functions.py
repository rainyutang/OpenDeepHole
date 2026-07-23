from pathlib import Path

from deephole_client.static_analysis.base import (
    in_scope,
    scope_prefix,
    scoped_functions,
)
from deephole_client.code_graph_build.code_database import CodeDatabase


def _insert_function(db: CodeDatabase, file_path: str, name: str, line: int) -> None:
    file_id = db.get_or_create_file(file_path)
    db.insert_function(
        name=name,
        signature=f"void {name}(void)",
        return_type="void",
        file_id=file_id,
        start_line=line,
        end_line=line + 2,
        is_static=False,
        linkage="external",
        body=f"void {name}(void) {{}}\n",
    )
    db.commit()


def test_get_functions_by_path_prefix_matches_directory_boundaries(tmp_path: Path) -> None:
    db = CodeDatabase(tmp_path / "code_index.db")
    try:
        _insert_function(db, "src/a.c", "a", 1)
        _insert_function(db, "src/nested/b.c", "b", 10)
        _insert_function(db, "src_extra/c.c", "c", 20)

        rows = db.get_functions_by_path_prefix("src")

        assert [row["name"] for row in rows] == ["a", "b"]
        assert [row["file_path"] for row in rows] == ["src/a.c", "src/nested/b.c"]
    finally:
        db.close()


def test_scoped_functions_uses_code_index_parent_as_project_root(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    db = CodeDatabase(project / "code_index.db")
    try:
        _insert_function(db, "module/a.c", "a", 1)
        _insert_function(db, "other/b.c", "b", 10)

        assert scope_prefix(db, project / "module") == "module"
        rows = scoped_functions(db, project / "module")

        assert [row["name"] for row in rows] == ["a"]
    finally:
        db.close()


def test_scope_helpers_keep_fake_db_compatible() -> None:
    class FakeDb:
        def get_all_functions(self):
            return [{"file_path": "src/a.c", "name": "a"}]

    assert scope_prefix(FakeDb(), Path("src")) is None
    assert scoped_functions(FakeDb(), Path("src")) == [{"file_path": "src/a.c", "name": "a"}]
    assert in_scope("src/a.c", "src")
    assert not in_scope("src_extra/a.c", "src")
