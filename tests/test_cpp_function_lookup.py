from pathlib import Path

from code_parser import CodeDatabase
from code_parser.cpp_analyzer import CppAnalyzer


def _index_source(tmp_path: Path, source: str) -> CodeDatabase:
    db = CodeDatabase(tmp_path / "code_index.db")
    CppAnalyzer(db).analyze_file("sample.cpp", source.encode("utf-8"))
    db.commit()
    return db


def test_cpp_qualified_member_lookup_does_not_match_other_class_send(tmp_path: Path) -> None:
    db = _index_source(
        tmp_path,
        """
class ru_emu_dpdk_transmitter { public: int send(int mode); };
class other_transmitter { public: int send(int mode); };

int ru_emu_dpdk_transmitter::send(int mode) {
    return mode;
}

int other_transmitter::send(int mode) {
    return mode + 1;
}
""",
    )
    try:
        rows = db.get_functions_by_name("ru_emu_dpdk_transmitter::send")

        assert len(rows) == 1
        assert rows[0]["name"] == "ru_emu_dpdk_transmitter::send"
        assert "other_transmitter::send" not in rows[0]["body"]
    finally:
        db.close()


def test_cpp_inline_member_function_is_indexed_by_short_name(tmp_path: Path) -> None:
    db = _index_source(
        tmp_path,
        """
class transmitter {
public:
    int send(int mode) {
        return mode;
    }
};
""",
    )
    try:
        rows = db.get_functions_by_name("send")

        assert len(rows) == 1
        assert rows[0]["name"] == "send"
        assert "int send(int mode)" in rows[0]["body"]
    finally:
        db.close()


def test_qualified_lookup_supports_old_short_name_index_when_signature_matches(tmp_path: Path) -> None:
    db = CodeDatabase(tmp_path / "code_index.db")
    file_id = db.get_or_create_file("sample.cpp")
    db.insert_function(
        name="send",
        signature="ru_emu_dpdk_transmitter::send(int mode)",
        return_type="int",
        file_id=file_id,
        start_line=10,
        end_line=12,
        is_static=False,
        linkage="extern",
        body="int ru_emu_dpdk_transmitter::send(int mode) {\n    return mode;\n}",
    )
    db.insert_function(
        name="send",
        signature="other_transmitter::send(int mode)",
        return_type="int",
        file_id=file_id,
        start_line=20,
        end_line=22,
        is_static=False,
        linkage="extern",
        body="int other_transmitter::send(int mode) {\n    return mode + 1;\n}",
    )
    db.commit()
    try:
        rows = db.get_functions_by_name("ru_emu_dpdk_transmitter::send")

        assert len(rows) == 1
        assert rows[0]["start_line"] == 10
        assert "ru_emu_dpdk_transmitter::send" in rows[0]["signature"]
    finally:
        db.close()
