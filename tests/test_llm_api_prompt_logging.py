from pathlib import Path

from backend.models import Candidate
from backend.opencode import llm_api_runner
from code_parser import CodeDatabase


def _write_code_index(project_dir: Path) -> None:
    db = CodeDatabase(project_dir / "code_index.db")
    file_id = db.get_or_create_file("sample.c")
    db.insert_function(
        name="leaky",
        signature="leaky(int mode)",
        return_type="void",
        file_id=file_id,
        start_line=10,
        end_line=17,
        is_static=False,
        linkage="extern",
        body=(
            "void leaky(int mode) {\n"
            "    char *p = malloc(8);\n"
            "    if (mode) {\n"
            "        return;\n"
            "    }\n"
            "    cleanup(p);\n"
            "}"
        ),
    )
    db.insert_function(
        name="cleanup",
        signature="cleanup(char *p)",
        return_type="void",
        file_id=file_id,
        start_line=20,
        end_line=22,
        is_static=False,
        linkage="extern",
        body=(
            "void cleanup(char *p) {\n"
            "    free(p);\n"
            "}"
        ),
    )
    db.commit()
    db.checkpoint()
    db.close()


def test_emit_initial_api_prompt_outputs_complete_single_candidate_messages() -> None:
    outputs: list[str] = []
    messages = [
        {"role": "system", "content": "system prompt\nline 2"},
        {"role": "user", "content": "unique single candidate detail\nline 2"},
    ]

    llm_api_runner._emit_initial_api_prompt(outputs.append, messages)

    assert len(outputs) == 1
    logged = "\n".join(outputs)
    assert "[API] 初始提示词" in logged
    assert "--- system ---" in logged
    assert "--- user ---" in logged
    assert "system prompt\nline 2" in logged
    assert "unique single candidate detail" in logged


def test_emit_initial_api_prompt_outputs_complete_batch_messages() -> None:
    outputs: list[str] = []
    messages = [
        {"role": "system", "content": "batch system prompt"},
        {
            "role": "user",
            "content": (
                "候选漏洞点（共 2 个）\n"
                "first batch candidate detail\n"
                "second batch candidate detail"
            ),
        },
    ]

    llm_api_runner._emit_initial_api_prompt(outputs.append, messages)

    logged = "\n".join(outputs)
    assert "[API] 初始提示词" in logged
    assert "--- system ---" in logged
    assert "--- user ---" in logged
    assert "候选漏洞点（共 2 个）" in logged
    assert "first batch candidate detail" in logged
    assert "second batch candidate detail" in logged
    assert "secret-api-key" not in logged


def test_user_prompt_uses_agent_project_dir_code_index(tmp_path, monkeypatch) -> None:
    _write_code_index(tmp_path)
    monkeypatch.setenv("AGENT_PROJECT_DIR", str(tmp_path))

    candidate = Candidate(
        file="sample.c",
        line=13,
        function="leaky",
        description="candidate issue",
        vuln_type="memleak",
        related_functions=["cleanup"],
    )

    prompt = llm_api_runner._build_user_prompt(candidate, "scan-id-without-index")

    assert "代码索引不可用" not in prompt
    assert "## 函数源码 (sample.c:10)" in prompt
    assert "  10 | void leaky(int mode) {" in prompt
    assert "## 相关函数源码" in prompt
    assert "  20 | void cleanup(char *p) {" in prompt


def test_batch_user_prompt_uses_agent_project_dir_code_index(tmp_path, monkeypatch) -> None:
    _write_code_index(tmp_path)
    monkeypatch.setenv("AGENT_PROJECT_DIR", str(tmp_path))

    candidates = [
        Candidate(
            file="sample.c",
            line=13,
            function="leaky",
            description="first leak candidate",
            vuln_type="memleak",
        ),
        Candidate(
            file="sample.c",
            line=15,
            function="leaky",
            description="second leak candidate",
            vuln_type="memleak",
        ),
    ]

    prompt = llm_api_runner._build_batch_user_prompt(candidates, "scan-id-without-index")

    assert "代码索引不可用" not in prompt
    assert "## 函数源码 (sample.c:10)" in prompt
    assert "  10 | void leaky(int mode) {" in prompt
    assert "候选漏洞点（共 2 个）" in prompt
    assert "first leak candidate" in prompt
    assert "second leak candidate" in prompt
