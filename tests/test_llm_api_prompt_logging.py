from backend.opencode import llm_api_runner


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
