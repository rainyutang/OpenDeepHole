import asyncio
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from backend.models import Candidate
from backend.opencode import llm_api_runner
from backend.opencode.llm_api_runner import LLMApiUnavailableError
from backend.opencode.runner import run_audit, run_audit_batch


def _candidate(line: int = 12) -> Candidate:
    return Candidate(
        file="sample.c",
        line=line,
        function="leaky",
        description="candidate issue",
        vuln_type="memleak",
    )


def test_api_checker_uses_api_even_when_legacy_global_switch_is_false(tmp_path: Path) -> None:
    candidate = _candidate()
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = object()

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.opencode.llm_api_runner.ensure_llm_api_available", new=AsyncMock(return_value=None)),
        patch("backend.opencode.llm_api_runner.run_audit_via_api", new=AsyncMock(return_value=expected)) as api_audit,
    ):
        result = asyncio.run(run_audit(tmp_path, candidate, "scan-1"))

    assert result is expected
    api_audit.assert_awaited_once()


def test_api_checker_falls_back_to_opencode_when_api_check_fails(tmp_path: Path) -> None:
    candidate = _candidate()
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = object()

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch(
            "backend.opencode.llm_api_runner.ensure_llm_api_available",
            new=AsyncMock(side_effect=LLMApiUnavailableError("bad api")),
        ),
        patch("backend.opencode.llm_api_runner.run_audit_via_api", new=AsyncMock()) as api_audit,
        patch("backend.opencode.runner._run_audit_via_opencode", new=AsyncMock(return_value=expected)) as opencode_audit,
    ):
        result = asyncio.run(run_audit(tmp_path, candidate, "scan-1"))

    assert result is expected
    api_audit.assert_not_awaited()
    opencode_audit.assert_awaited_once()


def test_api_checker_falls_back_to_opencode_when_api_call_fails(tmp_path: Path) -> None:
    candidate = _candidate()
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = object()

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.opencode.llm_api_runner.ensure_llm_api_available", new=AsyncMock(return_value=None)),
        patch(
            "backend.opencode.llm_api_runner.run_audit_via_api",
            new=AsyncMock(side_effect=LLMApiUnavailableError("call failed")),
        ) as api_audit,
        patch("backend.opencode.runner._run_audit_via_opencode", new=AsyncMock(return_value=expected)) as opencode_audit,
    ):
        result = asyncio.run(run_audit(tmp_path, candidate, "scan-1"))

    assert result is expected
    api_audit.assert_awaited_once()
    opencode_audit.assert_awaited_once()


def test_api_checker_batch_uses_api_even_when_legacy_global_switch_is_false(tmp_path: Path) -> None:
    candidates = [_candidate(12), _candidate(18)]
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = [object(), object()]

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.opencode.llm_api_runner.ensure_llm_api_available", new=AsyncMock(return_value=None)),
        patch("backend.opencode.llm_api_runner.run_batch_audit_via_api", new=AsyncMock(return_value=expected)) as api_audit,
    ):
        result = asyncio.run(run_audit_batch(tmp_path, candidates, "scan-1"))

    assert result is expected
    api_audit.assert_awaited_once()


def test_api_checker_batch_falls_back_to_opencode_when_api_check_fails(tmp_path: Path) -> None:
    candidates = [_candidate(12), _candidate(18)]
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = [object(), object()]

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch(
            "backend.opencode.llm_api_runner.ensure_llm_api_available",
            new=AsyncMock(side_effect=LLMApiUnavailableError("bad api")),
        ),
        patch("backend.opencode.llm_api_runner.run_batch_audit_via_api", new=AsyncMock()) as api_audit,
        patch("backend.opencode.runner._run_audit_via_opencode", new=AsyncMock(side_effect=expected)) as opencode_audit,
    ):
        result = asyncio.run(run_audit_batch(tmp_path, candidates, "scan-1"))

    assert result == expected
    api_audit.assert_not_awaited()
    assert opencode_audit.await_count == 2


def test_api_checker_batch_falls_back_to_opencode_when_api_call_fails(tmp_path: Path) -> None:
    candidates = [_candidate(12), _candidate(18)]
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = [object(), object()]

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.opencode.llm_api_runner.ensure_llm_api_available", new=AsyncMock(return_value=None)),
        patch(
            "backend.opencode.llm_api_runner.run_batch_audit_via_api",
            new=AsyncMock(side_effect=LLMApiUnavailableError("call failed")),
        ) as api_audit,
        patch("backend.opencode.runner._run_audit_via_opencode", new=AsyncMock(side_effect=expected)) as opencode_audit,
    ):
        result = asyncio.run(run_audit_batch(tmp_path, candidates, "scan-1"))

    assert result == expected
    api_audit.assert_awaited_once()
    assert opencode_audit.await_count == 2


def test_llm_api_health_check_uses_minimal_request_and_caches(monkeypatch) -> None:
    client_kwargs = []
    requests = []

    class FakeCompletions:
        def create(self, **kwargs):
            requests.append(kwargs)
            return object()

    class FakeOpenAI:
        def __init__(self, **kwargs):
            client_kwargs.append(kwargs)
            self.chat = SimpleNamespace(completions=FakeCompletions())

    config = SimpleNamespace(
        llm_api=SimpleNamespace(
            base_url="https://example.test/v1",
            api_key="secret",
            model="fake-model",
            timeout=30,
        )
    )

    openai_module = ModuleType("openai")
    openai_module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", openai_module)
    llm_api_runner._api_health_cache.clear()

    with patch("backend.opencode.llm_api_runner.get_config", return_value=config):
        asyncio.run(llm_api_runner.ensure_llm_api_available())
        asyncio.run(llm_api_runner.ensure_llm_api_available())

    assert len(client_kwargs) == 1
    assert client_kwargs[0]["base_url"] == "https://example.test/v1"
    assert client_kwargs[0]["api_key"] == "secret"
    assert client_kwargs[0]["timeout"] == 10.0
    assert len(requests) == 1
    assert requests[0]["model"] == "fake-model"
    assert requests[0]["max_tokens"] == 1


def test_llm_api_health_check_failure_is_cached(monkeypatch) -> None:
    requests = []

    class FakeCompletions:
        def create(self, **kwargs):
            requests.append(kwargs)
            raise RuntimeError("unauthorized")

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(completions=FakeCompletions())

    config = SimpleNamespace(
        llm_api=SimpleNamespace(
            base_url="https://example.test/v1",
            api_key="bad",
            model="fake-model",
            timeout=3,
        )
    )

    openai_module = ModuleType("openai")
    openai_module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", openai_module)
    llm_api_runner._api_health_cache.clear()

    with patch("backend.opencode.llm_api_runner.get_config", return_value=config):
        with pytest.raises(LLMApiUnavailableError, match="unauthorized"):
            asyncio.run(llm_api_runner.ensure_llm_api_available())
        with pytest.raises(LLMApiUnavailableError, match="unauthorized"):
            asyncio.run(llm_api_runner.ensure_llm_api_available())

    assert len(requests) == 1
