import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from backend.models import Candidate
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
        patch("backend.opencode.llm_api_runner.run_audit_via_api", new=AsyncMock(return_value=expected)) as api_audit,
    ):
        result = asyncio.run(run_audit(tmp_path, candidate, "scan-1"))

    assert result is expected
    api_audit.assert_awaited_once()


def test_api_checker_batch_uses_api_even_when_legacy_global_switch_is_false(tmp_path: Path) -> None:
    candidates = [_candidate(12), _candidate(18)]
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = [object(), object()]

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.opencode.llm_api_runner.run_batch_audit_via_api", new=AsyncMock(return_value=expected)) as api_audit,
    ):
        result = asyncio.run(run_audit_batch(tmp_path, candidates, "scan-1"))

    assert result is expected
    api_audit.assert_awaited_once()
