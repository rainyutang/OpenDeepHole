import asyncio
from pathlib import Path
from unittest.mock import patch

from backend.api import agent as agent_api
from backend.models import (
    AgentRemoteConfig,
    OpenCodePoolStatus,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    User,
)
from backend.store.sqlite import SqliteScanStore


def _usage_status(
    *,
    session_id: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    complete: bool = True,
) -> OpenCodePoolStatus:
    total = input_tokens + output_tokens
    return OpenCodePoolStatus(
        agent_session_id=session_id,
        updated_at="2026-07-27T00:00:00+00:00",
        token_usage={
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "reasoning_tokens": 0,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
            "total_tokens": total,
            "complete": complete,
            "by_model": [{
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "reasoning_tokens": 0,
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
                "total_tokens": total,
            }],
        },
    )


def _store(tmp_path: Path) -> SqliteScanStore:
    store = SqliteScanStore(tmp_path / "tokens.db")
    store.save_scan(
        ScanStatus(
            scan_id="scan-1",
            project_id="project-1",
            status=ScanItemStatus.AUDITING,
            progress=0,
            total_candidates=0,
            processed_candidates=0,
            vulnerabilities=[],
        ),
        ScanMeta(scan_items=[], created_at="2026-07-27T00:00:00+00:00"),
    )
    store.upsert_agent_record(
        agent_key="stable-agent",
        user_id="user-1",
        ip="10.0.0.8",
        machine_name="build-host",
        display_name="agent",
        agent_id="live-session",
        last_seen="2026-07-27T00:00:00+00:00",
        initial_config_json=AgentRemoteConfig().model_dump_json(),
    )
    return store


def test_token_snapshots_replace_same_session_and_sum_across_sessions(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = _usage_status(
        session_id="process-1",
        model="provider/model-a",
        input_tokens=10,
        output_tokens=5,
    )
    replacement = _usage_status(
        session_id="process-1",
        model="provider/model-a",
        input_tokens=12,
        output_tokens=7,
    )
    second = _usage_status(
        session_id="process-2",
        model="provider/model-b",
        input_tokens=3,
        output_tokens=2,
        complete=False,
    )

    for status in (first, replacement, second):
        store.upsert_scan_opencode_token_usage(
            scan_id="scan-1",
            agent_session_id=status.agent_session_id,
            status=status,
        )
        store.upsert_agent_opencode_token_usage(
            agent_key="stable-agent",
            user_id="user-1",
            agent_session_id=status.agent_session_id,
            status=status,
        )

    scan_usage = store.get_scan_opencode_token_usage("scan-1")
    agent_usage = store.get_agent_opencode_token_usage(
        agent_key="stable-agent",
        user_id="user-1",
    )
    assert scan_usage is not None
    assert agent_usage is not None
    assert scan_usage.total_tokens == agent_usage.total_tokens == 24
    assert scan_usage.input_tokens == 15
    assert scan_usage.output_tokens == 9
    assert scan_usage.complete is False
    assert {item.model: item.total_tokens for item in scan_usage.by_model} == {
        "provider/model-a": 19,
        "provider/model-b": 5,
    }


def test_scan_token_usage_is_deleted_with_scan(tmp_path: Path) -> None:
    store = _store(tmp_path)
    status = _usage_status(
        session_id="process-1",
        model="provider/model-a",
        input_tokens=4,
        output_tokens=1,
    )
    store.upsert_scan_opencode_token_usage(
        scan_id="scan-1",
        agent_session_id="process-1",
        status=status,
    )

    assert store.get_scan_opencode_token_usage("scan-1") is not None
    assert store.delete_scan("scan-1") is True
    assert store.get_scan_opencode_token_usage("scan-1") is None


def test_stable_agent_usage_endpoint_works_while_agent_is_offline(tmp_path: Path) -> None:
    store = _store(tmp_path)
    status = _usage_status(
        session_id="old-process",
        model="provider/model-a",
        input_tokens=6,
        output_tokens=2,
    )
    store.upsert_agent_opencode_token_usage(
        agent_key="stable-agent",
        user_id="user-1",
        agent_session_id="old-process",
        status=status,
    )

    with patch("backend.api.agent.get_scan_store", return_value=store):
        result = asyncio.run(
            agent_api.get_stable_agent_opencode_usage(
                "stable-agent",
                current_user=User(user_id="user-1", username="owner", role="user"),
            )
        )

    assert result is not None
    assert result.total_tokens == 8
    assert result.by_model[0].model == "provider/model-a"
