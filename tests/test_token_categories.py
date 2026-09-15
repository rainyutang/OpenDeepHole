import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from task_agent.token_categories import token_category
from task_agent.token_usage import (
    TokenCounters, attribute_token_usage, merge_token_usages, token_usage_from_dict, token_usage_from_models,
)


@pytest.mark.parametrize("metadata,expected", [
    ({"task_type": "threat_analysis"}, "threat_analysis"),
    ({"task_type": "fp_review", "mining_engine_id": "multi_version"}, "fp_review"),
    ({"task_type": "vulnerability_validation", "mining_engine_id": "static_candidate"}, "vulnerability_validation"),
    ({"task_type": "threat_analysis", "mining_engine_id": "multi_version"}, "multi_version"),
    ({"task_type": "vulnerability_mining", "mining_engine_id": "static_candidate"}, "static_candidate"),
    ({"task_type": "vulnerability_mining", "mining_engine_id": "threat_audit"}, "threat_audit"),
    ({"task_type": "vulnerability_mining", "mining_engine_id": "threat_pattern_audit"}, "threat_pattern_audit"),
    ({"task_type": "vulnerability_mining", "mining_engine_id": "custom"}, "custom"),
    ({"task_type": "vulnerability_mining", "mining_engine_id": "multi_version", "token_category": "vulnerability_dedup"}, "vulnerability_dedup"),
    ({"task_type": "vulnerability_mining", "task_name": "candidate-audit-test-1"}, "uncategorized"),
])
def test_live_category_uses_business_ownership(metadata, expected):
    assert token_category(metadata)[0] == expected


@pytest.mark.parametrize("metadata,expected", [
    ({"task_type": "audit"}, "static_candidate"),
    ({"task_type": "project_audit"}, "static_candidate"),
    ({"task_type": "vulnerability_mining", "task_name": "project-audit-s-0"}, "static_candidate"),
    ({"task_type": "vulnerability_mining", "task_name": "threat-pattern-audit-s-0"}, "threat_pattern_audit"),
    ({"task_type": "vulnerability_mining", "task_name": "threat-pattern-audit-s-0", "scan_mode": "multi_version"}, "multi_version"),
    ({"task_type": "vulnerability_mining", "task_name": "vulnerability-dedup-s-0", "scan_mode": "multi_version"}, "vulnerability_dedup"),
    ({"task_type": "vulnerability_mining", "task_name": "some-candidate-audit-s-0"}, "uncategorized"),
])
def test_historical_category_uses_known_names_only(metadata, expected):
    assert token_category(metadata, legacy=True)[0] == expected


def test_category_aggregation_is_orthogonal_to_models_and_preserves_legacy_balance():
    prompt = token_usage_from_models({"actual-model": TokenCounters(10, 5, 2, 4, 1)})
    analysis = attribute_token_usage(prompt, "threat_analysis")
    review = attribute_token_usage(prompt, "fp_review")
    merged = merge_token_usages([analysis, review.as_dict(), prompt])
    assert merged.counters.total_tokens == 66
    assert merged.by_model[0].counters.total_tokens == 66
    assert {item.category: item.counters.total_tokens for item in merged.by_category} == {
        "threat_analysis": 22, "fp_review": 22, "uncategorized": 22,
    }
    assert token_usage_from_dict(merged.as_dict()) == merged


def test_partial_collection_marks_only_its_category_incomplete():
    good = token_usage_from_models({"model": TokenCounters(3)})
    bad = token_usage_from_models({"model": TokenCounters(4)}, complete=False)
    merged = merge_token_usages([attribute_token_usage(good, "threat_analysis"), attribute_token_usage(bad, "fp_review")])
    assert not merged.complete
    assert {item.category: item.complete for item in merged.by_category} == {"threat_analysis": True, "fp_review": False}


def test_concurrent_engine_contexts_are_isolated_and_restore_parent_metadata():
    from deephole_client.vulnerability_mining.runtime import run_mining_engine
    from task_agent.task_service import bind_opencode_execution_context, _snapshot_execution_context

    async def run():
        seen = []

        async def engine_run(**kwargs):
            await asyncio.sleep(0)
            metadata = _snapshot_execution_context().task_metadata
            seen.append(token_category({**metadata, "task_type": "vulnerability_mining"})[0])
            return {"status": "success"}

        engines = [SimpleNamespace(manifest=SimpleNamespace(engine_id=key, label=key), run=engine_run)
                   for key in ("static_candidate", "threat_audit")]
        with bind_opencode_execution_context(task_metadata={"test_parent": True}):
            with patch("deephole_client.vulnerability_mining.runtime.normalize_mining_engine_output", side_effect=lambda engine, output: output):
                await asyncio.gather(*(run_mining_engine(engine) for engine in engines))
            assert "mining_engine_id" not in _snapshot_execution_context().task_metadata
        assert sorted(seen) == ["static_candidate", "threat_audit"]

    asyncio.run(run())
