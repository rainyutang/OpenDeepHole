from types import SimpleNamespace

from deephole_client import scanner
from deephole_client.scan_modes import (
    BUILTIN_PROFILE_ENGINE_IDS,
    THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS,
)


def test_iterative_engine_is_opt_in_for_legacy_agent_callers(monkeypatch):
    manifests = [SimpleNamespace(engine_id=name, label=name) for name in (
        "static_candidate", "threat_pattern_audit", "threat_pattern_iterative_audit",
    )]
    monkeypatch.setattr(scanner, "load_mining_engines", lambda: SimpleNamespace(manifests=lambda: manifests))
    _, defaults = scanner._resolve_mining_engines(raw_selections=None, threat_only=False)
    assert [item.engine_id for item in defaults] == ["static_candidate", "threat_pattern_audit"]
    _, explicit = scanner._resolve_mining_engines(
        raw_selections=[{"engine_id": "threat_pattern_iterative_audit", "engine_label": "iterative"}], threat_only=False,
    )
    assert explicit[0].engine_id == "threat_pattern_iterative_audit"
    assert explicit[0].enabled
    assert BUILTIN_PROFILE_ENGINE_IDS == ("static_candidate", "threat_pattern_audit")
    assert explicit[0].engine_id in THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS
