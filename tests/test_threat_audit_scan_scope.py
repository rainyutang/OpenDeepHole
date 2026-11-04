import pytest

from deephole_client.scan_paths import resolve_scan_scope
from deephole_client.vulnerability_mining.engines.threat_audit.runner import _tasks, _threat_prompt, _scope_vulnerabilities


def test_legacy_threat_tasks_intersect_module_paths_and_never_fallback_after_filtering(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    selected = source / "selected.c"
    selected.write_text("int selected;\n")
    other = source / "other.c"
    other.write_text("int other;\n")
    scope = resolve_scan_scope(tmp_path, code_scan_paths=[selected])
    tree = {"attack_trees": [{
        "tree_id": "tree", "value_asset": {"资产名": "data"},
        "nodes": [
            {"node_id": "leaf", "node_type": "叶子节点", "node_name": "module", "module_name": "module", "is_high_risk_module": True},
            {"node_id": "root", "node_type": "根节点", "node_name": "data"},
        ],
        "edges": [{"source": "leaf", "target": "root"}],
        "attack_paths": [{"path_id": "path", "node_ids": ["leaf", "root"],
                          "attack_patterns": [{"pattern_id": "pattern", "pattern_name": "test"}]}],
    }]}

    def tasks(paths):
        return _tasks("scan", tree, [{"模块名称": "module", "代码目录": paths}], scan_scope=scope)

    clipped = tasks(["src"])
    assert len(clipped) == 1
    assert clipped[0]["code_paths"] == [{"path": "src/selected.c", "description": ""}]
    assert "src/selected.c" in _threat_prompt(clipped[0])
    assert "other.c" not in _threat_prompt(clipped[0])
    assert tasks(["src/other.c"]) == []
    fallback = tasks([])
    assert len(fallback) == 1
    assert fallback[0]["code_paths"][0]["path"] == "src/selected.c"
    assert _scope_vulnerabilities([{"file": str(selected)}], scope) == [{"file": "src/selected.c"}]
    with pytest.raises(ValueError, match="outside the selected"):
        _scope_vulnerabilities([{"file": "src/other.c"}], scope)
