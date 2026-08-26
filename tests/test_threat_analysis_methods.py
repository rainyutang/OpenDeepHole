from __future__ import annotations

import inspect
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from fastapi import HTTPException

from backend.api.scan import _resolve_threat_analysis_method
from backend.models import (
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    ThreatAnalysisMethodSelection,
)
from backend.store.sqlite import SqliteScanStore
from deephole_client.threat_analysis import (
    DEFAULT_THREAT_ANALYSIS_METHOD_ID,
    THREAT_ANALYSIS_METHODS_DIR,
    build_threat_analysis_method_catalog,
    discover_threat_analysis_method_manifests,
    resolve_threat_analysis_method,
)
from deephole_client.threat_analysis_runner import (
    _load_implementation,
    _validate_native_result,
)


def _write_method(
    root: Path,
    method_id: str,
    manifest: str,
    *,
    complete: bool = True,
) -> Path:
    directory = root / method_id
    directory.mkdir()
    (directory / "method.yaml").write_text(manifest, encoding="utf-8")
    if complete:
        (directory / "__init__.py").write_text(
            "from .threat_analysis import run_threat_analysis\n",
            encoding="utf-8",
        )
        (directory / "threat_analysis.py").write_text(
            "def run_threat_analysis(code_path, output_path, is_resume=False, "
            "product_mcp=None, attack_modes=None):\n"
            "    return {'result': False, 'reason': 'not implemented'}\n",
            encoding="utf-8",
        )
    return directory


def test_method_catalog_uses_directory_ids_and_minimal_yaml() -> None:
    catalog = build_threat_analysis_method_catalog()

    assert catalog["errors"] == []
    assert catalog["methods"] == [
        {
            "method_id": DEFAULT_THREAT_ANALYSIS_METHOD_ID,
            "label": "DeepHole威胁分析",
            "description": "生成价值资产、高风险模块和攻击树。",
        },
        {
            "method_id": "codex_goal_threat_analysis",
            "label": "威胁分析",
            "description": "生成价值资产、高风险模块和攻击树。",
        },
    ]
    raw = yaml.safe_load(
        (
            THREAT_ANALYSIS_METHODS_DIR
            / DEFAULT_THREAT_ANALYSIS_METHOD_ID
            / "method.yaml"
        ).read_text(encoding="utf-8")
    )
    assert set(raw) == {"label", "description"}


def test_backend_resolves_default_method_and_rejects_unknown_selection() -> None:
    method_id, selection = _resolve_threat_analysis_method(None)

    assert method_id == DEFAULT_THREAT_ANALYSIS_METHOD_ID
    assert selection.method_label == "DeepHole威胁分析"
    assert _resolve_threat_analysis_method("  ")[0] == method_id
    with pytest.raises(HTTPException) as raised:
        _resolve_threat_analysis_method("missing")
    assert raised.value.status_code == 400


def test_method_discovery_rejects_extra_yaml_and_incomplete_directories(
    tmp_path: Path,
) -> None:
    _write_method(
        tmp_path,
        "valid",
        "label: Valid\ndescription: Valid method\n",
    )
    _write_method(
        tmp_path,
        "extra",
        "label: Extra\ndescription: Invalid\npackage_name: unnecessary\n",
    )
    _write_method(
        tmp_path,
        "incomplete",
        "label: Incomplete\ndescription: Missing entry\n",
        complete=False,
    )
    hidden = _write_method(
        tmp_path,
        "_hidden",
        "label: Hidden\ndescription: Hidden\n",
    )
    assert hidden.is_dir()

    manifests, errors = discover_threat_analysis_method_manifests(tmp_path)

    assert [item.method_id for item in manifests] == ["valid"]
    assert any("unknown method.yaml field(s): package_name" in item for item in errors)
    assert any("requires method.yaml, __init__.py" in item for item in errors)


def test_default_method_entry_has_the_documented_five_parameter_contract() -> None:
    manifest = resolve_threat_analysis_method(None)
    module = _load_implementation(manifest.method_id)

    assert Path(module.__file__).resolve() == manifest.directory / "__init__.py"
    signature = inspect.signature(module.run_threat_analysis)
    assert list(signature.parameters) == [
        "code_path",
        "output_path",
        "is_resume",
        "product_mcp",
        "attack_modes",
    ]
    assert signature.parameters["code_path"].default is inspect.Parameter.empty
    assert signature.parameters["output_path"].default is inspect.Parameter.empty
    assert signature.parameters["is_resume"].default is False
    assert signature.parameters["product_mcp"].default is None
    assert signature.parameters["attack_modes"].default is None


def test_copied_source_harness_loads_without_rewriting_native_imports(
    tmp_path: Path,
) -> None:
    repository = Path(__file__).resolve().parents[1]
    methods_dir = tmp_path / "methods"
    copied = methods_dir / "copied_threat_analysis"
    shutil.copytree(
        repository / "ThreatAnalysis" / "src" / "threat_analysis_harness",
        copied,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    (copied / "method.yaml").write_text(
        "label: Copied analysis\ndescription: Copied native harness\n",
        encoding="utf-8",
    )
    script = """
import inspect
import sys
from pathlib import Path

from deephole_client.threat_analysis.runtime import (
    discover_threat_analysis_method_manifests,
    load_threat_analysis_method_package,
    resolve_threat_analysis_method,
)

root = Path(sys.argv[1])
manifests, errors = discover_threat_analysis_method_manifests(root)
assert errors == []
assert [item.method_id for item in manifests] == ["copied_threat_analysis"]
manifest = resolve_threat_analysis_method("copied_threat_analysis", root)
module = load_threat_analysis_method_package(manifest)
assert module.__name__ == "threat_analysis_harness"
assert list(inspect.signature(module.run_threat_analysis).parameters) == [
    "code_path", "output_path", "is_resume", "product_mcp", "attack_modes"
]
"""

    result = subprocess.run(
        [sys.executable, "-c", script, str(methods_dir)],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_method_result_contract_requires_three_paths_or_failure_reason() -> None:
    with pytest.raises(ValueError, match="high_risk_modules_path"):
        _validate_native_result({
            "result": True,
            "value_asset_path": "value.json",
            "attack_tree_path": "tree.json",
        })
    with pytest.raises(ValueError, match="non-empty reason"):
        _validate_native_result({"result": False, "reason": ""})

    failed = {"result": False, "reason": "model unavailable"}
    assert _validate_native_result(failed) is failed


def test_method_selection_round_trips_through_scan_storage(tmp_path: Path) -> None:
    store = SqliteScanStore(tmp_path / "scan.db")
    selection = ThreatAnalysisMethodSelection(
        method_id="custom",
        method_label="Custom analysis",
        description="snapshot",
    )
    scan = ScanStatus(
        scan_id="scan-method",
        status=ScanItemStatus.PENDING,
        progress=0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
        threat_analysis_method="custom",
        threat_analysis_method_selection=selection,
    )
    meta = ScanMeta(
        scan_items=[],
        created_at="2026-08-05T00:00:00+00:00",
        threat_analysis_method="custom",
        threat_analysis_method_selection=selection,
    )

    store.save_scan(scan, meta)
    loaded_scan, loaded_meta = store.load_scan("scan-method")  # type: ignore[misc]

    assert loaded_scan.threat_analysis_method_selection == selection
    assert loaded_meta.threat_analysis_method == "custom"
    assert loaded_meta.threat_analysis_method_selection == selection


def test_legacy_scan_migration_adds_builtin_method_defaults(tmp_path: Path) -> None:
    database = tmp_path / "legacy.db"
    store = SqliteScanStore(database)
    scan = ScanStatus(
        scan_id="legacy-method",
        status=ScanItemStatus.COMPLETE,
        progress=1,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
    )
    meta = ScanMeta(scan_items=[], created_at="2026-08-03T00:00:00+00:00")
    store.save_scan(scan, meta)
    store.close()

    connection = sqlite3.connect(database)
    connection.execute("ALTER TABLE scans DROP COLUMN threat_analysis_method")
    connection.execute(
        "ALTER TABLE scans DROP COLUMN threat_analysis_method_selection_json"
    )
    connection.commit()
    connection.close()

    migrated = SqliteScanStore(database)
    loaded = migrated.load_scan("legacy-method")
    migrated.close()

    assert loaded is not None
    loaded_scan, loaded_meta = loaded
    assert loaded_scan.threat_analysis_method == DEFAULT_THREAT_ANALYSIS_METHOD_ID
    assert loaded_scan.threat_analysis_method_selection is None
    assert loaded_meta.threat_analysis_method == DEFAULT_THREAT_ANALYSIS_METHOD_ID
