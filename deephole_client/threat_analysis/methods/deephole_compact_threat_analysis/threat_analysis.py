"""Third-party callable threat-analysis API."""

from __future__ import annotations

from pathlib import Path
from deephole_client.threat_analysis.scope import prepare_method_scope
from types import SimpleNamespace
from typing import Any, Mapping

from task_agent.task_service import get_opencode_execution_context

from threat_analysis_harness.artifacts import ThreatAnalysisLayout
from threat_analysis_harness.module_scope import SCOPED_MODULES_FILE
from threat_analysis_harness.pipeline import ThreatAnalysisPipeline
from threat_analysis_harness.task_agent_submitter import TaskAgentSubmitter


def run_threat_analysis(
    code_path: str | Path,
    output_path: str | Path,
    is_resume: bool = False,
    product_mcp: str | None = None,
    attack_modes: Mapping[str, Any] | None = None,
    code_paths: list[str | Path] | None = None,
) -> dict[str, Any]:
    """Run threat analysis and return a JSON-serializable result object.

    ``product_mcp`` and ``attack_modes`` are accepted for forward compatibility.
    The current pipeline does not consume them yet.
    """

    del product_mcp, attack_modes
    try:
        code_root = _required_path(code_path, "code_path")
        artifact_root = _required_path(output_path, "output_path")

        selected_paths, is_resume = prepare_method_scope(code_root, artifact_root, code_paths, is_resume)
        layout = ThreatAnalysisLayout(artifact_root)
        submitter = TaskAgentSubmitter()
        # The platform facade binds a synchronous, thread-safe log callback.
        on_output = get_opencode_execution_context().on_output
        pipeline = ThreatAnalysisPipeline(
            submit_tasks=submitter.submit_tasks,
            layout=layout,
            progress_reporter=SimpleNamespace(emit=on_output) if on_output else None,
        )
        pipeline.run(input_files=list(selected_paths), code_root=code_root, resume=bool(is_resume))

        return {
            "result": True,
            "value_asset_path": str(layout.value_assets_final_dir / "value-assets.json"),
            "attack_tree_path": str(layout.attack_trees_final_dir / "attack_trees.json"),
            "high_risk_modules_path": str(
                layout.high_risk_final_dir / SCOPED_MODULES_FILE
            ),
        }
    except Exception as exc:
        return {
            "result": False,
            "reason": str(exc),
        }


def _required_path(value: str | Path, name: str) -> Path:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError(f"{name} is required")
    return Path(raw).expanduser()
