"""Threat analysis business pipeline."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from deephole_client.scan_paths import resolve_scan_scope

from threat_analysis_harness.artifacts import ThreatAnalysisLayout
from threat_analysis_harness.baselines import add_module_pattern_baselines
from threat_analysis_harness.module_scope import (
    SCOPED_MODULES_FILE,
    matches_tree_scope,
    scope_modules,
    scope_prompt,
    tree_scope_fingerprint,
)
from threat_analysis_harness.stages.attack_trees import AttackTreeStage
from threat_analysis_harness.stages.base import (
    ProgressReporter,
    SubmitTasks,
    completed_results,
    fill_pending_results,
    require_all_success,
    require_success,
    resume_existing_tasks,
    run_or_resume_task,
)
from threat_analysis_harness.stages.high_risk_modules import HighRiskModuleStage
from threat_analysis_harness.stages.value_assets import ValueAssetStage


@dataclass(frozen=True)
class ThreatAnalysisResult:
    value_assets: list[dict[str, Any]]
    high_risk_modules: list[dict[str, Any]]
    attack_trees: dict[str, Any]


class ThreatAnalysisPipeline:
    def __init__(
        self,
        *,
        submit_tasks: SubmitTasks,
        layout: ThreatAnalysisLayout,
        progress_reporter: ProgressReporter | None = None,
    ) -> None:
        self.submit_tasks = submit_tasks
        self.layout = layout
        self.progress_reporter = progress_reporter
        self.value_assets = ValueAssetStage(
            submit_tasks=submit_tasks,
            layout=layout,
        )
        self.high_risk_modules = HighRiskModuleStage(
            submit_tasks=submit_tasks,
            layout=layout,
        )
        self.attack_trees = AttackTreeStage(
            submit_tasks=submit_tasks,
            layout=layout,
        )

    def run(
        self,
        *,
        input_files: Sequence[str | Path],
        code_root: str | Path,
        high_risk_input_batches: Sequence[Sequence[str | Path]] | None = None,
        attack_tree_context_files: Sequence[str | Path] = (),
        timeout: float | None = None,
        resume: bool = False,
    ) -> ThreatAnalysisResult:
        pipeline_started_at = time.time()
        self.layout.ensure()
        code_root = Path(code_root).resolve()
        scope = resolve_scan_scope(code_root, code_scan_paths=input_files)
        prompt_scope = scope_prompt(code_root, scope)
        high_risk_batches = high_risk_input_batches or [input_files]
        self._progress(f"pipeline started: artifacts={self.layout.root}")

        value_tasks = self.value_assets.build_category_tasks(input_files=input_files)
        high_risk_map_tasks = self.high_risk_modules.build_map_tasks(
            input_batches=high_risk_batches,
        )
        for task in high_risk_map_tasks:
            task["runtime_prompt"] += prompt_scope
        self._progress(f"value asset map started: tasks={len(value_tasks)}")
        self._progress(f"high-risk module map started: tasks={len(high_risk_map_tasks)}")

        value_results, pending_value_tasks, pending_value_indexes = resume_existing_tasks(
            value_tasks,
            resume=resume,
            progress_reporter=self.progress_reporter,
        )
        (
            high_risk_map_results,
            pending_high_risk_map_tasks,
            pending_high_risk_map_indexes,
        ) = resume_existing_tasks(
            high_risk_map_tasks,
            resume=resume,
            progress_reporter=self.progress_reporter,
        )

        pending_map_tasks = pending_value_tasks + pending_high_risk_map_tasks
        pending_map_results = (
            self.submit_tasks(pending_map_tasks, timeout=timeout) if pending_map_tasks else []
        )
        pending_value_results = pending_map_results[: len(pending_value_tasks)]
        pending_high_risk_map_results = pending_map_results[len(pending_value_tasks) :]
        fill_pending_results(
            value_results,
            pending_value_indexes,
            pending_value_results,
        )
        value_results = require_all_success(completed_results(value_results))
        self._progress(f"value asset map completed: tasks={len(value_results)}")
        value_assets = self.value_assets.merge_category_outputs(
            [
                (
                    str(result.get("metadata", {}).get("asset_category", "")),
                    result.get("output") or [],
                )
                for result in value_results
            ]
        )
        self._progress(f"value asset merge completed: assets={len(value_assets)}")
        fill_pending_results(
            high_risk_map_results,
            pending_high_risk_map_indexes,
            pending_high_risk_map_results,
        )
        high_risk_map_results = require_all_success(completed_results(high_risk_map_results))
        self._progress(f"high-risk module map completed: tasks={len(high_risk_map_results)}")
        candidate_files = [result["output_path"] for result in high_risk_map_results]
        self._progress("high-risk module merge started: tasks=1")
        merge_task = self.high_risk_modules.build_merge_task(candidate_files=candidate_files)
        merge_task["runtime_prompt"] += prompt_scope
        high_risk_modules = require_success(
            run_or_resume_task(
                submit_tasks=self.submit_tasks,
                task=merge_task,
                # Recomputed candidates invalidate their previously merged result.
                resume=resume and not pending_high_risk_map_tasks,
                timeout=timeout,
                progress_reporter=self.progress_reporter,
            )
        )["output"]
        self._progress(f"high-risk module merge completed: modules={len(high_risk_modules)}")

        raw_module_count = len(high_risk_modules)
        scope_changes: list[dict[str, Any]] = []
        high_risk_modules = scope_modules(
            high_risk_modules, code_root=code_root, scope=scope, changes=scope_changes,
        )
        for change in scope_changes:
            self._progress("high-risk module scope: " + json.dumps(change, ensure_ascii=False))
        self.layout.write_final_json("high_risk_modules/final/scope-changes.json", scope_changes)
        scoped_modules_file = self.layout.write_final_json(
            f"high_risk_modules/final/{SCOPED_MODULES_FILE}", high_risk_modules,
        )
        self._progress(
            f"high-risk module scope applied: retained={len(high_risk_modules)} "
            f"excluded={raw_module_count - len(high_risk_modules)}"
        )
        fingerprint = tree_scope_fingerprint(scope, high_risk_modules, value_assets)
        marker = self.layout.attack_trees_final_dir / "scoped-inputs.json"
        resume_trees = resume and matches_tree_scope(marker, fingerprint)
        # A failed rebuild must never certify a mixture of old and new trees.
        marker.unlink(missing_ok=True)
        self._progress(f"attack tree analysis started: assets={len(value_assets)}")
        if any(module.get("是否外部暴露面") == "是" for module in high_risk_modules):
            attack_trees = self.attack_trees.run(
                value_assets=value_assets,
                high_risk_modules=high_risk_modules,
                high_risk_modules_file=scoped_modules_file,
                context_files=attack_tree_context_files,
                timeout=timeout,
                resume=resume_trees,
                progress_reporter=self.progress_reporter,
            )
        else:
            attack_trees = add_module_pattern_baselines({"attack_trees": []}, high_risk_modules)
            self.layout.write_final_json("attack_trees/final/attack_trees.json", attack_trees)
        self.layout.write_final_json("attack_trees/final/scoped-inputs.json", fingerprint)
        attack_tree_count = len(attack_trees.get("attack_trees", []))
        self._progress(f"attack tree analysis completed: trees={attack_tree_count}")
        self._progress(f"pipeline completed: duration={time.time() - pipeline_started_at:.1f}s")
        return ThreatAnalysisResult(
            value_assets=value_assets,
            high_risk_modules=high_risk_modules,
            attack_trees=attack_trees,
        )

    def _progress(self, message: str) -> None:
        if self.progress_reporter is not None:
            self.progress_reporter.emit(message)
