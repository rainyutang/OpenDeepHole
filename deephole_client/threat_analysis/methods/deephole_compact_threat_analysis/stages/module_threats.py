"""Per-high-risk-module direct attack-threat analysis stage (no attack tree)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from threat_analysis_harness.artifacts import ThreatAnalysisLayout
from threat_analysis_harness.baselines import add_module_pattern_baselines
from threat_analysis_harness.schemas import MODULE_THREAT_LIST_SCHEMA
from threat_analysis_harness.stages.attack_trees import (
    _module_code_paths,
    _stable_high_risk_module_id,
)
from threat_analysis_harness.stages.base import (
    ProgressReporter,
    SubmitTasks,
    TaskJson,
    require_all_success,
    run_or_resume_tasks,
)
from threat_analysis_harness.validate_module_threats import validate_module_threat_patterns


class ModuleThreatStage:
    task_type = "module_attack_threats"
    skill_name = "deephole-compact-module-attack-threats"

    def __init__(
        self,
        *,
        submit_tasks: SubmitTasks,
        layout: ThreatAnalysisLayout,
    ) -> None:
        self.submit_tasks = submit_tasks
        self.layout = layout

    def build_tasks(
        self,
        *,
        high_risk_modules: Sequence[dict[str, Any]],
        code_root: str | Path,
        runtime_prompt: str | None = None,
    ) -> list[TaskJson]:
        tasks: list[TaskJson] = []
        resolved_root = Path(code_root).resolve()
        for index, module in enumerate(high_risk_modules, start=1):
            module_id = _stable_high_risk_module_id(module)
            module_name = str(module.get("模块名称") or module.get("module_name") or "").strip()
            code_paths = _module_code_paths(module)
            task_id = f"module-attack-threats-{index:03d}-{module_id[4:14]}"
            tasks.append(
                {
                    "task_id": task_id,
                    "task_type": self.task_type,
                    "skill_name": self.skill_name,
                    "runtime_prompt": _module_threat_prompt(
                        module,
                        code_root=resolved_root,
                        runtime_prompt=runtime_prompt,
                    ),
                    "input_files": [str((resolved_root / path).resolve()) for path in code_paths],
                    "output_path": str(self.layout.attack_trees_raw_dir / f"{task_id}.json"),
                    "output_schema": MODULE_THREAT_LIST_SCHEMA,
                    "metadata": {
                        "stage": "module_threats",
                        "module_name": module_name,
                        "code_paths": code_paths,
                    },
                    "priority": 40,
                }
            )
        return tasks

    def run(
        self,
        *,
        high_risk_modules: Sequence[dict[str, Any]],
        code_root: str | Path,
        runtime_prompt: str | None = None,
        timeout: float | None = None,
        resume: bool = False,
        progress_reporter: ProgressReporter | None = None,
    ) -> dict[str, Any]:
        self.layout.ensure()
        if not high_risk_modules:
            combined: dict[str, Any] = {
                "analysis_mode": "module_threats_only",
                "attack_trees": [],
                "module_threats": [],
            }
            combined = add_module_pattern_baselines(combined, high_risk_modules)
            self.layout.write_final_json("attack_trees/final/attack_trees.json", combined)
            return combined

        tasks = self.build_tasks(
            high_risk_modules=high_risk_modules,
            code_root=code_root,
            runtime_prompt=runtime_prompt,
        )
        results = require_all_success(
            run_or_resume_tasks(
                submit_tasks=self.submit_tasks,
                tasks=tasks,
                resume=resume,
                timeout=timeout,
                progress_reporter=progress_reporter,
                validate_existing_output_schema=True,
            )
        )
        module_threats = [
            {
                "module_name": str(module.get("模块名称") or module.get("module_name") or "").strip(),
                "attack_patterns": validate_module_threat_patterns(
                    result.get("output") or [],
                    path_prefix=f"$.module_threats[{idx}].attack_patterns",
                ),
            }
            for idx, (module, result) in enumerate(zip(high_risk_modules, results))
        ]
        combined = {
            "analysis_mode": "module_threats_only",
            "attack_trees": [],
            "module_threats": module_threats,
        }
        combined = add_module_pattern_baselines(combined, high_risk_modules)
        self.layout.write_final_json("attack_trees/final/attack_trees.json", combined)
        return combined


def _module_threat_prompt(
    module: dict[str, Any],
    *,
    code_root: Path,
    runtime_prompt: str | None = None,
) -> str:
    module_name = str(module.get("模块名称") or module.get("module_name") or "").strip()
    code_paths = _module_code_paths(module)
    summary = {
        "模块名称": module_name,
        "代码目录": code_paths,
        "是否外部暴露面": str(module.get("是否外部暴露面") or "否").strip(),
        "判断为高风险模块的原因": str(module.get("判断为高风险模块的原因") or "").strip(),
    }
    instruction = runtime_prompt or "请仅针对以下高风险模块分析其可能面临的攻击威胁："
    return (
        f"{instruction}\n"
        f"{json.dumps(summary, ensure_ascii=False, indent=2)}\n\n"
        f"源码工作目录（相对路径基准）：{code_root}\n"
        f"当前模块允许查看的代码路径范围：{json.dumps(code_paths, ensure_ascii=False)}\n\n"
        "重要约束：\n"
        "1. 不要探索其它源码！仅查看上述“当前模块允许查看的代码路径范围”内的代码，不得读取或搜索代码仓其它目录的代码。\n"
        "2. 检查完该模块的代码职责与输入处理情况后，直接判断可能受到的攻击威胁并输出结果，不要做过度的代码探索，不要挖掘或验证具体漏洞。"
    )
