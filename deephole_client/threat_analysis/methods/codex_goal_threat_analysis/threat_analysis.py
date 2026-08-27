"""Threat analysis implemented as one resilient Codex Goal."""

from __future__ import annotations

import json
import traceback
from pathlib import Path
from typing import Any, Mapping

from .schema_validation import ArtifactValidationError, validate_artifacts


MAX_GOAL_PROMPT_CHARS = 4000
_FINAL_DIR = "final"
_VALUE_ASSET_FILE = "value-assets.json"
_HIGH_RISK_MODULES_FILE = "high-risk-modules.json"
_ATTACK_TREE_FILE = "attack-trees.json"
_CONTEXT_FILE = "scan-context.json"
_STATE_FILE = "codex-goal-state.json"
_PROMPT_FILE = "codex-goal-prompt.txt"
_LOG_FILE = "codex-goal.log"
_CODEX_SQLITE_DIR = ".codex-state"
_RESUMABLE_GOAL_STATUSES = {"active", "paused", "usageLimited"}


def run_threat_analysis(
    code_path: str | Path,
    output_path: str | Path,
    is_resume: bool = False,
    product_mcp: str | None = None,
    attack_modes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Analyze a source tree and return the platform's three artifact paths."""

    try:
        code_root = _required_directory(code_path, "code_path")
        artifact_root = _output_directory(output_path)
        paths = _artifact_paths(artifact_root)
        guidance_path, schema_paths = _reference_paths()

        if is_resume:
            try:
                _validate_outputs(paths, schema_paths)
            except ArtifactValidationError:
                pass
            else:
                return _success(paths)
        else:
            _clear_outputs(paths)

        context_path = artifact_root / _CONTEXT_FILE
        _write_json(
            context_path,
            {
                "context_version": 1,
                "source": {
                    "root": str(code_root),
                    "access": "read_only",
                },
                "artifacts": {
                    "root": str(artifact_root),
                    "files": {key: str(path) for key, path in paths.items()},
                },
                "resume_requested": bool(is_resume),
                "optional_inputs": {
                    "product_mcp": product_mcp,
                    "attack_modes": attack_modes,
                },
            },
        )
        prompt = build_goal_prompt(
            code_root=code_root,
            context_path=context_path,
            guidance_path=guidance_path,
            schema_paths=schema_paths,
            paths=paths,
        )
        (artifact_root / _PROMPT_FILE).write_text(prompt + "\n", encoding="utf-8")

        goal_status = _run_goal(
            prompt=prompt,
            artifact_root=artifact_root,
            is_resume=bool(is_resume),
        )
        if goal_status != "complete":
            return {
                "result": False,
                "reason": f"Codex Goal stopped before completion (status={goal_status})",
            }

        _validate_outputs(paths, schema_paths)
        return _success(paths)
    except Exception as exc:
        return {
            "result": False,
            "reason": _safe_reason(exc),
        }


def build_goal_prompt(
    *,
    code_root: Path,
    context_path: Path,
    guidance_path: Path,
    schema_paths: Mapping[str, Path],
    paths: Mapping[str, Path],
) -> str:
    """Build the single Goal prompt and enforce its hard size limit."""

    prompt = f"""你是威胁分析工程师。请使用攻击树威胁分析方法分析真实源码，生成可供后续威胁审计直接消费的最终产物。

开始前依次读取并遵守：
- 分析指南 JSON（规定分析步骤、证据要求、三类产物关系和完成检查）：{guidance_path}
- 价值资产输出 Schema：{schema_paths['value_asset_path']}
- 高风险模块输出 Schema：{schema_paths['high_risk_modules_path']}
- 攻击树输出 Schema：{schema_paths['attack_tree_path']}

分析范围：{code_root}（只读）。先识别项目架构、信任边界、外部入口、敏感数据流和安全关键职责，再按以下顺序落盘，可以参考代码仓中已有的相关文档：
1. 从代码职责和攻击损失识别价值资产，写入：{paths['value_asset_path']}
2. 找出外部暴露、处理不可信输入、执行安全决策或操作敏感数据的模块；“代码目录”使用源码根目录相对 POSIX 路径，写入：{paths['high_risk_modules_path']}
3. 以价值资产受损为根节点、可实施攻击入口为叶子节点，构造有代码证据支撑的节点、边和完整攻击路径，写入：{paths['attack_tree_path']}

三类产物必须一致：攻击树中的资产与价值资产条目一致；引用的高风险模块真实存在且名称一致；同一树内 ID 唯一，所有节点和边引用可解析，路径顺序能从叶子到根。攻击模式只能取自扫描上下文，无法证实关联时使用空数组。

不得修改源码，只能写指定产物。不得编造接口、调用关系或攻击路径，不得输出 Schema 之外的字段。

##完成条件:
1. 需要输出的三份文件，逐项检查 JSON Schema 和跨产物引用，必须检查通过；
2. 分析必须完整，没有遗漏价值资产、高风险模块和威胁，攻击树中要考虑所有可能的攻击模式，至少输出最高风险的前10个威胁，根据实际情况如果没有10个威胁也可以；
3. 不合格就修正后再结束 Goal。"""
    if len(prompt) > MAX_GOAL_PROMPT_CHARS:
        raise ValueError(
            f"Codex Goal prompt exceeds {MAX_GOAL_PROMPT_CHARS} characters: {len(prompt)}"
        )
    return prompt


def _run_goal(
    *,
    prompt: str,
    artifact_root: Path,
    is_resume: bool,
) -> str:
    # Imported lazily so method discovery remains available before optional
    # Agent dependencies have been installed.
    from codex_sdk import (
        ApprovalMode,
        CodexConfig,
        CodexController,
        OutputMode,
        ResumePolicy,
        Sandbox,
    )

    state_path = artifact_root / _STATE_FILE
    saved_thread_id = _saved_thread_id(state_path) if is_resume else None
    thread_options = {
        "approval_mode": ApprovalMode.deny_all,
        "sandbox": Sandbox.workspace_write,
        "config": {
            "sandbox_workspace_write": {
                "network_access": False,
                "writable_roots": [str(artifact_root)],
            }
        },
    }
    policy = ResumePolicy(max_attempts=6, max_elapsed_seconds=7200)
    log_path = artifact_root / _LOG_FILE
    sqlite_home = artifact_root / _CODEX_SQLITE_DIR
    sqlite_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    codex_config = CodexConfig(
        cwd=str(artifact_root),
        # A Goal launched by an Agent can otherwise contend with an enclosing
        # Codex process for the user's shared state databases.  Keep auth,
        # models, and config in the existing CODEX_HOME while isolating only
        # the writable SQLite state needed by this resumable Goal.
        env={"CODEX_SQLITE_HOME": str(sqlite_home)},
    )

    log_mode = "a" if is_resume else "w"
    with log_path.open(log_mode, encoding="utf-8") as output:
        try:
            with CodexController(
                # Keep the writable workspace on the artifact side. The source is
                # supplied as an absolute, read-only reference in the prompt.
                codex_config=codex_config,
                thread_id=saved_thread_id,
                output_mode=OutputMode.HUMAN,
                output=output,
                resume_policy=policy,
            ) as controller:
                if saved_thread_id:
                    controller.resume_thread(saved_thread_id, **thread_options)
                    current = controller.get_goal()
                    _write_codex_goal_state(
                        state_path,
                        controller.thread_id,
                        current.status if current else None,
                    )
                    if (
                        current is not None
                        and current.status in _RESUMABLE_GOAL_STATUSES
                    ):
                        result = controller.resume_goal()
                    else:
                        result = controller.goal(prompt)
                else:
                    controller.start_thread(**thread_options)
                    _write_codex_goal_state(
                        state_path,
                        controller.thread_id,
                        "active",
                    )
                    result = controller.goal(prompt)

                _write_codex_goal_state(
                    state_path,
                    controller.thread_id,
                    result.goal.status,
                )
                return result.goal.status
        except Exception as exc:
            # Startup failures happen before the controller can render an
            # event.  Preserve the SDK's stderr tail instead of leaving an
            # empty log and a bare TransportClosedError in the scan UI.
            detail = _exception_detail(exc)
            output.write(
                f"! Codex Goal runtime failure ({type(exc).__name__})"
                f"{f': {detail}' if detail else ''}\n"
            )
            output.write(traceback.format_exc())
            output.flush()
            raise


def _reference_paths() -> tuple[Path, dict[str, Path]]:
    references_root = Path(__file__).resolve().parent / "references"
    guidance_path = references_root / "analysis-guidance.json"
    schema_paths = {
        "value_asset_path": references_root / "value-assets.schema.json",
        "high_risk_modules_path": references_root / "high-risk-modules.schema.json",
        "attack_tree_path": references_root / "attack-trees.schema.json",
    }
    for path in (guidance_path, *schema_paths.values()):
        if not path.is_file():
            raise FileNotFoundError(f"threat-analysis reference file is missing: {path}")
    return guidance_path, schema_paths


def _artifact_paths(root: Path) -> dict[str, Path]:
    final = root / _FINAL_DIR
    final.mkdir(parents=True, exist_ok=True)
    return {
        "value_asset_path": final / _VALUE_ASSET_FILE,
        "high_risk_modules_path": final / _HIGH_RISK_MODULES_FILE,
        "attack_tree_path": final / _ATTACK_TREE_FILE,
    }


def _validate_outputs(
    paths: Mapping[str, Path],
    schema_paths: Mapping[str, Path],
) -> None:
    validate_artifacts(
        value_asset_path=paths["value_asset_path"],
        high_risk_modules_path=paths["high_risk_modules_path"],
        attack_tree_path=paths["attack_tree_path"],
        value_asset_schema_path=schema_paths["value_asset_path"],
        high_risk_modules_schema_path=schema_paths["high_risk_modules_path"],
        attack_tree_schema_path=schema_paths["attack_tree_path"],
    )


def _clear_outputs(paths: Mapping[str, Path]) -> None:
    for path in paths.values():
        path.unlink(missing_ok=True)


def _success(paths: Mapping[str, Path]) -> dict[str, Any]:
    return {
        "result": True,
        "value_asset_path": str(paths["value_asset_path"]),
        "attack_tree_path": str(paths["attack_tree_path"]),
        "high_risk_modules_path": str(paths["high_risk_modules_path"]),
    }


def _required_directory(value: str | Path, name: str) -> Path:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError(f"{name} is required")
    path = Path(raw).expanduser().resolve()
    if not path.is_dir():
        raise FileNotFoundError(f"{name} is not a directory: {path}")
    return path


def _output_directory(value: str | Path) -> Path:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("output_path is required")
    path = Path(raw).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise NotADirectoryError(f"output_path is not a directory: {path}")
    return path


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )


def _saved_thread_id(path: Path) -> str | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    thread_id = str(value.get("thread_id") or "").strip()
    return thread_id or None


def _write_codex_goal_state(
    path: Path,
    thread_id: str | None,
    goal_status: str | None,
) -> None:
    """Persist only state owned by this threat-analysis method."""

    _write_json(
        path,
        {
            "thread_id": str(thread_id or ""),
            "goal_status": str(goal_status or "unknown"),
        },
    )


def _safe_reason(exc: Exception) -> str:
    if isinstance(exc, ArtifactValidationError):
        return f"Codex Goal produced invalid threat-analysis artifacts: {exc}"
    if isinstance(exc, (FileNotFoundError, NotADirectoryError, ValueError)):
        return str(exc)
    if isinstance(exc, TypeError):
        detail = _exception_detail(exc)
        return f"Codex Goal type error{f': {detail}' if detail else ''}"
    if type(exc).__name__ == "TransportClosedError":
        detail = _exception_detail(exc)
        return (
            "Codex Goal runtime closed unexpectedly"
            f"{f': {detail}' if detail else ''}"
        )
    return f"Codex Goal threat analysis failed ({type(exc).__name__})"


def _exception_detail(exc: BaseException, *, limit: int = 2000) -> str:
    """Return a bounded one-line SDK diagnostic suitable for logs and UI."""

    detail = " ".join(str(exc).split())
    if len(detail) <= limit:
        return detail
    return detail[: limit - 3].rstrip() + "..."
