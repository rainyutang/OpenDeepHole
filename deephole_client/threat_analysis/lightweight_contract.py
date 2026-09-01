"""Shared prompt and artifact contract for lightweight threat analysis."""

from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path
from typing import Mapping

from ..codex_scan_config import codex_runtime_reference_root


MAX_LIGHTWEIGHT_PROMPT_CHARS = 4000
ATTACK_MODE_FILE = "attack_mode.json"


def reference_root() -> Path:
    return codex_runtime_reference_root()


def reference_paths() -> tuple[Path, dict[str, Path]]:
    references_root = reference_root() / "references"
    guidance_path = references_root / "analysis-guidance.json"
    attack_mode_path = references_root / ATTACK_MODE_FILE
    schema_paths = {
        "value_asset_path": references_root / "value-assets.schema.json",
        "high_risk_modules_path": references_root / "high-risk-modules.schema.json",
        "attack_tree_path": references_root / "attack-trees.schema.json",
    }
    for path in (guidance_path, attack_mode_path, *schema_paths.values()):
        if not path.is_file():
            raise FileNotFoundError(
                f"threat-analysis reference file is missing: {path}"
            )
    return guidance_path, schema_paths


def validation_command(
    *,
    guidance_path: Path,
    paths: Mapping[str, Path],
) -> str:
    validator_path = reference_root() / "schema_validation.py"
    if not validator_path.is_file():
        raise FileNotFoundError(
            f"threat-analysis validator is missing: {validator_path}"
        )
    return shlex.join(
        (
            sys.executable,
            str(validator_path),
            "--value-assets",
            str(paths["value_asset_path"]),
            "--high-risk-modules",
            str(paths["high_risk_modules_path"]),
            "--attack-trees",
            str(paths["attack_tree_path"]),
            "--references-root",
            str(guidance_path.parent),
        )
    )


def build_lightweight_prompt(
    *,
    code_root: Path,
    context_path: Path,
    guidance_path: Path,
    schema_paths: Mapping[str, Path],
    paths: Mapping[str, Path],
) -> str:
    """Build the byte-identical user prompt used by both lightweight methods."""

    attack_mode_path = guidance_path.parent / ATTACK_MODE_FILE
    command = validation_command(guidance_path=guidance_path, paths=paths)
    prompt = f"""你是威胁分析工程师。请使用攻击树威胁分析方法分析真实源码，生成可供后续威胁审计直接消费的最终产物。

开始前依次读取并遵守：
- 扫描上下文（动态输入与输出路径）：{context_path}
- 分析指南（完整节点定义、分析方法、跨产物约束和完成检查）：{guidance_path}
- 精简攻击模式库（C/C++、协议、密码学、系统边界；无 Web 专属模式；只能原样引用编号和名称）：{attack_mode_path}
- 价值资产输出 Schema：{schema_paths['value_asset_path']}
- 高风险模块输出 Schema：{schema_paths['high_risk_modules_path']}
- 攻击树输出 Schema：{schema_paths['attack_tree_path']}

分析范围：{code_root}（只读）。先识别项目架构、信任边界、外部入口、敏感数据流和安全关键职责，再按以下顺序落盘，可以参考代码仓中已有的相关文档：
1. 从代码职责和攻击损失识别价值资产，写入：{paths['value_asset_path']}
2. 找出外部暴露、处理不可信输入、执行安全决策或操作敏感数据的模块；“代码目录”使用源码根目录相对 POSIX 路径，写入：{paths['high_risk_modules_path']}
3. 按“外部暴露高风险模块（叶）→内部源码模块（中）→价值资产（根）”构造有代码证据支撑的攻击路径，写入：{paths['attack_tree_path']}

关键硬约束：每棵树的根节点必须是一个已识别价值资产，node_name 与该价值资产的资产名完全相同，tree.value_asset 使用该资产的原始四字段；每个叶子节点必须是“是否外部暴露面=是”的高风险模块，node_name/module_name 与该模块的规范名称完全相同；内部节点只能是路径中的真实内部源码模块，不是漏洞、攻击动作、条件、权限或结果。

三类产物必须保持来源一致：根节点关联的资产来自价值资产文件，叶子和路径引用的高风险模块来自高风险模块文件。路径首节点为叶子、末节点为根，中间只能是内部节点，边与节点逐段对应。扫描上下文中的 attack_modes 只作筛选或优先级提示，不能替代或扩写攻击模式库。

不得修改源码，只能写指定产物。不得编造接口、调用关系或攻击路径，不得输出 Schema 之外的字段。

##完成条件:
1. 三份文件写完后，必须在本 Goal 内执行以下校验命令：
{command}
命令退出码为0才允许结束 Goal；如果失败，必须根据错误修正产物并反复执行，直至通过。不得跳过命令或只做人工目测；
2. 分析必须完整，没有遗漏价值资产、高风险模块和威胁；针对每条攻击路径分析适用攻击模式并按可能性从高到低排列，有足够适用模式时至少输出10个，确实不足10个时输出全部实际适用模式"""
    if len(prompt) > MAX_LIGHTWEIGHT_PROMPT_CHARS:
        raise ValueError(
            "Codex Goal prompt exceeds "
            f"{MAX_LIGHTWEIGHT_PROMPT_CHARS} characters: {len(prompt)}"
        )
    return prompt


def validate_artifacts_locally(
    *,
    guidance_path: Path,
    paths: Mapping[str, Path],
) -> None:
    """Run the same validator once more outside the model Session."""

    command = validation_command(guidance_path=guidance_path, paths=paths)
    completed = subprocess.run(
        shlex.split(command),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        return
    detail = " ".join((completed.stderr or completed.stdout or "").split())
    raise ValueError(
        "Lightweight threat-analysis artifact validation failed"
        + (f": {detail}" if detail else f" (exit={completed.returncode})")
    )


__all__ = [
    "ATTACK_MODE_FILE",
    "MAX_LIGHTWEIGHT_PROMPT_CHARS",
    "build_lightweight_prompt",
    "reference_paths",
    "reference_root",
    "validate_artifacts_locally",
    "validation_command",
]
