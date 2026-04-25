"""入口点配置加载 — 从 yaml 文件读取外部接口定义。"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from backend.logger import get_logger
from .models import EntryPointInfo

if TYPE_CHECKING:
    from code_parser import CodeDatabase

logger = get_logger(__name__)


def load_entry_points(
    config_path: Path, db: "CodeDatabase | None" = None
) -> dict[str, EntryPointInfo]:
    """加载入口点配置。

    Args:
        config_path: entry_points.yaml 的路径。
        db: 可选的 CodeDatabase，用于模式匹配时获取所有函数名。

    Returns:
        {函数名: EntryPointInfo} 的映射。如果配置文件不存在，返回空字典。
    """
    if not config_path.exists():
        logger.warning("入口点配置文件不存在: %s", config_path)
        return {}

    with open(config_path, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if not config:
        return {}

    result: dict[str, EntryPointInfo] = {}

    # 自动检测模式：找出没有被任何函数调用的函数
    if config.get("auto_detect") and db is not None:
        auto = config["auto_detect"]
        if auto is True or (isinstance(auto, dict) and auto.get("uncalled")):
            detected = auto_detect_entry_points(db)
            result.update(detected)
            logger.info("自动检测到 %d 个入口函数（无调用者）", len(detected))

    # 精确指定的入口点
    for entry in config.get("entry_points", []) or []:
        name = entry.get("name", "")
        if not name:
            continue
        tainted = entry.get("tainted_params")
        if tainted == "all" or tainted is None:
            indices = None
        elif isinstance(tainted, list):
            indices = [int(i) for i in tainted]
        else:
            indices = None

        result[name] = EntryPointInfo(func_name=name, tainted_param_indices=indices)

    # 模式匹配的入口点
    patterns = config.get("entry_patterns", [])
    if patterns and db is not None:
        compiled = []
        for pat in patterns:
            try:
                compiled.append(re.compile(pat))
            except re.error:
                logger.warning("无效的入口点正则: %s", pat)

        if compiled:
            all_funcs = db.get_all_functions()
            for func_row in all_funcs:
                func_name = func_row["name"]
                if func_name in result:
                    continue
                for regex in compiled:
                    if regex.search(func_name):
                        result[func_name] = EntryPointInfo(
                            func_name=func_name, tainted_param_indices=None
                        )
                        break

    logger.info("加载了 %d 个入口函数", len(result))
    return result


def auto_detect_entry_points(
    db: "CodeDatabase",
) -> dict[str, EntryPointInfo]:
    """自动检测入口函数：找出没有被任何函数调用的、有参数的函数。

    逻辑：所有函数名 - 所有被调用过的函数名 = 无调用者的函数。
    过滤掉无参数的函数（没有外部输入）和 main 函数。
    """
    all_functions = db.get_all_functions()

    # 收集所有被调用的函数名
    called_names: set[str] = set()
    rows = db._conn.execute(
        "SELECT DISTINCT callee_name FROM function_calls"
    ).fetchall()
    for row in rows:
        called_names.add(row["callee_name"])

    result: dict[str, EntryPointInfo] = {}
    for func_row in all_functions:
        func_name = func_row["name"]

        # 跳过被调用过的函数
        if func_name in called_names:
            continue

        # 跳过 main（通常不是外部接口）
        if func_name == "main":
            continue

        # 跳过无参数的函数（没有外部输入可言）
        sig = func_row["signature"] or ""
        params = _count_params(sig)
        if params == 0:
            continue

        # 跳过 static 函数（内部链接，不太可能是外部接口）
        if func_row["is_static"]:
            continue

        result[func_name] = EntryPointInfo(
            func_name=func_name, tainted_param_indices=None
        )

    return result


def _count_params(signature: str) -> int:
    """从签名中粗略计算参数个数。"""
    start = signature.find("(")
    end = signature.rfind(")")
    if start < 0 or end < 0 or start >= end:
        return 0
    params_str = signature[start + 1:end].strip()
    if not params_str or params_str == "void":
        return 0
    return len([p for p in params_str.split(",") if p.strip()])
