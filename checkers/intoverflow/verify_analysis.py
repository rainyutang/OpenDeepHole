#!/usr/bin/env python3
"""整数溢出静态分析验证脚本。

用法:
    python3 checkers/intoverflow/verify_analysis.py /path/to/c/project

输入一个 C/C++ 代码仓路径，执行静态分析初筛，输出所有候选漏洞。
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

# 确保项目根目录在 sys.path 中
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from code_parser import CodeDatabase, CppAnalyzer
from checkers.intoverflow.analyzer import Analyzer


def main() -> None:
    parser = argparse.ArgumentParser(
        description="验证整数溢出静态分析：解析代码仓并输出初筛候选漏洞",
    )
    parser.add_argument("project_path", help="待分析的 C/C++ 代码仓路径")
    parser.add_argument(
        "--db-path",
        default=None,
        help="指定索引数据库路径（默认使用临时文件）",
    )
    args = parser.parse_args()

    project_path = Path(args.project_path).resolve()
    if not project_path.is_dir():
        print(f"错误: 路径不存在或不是目录: {project_path}", file=sys.stderr)
        sys.exit(1)

    # ---- 第一步：解析代码，构建索引 ----
    if args.db_path:
        db_path = Path(args.db_path)
    else:
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db_path = Path(tmp.name)
        tmp.close()

    print(f"[1/3] 解析代码仓: {project_path}")
    print(f"      索引数据库: {db_path}")

    db = CodeDatabase(db_path)
    cpp_analyzer = CppAnalyzer(db)
    cpp_analyzer.analyze_directory(project_path)

    func_count = len(db.get_all_functions())
    print(f"      解析完成: {func_count} 个函数")

    # ---- 第二步：运行静态分析 ----
    print(f"\n[2/3] 运行整数溢出静态分析...")

    analyzer = Analyzer()
    analyzer.on_progress = lambda cur, tot: print(
        f"      进度: {cur}/{tot} 函数", end="\r"
    )

    candidates = list(analyzer.find_candidates(project_path, db=db))
    print()  # 换行（清除进度行）

    # ---- 第三步：输出结果 ----
    print(f"\n[3/3] 分析结果: 共发现 {len(candidates)} 个候选漏洞")
    print("=" * 72)

    if not candidates:
        print("未发现候选漏洞。")
        return

    for i, c in enumerate(candidates, 1):
        print(f"\n{'─' * 72}")
        print(f"候选 #{i}")
        print(f"  文件: {c.file}")
        print(f"  行号: {c.line}")
        print(f"  函数: {c.function}")
        print(f"  类型: {c.vuln_type}")
        print(f"\n{c.description}")

    print(f"\n{'=' * 72}")
    print(f"总计: {len(candidates)} 个候选漏洞")


if __name__ == "__main__":
    main()
