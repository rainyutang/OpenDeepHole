# OpenDeepHole

基于 SKILL 的 C/C++ 源码白盒审计工具。通过静态分析找到候选漏洞点，再由 AI（opencode + skills）进行深度语义分析。

## 架构

```
单 Docker 容器
├── MCP Server (port 8100) — 常驻进程，提供源码查询工具
└── FastAPI (port 8000) — 后端 API + 前端静态文件（React + Tailwind CSS）
    └── opencode CLI — 由后端 subprocess 调用，通过 MCP 工具访问源码
```

### 扫描流程

1. 用户上传源码 zip，选择扫描项
2. **代码解析**（后台异步）：`CppAnalyzer` 用 tree-sitter 全量解析源码，结果存入 SQLite（`code_index.db`）
3. 扫描等待解析完成后，静态分析器从 `CodeDatabase` 查询数据，找到候选漏洞点
4. 每个候选点传递给 opencode，指定对应 skill + MCP 工具（MCP 工具也从同一 `CodeDatabase` 读取）
5. AI 深度分析，判断是否为真实漏洞
6. 汇总结果，前端展示漏洞列表，支持下载报告

## 插件式 Checker 架构

漏洞类型以插件形式组织在 `checkers/` 目录下，添加新类型无需修改代码：

```
checkers/<name>/
├── checker.yaml    # 必须：name, label, description, enabled[, mode, skill_name]
├── SKILL.md        # opencode 模式必须：opencode skill 定义
├── prompt.txt      # api 模式必须：LLM 系统提示词
└── analyzer.py     # 可选：静态分析器（导出 Analyzer 类，继承 BaseAnalyzer）
```

**内置 Checker：**

| Checker | 说明 | 模式 | 静态分析器 |
|---------|------|------|-----------|
| `npd` | 空指针解引用 (NPD) | opencode | 有（tree-sitter AST 分析） |
| `oob` | 数组/缓冲区越界 (OOB) | opencode | 有 |
| `memleak` | 异常分支内存泄漏 (MEMLEAK) | api | 有（自定义解析器） |
| `intoverflow` | 整数翻转/溢出 (INTOVFL) | opencode | 有（多阶段追踪） |
| `sensitive_clear` | 敏感信息未清零 (SENSITIVE_CLEAR) | opencode | 有 |

### 添加新 Checker

**第 1 步：创建目录和元数据**

```bash
mkdir checkers/uaf
```

创建 `checkers/uaf/checker.yaml`：

```yaml
name: uaf
label: UAF
description: Use-After-Free
enabled: true
# mode: opencode       # 可选，默认 opencode；设为 api 则使用 prompt.txt + LLM 直接调用
# skill_name: uaf-audit # 可选，opencode 模式下自定义 skill 名称
```

**第 2 步：编写 SKILL.md**

参考 `checkers/npd/SKILL.md` 模板，编写 opencode skill 定义。SKILL.md 指导 AI 如何分析该类漏洞，必须要求 AI 输出 ````json:result` 格式块。

**第 3 步（可选）：编写 analyzer.py**

如果需要静态分析预筛选候选点，创建 `checkers/uaf/analyzer.py`。如果不提供，该 checker 会跳过静态分析阶段。

**第 4 步：重启服务**

```bash
# 本地开发
pkill -f uvicorn
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Docker
docker-compose restart
```

Checker 在后端启动时自动发现注册，前端通过 `GET /api/checkers` 动态获取列表，无需重新构建前端。

### 编写 analyzer.py 指南

analyzer.py 是可选的静态分析器，用于在 AI 审计前预筛选候选漏洞点。

**基本结构：**

```python
from __future__ import annotations
from pathlib import Path
from typing import TYPE_CHECKING
from backend.analyzers.base import BaseAnalyzer, Candidate

if TYPE_CHECKING:
    from code_parser import CodeDatabase


class Analyzer(BaseAnalyzer):
    vuln_type = "uaf"  # 必须与 checker.yaml 的 name 一致

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> list[Candidate]:
        if db is None:
            return []
        candidates = []
        functions = db.get_all_functions()
        total = len(functions)
        for idx, func in enumerate(functions):
            # 进度回调（可选，用于前端进度条）
            if self.on_file_progress:
                self.on_file_progress(idx + 1, total)
            body = func["body"] or ""
            if not body:
                continue
            # ... 分析逻辑 ...
            candidates.append(Candidate(
                file=func["file_path"],
                line=func["start_line"],
                function=func["name"],
                description="检测到可疑模式...",
                vuln_type=self.vuln_type,
            ))
        return candidates
```

**约定和要求：**

- 类名**必须**是 `Analyzer`（registry 按此名称动态加载）
- **必须**继承 `BaseAnalyzer`
- `vuln_type` **必须**与 `checker.yaml` 中的 `name` 字段一致
- `find_candidates()` 接收项目根目录路径，返回 `Iterable[Candidate]`（列表或 generator 均可）
- 可以 `from backend.analyzers.base import BaseAnalyzer, Candidate` 一次性导入所需类

**Candidate 字段说明：**

```python
Candidate(
    file="src/main.c",      # 相对于项目根目录的文件路径
    line=42,                 # 漏洞所在行号
    function="process_data", # 漏洞所在函数名
    description="...",       # 漏洞描述（传递给 AI 的上下文）
    vuln_type="uaf",         # 漏洞类型（与 checker name 一致）
)
```

**CodeDatabase API 参考（`code_parser/code_database.py`）：**

当 `db` 参数非 `None` 时，可通过以下方法查询预构建的代码索引。所有查询方法返回 `list[sqlite3.Row]`，通过 `row["field_name"]` 访问字段。

| 方法 | 说明 | 返回字段 |
|------|------|---------|
| `db.get_all_functions()` | 获取所有函数（按文件和行号排序） | function_id, name, signature, return_type, start_line, end_line, is_static, linkage, body, file_path |
| `db.get_functions_by_name(name)` | 按名称精确匹配函数 | 同上 |
| `db.get_function_body(name)` | 获取第一个匹配函数的函数体 | 返回 `str \| None` |
| `db.get_calls_from_function(function_id)` | 查询指定函数发出的所有调用 | call_id, caller_function_id, callee_name, callee_function_id, line, column, file_path |
| `db.get_call_sites_by_name(callee_name)` | 查询指定函数名的所有被调用点 | 同上 + caller_name |
| `db.get_structs_by_name(name)` | 按名称查询结构体/类定义 | struct_id, name, start_line, end_line, definition, file_path |
| `db.get_global_variables_by_name(name)` | 按名称查询全局变量 | global_var_id, name, start_line, end_line, is_extern, is_static, definition, file_path |
| `db.get_global_variable_reference_by_name(name)` | 查询全局变量的所有引用点 | reference_id, variable_name, function_id, line, column, context, access_type, file_path, function_name |

**tree-sitter 辅助工具（`code_parser/code_utils.py`）：**

如需在 analyzer 中对函数体进行 AST 分析，可结合 tree-sitter 和以下辅助函数：

| 函数 | 说明 |
|------|------|
| `find_nodes_by_type(root_node, node_type, k=0)` | 递归查找所有指定类型的节点（DFS，最大深度 100） |
| `get_child_node_by_type(root_node, node_type: list)` | 返回第一个类型匹配的直接子节点 |
| `get_child_nodes_by_type(root_node, node_type: list)` | 返回所有类型匹配的直接子节点 |
| `get_child_field_text_by_type(root_node, field_name, node_type: list)` | 获取指定字段的文本（仅当字段节点类型匹配时） |
| `get_child_field_text(root_node, field_name)` | 获取指定字段的文本 |

使用示例：

```python
import tree_sitter_cpp
from tree_sitter import Language, Parser
from code_parser.code_utils import find_nodes_by_type

_CPP = Language(tree_sitter_cpp.language())
parser = Parser(_CPP)

tree = parser.parse(func_body.encode())
# 查找所有函数调用节点
for call in find_nodes_by_type(tree.root_node, "call_expression"):
    callee = call.child_by_field_name("function")
    if callee:
        print(callee.text.decode())
```

**常见模式：**

*1. 遍历所有函数并分析*

```python
for func in db.get_all_functions():
    name = func["name"]
    body = func["body"] or ""
    file_path = func["file_path"]
    start_line = func["start_line"]
    # 对函数体进行模式匹配或 AST 分析...
```

*2. 查询调用关系*

```python
# 查找所有 malloc 调用点
for call in db.get_call_sites_by_name("malloc"):
    print(f"{call['file_path']}:{call['line']} — 调用者: {call['caller_name']}")

# 查找某函数内部调用的所有函数
for call in db.get_calls_from_function(func["function_id"]):
    print(f"  调用了 {call['callee_name']} at line {call['line']}")
```

*3. Generator 模式（流式产出）*

`find_candidates` 可返回 `Iterator[Candidate]`，通过 `yield` 流式产出候选项，让 LLM 提前开始处理：

```python
from collections.abc import Iterator

def find_candidates(self, project_path: Path, db=None) -> Iterator[Candidate]:
    if db is None:
        return
    for func in db.get_all_functions():
        # ... 分析 ...
        yield Candidate(file=func["file_path"], ...)
```

*4. 进度回调*

```python
functions = db.get_all_functions()
total = len(functions)
for idx, func in enumerate(functions):
    if self.on_file_progress and idx % 20 == 0:  # 每 20 个函数更新一次
        self.on_file_progress(idx + 1, total)
```

*5. 不依赖 db 的分析*

也可跳过 db，直接遍历文件系统进行自定义解析（如 memleak checker）：

```python
def find_candidates(self, project_path: Path, db=None) -> list[Candidate]:
    candidates = []
    for src in project_path.rglob("*.c"):
        source = src.read_bytes()
        tree = self._parser.parse(source)
        # 自定义 AST 分析...
    return candidates
```

**实现建议：**

- 推荐使用 `db` 查询而非直接遍历文件系统（性能更好，且与 MCP Server 共享同一索引）
- Generator 模式适合耗时较长的分析器，可让 LLM 提前开始处理已发现的候选项
- `on_file_progress` 回调用于前端进度条显示，建议在循环中定期调用
- `description` 字段尽可能详细，它会作为 prompt 的一部分传递给 AI
- `mode: api` 的 checker 使用 `prompt.txt` 而非 `SKILL.md`，适用于无需 MCP 工具的场景
- 返回空列表是合法的，表示未找到候选点

## 快速开始

### Docker 部署

```bash
docker-compose up --build
```

访问 http://localhost:8000

### 本地开发

```bash
# 后端
pip install -r requirements.txt
python3 -m mcp_server.server &    # 启动 MCP Server
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# 前端（开发模式）
cd frontend
npm install
npm run dev
```

### 服务管理

```bash
# 查看日志
cat logs/opendeephole.log        # 文件日志
tail -f logs/opendeephole.log    # 实时跟踪
```

注意：使用 `--reload` 参数时，修改 `backend/` 下的 Python 文件会自动重载，但 `checkers/` 目录下的变更**不会**自动重载（因为 registry 在启动时一次性加载），需要手动重启。

### 重启服务（修改 MCP Server / 后端 / 添加新 Checker 后）

修改 MCP Server 代码、后端代码、或新增/修改 `checkers/` 下的漏洞类型后，需要重启对应服务才能生效：

```bash
kill $(lsof -t -i:8000) $(lsof -t -i:8100) 2>/dev/null; sleep 1; python3 -m mcp_server.server & uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

**什么时候需要重启：**

| 修改内容 | 需要重启的服务 |
|---------|--------------|
| `mcp_server/` 下的代码 | MCP Server（端口 8100） |
| `backend/` 下的代码 | 后端会自动热重载（`--reload`），通常无需手动重启 |
| `checkers/` 下新增或修改 checker | 后端（端口 8000），因为 registry 仅在启动时加载一次 |
| `checkers/` + `mcp_server/` 同时修改 | 两个都需要重启 |

**Docker 环境下：**

```bash
docker-compose restart
# 或完全重建
docker-compose up --build
```

## 配置

编辑 `config.yaml` 修改端口、存储路径、opencode 模型、日志级别等配置。

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `OPENCODE_MODEL` | AI 模型 | `anthropic/claude-sonnet-4-20250514` |
| `ANTHROPIC_API_KEY` | Anthropic API Key | - |

## 项目结构

```
OpenDeepHole/
├── checkers/              # 插件目录（每种漏洞类型一个子目录）
│   ├── npd/               # checker.yaml + SKILL.md/prompt.txt + analyzer.py
│   ├── oob/
│   ├── memleak/
│   ├── intoverflow/
│   └── sensitive_clear/
├── code_parser/           # 共享 C/C++ 代码解析器
│   ├── code_database.py   # SQLite 代码索引（函数/结构体/全局变量/调用关系）
│   ├── cpp_analyzer.py    # tree-sitter C++ 解析器
│   ├── code_utils.py      # tree-sitter 节点遍历辅助函数
│   └── code_struct.py     # 解析结果数据类
├── frontend/              # React + TypeScript + Vite + Tailwind CSS
├── backend/
│   ├── api/               # FastAPI 路由（upload, scan, checkers）
│   ├── registry.py        # Checker 自动发现与注册
│   ├── analyzers/base.py  # 静态分析器基类（含可选 db 参数）
│   └── opencode/          # opencode CLI 集成
├── mcp_server/            # MCP Server（源码查询工具，使用 code_index.db）
├── config.yaml            # 全局配置
├── Dockerfile
└── docker-compose.yml
```

## License

MIT
