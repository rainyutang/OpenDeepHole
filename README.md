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
├── checker.yaml    # 必须：name, label, description, enabled
├── SKILL.md        # 必须：opencode skill 定义
└── analyzer.py     # 可选：静态分析器（导出 Analyzer 类，继承 BaseAnalyzer）
```

**内置 Checker：**

| Checker | 说明 | 静态分析器 |
|---------|------|-----------|
| `npd` | 空指针解引用 (Null Pointer Dereference) | 占位（待实现） |
| `oob` | 数组/缓冲区越界 (Out-of-Bounds Access) | 占位（待实现） |

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
        # project_path 是用户上传的源码解压后的绝对路径
        # db 是可选的预构建代码索引，可通过 db.get_functions_by_name() 等方法查询
        candidates = []
        if db:
            # 使用代码索引快速查询（推荐）
            for func in db.get_all_functions():
                pass  # 分析函数...
        # 也可以直接读文件（不依赖 db）
        return candidates
```

**约定和要求：**

- 类名**必须**是 `Analyzer`（registry 按此名称动态加载）
- **必须**继承 `BaseAnalyzer`
- `vuln_type` **必须**与 `checker.yaml` 中的 `name` 字段一致
- `find_candidates()` 接收项目根目录路径，返回 `Candidate` 列表
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

**实现建议：**

- 可使用 tree-sitter 进行 AST 查询，或 joern 进行程序分析
- 也可使用简单的正则匹配作为初步筛选
- `description` 字段尽可能详细，它会作为 prompt 的一部分传递给 AI
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
# 重启后端（添加新 checker 后需要重启）
pkill -f uvicorn
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# 查看日志
cat logs/opendeephole.log        # 文件日志
tail -f logs/opendeephole.log    # 实时跟踪
```

注意：使用 `--reload` 参数时，修改 `backend/` 下的 Python 文件会自动重载，但 `checkers/` 目录下的变更**不会**自动重载（因为 registry 在启动时一次性加载），需要手动重启。

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
│   ├── npd/               # checker.yaml + SKILL.md + analyzer.py
│   └── oob/
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
