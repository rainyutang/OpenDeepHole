# OpenDeepHole

基于 SKILL 的 C/C++ 源码白盒审计工具。核心漏洞挖掘在用户本地执行，结果汇报到 Web 服务器统一展示。

## 整体架构

```
[服务器端]
  FastAPI (port 8000)
  ├── Web UI（React + Tailwind CSS）
  ├── 接收 Agent 上报的扫描结果
  ├── 存储扫描历史和误报反馈
  └── 提供 Agent 下载包

[用户本地]
  opendeephole-agent（从 Web UI 下载）
  ├── 代码索引（tree-sitter → SQLite）
  ├── 静态分析（checker 插件）
  ├── AI 审计（直接调 LLM API 或本地 opencode CLI）
  └── 将漏洞结果上报服务器
```

**源码不离开本地**：Agent 只上报漏洞分析结论，不上传源码文件。  
**误报反馈闭环**：用户在 Web UI 标记误报后，Agent 下次运行时自动拉取这些经验，注入 SKILL 中减少重复误报。

## 快速开始

### 部署服务器

**Docker（推荐）：**

```bash
docker-compose up --build
```

**本地运行：**

```bash
pip install -r requirements.txt
cd frontend && npm install && npm run build && cd ..
./start.sh
```

访问 `http://localhost:8000`

### 下载并运行 Agent

1. 打开 Web UI，点击右上角 **「下载 Agent」**，保存 `opendeephole-agent.zip`

2. 解压，编辑 `agent.yaml`：

```yaml
server_url: "http://your-server:8000"

mode: "api"   # 直调 LLM API（推荐）；或 "opencode"（需本地安装 opencode CLI）

llm_api:
  base_url: "https://api.anthropic.com"
  api_key: "your-api-key-here"
  model: "claude-sonnet-4-6"
```

3. 运行 Agent：

```bash
# Linux / macOS
chmod +x run_agent.sh
./run_agent.sh /path/to/your/project --name "MyProject"

# Windows
run_agent.bat C:\path\to\your\project --name "MyProject"
```

4. 回到 Web UI 查看实时扫描进度和漏洞结果。

### Agent 命令行参数

```
./run_agent.sh <项目路径> [选项]

选项：
  --server URL        覆盖 agent.yaml 中的 server_url
  --checkers LIST     指定 checker，逗号分隔，如 npd,oob,uaf
  --name NAME         扫描在 Web UI 显示的名称（默认为目录名）
  --config FILE       指定配置文件路径（默认 ./agent.yaml）
  --dry-run           本地执行，不向服务器上报结果
```

## 误报反馈机制

1. 在 Web UI 的漏洞列表中，将误报标记为「误报 (false_positive)」
2. Agent 下次扫描前自动拉取 `GET /api/agent/feedback`
3. 这些误报经验被注入到对应 SKILL 文件的「历史误报经验」章节
4. LLM 在分析同类候选时参考这些经验，减少重复误判

## 插件式 Checker 架构

漏洞类型以插件形式组织在 `checkers/` 目录下，添加新类型无需修改代码：

```
checkers/<name>/
├── checker.yaml    # 必须：name, label, description, enabled, mode
├── SKILL.md        # opencode 模式必须；定义 AI 分析技巧
├── prompt.txt      # api 模式可选；自定义系统提示词
└── analyzer.py     # 可选：静态分析器（导出 Analyzer 类，继承 BaseAnalyzer）
```

**checker.yaml 格式：**

```yaml
name: uaf
label: UAF
description: "Use-After-Free 检测"
enabled: true
mode: "api"         # "api"（直调 LLM）或 "opencode"（使用 opencode CLI）
single_pass: false  # api 模式：是否跳过工具调用，单轮输出结论
```

**内置 Checker：**

| Checker | 说明 |
|---------|------|
| `npd` | 空指针解引用 (Null Pointer Dereference) |
| `oob` | 数组/缓冲区越界 (Out-of-Bounds Access) |
| `uaf` | Use-After-Free |
| `intoverflow` | 整数翻转/溢出 |
| `memleak` | 内存泄漏 |

### 添加新 Checker

**第 1 步：创建目录和元数据**

```bash
mkdir checkers/mycheck
```

`checkers/mycheck/checker.yaml`：

```yaml
name: mycheck
label: MYCHECK
description: "我的自定义漏洞检测"
enabled: true
mode: "api"
```

**第 2 步（api 模式）：编写 prompt.txt**

```
你是专业的 C/C++ 漏洞审计专家。请分析以下函数是否存在 XXX 漏洞...
```

**第 2 步（opencode 模式）：编写 SKILL.md**

参考 `checkers/npd/SKILL.md`，定义分析步骤和可用 MCP 工具。

**第 3 步（可选）：编写 analyzer.py**

```python
from __future__ import annotations
from pathlib import Path
from typing import TYPE_CHECKING
from backend.analyzers.base import BaseAnalyzer, Candidate

if TYPE_CHECKING:
    from code_parser import CodeDatabase


class Analyzer(BaseAnalyzer):
    vuln_type = "mycheck"  # 必须与 checker.yaml 的 name 一致

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> list[Candidate]:
        candidates = []
        if db:
            for func in db.get_all_functions():
                # 静态分析逻辑...
                pass
        return candidates
```

**约定：**

- 类名**必须**是 `Analyzer`
- **必须**继承 `BaseAnalyzer`
- `vuln_type` **必须**与 `checker.yaml` 中的 `name` 一致
- 无 analyzer.py = 跳过静态分析，返回 0 个候选（合法）

**第 4 步：重启服务端**

```bash
./start.sh
```

Checker 在服务端启动时自动发现，Agent 下次运行即可使用新 Checker。

## 配置说明

### 服务端 config.yaml

```yaml
server:
  host: "0.0.0.0"
  port: 8000

storage:
  projects_dir: "/tmp/opendeephole/projects"
  scans_dir: "/tmp/opendeephole/scans"
  max_upload_size_mb: 2048

logging:
  level: "INFO"
  file: "logs/opendeephole.log"
```

### Agent agent.yaml

```yaml
server_url: "http://your-server:8000"
mode: "api"            # "api" 或 "opencode"
checkers: []           # 空列表 = 运行所有已启用 checker

llm_api:               # mode: "api" 时使用
  base_url: "https://api.anthropic.com"
  api_key: "your-api-key"
  model: "claude-sonnet-4-6"
  temperature: 0.1
  timeout: 120
  max_retries: 3

opencode:              # mode: "opencode" 时使用
  model: ""            # 空 = 使用 opencode 默认模型
  timeout: 300
```

## 本地开发

```bash
# 后端（含热重载）
pip install -r requirements.txt
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# 前端开发服务器（代理到 localhost:8000）
cd frontend
npm install
npm run dev

# 构建前端
npm run build

# 查看日志
tail -f logs/opendeephole.log
```

> **注意：** 修改 `checkers/` 下的内容需重启后端（registry 在启动时一次性加载）。

## 项目结构

```
OpenDeepHole/
├── agent/                 # 本地 Agent Python 包
│   ├── config.py          # agent.yaml 配置加载
│   ├── reporter.py        # 向服务器上报进度和结果
│   ├── scanner.py         # 完整扫描流程（索引→静态分析→AI审计→上报）
│   ├── local_mcp.py       # opencode 模式：本地启动 MCP Server
│   └── main.py            # CLI 入口
├── checkers/              # 插件目录（每种漏洞类型一个子目录）
│   ├── npd/               # checker.yaml + SKILL.md/prompt.txt + analyzer.py
│   ├── oob/
│   ├── uaf/
│   ├── intoverflow/
│   └── memleak/
├── code_parser/           # 共享 C/C++ 代码解析器（tree-sitter + SQLite）
├── frontend/              # React + TypeScript + Vite + Tailwind CSS
├── backend/
│   ├── api/
│   │   ├── agent.py       # Agent 专用 API（注册扫描/上报结果/下载包）
│   │   ├── scan.py        # 扫描管理 API
│   │   ├── feedback.py    # 误报反馈 CRUD
│   │   └── checkers.py    # Checker 列表 API
│   ├── registry.py        # Checker 自动发现与注册
│   ├── analyzers/base.py  # 静态分析器基类
│   └── opencode/          # opencode CLI + LLM API 集成
├── mcp_server/            # MCP Server（Agent opencode 模式本地启动）
├── agent.yaml             # Agent 配置模板
├── run_agent.sh           # Agent 启动脚本（Linux/macOS）
├── run_agent.bat          # Agent 启动脚本（Windows）
├── requirements-agent.txt # Agent 最小依赖
├── config.yaml            # 服务端全局配置
├── start.sh               # 服务端一键启动脚本
├── Dockerfile
└── docker-compose.yml
```

## License

MIT
