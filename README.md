# OpenDeepHole

基于 SKILL 的 C/C++ 源码白盒审计工具。核心漏洞挖掘在用户本地 Agent 上执行，源码不离开本机，结果汇报到 Web 服务器统一展示。

## 整体架构

```
[服务器端]
  FastAPI (port 8000)
  ├── Web UI（React + Tailwind CSS）
  ├── 接收 Agent 注册、心跳、扫描事件、扫描结果
  ├── 存储扫描历史和误报反馈
  ├── 向 Agent 下发扫描任务（新建扫描时推送）
  └── 提供 Agent 下载包

[用户本地]
  opendeephole-agent（守护进程，从 Web UI 下载）
  ├── 启动后向服务器注册，保持心跳
  ├── 等待服务器推送扫描任务
  ├── 收到任务后：代码索引 → 静态分析 → AI 审计
  └── 实时将事件和漏洞结果上报服务器
```

**交互流程：**

```
用户在 Web UI 点击「新建扫描」
  → 选择在线 Agent、填写代码路径（Agent 所在机器的路径）、选择检查项
  → 服务器推送任务到 Agent
  → Agent 在本地执行完整扫描流程
  → 进度和结果实时显示在 Web UI
```

**源码不离开本地**：Agent 只上报漏洞分析结论，不上传源码文件。  
**误报反馈闭环**：用户在 Web UI 标记误报后，Agent 下次扫描前自动拉取这些经验，注入 SKILL 中减少重复误报。

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

**第 1 步：下载安装包**

打开 Web UI，点击右上角 **「下载 Agent」**，保存 `opendeephole-agent.zip`，解压到本地目录。

**第 2 步：配置 agent.yaml**

```yaml
# Web Server 地址
server_url: "http://your-server:8000"

# Agent 监听端口（确保防火墙放行）
agent_port: 7000

# Agent 显示名称（显示在新建扫描的下拉列表中）
agent_name: "my-agent"

# LLM API 配置（供 mode: api 的检查项使用）
llm_api:
  base_url: "https://api.anthropic.com"
  api_key: "your-api-key-here"
  model: "claude-sonnet-4-6"

# opencode CLI 配置（供 mode: opencode 的检查项使用）
opencode:
  executable: "opencode"
  timeout: 300
```

> 每个检查项的调用方式（`api` 或 `opencode`）在其 `checker.yaml` 中独立配置，无需全局 `mode` 选项。

**第 3 步：启动 Agent 守护进程**

```bash
# Linux / macOS
chmod +x run_agent.sh
./run_agent.sh

# Windows
run_agent.bat
```

启动成功后，终端输出类似：

```
OpenDeepHole Agent Daemon
  Name    : my-agent
  Server  : http://your-server:8000
  Port    : 7000

  Registered as agent_id: a1b2c3d4...
```

Agent 常驻后台等待任务，无需每次手动启动。

**第 4 步：在 Web UI 创建扫描任务**

1. 点击右上角「新建扫描」
2. 从下拉列表选择已在线的 Agent
3. 填写代码路径（Agent 所在机器上的绝对路径，如 `/home/user/myproject`）
4. 选择要运行的检查项，点击「开始扫描」
5. 扫描进度实时显示在当前页面

### Agent 启动参数

```
./run_agent.sh [选项]

选项：
  --server URL        覆盖 agent.yaml 中的 server_url
  --port INT          覆盖监听端口（默认 7000）
  --name NAME         覆盖 Agent 显示名称
  --config FILE       指定配置文件路径（默认 ./agent.yaml）
```

### 停止与恢复扫描

- **停止**：在扫描详情页点击「停止扫描」，服务器直接通知 Agent 停止。当前候选处理完成后立即停止，已处理的结果保留。
- **恢复**：在扫描列表页点击「恢复」，服务器通知 Agent 继续同一扫描任务，自动跳过已处理的候选，从断点继续。无需重新启动 Agent 或重新索引代码。

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

每个 Checker 独立配置 `mode`，同一次扫描中不同 Checker 可使用不同调用方式。

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

Checker 在服务端启动时自动发现，Agent 下次扫描即可使用新 Checker。

## 配置说明

### 服务端 config.yaml

```yaml
server:
  host: "0.0.0.0"
  port: 8000

storage:
  projects_dir: "/tmp/opendeephole/projects"
  scans_dir: "/tmp/opendeephole/scans"

logging:
  level: "INFO"
  file: "logs/opendeephole.log"
```

### Agent agent.yaml

```yaml
# Web Server 地址
server_url: "http://your-server:8000"

# Agent 守护进程监听端口
agent_port: 7000

# Agent 显示名称（留空则使用主机名）
agent_name: ""

# 代理跳过列表，逗号分隔
no_proxy: ""

# 要运行的检查项，留空则运行全部已启用的检查项
checkers: []

# LLM API 配置（供 mode: api 的检查项使用）
llm_api:
  base_url: "https://api.anthropic.com"
  api_key: "your-api-key-here"
  model: "claude-sonnet-4-6"
  temperature: 0.1
  timeout: 120
  max_retries: 3

# opencode CLI 配置（供 mode: opencode 的检查项使用）
opencode:
  executable: "opencode"
  model: ""      # 留空则使用 opencode 默认模型
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
│   ├── main.py            # 守护进程入口（启动 uvicorn + 注册 + 心跳）
│   ├── server.py          # Agent HTTP 服务（接收任务、停止、恢复）
│   ├── task_manager.py    # 任务生命周期管理（创建/停止/恢复）
│   ├── scanner.py         # 完整扫描流程（索引→静态分析→AI审计→上报）
│   ├── reporter.py        # 向服务器上报进度和结果
│   └── local_mcp.py       # opencode 模式：本地启动 MCP Server
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
│   │   ├── agent.py       # Agent 专用 API（注册/心跳/注销/任务下发/结果接收/下载包）
│   │   ├── scan.py        # 扫描管理 API（新建/停止/恢复/查询）
│   │   ├── feedback.py    # 误报反馈 CRUD
│   │   └── checkers.py    # Checker 列表 API
│   ├── registry.py        # Checker 自动发现与注册
│   ├── analyzers/base.py  # 静态分析器基类
│   └── opencode/          # opencode CLI + LLM API 集成
├── mcp_server/            # MCP Server（Agent opencode 模式本地启动）
├── agent.yaml             # Agent 配置模板
├── run_agent.sh           # Agent 守护进程启动脚本（Linux/macOS）
├── run_agent.bat          # Agent 守护进程启动脚本（Windows）
├── requirements-agent.txt # Agent 最小依赖
├── config.yaml            # 服务端全局配置
├── start.sh               # 服务端一键启动脚本
├── Dockerfile
└── docker-compose.yml
```

## License

MIT
