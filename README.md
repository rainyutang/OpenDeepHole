# OpenDeepHole

OpenDeepHole（Web 界面名称为 DeepHole 2.0）是基于静态分析和 AI Skill 的 C/C++ 源码白盒审计平台。Web 服务管理扫描与结果，本地 Agent 在代码所在机器执行威胁分析、漏洞挖掘、去误报和漏洞验证。

[快速开始](#快速开始) · [文档](docs/README.md) · [开发指南](docs/development.md) · [更新日志](CHANGELOG.md)

## 主要功能

- **静态候选与 AI 审计**：通过规则发现代码风险点，再由对应 Skill 审计；支持添加 Checker 和用户 Skill。
- **威胁分析与攻击模式挖掘**：生成价值资产、高风险模块和攻击树，并据此执行漏洞挖掘。
- **多版本分析**：对 2–5 个本地版本进行扫描、跨版本匹配和结果归并。
- **去误报与漏洞验证**：提供对抗式复核、fp-check 复核，以及按产品扩展的验证方法。
- **任务与结果管理**：支持停止、续扫、人工反馈、扫描分享、Markdown/ZIP/CSV 报告和模型 Token 统计。
- **可选 MCP 能力**：按扫描配置 CodeGraph 和知识库连接；未启用时使用文件工具。

静态命中是待审计的候选点，AI 审计和复核结论仍需结合实际代码与运行环境确认。

## 工作方式

```text
Web UI → FastAPI 服务 → 本地 Agent → 静态分析 / AI 模型 / 验证方法
             ↑              │
             └── 事件与结果 ─┘
```

Agent 通过 WebSocket 接收任务，通过 HTTP 上报结果；浏览器通过 SSE 接收进度。服务端支持 SQLite 单 Worker 和 PostgreSQL 多 Worker。

扫描直接读取 Agent 上的代码仓，无需上传完整仓库。审计上下文可能发送给所配置的模型服务，漏洞报告也可能包含代码片段，因此不应将本地 Agent 理解为“源码绝不离开本机”。详见[架构与数据存储](docs/architecture.md)。

## 快速开始

以下从完整源码仓库启动服务，命令在仓库根目录执行。准备 Python（建议 3.12）、Node.js 20 和 npm；Agent 还需要支持 JSON 输出的 Universal Ctags，以及已配置模型访问凭据的 OpenCode 兼容程序。

### 1. 启动 Web 服务

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
npm --prefix frontend ci
npm --prefix frontend run build
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

访问 `http://localhost:8000`。空数据库首次启动会创建管理员，仓库默认账号为 `admin` / `admin123`；首次登录后修改密码，也可在首次启动前修改 `config.yaml` 的 `auth` 配置。默认使用 SQLite，并保持一个后端 Worker。

Windows 环境的虚拟环境激活、PostgreSQL 配置及现有 Docker 文件的使用限制见[部署与 Agent 安装](docs/getting-started.md)。

### 2. 连接本地 Agent

登录后在 Web UI 下载 Agent，解压到代码所在机器。下载包中的 `agent.yaml` 会填入服务地址和当前用户的 `owner_token`；确认该地址能从 Agent 访问。

Linux/macOS 在解压目录执行：

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-agent.txt
bash run_agent.sh
```

Windows 使用 `run_agent.bat`。Linux/macOS 需自行安装 Universal Ctags，Windows 下载包携带 Ctags。完整准备步骤见[Agent 安装](docs/getting-started.md#安装-agent)。

Agent 上线后，在「客户端配置」设置 OpenCode 兼容程序，并添加、启用至少一个明确的 `provider/model`。新注册 Agent 的模型池为空，未配置模型时不能创建或续扫任务。

### 3. 创建扫描

1. 打开「新建扫描」，选择在线 Agent。
2. 填写扫描名称、产品和 **Agent 机器上的项目绝对路径**；扫描模块路径可留空，填写时也必须是绝对路径。
3. 选择标准模式，按需启用漏洞验证、CodeGraph 或知识库，然后开始扫描。
4. 在扫描详情查看进度、候选审计、威胁分析和复核结果。

标准模式固定启用代码风险点引擎、攻击模式引擎、威胁分析和自动去误报。自定义模式及多版本模式见[扫描使用指南](docs/usage.md)。

## 文档

| 内容 | 文档 |
| --- | --- |
| 部署、依赖、登录与 Agent 安装 | [部署与 Agent 安装](docs/getting-started.md) |
| 扫描模式、停止续扫、反馈与导出 | [扫描使用指南](docs/usage.md) |
| 服务端、Agent、模型池与运行配置 | [配置参考](docs/configuration.md) |
| 组件职责、源码数据边界与存储目录 | [架构与数据存储](docs/architecture.md) |
| 本地开发、测试与贡献 | [开发指南](docs/development.md) |
| Checker、静态去重与候选审计 | [Checker 开发参考](docs/checker-development.md) |
| 框架扩展与 Task Agent 接口 | [框架开发](docs/framework_development.md) · [模型任务接口](docs/opencode_task_service.md) |
| PostgreSQL 部署与迁移 | [生产部署](docs/production_scaling.md) · [存储迁移](docs/database-storage-migration.md) |

更多专题见[文档目录](docs/README.md)。

## 开发与贡献

欢迎提交问题反馈、文档改进和 Pull Request。问题反馈请附复现步骤、运行环境和脱敏日志；扩展规则或方法前先阅读[框架开发指南](docs/framework_development.md)，提交时说明变更及验证结果。

主要目录：`backend/` 为 FastAPI 服务，`frontend/` 为 React 前端，`deephole_client/` 为本地 Agent 与分析过程，`task_agent/` 为模型任务框架，`tests/` 为测试。开发启动与检查命令见[开发指南](docs/development.md)。

## 许可证

本项目采用 [MIT License](LICENSE)。
