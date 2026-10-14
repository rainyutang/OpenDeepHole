# 部署与 Agent 安装

[文档目录](README.md) · [配置参考](configuration.md) · [扫描使用指南](usage.md)

## 环境要求

Web 服务和 Agent 可以运行在不同机器上。服务端应保留完整源码目录，以便提供规则目录、Agent 下载包和运行时更新包。

| 位置 | 依赖 |
| --- | --- |
| Web 服务 | Python，建议 3.12；安装 `requirements.txt` |
| 前端构建 | Node.js 20、npm；依赖由 `frontend/package-lock.json` 固定 |
| Agent | Python，建议 3.12；安装 `requirements-agent.txt`，其中包含 Semgrep 和 tree-sitter |
| Agent 代码索引 | 支持 JSON 输出的 Universal Ctags |
| Agent 模型调用 | 可用的 OpenCode 兼容程序、Provider 配置与模型凭据 |
| 可选能力 | 本地 CodeGraph CLI 或远端 MCP；Codex 威胁分析方法依赖 Codex CLI |

仓库的 `.python-version` 指定 3.11.9，Docker 运行阶段使用 Python 3.12。服务端依赖与 Agent 依赖分别维护；只运行 Web 服务不需要安装完整 Agent 依赖。

## 从源码启动 Web 服务

在完整仓库根目录执行：

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
npm --prefix frontend ci
npm --prefix frontend run build
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

Windows PowerShell 中将前两条命令替换为：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

随后使用 `python` 执行安装和 Uvicorn 命令。前端构建输出到 `backend/static/`，FastAPI 在启动时挂载该目录；访问 `http://localhost:8000`。

首次启动前可编辑根目录 `config.yaml`：

- `auth.default_admin_username` / `auth.default_admin_password` 只在数据库没有用户时用于初始化管理员，仓库默认值为 `admin` / `admin123`。
- `auth.secret_key` 留空会由各进程生成随机 JWT 密钥；多 Worker 部署必须配置同一个固定密钥，单 Worker 重启后也需要稳定密钥才能继续验证旧 Token。
- `storage.*_dir` 指定数据目录；相对路径按配置文件所在目录解析，运行用户需要写权限。

安装完成后，从 Web UI 登录并修改默认密码。已有数据库中的管理员密码应通过账户密码管理修改，重新修改初始化配置不会重置账号。

不设置 `OPENDEEPHOLE_DATABASE_URL` 时使用 SQLite，运行一个 Worker。PostgreSQL 的连接串、连接池和多 Worker 启动方式见[生产部署](production_scaling.md)。`config.yaml` 的 `server.host/port` 不会覆盖显式 Uvicorn 命令行参数。

### 现有 Docker 文件的限制

仓库保留了 [Dockerfile](../Dockerfile) 和 [docker-compose.yml](../docker-compose.yml)，Compose 声明 PostgreSQL 16、持久卷、8000 端口和 4 个后端 Worker，但当前镜像的 `COPY` 清单未覆盖完整后端运行及 Agent 分发所需资源：

- 缺少 `deephole_client/`、`task_agent/`、`codex_sdk/`；其中后端扫描 API 已直接导入 `deephole_client.scan_modes`。
- 缺少 `agent.yaml`、`run_agent.sh`、`run_agent.bat`、`requirements-agent.txt` 和包内 Windows Ctags 目录，无法生成完整 Agent 下载包。

因此当前版本不能仅运行 `docker compose up --build` 就完成可用部署。本文使用完整源码部署；自建镜像时需补齐上述资源，并为多个 Worker 配置共享的 `auth.secret_key`。

Compose 的 `OPENDEEPHOLE_POSTGRES_PASSWORD` 与连接串中的密码是两个独立配置，修改时必须保持一致。Compose 中保留的 `OPENCODE_MODEL` 不能代替 Web 中的 Agent 模型池配置。

## 安装 Agent

### 下载与本机配置

登录 Web UI，下载 `opendeephole-agent.zip`，解压到拥有待审计代码访问权限的机器。服务端根据当前用户自动填入：

```yaml
server_url: "http://your-server:8000"
agent_name: "my-agent"
owner_token: "下载包自动填入的用户令牌"
```

确认 `server_url` 可从 Agent 访问。若通过 `localhost` 下载后复制到另一台机器，需要改为可访问的服务器地址。`agent_name` 可自行填写，`owner_token` 用于绑定用户。

### 索引与模型工具

Linux/macOS 安装 Universal Ctags：

```bash
# Debian / Ubuntu
sudo apt install universal-ctags

# macOS
brew install universal-ctags
```

Windows 下载包包含 `ctags-p6.2.20260517.0-x64/ctags.exe`，启动脚本优先使用它。Git Bash/MSYS/Cygwin 下的 `run_agent.sh` 同样优先使用包内版本。启动脚本会检查 Ctags 版本与 JSON 输出能力，检查失败会退出。

在 Agent 上安装并配置可用的 OpenCode 兼容程序。可执行文件可以是 `opencode`、`nga` 或完整路径；通过「客户端配置」的 `base.executable` 选择。模型地址和凭据从 Agent 本机的有效 OpenCode 配置读取，配置发现与合并规则见[配置参考](configuration.md#opencode-运行配置)。

### 启动

Linux/macOS 在解压目录执行：

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-agent.txt
bash run_agent.sh
```

Windows 命令提示符中执行：

```bat
python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install -r requirements-agent.txt
run_agent.bat
```

脚本会检查 Python 依赖、Semgrep 和 Ctags，然后启动 Agent 守护进程。它通过 WebSocket 主动连接服务端，不需要在命令行传入项目路径。

可用参数：

| 参数 | 含义 |
| --- | --- |
| `--server URL` | 覆盖 `agent.yaml` 的服务地址 |
| `--name NAME` | 覆盖显示名称 |
| `--config FILE` | 指定配置文件，默认读取 `agent.yaml` |

连接成功后，在 Web「客户端配置」中选择该 Agent，添加并启用至少一个明确的 `provider/model`。新客户端注册时模型列表为空，本地模板或服务端 `OPENCODE_MODEL` 不会自动成为扫描模型。

## 更新与排查

- 服务端从完整源码构建 Agent runtime。任务前可自动同步 `deephole_client/`、`task_agent/`、`codex_sdk/`、`backend/`、`mcp_server/`、包内 Ctags 和 `requirements-agent.txt`；下载包携带 manifest 和文件哈希。
- 本地仍有扫描、复核或验证任务执行时，运行时更新会延后，避免替换正在工作的 Agent 进程。更新启动脚本后需要重新下载 Agent 包。
- WebSocket 单条接收上限默认 64 MiB，可通过正整数环境变量 `OPENDEEPHOLE_WS_MAX_MESSAGE_MB` 调整并重启 Agent。
- 后端日志默认位于 `logs/opendeephole.log`；扫描与模型任务信息也会打印到 Agent 终端。数据位置见[架构与数据存储](architecture.md#数据存储)。
- Agent 启动时还会准备 Codex CLI；安装失败会告警并继续连接。自动安装行为和轻量级威胁分析回退见[配置参考](configuration.md#codex-运行配置)。
