# 本地开发与贡献

[文档目录](README.md) · [框架开发指南](framework_development.md) · [Checker 开发参考](checker-development.md)

## 开发服务器

先按[部署文档](getting-started.md)创建虚拟环境并安装服务端依赖。在仓库根目录启动后端：

```bash
python3 -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

在另一终端启动前端：

```bash
npm --prefix frontend ci
npm --prefix frontend run dev
```

访问 Vite 终端输出的地址，开发服务器将 `/api` 代理到 `http://localhost:8000`。修改 Agent 或分析过程时，还需要在 Agent 环境安装 `requirements-agent.txt` 并运行对应任务。

构建发布用前端：

```bash
npm --prefix frontend run build
```

产物位于 `backend/static/`。根目录 `start.sh` 会停止匹配 `uvicorn backend.main:app` 的已有进程、构建前端并重新启动后端，适合明确需要重启的场景；日常开发可直接使用上面的命令。

## 页面路由

前端使用 React Router 的 `BrowserRouter`，页面状态以 URL 为准。首页扫描名称和“查看”链接在新页签打开详情，保留原页签的列表和筛选；新建、续扫和看板中的跳转在当前页签完成。

| 页面 | 地址 |
| --- | --- |
| 扫描列表 | `/` |
| 登录、注册 | `/login`、`/register` |
| 新建扫描 | `/scans/new` |
| 扫描详情 | `/scans/{scan_id}/{section}` |
| Agent 下载、配置 | `/agents/download`、`/agents/config?agent={agent_key}` |
| 检查器目录、结果看板 | `/checkers`、`/dashboard` |
| 用户管理 | `/admin/users`，仅管理员 |
| 匿名分享、外部集成 | `/shared-scan/{scan_id}/{section}?token=...`、`/public-scan/{scan_id}/{section}?token=...` |

`section` 为 `overview`、`index`、`static`、`threat`、`mining`、`validation`、`fp-review` 或 `issues`。省略栏目时进入 `overview`；`mining` 用 `engine` 查询参数记录引擎，`threat` 用 `view` 记录结果类别，例如 `/scans/123/threat?view=attackTrees`。弹窗、筛选和展开状态不进入 URL。同一扫描切换栏目不重新挂载详情或建立新的 SSE 连接。

浏览器前进、后退遵循当前页签的历史；页面内“返回”在没有站内历史时回首页。受保护页面在登录后恢复原目标地址。旧 `/#/shared-scan/...`、`/#/public-scan/...` 链接自动转换并保留令牌，外部集成接口新返回的 `result_url` 使用路径式地址。

FastAPI 在静态文件不存在时为页面地址返回 `index.html`，API 与缺失资源保留原有错误。更新时需同步部署后端和前端资源，无需数据库迁移或 Agent 更新。反向代理应将页面请求交给后端；若代理自行托管静态文件，需对 HTML 页面请求配置相同的入口回退，并保留 `/api` 和资源文件的错误响应。

## 验证改动

Python 测试按改动范围选择。服务端及 Agent 测试环境可安装两份依赖和测试工具：

```bash
python3 -m pip install -r requirements.txt -r requirements-agent.txt pytest pytest-asyncio
PYTHONPATH=. python3 -m pytest -q tests/test_scan_model_guard.py
```

前端测试命令在 [package.json](../frontend/package.json) 中，例如：

```bash
npm --prefix frontend run test:scan-paths
npm --prefix frontend run test:routing
npm --prefix frontend run test:task-queue
npm --prefix frontend run build
git diff --check
```

路由后端回归为 `PYTHONPATH=. python3 -m pytest -q tests/test_frontend_routes.py tests/test_external_integration_api.py`。

静态 Checker 自测见[规则测试](checker-development.md#本地测试)。真实模型/MCP 集成测试需要对应服务和配置；PostgreSQL 测试需要数据库，已有本机缓存的使用方式见 [PostgreSQL 测试文档](testing-postgres.md)，该缓存并非仓库自带依赖。

代码图谱 MCP 联调可使用仓库的确定性测试服务：

```bash
python3 tests/fixtures/fake_code_graph_mcp.py --port 9010 --marker scan-a
```

在新建扫描中选择远端 URL `http://127.0.0.1:9010/mcp`（该地址从 Agent 机器访问）。双图谱连接与隔离回归位于 `tests/test_scan_code_graph_mcp_integration.py`，需要真实 OpenCode Serve 环境。

只修改文档时，检查相对链接、锚点、示例命令、配置名称与实际实现是否一致即可，无需为文字调整新增业务测试。

## 扩展与提交

1. 根据[扩展类型](framework_development.md#1-先选择正确的扩展类型)选择 Checker、威胁分析方法、挖掘引擎、去误报方法或产品验证器。
2. 将详细用法放在 `docs/` 或对应组件 README，项目首页保留入门和导航。
3. 为行为变更补充相关验证，并更新文档与 [CHANGELOG.md](../CHANGELOG.md)。
4. Pull Request 说明实际问题、变更后的行为和验证结果；提交问题反馈时提供复现步骤与脱敏日志。

新增规则元数据可随目录刷新被发现；Agent 运行时代码通过任务前同步更新。启动脚本变化需重新下载 Agent 包，详见[更新说明](getting-started.md#更新与排查)。
