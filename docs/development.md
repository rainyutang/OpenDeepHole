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

## 验证改动

Python 测试按改动范围选择。服务端及 Agent 测试环境可安装两份依赖和测试工具：

```bash
python3 -m pip install -r requirements.txt -r requirements-agent.txt pytest pytest-asyncio
PYTHONPATH=. python3 -m pytest -q tests/test_scan_model_guard.py
```

前端测试命令在 [package.json](../frontend/package.json) 中，例如：

```bash
npm --prefix frontend run test:scan-paths
npm --prefix frontend run test:task-queue
npm --prefix frontend run build
git diff --check
```

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
