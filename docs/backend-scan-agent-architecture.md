# 扫描管理与 Agent 后端结构

本次拆分从 `8158fbf` 开始，保留已有 HTTP、WebSocket、SSE 协议和数据库格式。客户端执行入口仍为 `deephole_client/scanner.py`；这里管理的是服务端扫描记录、任务派发、结果接收和 Agent 连接。

## 模块归属

| 位置 | 职责 |
| --- | --- |
| `backend/api/scan.py`、`backend/api/agent.py` | 保持原路由入口，按原匹配顺序装配子路由 |
| `backend/api/scan_routes/`、`backend/api/agent_routes/` | HTTP 参数、用户身份、URL、下载响应和服务调用 |
| `backend/scans/` | 扫描配置、权限、创建、续扫、查询、复核、验证、反馈、报告和事件流 |
| `backend/scans/ingestion/` | Agent 回传的候选、漏洞、事件、进度、产物和终态对账 |
| `backend/agents/` | Agent 身份和连接、通信、RPC、配置、MCP、模型查询、重连协调及运行包升级 |
| `backend/application.py` | 可注入的应用运行状态、存储执行边界、事件发布和业务异常 |
| `backend/api/dependencies.py`、`backend/report_routes.py` | HTTP/WS 运行上下文绑定、业务错误到 HTTP 的转换、删除后历史回报确认 |

共享页面、外部平台集成、CodeGraph 和审查笔记同步直接调用服务。业务层不导入 `backend.api`；HTTP 返回类型不进入业务层。报告服务返回 `DownloadArtifact`，路由构造 `Response`。

## 运行状态与依赖

每个后端 worker 在应用 lifespan 内创建一个 `BackendRuntime`，或使用预先注入应用状态的实例。请求通过应用状态绑定这个实例，后台任务继承创建时的上下文。`use_runtime(runtime)` 允许测试或非 HTTP 调用明确指定实例；`get_runtime()` 读取当前绑定。无应用 lifespan 的工具调用仍可使用默认进程实例。SSE 订阅和跨 worker 广播沿用进程级 `backend.sse` 总线，每个 worker 部署一个应用实例。

- `runtime.scans` 持有运行中扫描、所有者和索引进度缓存。
- `runtime.agents` 持有本地连接、发送锁、配置兼容缓存、心跳/断线任务、RPC 等待对象和运行包下载 token。
- 数据库保存执行版本、会话归属和生命周期状态；内存缓存不能替代持久化 claim 或版本校验。
- `store`、`store_runner`、`config_factory`、`publisher` 和断连处理回调可注入。服务使用 application 的存储边界；默认执行器继续采用 SQLite 单线程和 PostgreSQL 有界并行。
- 传入存储执行器的可调用操作保留运行上下文，避免线程池内的辅助函数读取另一个应用实例。
- 关闭时先停止调度器和分布式任务，再取消并等待剩余连接维护任务、清理 RPC 等待对象，最后关闭存储。

测试应创建独立 runtime，注入临时 store、可控发送端和发布器。需要 mock 业务函数时修改实际调用模块中的绑定；原路由模块的私有函数和字典已不再是测试接口。

## 创建、续扫与恢复

创建扫描按 Agent 选择、配置解析、身份与验证配置、路径预检、构建记录、持久化和派发分阶段执行。`ResolvedScanConfiguration` 保存解析后的配置，路径预检仍先于扫描写入。

续扫先由 `ResumePlan` 计算需要执行的候选、威胁分析、引擎和独立复核工作，再执行 Agent 准备、claim、状态重置、命令构造与派发。`ResumeCheckpoint` 保存失败补偿所需的原阶段和候选状态。历史候选索引、已完成结果、执行版本和用户停止优先级保持原语义。

连接服务通过 `ReconnectState` 传递接管结果。WebSocket 发送 welcome 后启动后台恢复，并立即进入接收循环；恢复可以等待 stop RPC，接收循环持续处理回执和心跳。心跳仍先更新内存并 ACK，再合并持久化。

`AgentGateway` 负责连接解析、命令发送和 RPC；`RpcBroker` 在成功、发送失败、超时、取消和异常时释放等待对象。`LocalAgentTransport` 只执行当前 worker 的本地发送，分布式消费者使用它投递已领取的命令，避免再次入队。

## 行为兼容与修复

路由路径、方法、顺序、默认参数、响应模型和 OpenAPI 均与原始版本比较。扫描产物、复核结果、分页、SSE 重放及 v1/v2 回传格式保持兼容。运行包的文件选择规则、hash scope 和哈希算法保持不变；因源码文件发生变化，实际运行包内容与哈希会正常更新。

本次同时修复经原始版本复现的问题：

1. 创建扫描派发返回失败时残留 owner 缓存；派发抛异常时还会遗留 pending 扫描和运行缓存。现在统一标记失败、清理两个缓存并返回 502。
2. MCP 探测发送命令抛异常或取消时遗留 Future。发送和等待纳入同一个资源清理范围。
3. 已删除扫描的 FP review `stage-output` 回报未匹配历史回报保护器。现在返回 `discarded: scan_deleted`，与其他复核回报一致。

测试和性能的实测结果见 [重构验证记录](backend-scan-agent-validation.md)。性能测试采用固定数据与受控 Agent，不调用真实模型；结果用于比较服务端开销，不能外推为实际漏洞扫描耗时。
