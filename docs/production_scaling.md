# 生产环境扩展与迁移指南

## 适用范围

当前生产拓扑按以下规模设计和验证：

- 10–50 个同时打开页面的用户；
- 5–20 个在线 Agent；
- 最多约 10,000 条扫描历史；
- 单次扫描可以包含大量候选点、漏洞、事件、威胁审计任务和验证记录。

SQLite 仍用于单机兼容和开发环境，但只允许一个后端 Worker。生产环境建议使用 PostgreSQL 16 和 4 个后端 Worker。

## 架构边界

### HTTP 与数据库

- 所有同步存储操作都经过有界线程池，不占用 FastAPI 事件循环；SQLite 使用单线程串行执行，PostgreSQL 可按连接池并行执行。
- 登录密码校验、Agent 安装包和运行时压缩等 CPU/文件操作也在后台线程执行，避免拖慢 WebSocket 心跳和 SSE。
- 扫描历史使用稳定游标分页，默认首屏 50 条，不再一次返回全部扫描。
- 扫描详情拆为 overview、候选点、漏洞、事件、威胁审计任务和验证记录等分页接口；overview 同时返回候选审计与威胁审计的完整分状态聚合计数，页面首屏统计不使用第一批分页长度。旧接口保留兼容，但新前端不再用旧接口轮询大对象。
- 响应包含 `X-Request-ID` 和 `Server-Timing`；慢请求和慢存储操作会写入日志。

### Agent 通道

- Agent 协议 v2 将候选点和事件分批上报；候选审计以 `ScanCandidate.idx` 回写唯一状态/结果并据此续扫，旧版按位置组成的 processed key 端点仅保留滚动升级兼容。结束报文只携带终态计数；被下游接受的漏洞投影仍逐条实时上报。v1 单条及 v2 批量事件写入都会确认父扫描存在，扫描缺失时返回结构化 `scan_not_found` 404，避免迟到事件或存储目标不一致暴露为数据库外键 500；Agent 将事件视为 best-effort，权威进度与结果仍由各自接口对账。
- 候选审计终态、漏洞、威胁分析、威胁审计终态、去误报结果、验证终态和扫描完成等权威结果先写入 Agent 本地 SQLite outbox，再尝试 HTTP 上报。网络失败不会反向中断仍在运行的审计；同一扫描按入队顺序补传，只有后端返回 2xx 才删除本地记录。当前 Agent 进程会为正式漏洞保留一次性送达回调：在线时在有序发送拿到响应后继续派发去误报/验证，短暂离线时先让扫描继续并在补传成功后派发。后端按候选索引、漏洞身份、任务 ID/revision、复核 ID/漏洞索引等稳定业务键幂等落库，因此响应丢失后的重放不会产生重复业务结果。
- Agent 的 outbox 位于 `~/.opendeephole/report_outbox.sqlite3`，只包含尚未得到后端确认的记录；成功项不保留历史副本，并在删除后执行增量空间回收，队列清空时截断 WAL。该机制只防止升级后新产生的数据遗漏，不从旧日志反推或补造升级前已经丢失的审计结果。
- Agent 重连时会把当前进程的活动扫描、去误报、验证以及现有 outbox 待发终态身份与服务端持久状态对账。服务端在原扫描、复核和验证行上保存固定大小的 Agent process session 与单调 execution revision：活动任务只换连接，进程重启后缺失的非终态任务原子增加 revision 并从已有检查点恢复；“Agent 断开连接”属于基础设施中断，可以在宽限期后继续恢复。用户手动取消不恢复；如果 Agent 仍把它报告为活动扫描，服务端会在 welcome 后重新发送停止命令，直到客户端任务真正退出。待发终态先补传，旧 revision 的 409 报告直接删除。客户端不新增恢复表、恢复行或完成历史，因此该机制不会扩大 outbox 的持久存储边界。
- OpenCode 模型池仍周期上报累计 token、完成数、总任务数和当前运行/排队等小型快照；完成逻辑任务的 Session ID、成功/失败、错误分类及 Session 尝试轨迹改为按 `(Agent, scan_id, task_id, revision)` 单点上报。服务端通过 WebSocket capability 协商后才启用新模式；旧服务端仍接收旧版累计历史快照，支持先升级服务端再滚动升级 Agent。
- 候选审计和威胁审计的“排队中”只来自真实模型租约等待队列，“运行中”只在取得租约后产生；OpenCode 轻量级威胁分析会先登记一个扫描级“计划中”逻辑任务，首次 Lease 消费同一身份，因此页面连续显示计划、排队、运行和终态而不会重复计数。扫描级快照在首次租约前也包含已配置模型的零值容量行。模型池 POST 会检查非 2xx，失败时每 2 秒以内重试最新快照；首次失败及持续失败的限频采样会写 Agent 日志，恢复后记录恢复日志；若服务端以 413 拒绝，Agent 去除 Prompt 和非身份明细、标记 `details_truncated` 后重发。
- 用户停止扫描时，服务端先持久化取消意图，再通过带 request ID 的命令等待 Agent 有界确认；Agent 按扫描执行身份取消精确归属的 Task Agent 记录和 OpenCode Session，不终止共享 Serve。未收到确认时 API 返回 `agent_stop_state="pending"`，页面明确提示并依赖上述重连对账继续补发；迟到的同 revision 完成报告不能覆盖已持久化的“用户手动停止”。
- 恢复状态通过短期 HTTP manifest 获取，不再把大列表塞进 WebSocket 控制帧。
- 心跳先立即 ACK，持久化最多每 10 秒合并一次，数据库抖动不会直接阻塞心跳响应。
- 服务端先升级后，可继续接受 v1 Agent 一个发布周期。Agent 应逐台更新；手动更新以服务端持久化的扫描、去误报和验证生命周期为准，不中断仍在执行或刚提交的任务。Agent 上报的模型池快照只用于观测，不参与更新阻塞，因此用户停止全部任务后，即使快照短暂残留 `running` / `queued`，下一次调度也会下发更新。新建扫描和续扫仍会在任务命令中携带自动运行时更新，并在任务执行前完成客户端更新。
- WebSocket 断开和后端重启不会直接 `exec` Agent。内部进程替换只由运行时包更新触发，且本地存在扫描、去误报或验证时会延后；日志中的 `RESTART_REQUESTED`/`PROCESS_RESTARTED reason=runtime_update` 可确认该路径。只有 `PROCESS_STARTED reason=initial_or_external_supervisor` 时，需转查 systemd、容器 restart policy、批处理脚本或其它外部守护进程。

### 多 Worker 协调

- Agent 会话、命令、RPC 响应和 SSE 事件以 PostgreSQL 表为权威状态。
- 扫描进入完成、失败或取消终态时，会在同一数据库事务中清空模型池的运行中、排队中和计划中瞬时字段，同时保留完成任务、累计计数和 token 用量；历史终态记录在读取时应用相同规范，终态之后迟到的 Agent 模型池快照也只保存清理后的历史部分。续扫以持久化扫描状态为准并通过条件更新原子抢占，本地 Worker 缓存不能否决合法续扫，并发点击也只会有一个请求下发恢复命令。
- `LISTEN/NOTIFY` 只发送行 ID 并用于唤醒；丢失通知时，每个 Worker 最迟在 5 秒轮询中补读持久化记录。
- Agent 命令采用 claim、最多 3 次投递和崩溃恢复；连接转移到新 Worker 后，待处理命令会跟随新会话。
- PostgreSQL advisory lock 选出单一 leader。leader 仅对超过 120 秒没有有效 Agent 会话的工作执行取消；滚动重启不会把全部运行中扫描直接标错。
- SSE 使用每 Worker 10,000 条有界队列，最多 200 条或 50 ms 一批落库，并支持 `Last-Event-ID` 补放。

## 配置

推荐的生产环境变量：

```bash
export OPENDEEPHOLE_DATABASE_URL='postgresql://opendeephole:URL编码后的密码@db:5432/opendeephole'
export OPENDEEPHOLE_SERVER_WORKERS=4
export OPENDEEPHOLE_POSTGRES_POOL_MIN_SIZE=1
export OPENDEEPHOLE_POSTGRES_POOL_MAX_SIZE=10
```

还可调整：

```bash
export OPENDEEPHOLE_SLOW_REQUEST_SECONDS=1.0
export OPENDEEPHOLE_SLOW_STORE_MS=250
export OPENDEEPHOLE_EVENT_LOOP_PROBE_SECONDS=1.0
export OPENDEEPHOLE_EVENT_LOOP_WARN_SECONDS=0.25
export OPENDEEPHOLE_SERVER_WS_PING_INTERVAL=30
export OPENDEEPHOLE_SERVER_WS_PING_TIMEOUT=120
```

4 个 Worker、每个最大 10 个 psycopg 连接，再加每 Worker 一个通知连接，峰值约 44 个 PostgreSQL 连接。数据库的 `max_connections` 需要为应用、迁移和运维连接留出余量。

仓库的 `docker-compose.yml` 已提供 PostgreSQL 16、健康检查和 4 Worker 默认值。生产部署必须在 `.env` 或密钥系统中同时覆盖 `OPENDEEPHOLE_POSTGRES_PASSWORD` 和与其一致的 `OPENDEEPHOLE_DATABASE_URL`；URL 中的密码需要正确编码 URI 保留字符。不要把密码提交到仓库。

## PostgreSQL 重启恢复

连接池会在每次借出连接前验证连接是否仍然可用，并在执行、取数、提交或回滚失败后解除 Worker 线程与该连接的绑定。失效连接交回连接池后会被丢弃并补建，因此 PostgreSQL 完成重启并重新接受连接后，下一次请求会自动使用新连接，不需要重启后端 Worker。

数据库实际不可用期间，请求仍可能失败或等待到连接池超时。后端不会自动重放失败的 SQL 或结果未知的写事务，避免数据库已经提交但响应丢失时产生重复写入。跨 Worker Agent 命令、通知监听和 SSE 补读循环会在后台持续退避重连；恢复后重新注册 Worker，并从中断前的事件游标继续补读持久化记录。

发布后可执行一次维护窗口冒烟验证：先确认扫描历史和详情可读，只重启 PostgreSQL 并保持所有后端 Worker PID 不变，等待数据库健康检查通过，再确认历史、详情、Agent 命令和 SSE 更新恢复。重启窗口内出现请求错误或超时属于预期，数据库恢复后仍持续报错才属于故障。

## SQLite 迁移到 PostgreSQL

迁移需要短维护窗口。工具只读取 SQLite 的在线快照，包含 WAL 中已提交数据；目标 PostgreSQL 必须为空，工具不会合并或删除目标数据。

1. 先升级服务端代码和 Python 依赖，但暂时仍以 SQLite 单 Worker 运行。
2. 停止新任务提交，等待正在执行的扫描、模型任务、去误报和验证自然结束，然后停止后端写入。
3. 备份 SQLite 文件及其 `-wal`、`-shm` 文件，或备份整个扫描数据目录。
4. 对源库执行只读预检：

   ```bash
   python3 scripts/migrate_sqlite_to_postgres.py \
     --sqlite /path/to/scans.db \
     --dry-run
   ```

5. 创建一个空 PostgreSQL 数据库并执行迁移：

   ```bash
   python3 scripts/migrate_sqlite_to_postgres.py \
     --sqlite /path/to/scans.db \
     --database-url 'postgresql://user:password@db:5432/opendeephole'
   ```

6. 工具完成逐表计数校验后，设置 `OPENDEEPHOLE_DATABASE_URL` 和 `OPENDEEPHOLE_SERVER_WORKERS=4`，先启动服务端。
7. 验证登录、历史首屏、扫描详情、Agent 在线状态和 SSE 后，再让 Agent 逐台在服务端没有活动扫描、去误报或验证任务时更新。

迁移失败时不要向目标库继续写入。修正问题后使用新的空数据库重试；工具会拒绝非空目标，避免形成部分合并数据。

## 反向代理

WebSocket 需要较长的读超时；SSE 必须关闭代理缓冲和缓存。首次枚举 OpenCode Serve 模型的应用等待上限为 120 秒，对应普通 HTTP 路由的代理读取超时也必须高于该值，建议统一设为 180 秒。例如 Nginx：

```nginx
location /api/agent/ws {
    proxy_pass http://opendeephole;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 180s;
}

location ~ ^/api/(public/)?scans?/.*/events$ {
    proxy_pass http://opendeephole;
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 180s;
}

# Agent 首次启动 OpenCode Serve 时，模型枚举最多等待 120 秒。
location ~ ^/api/agent-configs/[^/]+/opencode-models$ {
    proxy_pass http://opendeephole;
    proxy_read_timeout 180s;
}
```

## 观测与告警

管理员可访问 `GET /api/admin/runtime/metrics`。指标是当前命中的 Worker 进程视角，`process.pid` 可用于区分 Worker；生产监控应通过每个实例或多次采集汇总。

重点观察：

- `requests.latency_ms.p95/p99` 和 `requests.slow_total`；
- `store.queue_ms`、`store.execution_ms`、`store.pending` 与 `store.errors`；
- `event_loop.lag_ms` 和 `lag_peak_ms`；
- `stream_events.queue`、`queue_peak`、`dropped` 与 `persisted`；
- 日志中的 `Slow request`、`Slow store operation`、Agent command 重试和 notification listener 重连。

建议初始告警线：事件循环延迟持续超过 250 ms、SSE `dropped` 增长、存储队列持续增长，或请求 p95 持续超过 1 秒。一次瞬时峰值不等同于故障，应结合持续时间和数据库慢查询判断。

## 回滚

回滚前必须停止所有后端写入：

1. 停止 4 Worker 服务；
2. 保留 PostgreSQL 完整备份；
3. 清除 `OPENDEEPHOLE_DATABASE_URL`，将 Worker 数恢复为 1；
4. 使用迁移前的 SQLite 备份启动旧版本。

切换到 PostgreSQL 后新增的数据不会自动回写旧 SQLite。若生产已产生新扫描或人工结论，直接回滚到旧 SQLite 会丢失这部分新增状态，必须先制定反向数据迁移或接受明确的数据截点。

## 验证命令

普通回归：

```bash
python3 -m pytest -q tests/test_scaling_architecture.py tests/test_scan_store_stats.py
npm --prefix frontend run build
```

真实 PostgreSQL 集成测试只允许指向空的临时数据库：

```bash
OPENDEEPHOLE_TEST_POSTGRES_DSN='postgresql://user:password@127.0.0.1:5432/opendeephole_test' \
  python3 -m pytest -q tests/test_postgres_store_integration.py
```

该测试覆盖 schema 初始化、SQLite 迁移、分页详情、并行连接、Agent 会话与命令、RPC、SSE 和 leader advisory lock；测试不会清空目标数据库，并会拒绝非空目标。
