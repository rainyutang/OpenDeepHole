# 扫描历史存储升级与生产迁移

本文配套 `scripts/migrate_scan_storage.py`。生产数据库在另一台电脑时，将本版本代码和依赖部署到生产电脑，在那里运行命令。开发电脑上的测试数据、数据库文件和迁移进度不需要复制到生产环境。

正文继续使用普通 TEXT/JSON，不增加应用层压缩。历史任务、Prompt、Session、审计报告、人工判定、Token 统计和恢复检查点属于业务历史，不按运行数据的 TTL 删除。

## 迁移前

1. 记录当前发布版本、数据库版本、应用配置位置以及数据目录位置。
2. 对生产数据库做一致性备份，并恢复到一个独立数据库验证备份可用。PostgreSQL 使用该环境现有的 [pg_dump](https://www.postgresql.org/docs/16/app-pgdump.html) 或备份工具；SQLite 使用 [backup API](https://www.sqlite.org/backup.html)，不能在运行中只复制主 `.db` 文件而忽略 WAL。
3. 同时备份扫描恢复依赖的文件和应用配置。数据库备份不能替代项目文件、Agent 工作区或本地尚未确认的报告 outbox。
4. 在恢复出的数据库上先演练本文全部流程，抽查历史扫描详情、报告导出、人工判定、任务 Prompt/Session、Token 面板和继续扫描。
5. 确保磁盘有容纳新旧数据并存及 PostgreSQL WAL 的空间。迁移初期保留旧数据，会暂时增加空间占用。

所有命令均从对应版本的仓库根目录执行，使用已安装该版本依赖的 Python。Linux 中可将 `python` 换为 `python3`。下面的 `config.yaml` 指生产电脑上实际使用的配置文件；该工具将配置里的相对数据路径按配置文件所在目录解析。

## 检查与部署

先将脚本和代码放到生产电脑，进行只读检查：

```console
python scripts/migrate_scan_storage.py --config config.yaml check
```

`--config` 读取明确指定的配置文件；如果服务通过 `OPENDEEPHOLE_DATABASE_URL` 覆盖数据库地址，应改用 `--database-url-env OPENDEEPHOLE_DATABASE_URL`。工具发现文件与运行环境的地址不一致时会停止，避免误操作另一个库。`check` 不执行建表、升级、回填或删除。输出仅包含数量和大小，不包含报告正文和数据库连接密码。请保存这份输出，与迁移后的结果比较。若生产使用环境变量提供数据库连接信息，也可以明确指定环境变量名称：

```console
python scripts/migrate_scan_storage.py --database-url-env OPENDEEPHOLE_MIGRATION_DSN check
```

部署兼容版本后，等待所有后端 worker 都完成更新再开始历史回填。不要同时运行会直接重写旧数据结构的旧版后端 worker。Agent 协议保留兼容路径，可以分批更新 Agent。

如需在应用启动前完成扩展表结构：

```console
python scripts/migrate_scan_storage.py --config config.yaml expand
python scripts/migrate_scan_storage.py --config config.yaml status
```

`expand` 创建兼容表和列。它不会清理扫描历史。应用读取旧扫描时保留旧格式回退路径；历史汇总只有在回填核对成功后才切换。PostgreSQL 使用短锁超时；繁忙时失败可以在低峰期重跑，不要无限提高锁超时。

PostgreSQL 另行执行在线索引准备，再进行回填：

```console
python scripts/migrate_scan_storage.py --config config.yaml indexes
```

索引使用事务外的 `CREATE INDEX CONCURRENTLY`，重跑会恢复本工具留下的无效索引。FP 任务与扫描的外键先以 `NOT VALID` 加入，约束新写入，暂不扫描旧记录。只有处理好历史孤立记录的关联后才能执行 `validate-constraints`，工具不会删除孤立任务。SQLite 不运行这两个 PostgreSQL 专用步骤。

Docker 部署应在生产机器的应用容器内执行对应命令，使脚本使用与后端相同的依赖、配置挂载和数据库网络地址；例如 `docker compose exec <应用服务名> python scripts/migrate_scan_storage.py --database-url-env OPENDEEPHOLE_DATABASE_URL check`。服务名按实际 Compose 配置替换。不要将容器数据库地址照搬到开发电脑。

## 分批回填

先执行少量批次，观察数据库 CPU、写入延迟、锁等待、WAL 和剩余空间：

```console
python scripts/migrate_scan_storage.py --config config.yaml backfill --batches 10
python scripts/migrate_scan_storage.py --config config.yaml status
```

确认负载可接受后持续回填：

```console
python scripts/migrate_scan_storage.py --config config.yaml backfill --until-complete --pause-ms 200
```

默认每批最多 500 条，任务历史的原始快照最多 32 MiB。可以降低 `--batch-rows`、`--batch-bytes`，或增加 `--pause-ms` 来控制负载。按需使用 `--phase tasks`、`--phase bodies` 或 `--phase summaries` 单独执行一个阶段。`bodies` 包含候选/漏洞正文、去误报阶段及结果、已结束的旧验证输出；仍在运行的旧验证和已混合新协议序列的旧投影保留兼容读取，后续自然更新或重跑回填。

进度保存在生产数据库的 `schema_migrations`，每次事务成功后才推进。按 Ctrl+C 中断、终端退出或进程重启后，重新运行相同命令即可续跑，不依赖开发电脑或本地临时进度文件。并发启动的迁移批次通过数据库串行领取进度，不会各自从头重写历史。

遇到格式损坏、超出单批大小限制或验证差异时，工具报错并保留原始数据。不要手工截断 JSON、清空字段或把错误记录标为已完成。超大旧快照需要单独处理；不能通过超过安全上限的批次参数强行迁移。

## 核对与观察

```console
python scripts/migrate_scan_storage.py --config config.yaml verify
python scripts/migrate_scan_storage.py --config config.yaml status
python scripts/migrate_scan_storage.py --config config.yaml check
```

也可指定 `verify --scan-id <扫描 ID>` 检查一个扫描。工具核对历史任务每个版本的正文、计数、终态接收记录、归档重建结果、当前正文引用及已启用的汇总，失败时退出码为 1。核对会逐扫描读取完整历史，建议低峰执行；它不是首屏查询，也不设短请求超时。汇总回填还会比较从原始业务表计算的指标与新汇总，再决定是否启用汇总读取。

原始快照保存在 `scan_legacy_payloads`，包括旧版本未知字段，不会因为新模型未定义这些字段而被丢弃。同一任务、同一版本的不同内容保存为不同记录，严格上报协议中的幂等冲突仍返回错误。

保存检查结果并完成前述页面、导出及恢复流程的抽查。历史孤立 FP 任务会在状态中报告，不能直接当作垃圾删除。确认关联完整后，PostgreSQL 执行：

```console
python scripts/migrate_scan_storage.py --config config.yaml validate-constraints
```

迁移成功条件：`scan-history-v1`、`scan-bodies-v1`、`scan-summaries-v1` 的状态为 `complete`，`remaining_scans`、`remaining_receipts`、`remaining_summaries`、`unverified_archives` 为 0，`verify` 无失败，且人工抽查通过。孤立任务应从备份恢复真实父扫描/关联，不要虚构扫描信息来让核对通过。

## 升级后的复核概览与模型池上报

如果 PostgreSQL 的 `/api/v2/scans/{scan_id}/fp-review/overview` 返回 `column "rowid" does not exist`，需要部署包含概览排序修复的后端。复核任务以 `created_at` 排序，时间相同时 PostgreSQL 使用已有的 `created_order`，SQLite 使用 `rowid`。此修复不需要新增迁移或重建索引；登录页、公开页及复核结果分页共用该查询。

扫描级 `POST /api/agent/scan/{scan_id}/opencode-pool` 返回 `409`、`detail="stale scan execution"`，表示上报的 `agent_session_id` 或 `execution_revision` 与当前扫描执行不一致，服务端已在模型池、Token 写入和 SSE 广播前拒绝该请求。Agent 级 `/api/agent/{agent_id}/opencode-pool` 的 `stale Agent session` 表示 Agent 会话已过期。索引创建本身不会产生这两种业务冲突。

新版 Agent 收到明确的过期响应后，只停止对应身份的模型池上报，包括后续状态变化、心跳和退出补发，并记录一次 `OPENCODE_POOL_DISCARDED_STALE`（目标、原请求会话、执行版本及响应原因）。新执行或新会话会恢复上报，其他扫描和正常任务继续运行。网络错误、5xx 及非过期 409 按普通失败处理，从本次尝试完成后至少等待 2 秒再重试，避免心跳期限过后密集发送。

后端部署后，还需通过现有 Agent runtime 更新流程部署并重启持续发送请求的 Agent，使停报逻辑生效；已经运行的旧 Agent 进程不会因后端升级自动改变重试行为。验收时确认概览正常返回、过期身份只记录一次停报日志、新执行能重新上报，并观察后端不再收到该旧身份的持续请求。

## 清理与回滚

运行数据保留策略与业务历史迁移分别管理。历史重复数据的清理必须独立执行，不能仅凭“回填命令结束”就清空旧字段。

当前终态接收记录的重复正文只有在完成验证、观察满 7 天、正文仍与对应版本完全一致时才具备清理条件：

```console
python scripts/migrate_scan_storage.py --config config.yaml cleanup-receipts
```

该命令分批处理，不删除独立正文版本、原始扫描快照和任何扫描记录。条件不满足时清理数量为 0。原始归档经过逐字段重建核对并观察满 7 天后，可以将其中重复正文替换为版本引用：

```console
python scripts/migrate_scan_storage.py --config config.yaml cleanup-archives
python scripts/migrate_scan_storage.py --config config.yaml verify
```

每次最多处理 500 条/32 MiB，按返回数量重复执行直到为 0。这不是删除历史：未知字段、旧结论、Session、人工标注仍可从归档及引用的正文版本还原。任何核对失败都会阻止该扫描的重复正文清理。业务历史不在后台自动清理范围内。

回滚应优先回到同样支持新旧格式读取的兼容版本。不要把新版本产生的数据直接交给只认识旧字段的古早版本；这类回退需要先停写，并重建旧格式字段或恢复已演练过的备份。恢复备份会影响备份之后产生的数据，必须先保存期间新增的扫描和未确认报告。

本版本提供旧字段重建工具，供确需回到旧存储代码的维护窗口使用：

```console
python scripts/migrate_scan_storage.py --config config.yaml restore-legacy --offline
```

执行前必须停止全部后端 worker、Agent 上报和迁移进程，先做新的备份。`--offline` 是操作人的停写确认，不会代为停止进程。工具逐扫描恢复当前完整任务池、正文、去误报阶段与结果、验证输出和接收记录字段，保留不可变版本、历史归档、删除标记及独立反馈。该步骤按单个扫描重建完整旧对象，会占用该扫描全部历史所需的内存和磁盘；它不适用在线分批回填的 32 MiB 内存目标。可以用 `--scan-id` 在演练库先重建一条。重建失败可在停写状态重跑。之后再次升级时可重新回填与核对。

不要通过回滚重新创建用户已经删除的扫描。删除标记需要随数据库一起保留。

PostgreSQL 常规清理主要使空间可供数据库复用，不保证数据文件立即变小；见 [官方空间回收说明](https://www.postgresql.org/docs/16/routine-vacuuming.html)。本工具不自动执行 `VACUUM FULL`。需要物理缩小时，另行安排维护窗口并准备足够空间。


## 运行数据清理与历史删除

后台运行数据清理默认每分钟通过数据库租约执行一次，总量不超过 1000 行；每类每轮最多 100 行，防止一个积压表占满批次。崩溃后租约可过期接管，进度和错误可通过 `status` 查看。

| 数据 | 默认保留策略 |
| --- | --- |
| 已送达 Agent 命令正文 | 1 天，随后保留元数据 |
| 已送达命令元数据 | 7 天 |
| 失败命令 | 终态后 30 天；旧记录缺终态时间时先记录观察起点 |
| 断开的 Agent session、无依赖 worker | 7 天，仍有未送达命令/活跃扫描/复核/验证则保留 |
| RPC 响应 | 1 天 |
| 恢复 manifest | 按原有过期时间 |
| SSE 传输缓存 | 24 小时、最近 50000 行、128 MiB，按先达到的界限分批回收 |
| 扫描报告、任务正文、Prompt/Session、人工判定、Token、恢复检查点 | 不设 TTL |
| Agent 未确认 outbox | 不设 TTL；收到终态确认才移除 |

SSE 缓存与扫描 `events` 业务日志是两个不同的数据集，回收传输缓存不会删掉历史业务日志。旧接口继续最多返回 200 条日志，但存储不再按这个界限删除旧行，完整历史可以通过事件分页读取。升级也不会清除旧版本已经写入的 Task Agent 事件；旧版本先前已经删除的内容只能从既有备份找回。新 SSE 主要传递资源失效通知；数据库提交后才向本机页面广播，溢出或重连要求页面重新同步。页面资源默认每页 50 条、最多 100 条，需要时显式加载后续页；验证列表只读状态，选择单条时获取正文。

可在实际后端配置中设置：

```yaml
storage:
  maintenance:
    enabled: true
    interval_seconds: 60
    batch_rows: 1000
```

其它保留字段见 `backend/config.py::StorageMaintenanceConfig`。关闭此开关只关闭运行数据 TTL 清理，不取消用户已经明确请求的扫描删除任务。

用户删除扫描时，先在同一事务中检查活跃扫描、去误报、验证状态，再保存删除标记，后台按子表依赖顺序分批删除。进程退出后继续处理；迟到的 Agent 报告得到 `scan_deleted` 终态确认，不会重新创建扫描。独立反馈/工单记录保留。为避免误删共享或恢复依赖文件，这一数据库删除流程保留项目目录；项目文件的磁盘清理需要另行核对目录归属。

## 本地验证与性能证据

迁移、归档核对、回滚重建、增量验证、重复上报、旧版本保护、稀疏漏洞索引及有界清理都有回归测试。PostgreSQL 集成测试只能指向独立测试库：`OPENDEEPHOLE_TEST_POSTGRES_DSN`，不能指向生产库；`test_postgres_store_integration.py` 要求空库。

本机模拟规模的测量及复现命令见 [存储查询基准](database-storage-benchmark.md)。查询提速不等于迁移后数据库文件立即缩小；新旧数据并存、版本索引、独立行开销都可能暂时增加体积。生产验收以恢复出的真实备份库为准。
