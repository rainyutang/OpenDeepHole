# 数据库容量与性能排查及优化方案

排查日期：2026-09-07。代码基线：`d4cd011`。

本文是实施前的排查报告和优化设计。本次交付包含方案、隔离复现工具、生产 PostgreSQL 只读诊断 SQL；业务代码、数据库结构和生产数据尚未变更。

## 1. 结论与证据边界

优先解决**任务历史重复保存与反复重写、列表统计读取放大、扫描删除残留、缺少数据生命周期**。当前已经有 PostgreSQL、连接池、游标分页和部分事件保留限制，仅增加连接池或继续添加普通索引，无法消除这些开销。

当前 PostgreSQL 实现继承 `SqliteScanStore` 的绝大多数业务方法，因此下文 `backend/store/sqlite.py` 中的业务 SQL 同样作用于生产 PostgreSQL。PostgreSQL 的连接、启动迁移和跨 Worker 协调另在 `backend/store/postgres.py` 实现。

证据分为三类：

- **当前代码确认**：23 张业务表、5 张 PostgreSQL 协调表，及后端、Agent、前端的实际调用链。
- **隔离复现确认**：当前存储方法与任务历史合并函数，在临时 SQLite 库上重现读写放大及删除残留。
- **生产待测**：本次环境未配置生产 DSN，也未连接生产 PostgreSQL。最大表、TOAST 实际占比、膨胀率、慢查询计划、I/O 和可释放磁盘量均不能由本地结果代替。PostgreSQL 建议以仓库部署的 16 系列为基准，现场版本须先确认。

本地现存库约 24.08 MiB，包含 26 个扫描，检查时有 2 条无对应扫描的 `fp_review_jobs`；`scans.opencode_pool` 逻辑文本约 3.13 MiB，`vulnerabilities.function_source` 约 2.94 MiB。该库仍有旧表 `mining_agent_runs`，缺少部分当前新列，**只能作为历史数据和残留问题的旁证，不能作为生产容量样本**。检查只读，没有运行迁移。

## 2. 已确认的问题

| 优先级 | 问题和实际路径 | 对容量或速度的影响 |
| --- | --- | --- |
| P0 | `report_agent_opencode_task()` 写 `opencode_task_reports` 后，调用 `_merge_completed_opencode_tasks()`，再把完整完成历史写进 `scans.opencode_pool` | 同一任务历史同时存在明细表和扫描 JSON；每新增一条终态仍重写已有历史 |
| P0 | `agent_push_opencode_pool()` 把空历史心跳与旧历史合并，然后重新保存并发布 `scan_status`；移除 SSE `completed_tasks` 的判断发生在合并之后 | Agent 已省去历史传输，后端又恢复整份历史；重复产生数据库、序列化、SSE 持久化和跨 Worker 读取开销 |
| P0 | `delete_scan()` 只执行 `DELETE FROM scans`；`fp_review_jobs.scan_id` 没有外键，结果和阶段输出只级联关联复核任务 | 删除扫描后复核任务及其正文残留；单独删除扫描不会回收这些数据 |
| P1 | `list_scans_page()` 使用 `SELECT s.*`，`_row_to_scan_summary()` 解析完整 `opencode_pool`；`get_scan_meta()` 也读取整行 | 列表只显示计数，查询却读取、解析所有历史任务和 Prompt；普通用户分页权限检查也可能重复读取大行 |
| P1 | `_enrich_scan_summaries()` 批量读取本页每个扫描的所有漏洞统计行和复核历史，再在 Python 中计算指标 | 虽然扫描分页为 50 条，工作量仍随这 50 个扫描的漏洞和复核数量增长；不是每页固定 50 行工作量 |
| P1 | `load_scan_overview()` 包含 19 个 `COUNT` 子查询；该方法也被模型池、任务终态等写入接口用来确认扫描状态 | 候选表重复计数 6 次、威胁任务表重复计数 9 次；高频上报也承担详情统计成本 |
| P1 | `scan_candidates.audit_result` 序列化完整 `Vulnerability`，确认结果还投影到 `vulnerabilities`；复核阶段文本既可存在 `fp_review_stage_outputs.markdown`，也可存在 `fp_review_results.stage_outputs` | 源码、分析、报告、阶段文本可能出现多份副本；需按内容与业务语义去重，不能直接删掉其中一份 |
| P1 | 验证每次 `emit_stdout()`/`publish_artifact()` 发送完整快照，后端完整 UPSERT 并通过 SSE 发布；正文同时进入 sections/intermediate、artifacts/code 等字段 | 输出增长时持续重写历史输出；单节截断不能等同于整条记录字节上限 |
| P1 | `agent_commands` 已投递/失败后仍保留完整 `payload_json`；`agent_sessions`、`backend_workers` 没有定期删除历史行 | 扫描、恢复、复核、验证命令中的配置、候选、报告等可永久残留；会话和 Worker 数随重连/重启增长 |
| P1 | SSE 表按全局 `MAX(id)-50000` 清理，在每次写入事务执行；保留的是完整 `data_json` | 正常串行情况下约保留 50,001 行，但不是字节或时间上限；高频大快照仍产生持续 INSERT/DELETE、索引和 WAL 开销 |
| P2 | 详情分页后，`loadDetailResource()` 会循环读完当前页签所需资源；SSE 每 30 秒补拉完整复核结果，运行中另有 10 秒 overview 刷新 | 首屏虽拆分，进入页签仍可拉完全部候选/漏洞/验证；复核正文和阶段输出仍可反复全量读取 |
| P2 | 每个 PostgreSQL Worker 启动都经过 `_bootstrap()`，读取所有扫描名称/引擎 JSON，更新兼容标签，执行候选历史回填 | 无迁移版本账本；启动成本随历史规模增长，多个 Worker 依次执行部分相同工作；不能把历史库重写放进常规启动 |
| P2 | 当前已有分页复合索引，但存在重复/缺失的特定索引 | `idx_scan_stream_events_id` 与其主键重复；`agent_resume_manifests.scan_id` 缺少前导索引；项目引用计数及部分会话/清理查询也需定向补齐 |

源码入口：[业务存储](../backend/store/sqlite.py)、[PostgreSQL 适配](../backend/store/postgres.py)、[Agent 上报 API](../backend/api/agent.py)、[扫描 API](../backend/api/scan.py)、[SSE 持久化](../backend/sse.py)、[跨 Worker 分发](../backend/distributed.py)、[Agent 模型池上报](../deephole_client/reporter.py)、[验证输出](../deephole_client/vulnerability_validation/runtime.py)、[详情分页](../frontend/src/components/ScanStatus.tsx)、[重连补拉](../frontend/src/hooks/useScanSSE.ts)。

### 已有措施应保留

- `events` 每次新写入会保留该扫描最近 200 条；这不是无限增长的单扫描日志表。旧 PostgreSQL 行不会因为新建临时 SQLite Schema 而自动执行 SQLite 的历史日志清理，旧库仍需核对实际数量。
- `scan_stream_events` 已有约 5 万全局 ID 窗口；应优化负载和清理方式，而不是假定完全没有限制。
- 扫描历史已有 `(created_at DESC, scan_id DESC)`、`(user_id, created_at DESC, scan_id DESC)` 游标索引；候选/漏洞已有扫描与索引键约束。
- Agent 心跳已有合并，模型池已有 debounce，终态已使用幂等业务键及本地 outbox。优化应保留离线补传、revision、重连恢复及累计 token 语义。
- 任务历史中保留完整业务 Prompt 和 Session 是当前产品功能。应移到按需明细或归档读取，不能仅保存 `prompt_length` 后永久丢弃正文。

## 3. 全部存储对象与生命周期

以下覆盖当前新库的 28 张表；生产多出的旧表要按实际 catalog 补充清单。

| 表 | 内容、增长维度及当前边界 | 优化方向 |
| --- | --- | --- |
| `scans` | 扫描配置、生命周期、进度、大型模型池 JSON；随扫描增长 | 小型元数据与汇总；热状态与历史明细分离 |
| `scan_candidates` | 候选、metadata、完整审计结果；按扫描/候选键保存；删除扫描级联 | 摘要分页，审计原文引用独立内容，保留无漏洞/失败/去重结论及续扫身份 |
| `vulnerabilities` | 漏洞字段、源码、报告、来源、版本位置；扫描级联 | 检索列与报告正文分离；源码按版本/内容哈希复用 |
| `vulnerability_validations` | 每漏洞当前验证状态与输出/产物；扫描级联 | 状态、分段日志、产物分离；正文按需读取 |
| `events` | 每扫描业务日志，新写入保留 200 条；扫描级联 | 保留条数限制，增加总字节约束和独立清理周期 |
| `processed_keys` | 旧协议位置检查点；扫描级联 | 保留兼容期内的恢复数据；确认不再使用后迁移/归档 |
| `agent_resume_manifests` | 短期恢复 payload，读取有过期校验，新建时清理过期项；扫描级联 | 周期清理替代仅写入触发，补 `scan_id` 索引 |
| `skill_reports` | 扫描/checker/filename 唯一正文；扫描级联 | 保留索引元数据，内容去重/压缩归档 |
| `threat_analysis` | 每扫描一份原始 JSON 产物包；扫描级联 | 按哈希存原始产物，保留恢复和导出能力；不重复广播全文 |
| `threat_audit_tasks` | 威胁任务、路径、状态、来源；扫描级联 | 小型状态与大描述分离，保留当前/被替代任务语义 |
| `feedback_entries` | 跨扫描人工结论、原因、源码；`source_scan_id` 仅追溯字段 | 独立长期业务数据；删除源扫描不应连带删除用户反馈 |
| `fp_review_jobs` | 复核生命周期、总结；当前没有扫描外键 | 修复所有权与删除链，摘要/全文分离 |
| `fp_review_results` | 复核结论、报告和阶段文本；复核任务级联 | 小型结论表与正文引用；保留最新有效结果和历史追溯 |
| `fp_review_stage_outputs` | 分阶段 Markdown；复核任务级联 | 作为阶段正文唯一来源，批量查询，避免每结果额外取数 |
| `git_history_patterns` | 扫描历史模式；扫描级联 | 和扫描归档，不单独无限扩展 |
| `users` | 用户与认证信息 | 核心数据，按用户生命周期管理 |
| `agents` | Agent 配置、目录/探测快照 | 核心配置，正文大小限制；不因扫描归档删除 |
| `scan_config_memories` | 每用户/Agent 配置记忆 | 保留当前值；独立处理已删除用户/Agent 的孤儿项 |
| `agent_opencode_pool_models` | 每 Agent/session/model 状态和累计计数，无过期策略 | 当前会话热表，旧会话聚合；避免每次全行清零再更新同一批行 |
| `scan_opencode_token_usage` | 每扫描/session/model 累计 token；扫描级联 | 保留累计值，差异 UPSERT 替代每次 DELETE+INSERT |
| `agent_opencode_token_usage` | 每 Agent/session/model 累计 token；Agent 级联 | 旧会话按周期聚合，保留总账；计数列评估升级 BIGINT |
| `opencode_task_reports` | 每 Agent/扫描/task/revision 不可变终态及幂等键；扫描级联 | 任务历史唯一权威来源，分页与正文引用；幂等凭据不随正文 TTL 丢失 |
| `announcements` | 公告 | 与扫描量无直接关系，常规管理 |
| `backend_workers` | Worker 心跳，进程重启新增身份 | 只清理不再存活、无命令/会话引用的历史身份 |
| `agent_sessions` | 连接身份与心跳，断开仅标记 | 保留活跃和恢复窗口，周期删除过期且无依赖会话 |
| `agent_commands` | 持久命令、完整 payload、投递状态 | 活跃命令保护；完成后先裁剪大 payload，再按状态保留时间清理 |
| `agent_rpc_responses` | 待读 RPC；消费时删除，新写入清理一天前记录 | 周期过期清理，补时间索引，避免闲置时长期残留 |
| `scan_stream_events` | SSE 全文、全局序号、Worker 来源 | 小型变化通知、时间/字节窗口、后台批量清理、超窗重同步 |

数据库之外还要分别记账：服务端 `storage.projects_dir`、Agent 扫描/复核/验证工作目录、源目录的 `code_index.db`、OpenCode Session 存储、日志、备份和 PostgreSQL WAL。`code_index.db` 由 [index_store.py](../deephole_client/code_graph_build/index_store.py) 放在实际源码目录；它不是后端 PostgreSQL 表。Agent 的 `report_outbox.sqlite3` 只保留未确认上报，成功后删除并增量回收；不能用普通历史 TTL 删除待补传终态。服务端删除项目目录也不等于删除远端 Agent 工作目录。

## 4. 可复现的开销

运行 [隔离复现工具](../scripts/benchmark_scan_storage.py)：

```bash
python3 scripts/benchmark_scan_storage.py
python3 scripts/benchmark_scan_storage.py --tasks 1000
```

工具只创建自动清理的临时 SQLite 库，不读取配置数据库、不接受生产 DSN。默认 50 个扫描，每扫描 500 条完成任务，每任务 2,048 字节合成 Prompt，每扫描 1,000 条最小漏洞记录。以下是第一次运行的结果，单位为未压缩逻辑字节：

| 观察项 | 实测 |
| --- | --- |
| 单扫描完成历史快照 | 1,074,568 bytes，约 1.02 MiB |
| 依次添加 500 个任务时累计 JSON 序列化 | 269,206,024 bytes，约 256.74 MiB |
| 50 条扫描列表读取的模型池字段总量 | 53,728,400 bytes，约 51.24 MiB |
| 列表本体，3 次运行中位数 | 91.64 ms；不含 HTTP、后续统计或 PostgreSQL 网络 |
| 本页漏洞统计读取 | 50,000 行，136.96 ms；仅最小统计字段 |
| overview 内的 COUNT 子查询 | 19 个；不是 19 次网络请求 |
| 空历史心跳合并后 | 仍包含 500 个历史任务，SSE 省略历史条件不成立 |
| 删除扫描后残留 | 复核任务、结果、阶段输出各 1 行 |

工具也输出只取四个标量列的 SQL 参考耗时，它不实现同等 API 功能，不能拿它宣称完整接口加速倍数。累计序列化量不等于物理写入量、WAL 量或生产库大小。追加 N 条任务时持续序列化 1…N 条历史，逻辑工作量随 N² 增长；保留一次最终历史本身只随 N 增长。

第二组将任务数增加到 1,000：最终快照 2,149,070 bytes，累计序列化 1,075,652,276 bytes。任务数翻倍，最终快照约翻倍，累计序列化约增至 4 倍，与上述增长路径一致。

另在隔离存储上直接调用当前两个 Agent API 处理函数，仅替换连接身份解析、存储异步调度与 SSE 接收端：一条合法终态报告产生 1 条任务明细和 1 份扫描 JSON 历史；随后空历史心跳的 SSE 仍带这条历史。此验证覆盖后端处理链，但未启动 HTTP 服务或 PostgreSQL。

## 5. 推荐目标设计

### 5.1 列表、概览和高频写入只访问小型状态

1. 新增扫描汇总投影，包含候选分状态、漏洞总数、有效问题、人工确认、已验证、可续扫项、任务总数/完成数及 `summary_revision`。`scans` 保留稳定查询字段；易变模型状态可独立为 `scan_runtime`，完成历史不放入该行。
2. `list_scans_page()` 显式列出字段，关联汇总，不读取 `opencode_pool`/正文，不把全部漏洞或复核历史加载到 Python。删除当前列表中计算后又被覆盖的原始漏洞 COUNT。
3. 增加小型 `get_scan_execution_state()`/所有权查询；Agent 上报验证扫描身份时不调用带 19 个统计的 overview。完整配置和恢复清单另按操作需要加载。
4. 第一步可将同表多个 COUNT 合并为一次条件聚合；最终由汇总投影服务频繁读取。针对整个扫描的重算放在迁移、对账和修复任务中。
5. 计数更新与权威结果写入同事务，按旧值到新值的差量维护；重复上报不重复加一，旧 execution revision 不更新。并发更新锁定相关业务行/汇总行，不使用读出后无条件覆盖。
6. 最新有效复核结果先形成按真实 `(scan_id, vuln_index)` 的小型投影，再计算指标。沿用 `scan_metrics.py` 的有效结论、失败前缀、人工裁定规则，验证 provisional 对账、稀疏索引和重新复核后的变化。不能把现有“有效问题”替换为简单 `COUNT(confirmed)`。
7. 汇总是可重建投影；记录数据版本及对账时间，支持单扫描重建、抽样与全量后台校验。多 Worker 读取依赖数据库 revision，不能只依赖进程缓存失效。

### 5.2 完成历史单独保存，正文按需读取

1. 复用 `opencode_task_reports` 的 `(agent_key, scan_id, task_id, revision)` 唯一身份；历史写入与小型计数更新原子完成。新快照不再合并、保存或广播历史数组。
2. 增加任务历史分页接口和单任务详情接口。分页默认只返回任务类型、时间、状态、模型、最后 Session、错误分类、revision；完整 Prompt、Session 尝试轨迹按点击展开获取。旧 revision 不覆盖新 revision，成功/失败/超时/取消的 Session 均可查看。
3. SSE 发送任务 ID、revision、变化类型及小型状态；正文更新通过按需 GET 获取。分页游标按稳定序列前进，并明确“最新任务投影”和“全部尝试历史”的区别。
4. 报告、源码、Prompt、阶段 Markdown、威胁分析 JSON 采用内容寻址存储。数据库保留所属用户/扫描、内容哈希、类型、原始字节数、压缩方式与对象位置；相同内容只存一次。
5. 第一阶段可先拆到独立内容表并使用 PostgreSQL TOAST，减少热路径读取和重复字段。需要显著降低数据库容量时，再把冷正文迁到共享对象存储或有备份的共享文件存储。外置是转移字节；**全系统总占用下降还依赖去重、压缩和保留策略**。
6. 通过引用表关联候选审计原文、正式漏洞、复核报告和输出；只有内容哈希相同才复用，保留候选非问题/失败/去重结论，保留人工修订前后的语义。反馈源码按项目版本或内容哈希复用，不能用当前工作区源码替代历史证据。
7. 原始威胁分析产物是续扫输入；迁移需验证 `restore_json_artifacts()` 可重建全部所需文件和 scan scope，不能仅保留渲染后的攻击树摘要。
8. 对象写入校验成功后才提交引用；双读兼容迁移期间的旧字段。对象删除基于全部引用检查及延迟 GC，备份同时覆盖对象与数据库；鉴权以扫描/用户归属为准，内容哈希不能直接成为下载凭证。

### 5.3 验证输出和 SSE 控制写入量

- 验证日志改为带 execution revision 和单调序号的分段追加，短时间批量上报；状态快照仅保留摘要、游标和有限尾部。终态及完整产物仍须可补传和导出。
- 模型池和 token 只更新发生变化的字段/行；token 累计值使用幂等 UPSERT，不做每次 DELETE+INSERT。Agent model 快照只清理本次真正消失的型号，避免同一行先重置后完整更新。
- SSE 事件按实际内容设字节预算，大型字段改为引用；变化通知可合并，权威结果不能因节流丢弃。终态、停止和恢复状态不等待长周期批处理。
- 把 SSE 清理移出请求事务，由维护任务按主键分批处理；保留时间、行数、总字节和最早可回放游标均可观测。
- 客户端游标早于回放窗口、Worker 落后超过窗口或队列丢事件时，明确发送/返回 `resync_required`，重新读取 overview 和已访问资源。不能缩短窗口后静默缺失历史事件。
- 从当前按 sequence 获取 `id > last_id` 的代码推断，跨事务晚提交的较小 ID 存在被跳过的风险，本次没有 PostgreSQL 并发复现。改动事件持久化时应同时验证提交顺序；可采用受控顺序写入或具有提交可见性保障的消费协议。
- 前端保留分页，改为用户展开/滚动时取下一页，筛选与计数由服务端完成。复核增加 summary 与结果分页，合并 overview 的定时刷新和事件触发刷新，页面隐藏时停止周期补拉。

### 5.4 完整删除和数据保留

建议策略是**默认长期保留结论及证据，自动归档旧正文，有限保留瞬时状态**。以下天数为待现场流量与业务保留要求校准的初始建议，不代表当前已有配置。

| 数据 | 建议初始策略 | 必须满足的条件 |
| --- | --- | --- |
| 扫描结论、人工反馈、漏洞报告、累计 token | 长期保留；支持显式删除和项目保留规则 | 归档后仍能查看、导出、追溯 |
| 终态扫描大正文 | 终态且最近活动超过 30 天转冷存储 | 扫描、复核、验证均不活跃；恢复所需检查点可还原；固定/待处理项目排除 |
| 已投递命令 | 1 天后去除大 payload，保留小型投递摘要 7 天 | 确认终态，不在 pending/delivering，不再被恢复引用 |
| 失败命令 | 保留诊断信息 30 天后删除 | 重试已结束；删除前保留必要错误摘要 |
| 已断开的 Agent 会话、过期 Worker | 7 天 | 无活跃命令、会话或恢复依赖 |
| RPC / manifest | 沿用各自过期时间，按分钟周期回收 | 活跃请求与恢复宽限期保护 |
| SSE | 初始 24 小时，叠加总字节/条数上限 | 流量决定实际可回放窗口；超窗必须显式重同步 |
| Agent 旧 session 模型统计 | 30 天后汇总 | 历史统计、健康隔离与累计 token 不丢失、不重复累加 |

删除实施顺序：

1. 查询数据库中的扫描、复核、验证持久状态，在多 Worker 下原子取得删除资格；不能只用 `_running_scans` 判断。
2. 先修复 `fp_review_jobs.scan_id` 的所有权约束。清点现存孤儿，按项目/备份核对后处理；PostgreSQL 外键可先 `NOT VALID` 约束新写入，历史处理后再 `VALIDATE CONSTRAINT`。
3. 对小扫描，在同一事务删除附属数据；大扫描采用标记删除、阻止新写入、按子表有界批量删除、最后删除父行的任务。直接一次级联数百万行可能形成大事务和 WAL 峰值。
4. 幂等删除重试必须可恢复；对象引用、共享项目目录及扫描级 SSE 由同一生命周期任务对账。反馈独立保留。
5. `opencode_task_reports` 的正文可以归档，但不能按较短 TTL 丢掉幂等身份/摘要：Agent outbox 的离线补传目前没有固定最大延迟。已删除扫描的迟到权威报告，需要明确墓碑/终止补传协议，防止服务端永久 404、客户端永久保留待传数据。
6. 维护任务用数据库锁或租约实现单一执行者并支持接管，记录游标、批次、删除行数、释放的逻辑字节、错误和最后成功时间。按耗时/I/O 自适应批量，不能每请求全表清理。

## 6. PostgreSQL 定向调整

### 查询和索引

先采集计划及实际索引，不执行统一“全部加索引”：

- `agent_resume_manifests(scan_id)`：补充外键删除检查的前导索引。
- `scans(project_id)`：支持删除后的项目引用计数；项目页面查询是否复用需核对。
- `agent_sessions(name, user_id, last_seen DESC)`：候选，用于真实 `get_live_agent_session_by_name()` 查询；评估只覆盖未断开会话的部分索引。
- `agent_commands(claimed_at, id) WHERE status='delivering'`、终态清理使用的时间索引：根据恢复/清理计划建立，保留现有 `(target_worker,status,id)` 投递索引。
- `agent_rpc_responses(created_at)`、未来 SSE 时间清理索引：随相应清理 SQL 一起评估。
- `vulnerabilities(scan_id, source_task_id)`：仅在任务关联查询的扫描内扫描量较大时增加。
- 任务历史新查询按 `(scan_id, task_id, revision, sequence)` 等真实访问方式评估；不能盲目把巨大的 `task_json`/Prompt 放进 INCLUDE 或 GIN 索引。
- 核对并移除明确重复的 `idx_scan_stream_events_id`。其它被复合主键前缀覆盖的单列索引，结合大小、实际使用、约束依赖再决定；`idx_scan=0` 本身不足以证明可删除。

线上大表索引构建应使用适合线上写入的迁移步骤，例如 `CREATE INDEX CONCURRENTLY`，放在事务块外，监控锁等待和无效索引后再切换。[PostgreSQL 16 索引文档](https://www.postgresql.org/docs/16/sql-createindex.html)

### 空间和维护

- 分别度量主表、TOAST、索引、WAL/复制槽、归档及备份。`pg_total_relation_size` 已含附属 TOAST 和索引，不重复相加；数据库大小和磁盘总使用量不是同一指标。[容量函数](https://www.postgresql.org/docs/16/functions-admin.html)
- 对 `scans`/未来 runtime、SSE、命令、验证等写热点及其 TOAST，观察更新/删除速率、dead tuples、autovacuum 延迟与长事务，再按表调整阈值和成本预算。小固定规模但高 churn 的 SSE 表不能只看当前行数。dead tuples 估计不是精确膨胀率。
- 普通 `VACUUM (ANALYZE)` 主要让旧版本空间可复用，通常不会让数据库文件明显缩小；`VACUUM FULL` 重写表、需要额外空间并持排他锁。先停止重复写入和处理保留策略，再安排需要的物理收缩；不能把 `VACUUM FULL` 当在线定时清理。[PostgreSQL 16 VACUUM 说明](https://www.postgresql.org/docs/16/routine-vacuuming.html)
- PostgreSQL 已自动对大 TEXT 使用 TOAST 压缩/外置；仅把所有 JSON TEXT 改成 JSONB 不会消除重复历史和全量覆盖。可对真实样本比较压缩算法、独立内容表和对象存储，不能直接承诺压缩百分比。[TOAST 机制](https://www.postgresql.org/docs/16/storage-toast.html)
- 保持每 Worker 的线程池和连接池有界。当前默认 4 Worker × 10 池连接，另有每 Worker 一个通知连接，合计约 44；leader 的 advisory lock 长期占用池内一个连接，应计入可用并发预算。只有确认连接等待而非 I/O/锁等待是瓶颈，才增加池容量。
- 当前 SQLite 兼容 DDL 把部分计数映射到 PostgreSQL `INTEGER`；累计 token、长周期总数需要评估 BIGINT。时间目前为 TEXT，新增保留字段宜使用规范 UTC 时间类型；历史时间转换需独立校验。
- 分区作为后续选项，优先考虑时间驱动的短期事件表；要配合时间条件与归档策略。直接给全部扫描表按月分区会涉及唯一约束、外键和无时间条件的扫描详情查询，不能作为第一步。[分区约束与裁剪](https://www.postgresql.org/docs/16/ddl-partitioning.html)

## 7. 生产只读诊断与容量基线

使用 [diagnose_postgres_storage.sql](../scripts/diagnose_postgres_storage.sql)。默认只查询 catalog、大小、统计及监控视图，设置会话只读、每语句 10 秒超时和 1 秒锁超时；不初始化应用、不执行迁移、不清数据、不创建扩展、不输出 SQL 正文或业务正文。

```bash
# 通过已有 libpq service/.pgpass 配置连接信息，避免把密码写进命令或仓库。
psql -X -d 'service=opendeephole_prod' \
  -f scripts/diagnose_postgres_storage.sql > /tmp/odh-db-catalog.txt

# 可选：低峰或恢复副本，额外采样大字段，并统计孤儿、命令/SSE payload。
psql -X -d 'service=opendeephole_prod' -v details=1 \
  -f scripts/diagnose_postgres_storage.sql > /tmp/odh-db-detail.txt
```

非 `public` schema 追加 `-v app_schema=实际名称`。监控数据完整性取决于现场账户权限。脚本为 PostgreSQL 16 编写，本次环境没有 PostgreSQL/psql，**尚未在 PostgreSQL 上执行验证**；执行前由运维确认版本和只读账户。任何查询超时或权限错误会退出，已输出部分仍可用于第一轮判断。

采样使用 1% 数据页、最多 200 行/列，小表可能采不到；采样逻辑字节不能直接推算整表磁盘量。生产进一步需要：

1. 在业务高峰前后各采一轮，结合统计重置时间计算增量，记录每小时新增扫描/候选/任务数量。
2. 捕获历史首屏、深游标、overview、任务终态、模型池上报、删除六类调用的 store 和 HTTP p50/p95/p99；现有 `/api/admin/runtime/metrics` 是单 Worker 视角，按进程汇总。
3. `pg_stat_statements` 有条件时按总耗时、调用次数、读块、临时写入、WAL 取 Top SQL。扩展不存在时脚本跳过；启用需现场配置和必要的重启安排，不由诊断脚本代办。[官方统计扩展说明](https://www.postgresql.org/docs/16/pgstatstatements.html)
4. 对代表性只读查询在恢复副本执行 `EXPLAIN (ANALYZE, BUFFERS, SETTINGS)`；生产可先用不执行语句的 EXPLAIN。写入 `EXPLAIN ANALYZE` 会真实执行，不能直接对生产删除/更新语句运行。
5. 数据库外记录 `pg_wal`、归档、备份、项目、Agent 工作区的独立大小；复制槽保留和归档失败先按对应原因修复。

容量估算按各类数据分别计算：

`在线存储 = 保留的有效数据 + 重复副本 + 表/TOAST旧版本与空闲页 + 索引`。

`实例磁盘 = 在线存储 + WAL + 归档/备份 + 其它文件`。

新设计的冷正文仍有存储成本；以去重后的新增正文/天 × 保留天数、短期事件字节/秒 × 实际窗口，以及重写/索引构建所需临时空间做容量规划。拿到生产样本前不给出“节省 80%”或固定倍数提速的承诺。

## 8. 分阶段实施、迁移与验收

| 阶段 | 交付 | 完成条件 |
| --- | --- | --- |
| A：基线和止住放大 | 生产诊断；小型身份读取；完成历史与热快照解耦；SSE 大字段改引用；删除残留修复 | 新任务只追加自身明细，心跳不重写历史；删除链覆盖复核；保留完整 Prompt/Session |
| B：固定查询成本 | 汇总投影；列表显式列；overview 条件聚合/汇总读取；FP summary/分页；前端按需加载 | 页面查询读取量不再随已完成历史/正文大小线性增加；统计与权威明细一致 |
| C：控制长期容量 | 内容去重、冷正文归档、命令/会话周期清理、验证日志分段 | 新扫描单位持久化字节稳定；过期瞬时数据可回收；旧扫描可查看、导出、恢复 |
| D：历史回收 | 分批迁移、按表 vacuum/索引维护、必要的维护窗口收缩 | 迁移计数/哈希/恢复校验完成；物理容量与增速达到基线约定 |

历史迁移采用扩展、回填、切读、停止旧写、清理旧字段的顺序：

1. 建立 `schema_migrations`，单迁移执行器加数据库锁记录版本；常规 Worker 启动只做轻量兼容检查。大规模数据回填不在所有 Worker 的启动路径执行。
2. 先加新表/列/索引和双读能力，部署服务端兼容层；保留 v1/v2 Agent 的旧输入，由服务端转换为统一新存储。
3. 按主键游标分批导入 `scans.opencode_pool.completed_tasks` 等历史；老任务可能不在明细表，必须先恢复任务身份、revision、Prompt/Session 和累计计数。批次有断点、失败记录、校验和和限速。
4. 幂等回填不能覆盖实时较新 revision。以扫描级版本/锁保证同一扫描的新写入与切换不会互相丢失；重试不重复计数。
5. 在恢复副本和少量扫描上对比列表、报告、最终结论、token、归档读取、跨版本位置及续扫。后台逐扫描核对行数与内容哈希后切换读路径。
6. 观察一个约定兼容窗口后才清空旧大字段/删除冗余索引，最后执行物理空间维护。回滚需保留双读/新表及完整备份；旧字段清除或对象迁移后，不能直接回退到只认识旧列的程序。

建议验收矩阵：

- **规模**：1,000/10,000/100,000 个历史扫描；每扫描 100/1,000/10,000 条任务；正文小/大两组；同时间戳游标、深页、管理员/普通用户分别测。
- **并发**：仓库现有 10–50 用户、5–20 Agent 作为起始负载，增加同时上报和删除/归档负载；记录硬件、数据库版本、缓存冷热与网络延迟，不混用不同环境的结果。
- **性能目标**：在约定生产等价负载下，50 条历史首屏与常用 overview 的 p95 先以 500 ms 为目标，终态写入 p95 以 250 ms 为目标；更关键的是固定页面查询返回行数/字节和每新增任务写入量不随历史任务数增长。绝对延迟门槛以基线校准。
- **容量目标**：热快照不包含完成历史或完整 Prompt；单任务追加只产生自身内容与固定状态变更；归档前后按关系总大小、对象存储、WAL 增量分别记账，SSE/命令保留窗口稳定。
- **一致性**：outbox 重放、响应丢失、同 revision 重复/冲突报告、旧 session/revision、并发任务终态、人工修改、取消后迟到结果、恢复/重跑、provisional 转正式、FP 更新都不多计、不漏计。
- **回放和删除**：跨 Worker 晚提交事件、队列丢事件、Last-Event-ID 超窗有重同步；删除活跃扫描/验证被阻止，大扫描中断删除可继续，复核/正文引用无孤儿，人工反馈保留。
- **归档/回滚**：旧扫描完整 Prompt/Session、报告和原始威胁产物可读可恢复；模拟对象暂不可用、迁移中断及切读回滚，不清掉唯一副本。
- **数据库恢复**：PostgreSQL 重启后连接池恢复；不重放结果未知的数据库事务；跨 Worker 汇总与 SSE 恢复不引入旧状态覆盖。

本次已完成代码排查、500/1,000 任务隔离复现、API 处理链复现、文档链接检查、28 张当前表的清单覆盖检查及诊断 SQL 中 20 个应用采样列的 Schema 对照。生产基线采集、业务实现、PostgreSQL 诊断 SQL 实际执行、线上迁移和生产验收属于后续实施工作，不能把本文的本地测量视为已解决生产性能问题。
