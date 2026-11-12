# Scan / Agent 重构验证记录

基线为 `8158fbfd0632bf847ebbe5ee789b79468c577df3` 的 `git archive` 快照；测试所需但未纳入 Git 的 `ThreatAnalysis/` 从同一工作区补入。重构生产代码为 `d62b870`（结构拆分 `2f12619`，bug修复 `d62b870`），验证记录单独提交。日期：2026-11-12。所有结果均为本地验证，未部署。最终末尾空白清理逐文件校验AST等价；运行包数据已按清理后的最终源码刷新。

本地结果：查询、批量回传、重连接管及跨worker的主要耗时接近基线，API/WS回放峰值RSS变化小于1%，相同种子数据的数据库大小和WAL完全相同，Agent ZIP增加1.35%。这不是零开销结论：同步身份桩下8并发RPC尾延迟两轮增加7.0%/12.7%；改用async身份桩后8并发p95为-1.24%，单并发CPU仍增加约23.9µs。profile定位到约20µs/次的结构调用成本，未因此引入额外微优化。所有场景分别披露，不对生产性能或实际扫描总耗时作外推。

## 方法和环境

- Linux / WSL2，12 个逻辑 CPU。SQLite/API 使用 Python 3.12.3、FastAPI 0.135.3、Pydantic 2.12.5；PostgreSQL 使用缓存 Python 3.10.12、FastAPI 0.141.1、Pydantic 2.13.5 与 PostgreSQL 16。
- 基线和重构版本在相同解释器、相同脚本和固定数据下依次交替运行；正式计时期间停止其他测试、构建和基准。SQLite 使用独立临时文件；每个 PostgreSQL 测量新建临时集群，连接池 1–4，仅 Unix socket，测试后删除。
- HTTP/WS 回放使用真实 FastAPI ASGI 路由、序列化和 `run_store_call` 执行器，身份依赖固定为测试管理员，不包含登录、JWT或数据库认证校验耗时。主回放保留同步身份桩（`--auth-mode sync`），会经过FastAPI的依赖线程池；另用与生产依赖相同的异步形态（`--auth-mode async`）单独对照RPC，两个数据集不混合。受控 Agent 通过真实 ASGI WebSocket 收发 hello、welcome、heartbeat 和 RPC 结果；不调用模型。
- 主回放预置 100 个完成扫描、2 个活动扫描（事件和候选分开）、10,000 条任务和每条 1 KiB 的任务正文；事件和候选每批 10 条。每场景分别使用 1 / 8 并发，预热 30 次、每轮 200 次、共 5 轮；表内取 5 轮指标的中位数。延迟从获取并发槽位后计时，吞吐按整轮 wall time。
- 双 worker 回放使用两个独立 Python 进程，HTTP 请求在 A、Agent WS 在 B，命令和 RPC 结果经 PostgreSQL 传递，再等待持久化 SSE 广播到 A 的订阅队列；每轮验证确认 ID 唯一。此项包含持久化事件投递，不包含浏览器端 SSE 文本解析。
- 运行包正式比较使用 `/tmp/odh-package-baseline` 和 `/tmp/odh-package-refactor` 两份新快照，预先排除旧 `__pycache__` 后由同一解释器导入，消除工作区与 `/tmp` 的文件系统及历史缓存差异；原工作区比较保留为诊断数据，最终归档数字以 `*-package-samefs.json` 为准。
- 重连回放准备 8 个独立 Agent（不同 machine_name，并断言 agent_key 唯一），各带 1 个活动扫描、1 个 FP review 和 1 个 validation，测量 hello 到 welcome、心跳 ACK 和断连；验证扫描执行版本被接管，不把后台恢复全部完成时间计入。
- 存储基准复用 `benchmark_scan_storage.py`，10,000 个扫描、100,000 条任务，其中一个扫描 10,000 条任务；两版本都使用现有规范化存储，均不使用 `--legacy`。该项每场景 1 次预热、200 次串行采样，沿用原脚本的 `jit=off` 与在线索引准备；API 回放使用 PostgreSQL 默认 JIT 设置。两版统一禁用日志，避免 dashboard 重复发现 checker 的大量日志输出影响计时。
- heartbeat 计时关注 ACK 热路径；持久化仍由原有合并写入机制执行，不把每个 ACK 解释为一次数据库写入。
- CPU 为测量进程的 CPU 时间，未包含数据库 CPU；双 worker 另列远端进程总 CPU。RSS 使用 Linux `/proc/self/status` 的 VmHWM，包含导入、初始化和数据准备，不是请求增量。避免使用提权启动器可能遗留的 exec 前 `ru_maxrss` 峰值。store calls 为执行器调用数，不等于 SQL 条数；event loop lag 为 5 ms ticker 的超期量。

## 性能结果

### SQLite HTTP / WS

延迟单位 ms；CPU 为 ms/次，吞吐为次/秒；Δ 为 `(新版 / 基线 − 1) × 100%`，p95 为负表示延迟减少。

| 场景 / 并发 | p50 基线 → 新版 | p95 基线 | p95 新版 | p95 Δ | 吞吐 基线 → 新版 | CPU 基线 → 新版 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| scan_list / 1 | 2.77 → 2.82 | 4.01 | 3.99 | -0.3% | 330.96 → 329.24 | 3.05 → 3.07 |
| scan_list / 8 | 21.01 → 21.46 | 29.13 | 30.06 | +3.2% | 328.96 → 319.54 | 3.14 → 3.22 |
| scan_overview / 1 | 6.25 → 6.43 | 7.83 | 8.12 | +3.8% | 153.27 → 149.22 | 6.53 → 6.71 |
| scan_overview / 8 | 37.23 → 37.40 | 52.72 | 57.55 | +9.1% | 158.90 → 150.88 | 6.38 → 6.70 |
| task_page / 1 | 41.55 → 41.45 | 49.80 | 47.27 | -5.1% | 22.92 → 23.59 | 43.86 → 42.59 |
| task_page / 8 | 332.78 → 336.87 | 347.52 | 350.90 | +1.0% | 23.93 → 23.62 | 42.13 → 42.66 |
| batch_events_10 / 1 | 4.72 → 4.65 | 6.11 | 6.00 | -1.7% | 202.36 → 209.74 | 1.61 → 1.49 |
| batch_events_10 / 8 | 15.90 → 16.47 | 19.97 | 20.06 | +0.5% | 485.93 → 471.90 | 1.31 → 1.36 |
| batch_candidates_10 / 1 | 1.21 → 1.24 | 1.84 | 1.77 | -4.2% | 770.96 → 759.21 | 1.31 → 1.34 |
| batch_candidates_10 / 8 | 9.77 → 10.68 | 12.74 | 13.20 | +3.6% | 734.52 → 687.51 | 1.43 → 1.52 |
| mixed_overview_events / 1 | 5.72 → 6.03 | 7.54 | 8.21 | +8.8% | 175.38 → 165.78 | 4.05 → 4.29 |
| mixed_overview_events / 8 | 35.93 → 39.98 | 47.92 | 49.68 | +3.7% | 211.90 → 189.94 | 4.73 → 4.86 |
| local_rpc_models / 1 | 0.544 → 0.586 | 0.817 | 0.853 | +4.4% | 1673.65 → 1561.80 | 0.597 → 0.640 |
| local_rpc_models / 8 | 3.01 → 3.32 | 6.44 | 6.89 | +7.0% | 1796.84 → 1733.52 | 0.575 → 0.599 |
| heartbeat / 1 | 0.024 → 0.026 | 0.034 | 0.035 | +2.7% | 31055.05 → 28594.40 | 0.032 → 0.035 |
| heartbeat / 8 | 0.131 → 0.124 | 0.242 | 0.330 | +36.1% | 37304.95 → 39664.74 | 0.027 → 0.025 |

### PostgreSQL HTTP / WS

延迟单位 ms；CPU 为 ms/次，吞吐为次/秒；Δ 为 `(新版 / 基线 − 1) × 100%`，p95 为负表示延迟减少。

| 场景 / 并发 | p50 基线 → 新版 | p95 基线 | p95 新版 | p95 Δ | 吞吐 基线 → 新版 | CPU 基线 → 新版 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| scan_list / 1 | 7.24 → 7.33 | 8.98 | 9.18 | +2.3% | 131.79 → 129.41 | 6.03 → 6.11 |
| scan_list / 8 | 67.77 → 68.16 | 83.53 | 81.60 | -2.3% | 115.40 → 114.58 | 10.35 → 10.44 |
| scan_overview / 1 | 10.28 → 10.65 | 12.19 | 12.41 | +1.8% | 94.49 → 91.22 | 9.70 → 10.02 |
| scan_overview / 8 | 73.56 → 74.28 | 104.22 | 108.30 | +3.9% | 86.76 → 85.60 | 13.01 → 13.14 |
| task_page / 1 | 98.97 → 98.76 | 107.53 | 105.92 | -1.5% | 9.98 → 10.03 | 4.73 → 4.76 |
| task_page / 8 | 242.74 → 244.40 | 271.15 | 271.27 | +0.0% | 32.35 → 32.33 | 4.44 → 4.49 |
| batch_events_10 / 1 | 5.57 → 5.58 | 7.26 | 7.34 | +1.0% | 170.52 → 172.19 | 3.70 → 3.67 |
| batch_events_10 / 8 | 54.86 → 56.11 | 63.51 | 64.32 | +1.3% | 143.92 → 140.71 | 8.45 → 8.62 |
| batch_candidates_10 / 1 | 6.71 → 6.87 | 8.41 | 8.48 | +0.9% | 141.45 → 140.22 | 3.75 → 3.79 |
| batch_candidates_10 / 8 | 57.90 → 57.96 | 65.98 | 65.45 | -0.8% | 135.73 → 135.38 | 7.07 → 7.08 |
| mixed_overview_events / 1 | 9.15 → 9.24 | 11.23 | 11.80 | +5.1% | 119.01 → 116.19 | 6.66 → 6.88 |
| mixed_overview_events / 8 | 79.30 → 79.94 | 112.20 | 112.60 | +0.4% | 96.45 → 94.77 | 12.24 → 12.40 |
| local_rpc_models / 1 | 1.46 → 1.56 | 2.15 | 2.54 | +17.8% | 635.23 → 570.78 | 1.47 → 1.64 |
| local_rpc_models / 8 | 20.34 → 20.50 | 24.28 | 24.13 | -0.6% | 387.70 → 383.94 | 3.13 → 3.14 |
| heartbeat / 1 | 0.036 → 0.037 | 0.057 | 0.058 | +2.6% | 20642.34 → 18818.32 | 0.048 → 0.053 |
| heartbeat / 8 | 0.182 → 0.178 | 0.298 | 0.450 | +51.2% | 28499.48 → 28483.48 | 0.035 → 0.035 |

### PostgreSQL 双 worker RPC + 持久化 SSE

延迟单位 ms；CPU 为 ms/次，吞吐为次/秒；Δ 为 `(新版 / 基线 − 1) × 100%`，p95 为负表示延迟减少。

| 场景 / 并发 | p50 基线 → 新版 | p95 基线 | p95 新版 | p95 Δ | 吞吐 基线 → 新版 | CPU 基线 → 新版 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| cross_worker_rpc_sse / 1 | 112.33 → 112.69 | 117.68 | 117.41 | -0.2% | 8.86 → 8.85 | 13.33 → 13.70 |
| cross_worker_rpc_sse / 8 | 116.29 → 121.93 | 147.08 | 148.96 | +1.3% | 68.12 → 67.42 | 8.77 → 9.39 |

### 活动任务重连接管

延迟单位 ms；CPU 为 ms/次，吞吐为次/秒；Δ 为 `(新版 / 基线 − 1) × 100%`，p95 为负表示延迟减少。

| 场景 / 并发 | p50 基线 → 新版 | p95 基线 | p95 新版 | p95 Δ | 吞吐 基线 → 新版 | CPU 基线 → 新版 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| active_reconnect / 1 | 10.36 → 10.53 | 12.49 | 12.49 | -0.0% | 93.03 → 92.82 | 4.99 → 5.05 |
| active_reconnect / 8 | 78.70 → 79.87 | 88.61 | 86.85 | -2.0% | 99.08 → 97.91 | 4.66 → 4.81 |

### 内存和执行器开销

RSS 为整个进程 VmHWM，单位 MiB。该峰值包含数据准备，不能理解为每次请求需要同样内存。

| 回放进程 | 基线 | 新版 | Δ |
| --- | ---: | ---: | ---: |
| api | 97.04 | 96.93 | -0.1% (-0.11 MiB) |
| pg-api | 110.23 | 109.76 | -0.4% (-0.47 MiB) |
| cross-worker | 86.36 | 86.62 | +0.3% (+0.27 MiB) |
| cross-worker 远端 | 78.40 | 78.84 | +0.6% (+0.44 MiB) |
| reconnect | 79.62 | 79.56 | -0.1% (-0.07 MiB) |
| package | 110.81 | 116.14 | +4.8% (+5.33 MiB) |

| 数据库 / 场景 / 并发 | store calls/次 基线 → 新版 | event loop lag p95 基线 → 新版 (ms) |
| --- | ---: | ---: |
| api / scan_list / 1 | 6.00 → 6.00 | 1.09 → 1.06 |
| api / scan_list / 8 | 6.00 → 6.00 | 6.75 → 6.85 |
| api / scan_overview / 1 | 2.00 → 2.00 | 2.87 → 3.27 |
| api / scan_overview / 8 | 2.00 → 2.00 | 42.83 → 45.40 |
| api / task_page / 1 | 2.00 → 2.00 | 0.945 → 0.937 |
| api / task_page / 8 | 2.00 → 2.00 | 1.04 → 0.972 |
| api / batch_events_10 / 1 | 3.00 → 3.00 | 1.09 → 1.07 |
| api / batch_events_10 / 8 | 3.00 → 3.00 | 1.14 → 1.24 |
| api / batch_candidates_10 / 1 | 4.00 → 4.00 | 0.385 → 0.409 |
| api / batch_candidates_10 / 8 | 4.00 → 4.00 | 0.633 → 0.646 |
| api / mixed_overview_events / 1 | 2.50 → 2.50 | 5.59 → 6.27 |
| api / mixed_overview_events / 8 | 2.50 → 2.50 | 24.25 → 21.78 |
| api / local_rpc_models / 1 | 0.000 → 0.000 | 0.514 → 0.438 |
| api / local_rpc_models / 8 | 0.000 → 0.000 | 2.52 → 3.51 |
| api / heartbeat / 1 | 0.000 → 0.000 | 1.09 → 0.937 |
| api / heartbeat / 8 | 0.000 → 0.000 | 0.597 → 0.626 |
| pg-api / scan_list / 1 | 7.00 → 7.00 | 1.55 → 1.55 |
| pg-api / scan_list / 8 | 7.00 → 7.00 | 2.82 → 2.98 |
| pg-api / scan_overview / 1 | 2.00 → 2.00 | 7.24 → 7.60 |
| pg-api / scan_overview / 8 | 2.00 → 2.00 | 64.75 → 65.36 |
| pg-api / task_page / 1 | 2.00 → 2.00 | 0.388 → 0.407 |
| pg-api / task_page / 8 | 2.00 → 2.00 | 0.916 → 0.920 |
| pg-api / batch_events_10 / 1 | 4.00 → 4.00 | 1.12 → 1.09 |
| pg-api / batch_events_10 / 8 | 4.00 → 4.00 | 1.49 → 1.64 |
| pg-api / batch_candidates_10 / 1 | 4.00 → 4.00 | 1.04 → 1.07 |
| pg-api / batch_candidates_10 / 8 | 4.00 → 4.00 | 1.34 → 1.34 |
| pg-api / mixed_overview_events / 1 | 3.00 → 3.00 | 6.89 → 7.44 |
| pg-api / mixed_overview_events / 8 | 3.00 → 3.00 | 47.61 → 47.76 |
| pg-api / local_rpc_models / 1 | 1.00 → 1.00 | 0.651 → 0.778 |
| pg-api / local_rpc_models / 8 | 1.00 → 1.00 | 1.97 → 1.94 |
| pg-api / heartbeat / 1 | 0.000 → 0.000 | 0.797 → 0.990 |
| pg-api / heartbeat / 8 | 0.000 → 0.000 | 0.647 → 0.816 |
| cross-worker / cross_worker_rpc_sse / 1 | 8.01 → 8.01 | 0.932 → 0.930 |
| cross-worker / cross_worker_rpc_sse / 8 | 6.04 → 5.90 | 1.07 → 1.12 |
| reconnect / active_reconnect / 1 | 15.00 → 15.00 | 1.07 → 1.07 |
| reconnect / active_reconnect / 8 | 14.99 → 14.99 | 1.10 → 1.09 |

双 worker 远端 CPU 是包含导入、连接和全部采样的整段进程 CPU；与上表 origin 每次 CPU 口径不同：
13.803s → 13.961s。双方分别收到 2060 / 2060 条唯一 RPC/SSE 确认。

### PostgreSQL 现有存储基准

| 场景 | p50 基线 → 新版 (ms) | p95 基线 → 新版 (ms) | p95 Δ | 客户端 CPU 基线 → 新版 (ms/次) |
| --- | ---: | ---: | ---: | ---: |
| scan_first_page_50 | 3.10 → 3.07 | 4.13 → 4.16 | +0.7% | 1.25 → 1.25 |
| large_scan_overview | 0.680 → 0.710 | 1.19 → 1.10 | -7.6% | 0.460 → 0.470 |
| task_first_page | 38.26 → 39.06 | 44.17 → 43.77 | -0.9% | 1.21 → 1.18 |
| checker_dashboard | 71.11 → 72.68 | 76.72 → 78.70 | +2.6% | 16.60 → 17.52 |

PostgreSQL 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)。种子数据后的数据库大小 406,151,695 → 406,151,695 bytes；种子 WAL 229,683,032 → 229,683,032 bytes。这两项受初始化/页写入影响，不是单次请求开销。

### 运行包生成

每个 URL 首次 1 次、随后重复 5 次；表内重复耗时取中位数，未沿用 HTTP 主回放的 200×5。

| 场景 | 首次 基线 → 新版 (ms) | 重复中位 基线 → 新版 (ms) | 重复 Δ | CPU 基线 → 新版 (ms) | 响应 bytes 基线 → 新版 |
| --- | ---: | ---: | ---: | ---: | ---: |
| runtime_manifest | 73.20 → 56.23 | 43.68 → 46.01 | +5.3% | 43.56 → 45.90 | 95,358 → 107,220 |
| agent_zip | 371.21 → 380.41 | 376.67 → 386.38 | +2.6% | 376.60 → 386.34 | 4,753,033 → 4,816,968 |

manifest 文件数 583 → 673；ZIP entries 587 → 677。hash scope 完全一致；源码拆分新增文件，因此内容、大小和哈希会正常变化。

原始数据：[JSON 目录](benchmarks/scan-agent-refactor/)，包含每轮 p50/p95、吞吐、CPU、RSS、执行器操作分布和全部结果计数。各场景响应断言和 RPC/WS 协议确认均通过，正式有效采样未出现测量失败。

## 反序复测与误差

对首轮变化超过约5%的场景，进一步先运行新版、再运行基线；每个版本重新创建数据，选定相同场景和顺序。它们是独立场景复测，不复刻此前其他场景产生的全部数据库历史。主回放结果保留，不用复测中更好的数字替换。

| 场景 / 并发 | 主回放 p95 Δ | 反序 p95 Δ | 反序 CPU Δ |
| --- | ---: | ---: | ---: |
| SQLite / scan_overview / 1 | +3.77% | +5.22% | +4.35% |
| SQLite / scan_overview / 8 | +9.15% | +1.27% | +1.88% |
| SQLite / batch_candidates_10 / 1 | -4.20% | -1.66% | +2.90% |
| SQLite / batch_candidates_10 / 8 | +3.62% | +1.31% | +0.88% |
| SQLite / mixed_overview_events / 1 | +8.83% | +2.58% | +3.29% |
| SQLite / mixed_overview_events / 8 | +3.66% | +9.45% | +0.43% |
| SQLite / local_rpc_models / 1 | +4.43% | -4.88% | +2.70% |
| SQLite / local_rpc_models / 8 | +6.98% | +12.72% | +3.78% |
| SQLite / heartbeat / 1 | +2.70% | -13.87% | -2.48% |
| SQLite / heartbeat / 8 | +36.14% | -9.45% | +1.96% |
| PostgreSQL / local_rpc_models / 1 | +17.81% | +1.06% | +0.79% |
| PostgreSQL / local_rpc_models / 8 | -0.62% | +2.21% | +1.48% |
| PostgreSQL / heartbeat / 1 | +2.65% | +39.84% | +24.11% |
| PostgreSQL / heartbeat / 8 | +51.19% | -18.21% | -3.13% |
| PostgreSQL / mixed_overview_events / 1 | +5.05% | +4.04% | +4.75% |
| PostgreSQL / mixed_overview_events / 8 | +0.36% | +0.31% | +1.12% |
| 双worker / cross_worker_rpc_sse / 8 | +1.28% | -0.50% | -4.91% |

heartbeat另以每轮2,000次、5轮、预热200次反序回放，避免把几十微秒尺度的少数调度尖峰放大为百分比结论：

| 环境 / 并发 | p95 基线 → 新版 (µs) | CPU 基线 → 新版 (µs/次) |
| --- | ---: | ---: |
| SQLite / 1 | 35.11 → 38.21 | 33.36 → 33.81 |
| SQLite / 8 | 173.97 → 166.33 | 23.50 → 23.21 |
| PostgreSQL / 1 | 55.92 → 54.12 | 49.18 → 52.58 |
| PostgreSQL / 8 | 256.84 → 261.05 | 37.44 → 35.78 |

跨worker与重连的store调用包含周期维护和合并心跳写入，轮次边界可能相差几次；业务操作次数不变。HTTP主回放各场景的执行器调用数完全相同。不计算混合不同场景权重的总分，所有变化逐场景披露。

重连前置试跑曾固定machine_name，使8个连接共享稳定agent_key；这不符合8个独立Agent的场景定义。已改为独立machine_name并断言key唯一，双方完整重跑后才纳入上表。旧共享身份及单Agent诊断数据留在/tmp，未作为正式结果。运行包原工作区与/tmp直接比较的manifest耗时曾为+21.2%，最终同文件系统、同历史缓存条件下为+5.33%，因此正式表采用后者。

### RPC主线程诊断与身份依赖

同步身份桩下SQLite 8并发RPC的p95两轮增加约0.45–0.80ms。仅对2,000次RPC测量段采集cProfile（排除导入、种子及预热；不拿profile延迟作为性能结果），主线程自身耗时总和2.746→2.785s，增加约39.5ms，即19.7µs/次。新增路由适配、runtime访问和RPC broker有固定成本；未增加数据库调用。自身耗时不重复累加被调函数，且cProfile记录的是经过时间，不等同于纯CPU。详见 [profile摘要](benchmarks/scan-agent-refactor/rpc-profile-summary.json)。

进一步仅更换身份桩为async，与生产认证依赖形态一致，保持固定User和RPC回包不变，得到：

| RPC并发 | p95基线 → 新版(ms) | p95变化 | CPU基线 → 新版(ms/次) | CPU变化 |
| --- | ---: | ---: | ---: | ---: |
| 1 | 0.5738 → 0.6130 | +6.82%（+39µs） | 0.4265 → 0.4504 | +5.61%（+23.9µs） |
| 8 | 2.5768 → 2.5450 | -1.24% | 0.3941 → 0.3960 | +0.48% |

因此不能把同步身份桩的线程池尾延迟直接归为生产RPC退化，也不能把单请求额外几十微秒描述为零成本。全部原始回放、反序和async对照均保留。

## 行为与测试

Scan、Agent、公有 Agent、集成及共享路由共 209 条有序路由、208 个 HTTP operation；基线与重构版的路径、方法、名字和 OpenAPI JSON 在各自两套解释器环境中完全一致。OpenAPI 序列化随 FastAPI 版本变化，因此分别固定各环境的基线 digest，测试允许这两个已核验值。

完整 `tests/` 全量：基线 **3273 passed、24 failed、201 skipped、99 subtests passed**；重构版 **3293 passed、24 failed、201 skipped、99 subtests passed**，新增 20 项通过，24 个失败节点逐一相同。测试执行完成，但全仓测试并非全部成功。201 个跳过为 198 个 PostgreSQL 用例（另在真实 PG 集补测）、2 个 Windows 用例、1 个可选真实 OpenCode skills 用例。

| 既有失败模块 | 数量 |
| --- | ---: |
| `test_agent_feedback` | 1 |
| `test_agent_result_paths` | 1 |
| `test_agent_scan_paths` | 2 |
| `test_checker_test_cli` | 1 |
| `test_codex_runtime` | 1 |
| `test_command_injection_integration` | 1 |
| `test_opencode_workspace` | 11 |
| `test_runner_mode_dispatch` | 3 |
| `test_sensitive_clear_grouped` | 1 |
| `test_static_checker_isolation` | 1 |
| `test_vulnerability_mining_engines` | 1 |

`test_codex_runtime` 会留下缺少 `llm_providers` 的运行时替身，后续 `test_opencode_workspace` 在全量顺序中出现连锁失败；其他节点的原始断言/环境失败同样在未修改基线复现。完整节点名存于结果 JSON。本次未把这些跨模块既有问题并入产品重构。

一次中间全量额外出现未修改模块的 SIGTERM 子进程 15 秒退出超时；原版和新版分别重复复测通过，最终完整重跑也消失，不计作修复或仍存回归。另一次省略 `tests/` 的探索性收集额外收集本地扩展、技能及插件目录后出现 7 个收集错误，主基线与最终验证均明确限定同一 `tests/` 范围。

完整测试结果和失败节点见 [test-summary.json](benchmarks/scan-agent-refactor/test-summary.json)。主 Python 全量按 `tests/` 范围执行；PostgreSQL 再执行全部 28 个相关模块，包含迁移、共享、恢复、任务顺序、审计、worker 命令和 RPC/SSE 等真实数据库用例。两组存在重复用例，不能相加作为唯一测试数量。

PostgreSQL 的原始迁移测试有两项既有 fixture 问题：旧的精确 counts 断言漏掉已经存在的 10 个 threat-pattern 字段；之前的测试留下 scan tombstone 导致空库迁移前置条件失败。本次仅更新测试精确字段并为迁移创建隔离 schema；原始基线日志保留，用相同更新后的 fixture 测试旧代码和新代码，均为 **534 passed、1 skipped、0 failed**。唯一跳过的是共享会话用例的 SQLite 变体；PostgreSQL 变体通过。这属于测试修复，不计作产品 bug。

本次产品 bug 修复由原始版本复现并新增回归用例覆盖：

1. 创建扫描派发失败遗留 owner 缓存；派发抛异常遗留 pending 扫描和运行缓存。统一标记失败、清理缓存并返回 502。见 `test_scan_creation_cleanup.py`。
2. MCP 探测发送异常或取消时遗留等待 Future。RPC broker 统一在 finally 中清理。见 `test_agent_rpc_lifecycle.py`。
3. 已删除扫描的 FP review stage-output 回报漏过历史回报保护器。现在确认并丢弃该回报，返回 `discarded: scan_deleted`。见 `test_storage_deletion.py`。

## 复现命令

```bash
# 基线准备；ThreatAnalysis 为已有本地测试依赖，需另行提供相同内容。
mkdir -p /tmp/odh-refactor-baseline
git archive 8158fbfd0632bf847ebbe5ee789b79468c577df3 | tar -x -C /tmp/odh-refactor-baseline

PYTHONPATH=. python3 -m pytest -q tests --tb=short -o faulthandler_timeout=60
PYTHONPATH=. python3 -m pytest -q tests/test_backend_refactor_contracts.py

python3 scripts/benchmark_backend_refactor.py --source /tmp/odh-refactor-baseline --mode all --auth-mode sync --output /tmp/baseline-api.json
python3 scripts/benchmark_backend_refactor.py --source . --mode all --auth-mode sync --output /tmp/refactor-api.json
python3 scripts/benchmark_postgres_refactor.py --source /tmp/odh-refactor-baseline --mode all --auth-mode sync --output /tmp/baseline-pg-api.json
python3 scripts/benchmark_postgres_refactor.py --source . --mode all --auth-mode sync --output /tmp/refactor-pg-api.json
python3 scripts/benchmark_postgres_refactor.py --source /tmp/odh-refactor-baseline --mode cross-worker --output /tmp/baseline-cross-worker.json
python3 scripts/benchmark_postgres_refactor.py --source . --mode cross-worker --output /tmp/refactor-cross-worker.json
python3 scripts/benchmark_postgres_refactor.py --source /tmp/odh-refactor-baseline --mode storage --output /tmp/baseline-storage.json
python3 scripts/benchmark_postgres_refactor.py --source . --mode storage --output /tmp/refactor-storage.json
python3 scripts/benchmark_backend_refactor.py --source /tmp/odh-refactor-baseline --mode reconnect --agents 8 --output /tmp/baseline-reconnect.json
python3 scripts/benchmark_backend_refactor.py --source . --mode reconnect --agents 8 --output /tmp/refactor-reconnect.json
# 包比较须使用同一文件系统下的新快照，并排除原有__pycache__。
# 目标目录须是新目录；目录已存在时换用新路径，避免混入旧源码。
python3 - <<'PY_SNAPSHOT'
from pathlib import Path
import shutil

baseline = Path("/tmp/odh-refactor-baseline")
ignore = shutil.ignore_patterns("__pycache__", ".pytest_cache")
shutil.copytree(baseline, "/tmp/odh-package-baseline", ignore=ignore)
def current_ignore(path, names):
    return set(ignore(path, names)) | ({"backend"} if Path(path) == baseline else set())
shutil.copytree(baseline, "/tmp/odh-package-refactor", ignore=current_ignore)
shutil.copytree("backend", "/tmp/odh-package-refactor/backend", ignore=ignore)
PY_SNAPSHOT
python3 scripts/benchmark_backend_refactor.py --source /tmp/odh-package-baseline --mode package --output /tmp/baseline-package-samefs.json
python3 scripts/benchmark_backend_refactor.py --source /tmp/odh-package-refactor --mode package --output /tmp/refactor-package-samefs.json

# 异步身份桩诊断；仍然是固定身份，不执行真实认证。
python3 scripts/benchmark_backend_refactor.py --source /tmp/odh-refactor-baseline --mode ws --scenarios local_rpc_models --auth-mode async --output /tmp/baseline-rpc-async-auth.json
python3 scripts/benchmark_backend_refactor.py --source . --mode ws --scenarios local_rpc_models --auth-mode async --output /tmp/refactor-rpc-async-auth.json

# 定向反序复测时先当前版本，再--source基线，分别保存输出。
python3 scripts/benchmark_backend_refactor.py --mode all --scenarios scan_overview batch_candidates_10 mixed_overview_events local_rpc_models heartbeat --output /tmp/refactor-api-repeat.json
python3 scripts/benchmark_postgres_refactor.py --mode all --scenarios local_rpc_models heartbeat mixed_overview_events --output /tmp/refactor-pg-api-repeat.json
python3 scripts/benchmark_postgres_refactor.py --mode cross-worker --concurrency 8 --output /tmp/refactor-cross-worker-repeat.json
python3 scripts/benchmark_backend_refactor.py --mode ws --scenarios heartbeat --samples 2000 --warmup 200 --output /tmp/refactor-heartbeat-large.json
python3 scripts/benchmark_postgres_refactor.py --mode all --scenarios heartbeat --samples 2000 --warmup 200 --output /tmp/refactor-pg-heartbeat-large.json

# Profile只覆盖指定测量段，不把其延迟当性能数据；两版本顺序执行。
python3 scripts/benchmark_backend_refactor.py --mode ws --scenarios local_rpc_models --concurrency 8 --samples 2000 --warmup 200 --rounds 1 --profile-output /tmp/refactor-rpc.prof --output /tmp/refactor-rpc-profile.json
```

PostgreSQL 用例清单保存在结果JSON，以下命令使用完整28文件；基线PG验证先复制同一修复后的 `tests/test_postgres_store_integration.py` 到快照（仅测试文件），在对应源码目录运行。缓存安装已存在，基准脚本不下载依赖，不连接用户数据库。

```python
import json
import shutil
import subprocess
from pathlib import Path

current = Path.cwd()
baseline = Path("/tmp/odh-refactor-baseline")
with open("docs/benchmarks/scan-agent-refactor/test-summary.json") as file:
    modules = json.load(file)["postgres_modules"]
shutil.copyfile(current / "tests/test_postgres_store_integration.py",
                baseline / "tests/test_postgres_store_integration.py")
for source in (baseline, current):
    subprocess.run([
        "python3", "scripts/run_postgres_tests.py", "-q", *modules,
        "--tb=short", "-o", "faulthandler_timeout=40",
    ], cwd=source, check=True)
```

## 边界

不调用真实 LLM，不测生产数据、真实网络延迟、Windows 运行行为或长时间内存泄漏。初始一次基准共享活动扫描，事件上报完成静态阶段后使候选回报被正确丢弃，响应断言中止；该次不计入正式结果。改为独立候选扫描，完成 SQLite / PostgreSQL 全顺序短测后，双方从头使用相同数据正式计时。此处数据只能比较本地服务端开销，不能推算实际漏洞扫描总耗时。少量毫秒级或微秒级差异受操作系统调度、磁盘和缓存影响；轮次离散值保留在 JSON 中，不将单次百分比直接宣称为稳定优化。
