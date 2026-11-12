# 前端重构验证报告

2026-11-12。本轮拆分扫描详情、问题详情、创建与配置、历史列表、威胁分析，以及 API、类型、快照和 SSE 模块。保持已有 URL、请求和事件协议，增加两处已在旧版本复现的 bug 修复。模块职责见[前端架构](frontend-architecture.md)。

## 版本与范围

基线为 `8c42af5`，使用独立源码目录；实现分为 API/运行时 `4d6ac70`、页面结构 `321b98d`、bug 修复 `e338eb8`、性能优化 `ec75d76`。两版共用 Node v24.14.0 和同一套依赖，未新增依赖。最终 TypeScript 源码摘要及 lockfile 摘要保存在 [bundle-final.json](benchmarks/frontend-refactor/bundle-final.json)，已与 `ec75d76` 核对一致。测试和测量完成后出现的并行超时策略/配置修改不属于本报告范围，保留在工作区并排除出本轮提交。

| 原文件 | 原行数 | 重构后的职责与规模 |
| --- | ---: | --- |
| `ScanStatus.tsx` | 7,734 | 7 行兼容入口；`ScanDetailPage.tsx` 610 行，状态、事件、模型和面板分别拥有明确职责 |
| `VulnerabilityList.tsx` | 1,620 | 2 行兼容入口；列表主体 244 行，详情、反馈、报告与选择器独立 |
| `NewScanForm.tsx` | 441 | 276 行视图，草稿与控制器独立 |
| `AgentConfigPage.tsx` | 591 | 206 行视图，配置转换、异步状态与高级设置独立 |
| `ScanHistory.tsx` | 808 | 368 行视图，分页、筛选与公告状态独立 |
| `ThreatAnalysisPanel.tsx` | 913 | 204 行面板，纯模型、树和表格独立 |
| `api/client.ts` / `types.ts` | 1,313 / 1,350 | 114 / 14 行兼容出口，领域模块保留全部 121 / 132 个导出 |
| `scanRuntime.ts` / `useScanSSE.ts` | 702 / 802 | 6 / 2 行兼容出口，归一化与连接协调按职责拆分 |

当前 `frontend/src` 最大 TS/TSX 文件为 686 行。保留组件身份、详情状态、单一 Axios 实例、快照请求去重和同一扫描的单条 SSE；日志/状态/资源批处理仍为 50/75/150 ms，后备轮询 30 秒，进度摘要 60 秒。

## 测试结果

| 验证 | 结果 |
| --- | --- |
| 原版本全部 28 个测试脚本 | 425 项：424 通过、1 失败；0 跳过 |
| 最终版本全部 35 个测试脚本 | **458/458 通过**；0 失败、取消或跳过 |
| 修正断言后的分享测试，分别加载旧/新版本 | 两版均 16/16 通过 |
| 最终架构检查复跑 | 3/3 通过：无运行时循环、无反向兼容入口依赖、纯模型无 UI/HTTP/浏览器状态依赖 |
| 后端 SPA 路由集成 `tests/test_frontend_routes.py` | **26/26 通过** |
| TypeScript 与 Vite 生产构建 | 成功；保留原有大于 500 kB 的 chunk 警告 |
| 最终 bundled 与 SSR 交互基准 | 各 20 个独立进程样本，语义断言全部通过 |
| 覆盖图基准 `--repeat 5 --check` | 旧/新各 25 个样本，全部通过既有耗时/内存门限 |

[原测试汇总](benchmarks/frontend-refactor/tests-baseline.json)与[最终测试汇总](benchmarks/frontend-refactor/tests-final.json)记录每个脚本的结果。全量测试包括路由、公开/分享权限、分页与竞态、SSE 恢复、稳定索引定位、反馈状态、复制扫描、配置、报告、审计及覆盖图。

原版本唯一失败是分享测试用 `/续扫/` 匹配任意按钮，误将“未完成，可续扫”的流程导航认作续扫操作。修正为匹配实际操作按钮的完整名称，并新增验证：状态导航只切换展示，所有 HTTP 请求仍为 GET。此项属于测试误报修正，不计作产品 bug。

最初基线环境遗漏 `docs/examples`，另有子进程日志未捕获的尝试；补齐同一提交的示例并改为直接写日志后重跑，表格只使用有完整汇总的结果。Python 路由测试第一次在沙箱中挂起并被中断，非沙箱复跑 26 项通过。未运行完整后端/客户端测试、真实模型任务或浏览器视觉验收。

## 修复的 bug

1. **知识库探测结果串入新草稿。** 探测期间切换客户端，或关闭再开启知识库，旧请求仍可能把旧项目和连接成功状态写入当前草稿。增加请求代次，并在客户端/开关变化与卸载时失效；两条回归在原版本失败，最终版本通过。
2. **普通问题列表缺少跳转定位。** `all_results` 分支没有给行绑定定位 ref 和 `aria-current`，从审计结果跳转时不能滚动并标记目标。补齐与最终 TP 列表一致的绑定，保持后端稀疏 `vuln_index`；两条回归在原版本失败，最终版本通过。

## 交互性能与内存

同一 fixture 分别包含 105 与 10,000 条问题、复核结果及验证记录。执行挂载、每页 50 条的全量读取、翻到第 3 页、筛选末项、页签往返及三批 SSE，每批 100 个状态事件和 20 个资源通知。旧/新交替顺序，每种规模五轮；以下为各自中位数，变化为 `(新/旧 - 1) × 100%`。

采用已有 esbuild 合并本地模块，外部依赖保持一致，保留 React 开发版 Profiler。编译、导入和 fixture 构造不计时；这仍是 **Node 组件基准，不包含浏览器布局/绘制、真实网络或模型任务**。CPU 包含渲染，不能与 render 时间相加。内存为 GC 后增量 heap，排除初始化及 fixture，并非 RSS 或峰值。

| 指标 | 105 条：旧 → 新 | 变化 | 10,000 条：旧 → 新 | 变化 |
| --- | ---: | ---: | ---: | ---: |
| 动作完成耗时（ms，含既有批处理等待） | 597.13 → 584.97 | −2.04% | 4,553.16 → 4,035.05 | **−11.38%** |
| CPU 时间（ms） | 284.05 → 276.66 | −2.60% | 5,099.68 → 4,258.62 | **−16.49%** |
| React render 时间（ms） | 111.52 → 101.00 | −9.44% | 3,791.15 → 3,289.50 | −13.23% |
| 问题页加载后 heap（MiB） | 4.135 → 3.924 | −5.10% | 16.432 → 15.833 | −3.65% |
| 最终状态 heap（MiB） | 4.711 → 4.676 | −0.75% | 14.659 → 14.030 | −4.29% |
| React commits | 64 → 64 | 不变 | 1,443 → 1,443 | 不变 |
| HTTP 请求 | 30 → 30 | 不变 | 621 → 621 | 不变 |
| SSE 连接 / 事件 | 1 / 360 → 1 / 360 | 不变 | 1 / 360 → 1 / 360 | 不变 |

普通场景五轮完成耗时范围为旧 592.96–609.73 ms、新 583.73–589.84 ms；大场景为旧 4,490.79–4,778.97 ms、新 3,929.13–4,088.83 ms。每个样本均断言列表完整、稳定索引不变、翻页复用已加载数据、每批 overview 只请求一次、卸载关闭连接。

优化包括把批量问题标注与筛选放入纯模型，以及按正文 `content` 缓存 Markdown 子树，避免详情分页/实时更新重复解析未变化报告；正文变化仍立即重新渲染。上述数字衡量最终整体变化，不分别归因于某一项优化。

初始纯拆分的 SSR 大场景曾出现 4,733→5,501 ms（+16.22%）回退，已保留[初始原始数据](benchmarks/frontend-refactor/performance-ssr-initial.json)。调查涉及列表派生、规范化和开发加载器的模块访问成本，不能把回退全部归因于加载器。最终优化后，同样 SSR 模式五轮为 4,688.24→4,378.95 ms（−6.60%），CPU −13.24%，render −7.48%。各模式只比较同组旧/新样本。

完整样本：[最终 bundled](benchmarks/frontend-refactor/performance-bundled-final.json)、[最终 SSR](benchmarks/frontend-refactor/performance-ssr-final.json)；详细测量口径见[方法说明](benchmarks/frontend-refactor/methodology.md)。

## 覆盖图与构建开销

覆盖图算法 `coverage.ts` 及其基准脚本未修改，五轮中位数如下。此处 heap 包含 fixture 及树/overlay，与上文排除 fixture 的交互基准口径不同。该组单独测试既有算法，耗时波动不作为优化收益。

| 场景 | 构建耗时旧 → 新（ms） | 保留 heap 旧 → 新（MiB） |
| --- | ---: | ---: |
| 10,000 条 | 17.91 → 21.59 | 3.721 → 3.721 |
| 200,000 条 | 280.39 → 283.03 | 68.669 → 68.679 |
| 200,000 条、50 种模式 | 259.05 → 264.69 | 71.474 → 71.482 |
| 重叠模块 | 179.53 → 177.88 | 61.553 → 61.552 |
| 200,000 条、10,000 个问题 | 206.55 → 200.84 | 64.060 → 64.060 |

普通小场景增加 3.69 ms（20.6%）；其余构建场景中位数在 −2.8% 至 +2.2% 内。问题 overlay 每轮刷新最大耗时的五轮中位数为 31.54→32.23 ms（+2.2%）。最终版本 25 个样本中构建最多 339.64 ms、保留 heap 最多 71.58 MiB，满足既有 2,000 ms / 256 MiB 门限。[旧版样本](benchmarks/frontend-refactor/coverage-baseline.json)、[新版样本](benchmarks/frontend-refactor/coverage-refactor.json)。

生产构建统计所有 JS/CSS 文件，不含 HTML；gzip 使用 level 9、mtime 0，口径与 Vite 控制台显示的压缩级别不同：

| 产物 | 原版本 | 最终版本 | 变化 |
| --- | ---: | ---: | ---: |
| JS + CSS 原始字节 | 1,116,622 | 1,137,236 | +20,614（+1.85%） |
| JS + CSS gzip 字节 | 311,587 | 320,377 | **+8,790（+2.82%，约 8.58 KiB）** |

运行场景耗时下降，但模块拆分后构建产物略有增大，不能声称零开销。没有新增请求、SSE 连接、依赖或数据库操作；包体积证据见 [bundle-final.json](benchmarks/frontend-refactor/bundle-final.json)。

## 复现与交付

在仓库根目录运行：

```bash
npm --prefix frontend test
npm --prefix frontend run build
PYTHONPATH=. python3 -m pytest -q tests/test_frontend_routes.py
node frontend/scripts/benchmarkFrontendRefactor.mjs --root frontend --compare BASELINE_FRONTEND --module-mode bundled --repeat 5 --json /tmp/frontend-performance.json
npm --prefix frontend run benchmark:threat-coverage -- --repeat 5 --check
```

`BASELINE_FRONTEND` 指向从 `8c42af5` 导出的独立 `frontend` 目录，基线根目录同时需要该版本的 `docs/examples`；依赖须与当前版本一致。`--module-mode ssr` 可复现开发模块模式。

本轮完成本地实现、测试、文档与提交；未推送、未部署。构建产物位于本地 `backend/static/`。发布时只需更新前端，不需要后端/客户端升级或数据库迁移。
