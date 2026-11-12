本目录保存 2026-11-12 前端重构的测试与性能证据。基线为提交 `8c42af5` 的独立源码快照，复用同一份已安装依赖；Node `v24.14.0`，Linux x64，12 个逻辑 CPU。基线所需的 `docs/examples` 也从同一提交补齐。初次运行因缺少示例文件或未捕获测试输出产生的结果不作为测试结论。

| 文件 | 含义 |
| --- | --- |
| `tests-baseline.json` | 补齐环境并可靠捕获日志后的旧版本测试结果：28 个脚本、425 个用例，424 通过、1 失败。失败为共享页面 complete 状态下“续扫”按钮断言，发生在未修改的基线。 |
| `performance-ssr-initial.json` | 初始拆分后的 SSR 五轮原始数据，保留已发现的回退。 |
| `performance-bundled-final.json` | 最终代码的 bundled 五轮原始数据，包含 selectors 与 Markdown 内容缓存的组合优化。 |
| `performance-ssr-final.json` | 最终代码沿用 SSR 模式的五轮原始数据，用于与初始 SSR 结果交叉检查。 |
| `coverage-baseline.json`、`coverage-refactor.json` | 现有 threat-coverage 基准各五轮结果，均使用 `environment`、`scenarios` 容器；保留每个原始 sample 和门限。 |

交互基准使用同一份 `frontend/scripts/frontendRefactorFixture.mjs` 和同一组动作，分别加载 105 与 10,000 条问题、复核结果及验证记录。动作包含初次挂载、自动读取每页 50 条的全部详情、列表翻至第 3 页、过滤到末项、页签往返，以及连续三批 SSE 通知；每批包含 100 个状态事件和 20 个 overview 失效事件。断言验证稀疏稳定索引、末项报告、完整页数、详情保留、通知合并和卸载关闭连接。每轮旧、新版本各用独立 Node 进程，并在相邻轮次反转运行顺序；两个规模各五轮，共 20 个样本。采样期间停止其他测试和构建负载。

`ssr` 使用 Vite SSR 开发模块；`bundled` 用已有 esbuild 将本地源码与测量入口导出合并为一个 ESM，外部依赖保持 external，与 test renderer 共用同一 React 实例，CSS 为空。两种模式都保留开发版 React Profiler。bundled 消除了 Vite SSR 对本地模块导入的动态访问方式，更接近生产构建的模块组织；它仍是 Node 内的组件基准，不测浏览器布局、绘制、真实网络，也不等于完整生产浏览器性能。

编译、模块载入、Vite 关闭和 fixture 构造均在计时与 GC heap 基线之前。`completionMs` 为动作完成的墙钟时间，包括现有 75/150 ms 合并窗口；`activeCpuMs` 为进程用户态与系统态 CPU 时间，包含渲染；`renderMs` 为 React Profiler 的 actualDuration。SSE dispatch 与 timer callback 记录同步回调耗时，可能与 render 重叠，不能相加或相减后宣称是独立的纯处理时间。`issuesHeapMiB` 与 `retainedMiB` 分别是问题页加载后和最终状态下 GC 后的增量 heap，均排除初始化和 fixture；它们不是进程 RSS 或峰值内存。Axios fixture 无网络延迟，HTTP、SSE 和 commit 数单独记录。

初始 SSR 大规模场景的 completion 中位数由 4,733 ms 增至 5,501 ms（+16.22%），主要集中在全量详情加载；commit 与 HTTP 数未变。CPU profile 指向列表标注/排序、漏洞规范化与流程统计等热点。临时导入快照实验改变了部分测量，但部分诊断与后续源码优化处于不同时间点，不能据此把全部回退归因于 SSR getter，也不能将某个快照实验解释为单一函数的确定收益。原始回退数据始终保留。

最终 bundled 五轮的比较支持 selectors 与 Markdown 内容缓存的组合效果，不做单项收益归因。普通规模 completion 中位数为 597.13→584.97 ms，CPU 为 284.05→276.66 ms，render 为 111.52→101.00 ms；万问题规模分别为 4,553.16→4,035.05 ms、5,099.68→4,258.62 ms、3,791.15→3,289.50 ms。每个版本的普通规模均为 64 commits、30 HTTP，万问题均为 1,443 commits、621 HTTP；两种规模均为 1 条 SSE 连接、360 个事件，结束时连接关闭。正式汇总应从对应五轮 JSON 计算中位数与范围，避免混用早期 smoke、profile 和最终数据。

最终 SSR 五轮也显示改善：万问题 completion 4,688.24→4,378.95 ms（−6.60%）、CPU 5,299.26→4,597.78 ms（−13.24%）、render 3,912.41→3,619.66 ms（−7.48%）。各模式分别比较其同轮旧、新样本，不跨模式计算优化比例。

从仓库根目录复现；将 `BASELINE_FRONTEND` 替换为旧版本 frontend 的绝对路径：

```bash
node frontend/scripts/runTests.mjs --root BASELINE_FRONTEND --log-dir /tmp/frontend-baseline-tests --json /tmp/frontend-baseline-tests.json --quiet
node frontend/scripts/benchmarkFrontendRefactor.mjs --root frontend --compare BASELINE_FRONTEND --module-mode bundled --repeat 5 --json /tmp/frontend-performance-bundled.json
node frontend/scripts/benchmarkFrontendRefactor.mjs --root frontend --compare BASELINE_FRONTEND --module-mode ssr --repeat 5 --json /tmp/frontend-performance-ssr.json
```

覆盖基准在各版本的 frontend 目录运行 `npm run benchmark:threat-coverage -- --repeat 5 --check`，门限为 build/issue update 不超过 2 秒、retained heap 不超过 256 MiB。独立 CPU 诊断可使用 `node --cpu-prof --expose-gc frontend/scripts/benchmarkFrontendRefactor.mjs --sample --scenario large --module-mode ssr --root FRONTEND_PATH`；诊断运行不混入正式样本。
