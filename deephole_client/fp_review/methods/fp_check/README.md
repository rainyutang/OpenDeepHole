# Trail of Bits fp-check 去误报方法

该目录是 `fp_check` 方法的完整所有权边界：`method.py` 实现统一的
`async def run(**kwargs)` 单漏洞入口，`method.yaml` 声明名称、并发度、阶段和展示文档，
`skills/` 保存中文化后的 Trail of Bits fp-check Skill。

每次调用只接收一个 `vulnerability` 和对应 `vuln_index`，执行主张与上下文重述后选择标准或
深度验证路径。证据完整时只返回二元 TP/FP；结构化阶段不完整则返回 `error`，由平台保留阶段
输出并决定是否补跑。方法不生成跨漏洞攻击链或批次汇总。

Agent 根据清单中的 `max_concurrency: 4` 并行调度不同漏洞，但每个方法调用仍保持漏洞粒度，
产物写入当前漏洞的 `<work_dir>/artifacts/`。
