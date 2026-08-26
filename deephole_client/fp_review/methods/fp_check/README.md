# Trail of Bits fp-check 去误报方法

该目录是 `fp_check` 方法的完整所有权边界：`method.py` 实现统一的
`async def run(**kwargs)` 单漏洞入口，`method.yaml` 声明名称、并发度、阶段和展示文档，
`skills/` 保存中文化后的 Trail of Bits fp-check Skill。

每次调用只接收一个 `vulnerability` 和对应 `vuln_index`，执行主张与上下文重述后选择标准或
深度验证路径。证据完整时只返回二元 TP/FP；结构化阶段不完整则返回 `error`，由平台保留阶段
输出并决定是否补跑。方法不生成跨漏洞攻击链或批次汇总。

模型侧每个阶段都通过 `/fp-check` 调用相邻 Skill。首阶段 Prompt 只提供当前任务和漏洞挖掘产生
的 Markdown 报告和当前阶段 JSON Schema；后续阶段只追加已经完成阶段的 `stage_markdown`，不传
完整漏洞、反馈、历史、`prior_stages` JSON 或 Skill 正文。逐阶段字段语义写在
`skills/fp-check/SKILL.md` 中，同一 Schema 也通过 `output_schema` 供 Task Agent 校验和纠正最终
JSON。

Agent 根据清单中的 `max_concurrency: 4` 并行调度不同漏洞，但每个方法调用仍保持漏洞粒度，
产物写入当前漏洞的 `<work_dir>/artifacts/`。
