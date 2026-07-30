# Trail of Bits fp-check 复核过程

公开入口为异步函数 `run_fp_check_review(**kwargs)`。它与既有
`deephole_client.fp_review.run_fp_review()` 相互独立，不替换旧流程。
该方案来源于 Trail of Bits Skills Marketplace 的 `fp-check`，并在本项目中完成中文化和运行时适配。

必填参数：

- `operation`：`item` 执行一个漏洞的单项复核，`summary` 只生成跨漏洞攻击链和批次汇总。
- `project_path`：只读分析的真实项目目录。
- `work_dir`：本次复核目录，Agent 固定放在
  `~/.opendeephole/fp_reviews/<review_id>/`。
- `scan_id`、`review_id`。
- `vulnerabilities`：带扫描内 `index` 的问题列表；`item` 模式必须且只能有一项。

可选参数包括 `feedback_entries`、`history`、`processed_offset`、
`concurrency`、`required_capability`、`invalid_json_retry_count`、
`task_agent_config`、`output` 和 `cancel_event`。`summary` 模式另外接收
`individual_results` 与 `unresolved_indices`。

运行方式：

1. 每个确认问题立即以 `item` 模式独立执行步骤 0、标准/深度路由和六道门；Agent 最多并发四项。
2. 扫描完成后，Agent 等待当前单项任务结束，从服务端读取最新持久化结果，再以 `summary` 模式检查跨漏洞攻击链。
3. 攻击链与批次汇总独立保存，不得修改、提升或删除任何单项 TP/FP。
4. 有效单项结果少于两项时跳过模型攻击链检查，直接生成确定性汇总。

返回值中的 `results` 只包含证据完整的二元结论。结构化输出不完整或
阶段执行失败的索引进入 `unresolved_indices`，已有阶段 Markdown 仍保存在
`artifacts/<vuln_index>/`，本轮以错误状态结束并允许补跑。汇总失败时保留
上一次成功汇总及全部单项结果。
