# 证据门禁复核过程

公开入口为异步函数 `run_fp_check_review(**kwargs)`。它与既有
`deephole_client.fp_review.run_fp_review()` 相互独立，不替换旧流程。

必填参数：

- `project_path`：只读分析的真实项目目录。
- `work_dir`：本次复核目录，Agent 固定放在
  `~/.opendeephole/fp_reviews/<review_id>/`。
- `scan_id`、`review_id`。
- `vulnerabilities`：带扫描内 `index` 的问题列表。

可选参数包括 `feedback_entries`、`history`、`processed_offset`、
`concurrency`、`required_capability`、`invalid_json_retry_count`、
`task_agent_config`、`output` 和 `cancel_event`。

执行顺序：

1. 全部问题执行步骤 0 并独立选择标准/深度路径。
2. 先完成所有标准路径，升级项携带已有证据进入深度路径。
3. 深度项依次执行数据流、可利用性、影响、PoC、反方审查和六道门。
4. 最后执行全批次攻击链复核并生成 `summary_markdown`。

返回值中的 `results` 只包含证据完整的二元结论。结构化输出不完整或
阶段执行失败的索引进入 `unresolved_indices`，已有阶段 Markdown 仍保存在
`artifacts/<vuln_index>/`，后续重跑可只选择这些未完成项。
