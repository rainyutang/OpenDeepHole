# Codex Goal 威胁分析

该方法保持平台规定的五参数同步入口，只调用一次 `CodexController.goal()` 完成威胁建模。

## 输入

| 参数 | 处理方式 |
| --- | --- |
| `code_path` | 必填、必须存在的源码目录；作为只读绝对路径交给 Goal |
| `output_path` | 必填；用于三份最终产物、Goal 状态、扫描上下文、提示词和日志 |
| `is_resume` | 已有产物有效时直接复用，否则按保存的 Thread ID 恢复 Goal |
| `product_mcp` | 写入运行上下文，供 Goal 判断是否使用产品知识 |
| `attack_modes` | 写入运行上下文，供 Goal 生成攻击模式关联 |

## 必须输出

成功时返回 `result=true`，以及下面三个位于 `output_path/final/` 的文件路径：

- `value_asset_path`：`value-assets.json`，顶层为价值资产数组。
- `high_risk_modules_path`：`high-risk-modules.json`，顶层为高风险模块数组。
- `attack_tree_path`：`attack-trees.json`，顶层对象必须包含 `attack_trees` 数组。

字段和嵌套结构由本方法 `references/` 下的三份独立 JSON Schema 定义；分析步骤、节点语义、
攻击模式匹配方法、跨产物关系和完成检查由 `analysis-guidance.json` 定义。默认攻击模式来自同目录
的 `attack_mode.json`（由 DeepHole 威胁分析的模式库同步复制，当前包含 CAPEC、ATT&CK 等整理后
的模式）。动态路径、续扫状态、产品 MCP 名称和攻击模式筛选提示写入
`output_path/scan-context.json`；动态 `attack_modes` 不能扩充或改写默认模式库。

Goal 初始提示词只保留参考文件路径和最关键的根/中间/叶节点约束，运行时硬性限制为不超过
4000 字符，并另存为 `output_path/codex-goal-prompt.txt`。完整方法不内联进提示词。提示词还提供
`schema_validation.py` 的完整命令，要求 Goal 写完三份产物后执行；校验失败必须修正并重跑，
只有命令退出码为 0 才允许 Goal 结束。方法不会在 Goal 结束后再次执行 Schema 校验。

Goal 内的校验同时检查 JSON Schema 和跨产物语义：根节点名称与价值资产名完全相同；叶子节点
名称与外部暴露高风险模块名完全相同；内部节点保持真实模块语义；路径的节点和边连续；路径
覆盖全部相关高风险模块。每条路径分析可能适用的攻击模式并按可能性排序；存在足够适用模式时
至少输出 10 个，实际不足 10 个时输出全部适用模式。所有已选择模式的编号和名称必须存在于
`attack_mode.json`。

## Codex 模型与认证

Agent 启动时会先检查/安装 Codex CLI。本方法使用 app-server 支持的启动命令：

```text
codex app-server --listen stdio://
```

本方法不向 app-server、Thread 或 Goal 传入模型 ID 或 profile，模型与认证完全使用当前
Codex 默认配置。`codex-goal-state.json` 保存 `thread_id`、`goal_status` 和用于避免复用旧校验
流程产物的 `validation_policy_version`。工具不修改
用户的 `$CODEX_HOME/config.toml` 或 Codex 默认模型；Codex CLI 不可用时直接返回配置错误。
