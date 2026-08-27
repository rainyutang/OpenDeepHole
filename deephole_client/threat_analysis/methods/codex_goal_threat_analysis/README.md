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

字段和嵌套结构由本方法 `references/` 下的三份独立 JSON Schema 定义；分析步骤、证据要求、
跨产物关系和完成检查由同目录的 `analysis-guidance.json` 定义。动态路径、续扫状态、产品 MCP
名称和攻击模式写入 `output_path/scan-context.json`。Goal 和返回前校验器读取相同的私有参考
文件，不依赖其它威胁分析方法。Goal 初始提示词运行时硬性限制为不超过 4000 字符，并另存为
`output_path/codex-goal-prompt.txt`。

## Codex 模型与认证

Agent 启动时会先检查/安装 Codex CLI。本方法使用 app-server 支持的启动命令：

```text
codex app-server --listen stdio://
```

本方法不向 app-server、Thread 或 Goal 传入模型 ID 或 profile，模型与认证完全使用当前
Codex 默认配置。`codex-goal-state.json` 只保存 `thread_id` 和 `goal_status`。工具不修改
用户的 `$CODEX_HOME/config.toml` 或 Codex 默认模型；Codex CLI 不可用时直接返回配置错误。
