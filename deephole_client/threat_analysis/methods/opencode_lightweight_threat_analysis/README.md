# OpenCode 轻量级威胁分析

该方法通过一次逻辑上的 `run_opencode_task(task_type="threat_analysis")`
完成价值资产、高风险模块和攻击树分析。它与 Codex 轻量级方法调用同一个
Prompt 构造函数，保留相同的建模规则，仅输出格式和完成条件按方法区分。

价值资产和高风险模块仍分别写入 `final/value-assets.json` 与
`final/high-risk-modules.json`。`attack_tree_path` 指向 `final/attack-trees/`：

```text
attack-trees/
  index.json
  attack-tree-001.json
  attack-tree-002.json
```

清单格式为 `{"attack_trees":[{"tree_id":"T001","file":"attack-tree-001.json"}]}`。
每个树文件直接保存 `tree_id`、`value_asset`、`nodes`、`edges`、`attack_paths`
组成的单树对象，不使用 `attack_trees` 数组包装。所有树的 ID 唯一，文件名必须
是当前目录中的 `attack-tree-xxx.json`，清单登记顺序也是后续审计的树顺序。

校验命令沿用 `--attack-trees`，参数改为该目录。模型可执行任务绑定命令自检，
是否调用不作为 Session 完成条件；Task Agent 在每次完整回复结束后独立校验。
诊断包含缺失树、文件名、树 ID、JSON 错误行列和具体字段问题，首次失败回到
同一 Session 修正对应文件，之后沿用 Agent 的 `threat_analysis.model_policy`
超时和全新 Session 重试策略；重试耗尽后的 DeepHole 回退由扫描编排层负责。

上传保存清单及各树文件，平台展示和审计读取时在内存中适配现有树列表，不生成
额外的合并总文件。恢复时还原目录，已完成的历史单文件结果仍可复用；Codex
轻量级方法继续使用原有单文件输出。
