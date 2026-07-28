# 威胁审计过程

公开入口是异步函数 `run_threat_audit(**kwargs)`。它读取威胁分析的原生攻击树和高风险
模块产物，为每个 `attack_pattern` 单独创建一个审计任务，不依赖威胁分析 Python 包。

| key | 必填 | 类型 | 说明 |
|---|---:|---|---|
| `project_path` | 是 | path | 项目根目录 |
| `work_dir` | 是 | path | 过程工作目录 |
| `scan_id` | 是 | str | 扫描标识 |
| `attack_tree_path` | 是 | path | 原生 `attack_trees.json` |
| `high_risk_modules_path` | 是 | path | 原生 `high-risk-module-merge.json` |
| `concurrency` | 否 | int | 并发任务数，默认 `1` |
| `required_capability` | 否 | `low` 或 `high` | 默认 `high` |
| `include_task_ids` | 否 | `list[str]` | 只执行指定派生任务 |
| `exclude_task_ids` | 否 | `list[str]` | 排除指定派生任务 |
| `task_agent_config` | 否 | path | 独立 Task Agent 配置 |
| `output` | 否 | callable | 同步或异步事件回调 |
| `cancel_event` | 否 | event | 提供 `is_set()` 的取消信号 |

```python
from deephole_client.threat_audit import run_threat_audit

result = await run_threat_audit(
    project_path="/src/project",
    work_dir="/tmp/threat-audit",
    scan_id="standalone",
    attack_tree_path="/tmp/threat-analysis/final/attack_trees.json",
    high_risk_modules_path="/tmp/threat-analysis/final/high-risk-module-merge.json",
    task_agent_config="./task-agent.yaml",
)
```

独立 CLI：

```bash
python -m deephole_client.threat_audit \
  --project-path /src/project \
  --work-dir /tmp/threat-audit \
  --attack-tree-path /tmp/threat-analysis/final/attack_trees.json \
  --high-risk-modules-path /tmp/threat-analysis/final/high-risk-module-merge.json \
  --task-agent-config ./task-agent.yaml
```

返回值包含 `status`、逐攻击模式的 `tasks` 和汇总后的 `vulnerabilities`。

威胁审计保持独立执行且不加载候选点 Skill。每个“攻击面 × 攻击方式”模型任务返回
裸 JSON List，允许一次返回多个独立问题；没有问题时返回仅包含一个
`confirmed=false` 结论的 List。列表项与候选点/项目级审计共用
`task_agent.audit_schema.VULNERABILITY_ITEM_SCHEMA`，模型不再返回
`ai_analysis`、`ai_verdict` 或 `vulnerability_report`。过程入口仍使用上述
`status/tasks/vulnerabilities` 外层对象汇总全部任务，避免改变扫描协调接口。
