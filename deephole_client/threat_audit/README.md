# 威胁审计过程

公开入口是异步函数 `run_threat_audit(**kwargs)`。它读取威胁分析的原生攻击树和高风险
模块产物，对每条攻击路径中的节点与 `attack_pattern` 逐一配对创建审计任务，不依赖
威胁分析 Python 包。同一攻击树中相同的“节点 + 攻击模式”只保留一个任务，多条攻击
路径的上下文会合并。

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

返回值包含 `status`、逐节点/攻击模式的 `tasks` 和汇总后的 `vulnerabilities`。

威胁审计保持独立执行且不加载候选点 Skill。Prompt 只注入原生威胁分析产物中实际
存在的信息：节点与边、攻击模式、价值资产、攻击路径、关联高风险模块及其代码目录，
以及已识别的对外暴露面；缺失字段不会推测补全。同一节点和攻击模式出现在多条路径时，
代码路径、暴露面与关联说明按原始顺序去重合并。

每个模型任务返回裸 JSON List，允许一次返回多个独立漏洞；没有漏洞时返回 `[]`，
任务仍标记为 `completed`。列表项使用专用
`deephole_client.threat_audit.audit_schema.THREAT_AUDIT_VULNERABILITY_ITEM_SCHEMA`，
不包含
`confirmed`，并要求填写严重程度、漏洞位置、类型、资产影响、完整相关代码、入口到
触发点调用链、攻击入口、根因和触发条件。模型不返回 `ai_analysis`、`ai_verdict`
或 `vulnerability_report`；过程在汇总到平台漏洞对象时统一补充
`confirmed=true` 和 `ai_verdict=confirmed`，因此外层
`status/tasks/vulnerabilities` 接口保持不变。`call_chain` 的每个元素均包含
`function`、`file` 和函数定义起始行 `line`，并按外部入口到漏洞触发点排序。
