# DeepHole Client

`deephole_client` 是仍以 “Agent” 展示和通信的本地客户端包。后端只下发任务；客户端协调
下面七类可独立运行的业务过程，并把它们的事件和最终结果转换成现有 HTTP/WebSocket 上报。

| 过程实现 | 平台异步入口 |
|---|---|
| `code_graph_build/` | `run_code_graph_build(**kwargs)` |
| `threat_analysis/methods/<method_id>/` | `threat_analysis_runner.run_threat_analysis(**kwargs)` |
| `vulnerability_mining/engines/static_candidate/static_analysis/` | `run_static_analysis(**kwargs)` |
| `vulnerability_mining/engines/static_candidate/candidate_audit/` | `run_candidate_audit(**kwargs)` |
| `vulnerability_mining/engines/threat_audit/` | `run_threat_audit(**kwargs)` |
| `fp_review/methods/<method_id>/` | `run_fp_review(**kwargs)`（单漏洞） |
| `vulnerability_validation/` | `run_vulnerability_validation(**kwargs)` |

平台入口均为 `async`，只接受 `**kwargs`，未知 key 会报错。框架自有过程通过各目录 README
记录输入契约并可按需提供 `__main__.py`；每个威胁分析方法目录保留原生同步入口，平台发现、
选择和适配代码位于方法目录外。业务过程不导入 `backend`、`reporter`、`server` 或其它业务
过程；需要模型时只调用 `task_agent.run_opencode_task()`。

单独提取普通过程时复制目标过程目录即可；提取静态分析或候选点审计时复制整个
`vulnerability_mining/engines/static_candidate/`，以同时保留两个过程的公共规则树。需要模型的
过程还要让通用 `task_agent` 包可导入，并可通过 `task_agent_config` 指向自己的
`task-agent.yaml`。不调用模型的代码图谱构建和静态规则分析无需 Task Agent 配置。

接入已有实现时，实现可以直接占用对应过程目录，平台适配器放在目录外，只负责参数校验、
上下文绑定和调用。已有入口是同步函数也不需要修改实现，可由异步门面调用
`task_agent.run_sync_component()`；同步实现内部仍可正常使用
`task_agent.run_opencode_task()`。通用过程仍可通过门面的 `skill_paths` 上下文临时合并自己的
Skill。威胁分析同样只把本次所选方法相邻 `skills/` 中的 Skill 根加入任务上下文，不再把
内置方法的 Skill 全局复制到 Agent workspace。内置
`threat_analysis/methods/deephole_threat_analysis/` 可由
`ThreatAnalysis/src/threat_analysis_harness` 的内容直接覆盖；相邻的
`threat_analysis_runner.py` 将所选方法按原包名加载，不修改原生绝对导入。

完整的威胁分析方法目录、清单、原生五参数入口和三份 JSON 返回契约见
[威胁分析方法扩展](threat_analysis/README.md)。

威胁审计过程及专用输出 Schema 由 `vulnerability_mining/engines/threat_audit/` 直接拥有，
不再使用顶层 `threat_audit/` 或专用 `threat_audit_skills/`；该过程继续直接构造 Prompt，
不加载 Skill。

## 威胁分析入口

```python
from deephole_client.threat_analysis_runner import run_threat_analysis

result = await run_threat_analysis(
    method_id="deephole_threat_analysis",
    code_path="/src/project",
    output_path="/tmp/threat-analysis",
    is_resume=True,
    task_agent_config="./task-agent.yaml",
)
```

| key | 必填 | 类型 | 说明 |
|---|---:|---|---|
| `method_id` | 否 | str | 威胁分析方法目录名，默认 `deephole_threat_analysis` |
| `code_path` | 是 | path | 待分析代码目录 |
| `output_path` | 是 | path | 原生产物输出目录；不存在时创建 |
| `is_resume` | 否 | bool | 是否复用原生阶段产物，默认 `false` |
| `product_mcp` | 否 | str 或 null | 原生预留参数，原样传入 |
| `attack_modes` | 否 | mapping 或 null | 原生预留参数，原样传入 |
| `task_agent_config` | 否 | path | 脱离平台运行时使用的 Task Agent YAML |
| `output` | 否 | callable | 同步或异步事件回调 |
| `cancel_event` | 否 | event | 提供 `is_set()` 的取消信号 |

成功时必须包含 `result=true`、`value_asset_path`、`attack_tree_path` 和
`high_risk_modules_path`；失败时必须包含 `result=false` 与非空 `reason`。外层适配器保留原生
返回字段，同时校验方法签名和返回契约。

统一事件格式：

```json
{
  "process": "candidate_audit",
  "kind": "log|progress|item|artifact",
  "message": "...",
  "data": {}
}
```

协调器先调用代码图谱构建，再按扫描快照启动独立威胁分析和所选漏洞挖掘引擎；无需威胁
产物的引擎可与威胁分析并发。静态分析只读取已有 `code_index.db`，候选点审计只消费静态
分析结果。威胁分析保持原生三份 JSON 产物和原生返回值，使用独立开关及生命周期，协调器
只在上报时把文件装入透明 artifact bundle。威胁审计不是威胁分析的一部分：选择它时必须
同时启用威胁分析，并等待分析成功后再读取攻击树和高风险模块文件。任务按最终攻击树实例隔离，
仅以该树内的“叶子节点 + 关联攻击模式”拆分；不同树复用局部 ID 时也不会合并。每个任务携带
该叶子节点向价值资产追溯的最长可用路径、路径上按模块聚合并去重后的代码路径和目标资产说明；
每个模块在相关代码路径列表中只出现一次，同一模块的多个路径合并在该条目中。路径中的
空 ID、未知、重复或类型位置错误节点会被跳过，未到根节点也继续审计，完全不可恢复的单条路径
只记录告警而不阻止其它任务。普通内部节点没有代码路径时省略。也可以显式不选任何漏洞挖掘
引擎，仅运行威胁分析。后端不执行这些过程，也不维护实现专属 Schema。
