# Threat Analysis

威胁分析的实现、CLI、Skill、参考资料和结果解析全部集中在本目录。平台协调器只调用
`run_threat_analysis(**kwargs)`；本目录不导入后端或其它业务过程。

## 配置

```yaml
threat_analysis:
  enabled: true
  implementation: "attack_tree"
  attack_path_audit_mode: "after_analysis"
  product_mcp_name: "product-info"
  product_mcp_detection_timeout_seconds: 60
```

`attack_path_audit_mode` 是平台协调器的调度配置，不是本过程的输入：

- `after_analysis`：默认值。先等威胁分析所有阶段完成并归并结果，再统一启动威胁审计。
- `immediate`：每当攻击路径写入并归并到 JSONL 后，立即派发对应威胁审计任务；最终只补跑未被即时派发的路径。

`attack_tree` 是默认实现。运行时会先在 OpenCode 当前配置中检测
`product_mcp_name` 对应的产品信息 MCP：

- 当前威胁分析代码扫描范围仅限 C/C++ 源文件、头文件和 C/C++ 构建文件；
  Python、TypeScript、Go、Java 等非 C/C++ 文件不会进入代码索引、分片派发或代码证据。
- 检测到时，基础建模阶段优先使用该 MCP 获取价值资产、高风险外部接口和关联关系，再做代码增量补充。
- 未检测到时，基础建模阶段完全从代码识别资产、接口和关联关系。
- 基础建模阶段先启动 1 个 `threat-asset-interface-agent`，一次性识别当前完整
  C/C++ 扫描范围内的价值资产、关键风险、高风险外部接口、资产接口关系和攻击目标。
- 初始识别完成后，Harness 会把当前已识别的价值资产和攻击目标列入输入，
  并行启动 3 个 `threat-base-model-gap-review-agent` 追问是否存在遗漏。
  追问 Agent 只输出遗漏或需要补充的项目，已覆盖项目不重复输出。
- Harness 最终合并初始识别 Agent 和 3 个追问 Agent 的结果，仍输出原有
  `assets`、`high_risk_external_interfaces`、`asset_interface_links`、
  `risks`、`attack_goals` JSON 契约。
- 基础建模合并会先把初始识别和追问补充中的资产、风险、接口和攻击目标 ID 归一，再按人类可读
  名称和语义 key 去重，避免同一价值资产被多个 `ASSET-*` 编号重复保留。
- 基础建模之后采用攻击树深度优先调度：拿到一个攻击目标后，按
  `攻击目标 -> 攻击域 -> 攻击面 -> 必要的方法确认` 逐分支下钻；一个
  攻击面及其方法确认处理完后再处理同域下一个攻击面，一个攻击域处理完后再处理
  同目标下一个攻击域，一个攻击目标处理完后再处理下一个攻击目标。不会先把所有
  攻击目标、攻击域或攻击面同层分解完再进入下一层。

新流程的事实源是传入 `work_dir` 下的
`run/stream/attack_paths.jsonl`，中间结果 `run/res.json` 由 JSONL 归并生成。
公共函数最终把归一化结果写到 `result_path`；未传时沿用
`<project_path>/res.json`，也可以显式指定到过程工作目录。

默认实现会安装以下内置 Skill 到 OpenCode workspace：

- `threat-base-model-shard-planner`
- `threat-asset-interface-agent`
- `threat-base-model-gap-review-agent`
- `threat-asset-enumerator`
- `threat-attack-goal-enumerator`
- `threat-code-evidence-mapper`
- `threat-attack-goal-agent`
- `threat-attack-domain-agent`
- `threat-attack-surface-agent`
- `threat-method-confirm-agent`

## 新增实现

1. 在本目录新建实现类，满足 `base.ThreatAnalysisImplementation`。
2. 在本目录的 `registry.py` 注册实现 ID，并在 `runner.py` 接入其执行适配。
3. 保持对外仍只通过 `run_threat_analysis(**kwargs)` 调用。

## 单独运行

```bash
python -m deephole_client.threat_analysis \
  --project-path /path/to/project --work-dir /tmp/threat-analysis \
  --task-agent-config ./task-agent.yaml
```
