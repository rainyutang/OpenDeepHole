---
name: fp-check
description: 系统验证已经发现的安全问题，通过完整证据链排除误报，并为每个问题给出 TRUE POSITIVE 或 FALSE POSITIVE 结论。适用于判断具体漏洞是否真实、可利用或属于误报；不用于发现新漏洞。
---

# Trail of Bits fp-check 复核

本 Skill 来源于 Trail of Bits Skills Marketplace 的 `fp-check`，并针对 DeepHole 2.0 运行流程完成中文化适配。

## 适用范围

在用户要求判断“漏洞是否真实”“是否可利用”“是否为误报”或验证某个既有安全发现时使用。

不要用于漏洞挖掘、一般代码审查、功能开发、重构，或用户明确要求只做快速扫描的场景。

## 必须拒绝的自我简化

| 自我简化 | 问题 | 必须采取的动作 |
|---|---|---|
| “快速分析剩余漏洞” | 每个漏洞都必须完整验证 | 返回任务列表，按完整路径验证下一项 |
| “这个模式看起来危险” | 模式匹配不是证据 | 先完成源到汇的数据流追踪 |
| “为提高效率跳过阶段” | 不允许残缺分析 | 执行所选路径的全部步骤 |
| “函数本身不安全” | 上游调用者可能施加约束 | 至少向上追踪两层调用者 |
| “类似代码以前有漏洞” | 每个实例的上下文不同 | 独立验证当前实例 |
| “显然是高危” | 模型容易高估风险 | 完成反方审查和六道门验证 |

## 步骤 0：理解主张与上下文

先用自己的话精确重述漏洞。记录：

- 精确漏洞主张、声称的根因、触发条件和影响。
- 威胁模型：攻击者原有权限、代码运行权限、沙箱和信任边界。
- 漏洞类别，并应用 `references/bug-class-verification.md`。
- 正常执行时如何到达该路径。
- 调用者施加的输入约束。
- 架构中的其它保护层。
- 相关历史变更、已知问题和安全审查。

如果无法形成连贯、可验证的主张，不得猜测结论。

## 选择标准路径或深度路径

仅当以下条件全部满足时选择标准路径：

- 主张清晰具体。
- 路径只涉及单一组件。
- 漏洞类别成熟明确。
- 触发过程不涉及并发或异步竞态。
- 从输入源到危险操作的数据流直接。

执行 `references/standard-verification.md`。标准路径有两个强制升级检查点；任一检查点不满足时，携带已有证据进入深度路径。

以下任一条件成立时选择深度路径：

- 主张有多种解释。
- 数据跨越三个及以上模块或服务。
- 涉及竞态、TOCTOU 或并发。
- 属于缺少明确规范的逻辑漏洞。
- 标准路径无法得出结论或触发升级。
- 用户明确要求完整验证。

执行 `references/deep-verification.md`。

## DeepHole 2.0 单漏洞流程

1. 每个已确认漏洞立即独立执行步骤 0，并选择标准或深度路径。
2. 深度路径严格按依赖顺序执行数据流、可利用性、影响、PoC、反方审查和六道门。
3. 只使用当前调用传入的漏洞上下文形成结论，不读取、汇总或修改其它漏洞的结果。

## DeepHole 分阶段输入合同

DeepHole 会为每个阶段创建独立任务。业务 Prompt 的第一行是 `/fp-check`，随后只提供当前阶段
任务、`原始漏洞报告`、当前阶段 JSON Schema，以及确有依赖时的 `已完成阶段报告` Markdown。
不得要求完整漏洞 JSON、人工反馈、历史模式或 `prior_stages` JSON。

只执行 Prompt 指定的当前阶段，不得提前执行后续阶段。每个阶段都必须读取真实代码并在最终回复
中只返回一个纯 JSON 对象，不得使用 Markdown 代码围栏或附加说明。完整、可供后续阶段阅读的
论证写入 `stage_markdown`。

### `claim_context`：主张与上下文

应用 `references/bug-class-verification.md`，精确重述主张并选择路径。返回：

- `route`：`standard` 或 `deep`
- `claim`、`root_cause`、`trigger`、`claimed_impact`、`threat_model`、`bug_class`
- `stage_markdown`

### `standard_verification`：标准验证

应用 `references/standard-verification.md`、`references/false-positive-patterns.md` 和
`references/gate-reviews.md`。返回：

- `decision`：`verdict`、`escalate` 或 `incomplete`
- `reason`、`evidence`、`stage_markdown`
- `gates`：必须逐项给出布尔值 `process`、`reachability`、`real_impact`、
  `poc_validation`、`math_bounds`、`environment`
- `completeness`：必须逐项给出布尔值 `claim_restatement`、`data_flow`、
  `escalation_checkpoint_one`、`exploitability`、`impact`、
  `escalation_checkpoint_two`、`poc`、`devil_advocate`、`gate_review`

### `data_flow`：数据流分析

应用 `references/deep-verification.md` 和 `agents/data-flow-analyzer.md`。返回 `complete`、
`reason`、`evidence`、`stage_markdown`，并在 `completeness` 中逐项给出布尔值
`phase_1_1`、`phase_1_2`、`phase_1_3`、`phase_1_4`。

### `exploitability`：可利用性验证

应用 `references/deep-verification.md` 和 `agents/exploitability-verifier.md`。返回 `complete`、
`reason`、`evidence`、`stage_markdown`，并在 `completeness` 中逐项给出布尔值
`phase_2_1`、`phase_2_2`、`phase_2_3`、`phase_2_4`。

### `impact`：影响评估

应用 `references/deep-verification.md`。返回 `complete`、`reason`、`evidence`、
`stage_markdown`，并在 `completeness` 中逐项给出布尔值 `confidentiality`、`integrity`、
`availability`、`authentication`、`authorization`、`primary_vs_defense_in_depth`。

### `poc`：PoC 构建

应用 `references/deep-verification.md` 和 `agents/poc-builder.md`。返回 `complete`、`reason`、
`evidence`、`stage_markdown`，并在 `completeness` 中逐项给出布尔值 `phase_4_1`、
`phase_4_2`、`phase_4_3`、`phase_4_4`、`phase_4_5`。

### `devil_advocate`：反方审查

逐项应用 `references/false-positive-patterns.md`。返回 `complete`、`reason`、`evidence`、
`stage_markdown`，并在 `completeness` 中逐项给出布尔值 `challenge_1` 至 `challenge_13`。

### `gate_review`：六道门复核

应用 `references/gate-reviews.md` 综合全部报告。返回 `complete`、`reason`、`evidence`、
`stage_markdown`，并在 `gates` 中逐项给出布尔值 `process`、`reachability`、
`real_impact`、`poc_validation`、`math_bounds`、`environment`。

所有 `reason` 必须是非空结论摘要，所有 `evidence` 必须是字符串数组。`stage_markdown` 必须包含
当前阶段结论、关键 `file:line` 证据、完整推理和仍未解决的问题，不能只是字段摘要。

## 结论规则

- 六道门全部通过：`TRUE POSITIVE`，严重性为高。
- 任意一道门失败：`FALSE POSITIVE`，严重性为低。
- 阶段缺失、结构化输出错误、证据不足或执行失败：不得生成 TP/FP，保留已有阶段证据并标记为未完成以便重试。
- 不得根据其它漏洞、跨漏洞攻击链或扫描级统计提升或改写当前单项结论。

## 参考资料

- `references/standard-verification.md`：直接漏洞的线性验证。
- `references/deep-verification.md`：复杂漏洞的完整依赖流程。
- `references/gate-reviews.md`：六道门和最终判定格式。
- `references/bug-class-verification.md`：按漏洞类别补充验证要求。
- `references/false-positive-patterns.md`：13 项误报挑战。
- `references/evidence-templates.md`：证据记录模板。
