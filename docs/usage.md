# 扫描使用指南

[文档目录](README.md) · [安装 Agent](getting-started.md#安装-agent) · [配置参考](configuration.md)

## 创建扫描

1. 登录后打开「新建扫描」，选择在线 Agent。该 Agent 必须已配置至少一个启用的 `provider/model`。
2. 填写扫描名称、项目总路径、扫描模块路径和产品。
3. 选择扫描模式，按需配置 MCP 与漏洞验证。
4. 开始扫描，在详情页查看威胁分析、候选点、漏洞挖掘、复核和验证结果。

项目总路径和非空的扫描模块路径必须是目标 Agent 上的绝对路径，例如 `/home/user/project/src`、`C:\work\project\src` 或 `\\server\share\project\src`。不接受 `src`、`./src`、`../src`、`~/project`、`C:src`。模块路径留空表示整个项目；目录是否存在及是否位于项目内由 Agent 检查。多版本模式逐版本校验路径。

Checker 在「客户端配置 → 高级配置 → 漏洞挖掘」中按模式维护，新建扫描页面不逐项选择 Checker。服务端在创建扫描时固化规则和方法选择，续扫沿用该扫描的快照。

## 扫描模式

| 模式 | 当前行为 |
| --- | --- |
| 标准 | Web 默认；固定运行 `static_candidate` 与 `threat_pattern_audit`，启用威胁分析和默认去误报方法；规则默认排除 `skill_only_project_audit` |
| 自定义 | 可选择威胁分析、漏洞挖掘引擎、是否自动去误报及其方法 |
| 多版本测试 | 对 2–5 个版本执行规则扫描与跨版本归并；列表首项为基准版本，固定关闭 CodeGraph 和知识库 MCP |
| 智能 | 页面占位，当前不可选择 |
| 快速 | 保留 API、客户端高级配置与历史续扫兼容，Web 新建扫描不再提供入口 |

标准模式的两个引擎在 UI 中分别为“DeepHole基于代码风险点的漏洞挖掘引擎”和“DeepHole基于攻击模式的漏洞挖掘引擎”。规则是否可用还受清单的 `enabled`、`visibility` 和用户权限限制，不代表所有规则目录都会执行。

多版本静态候选按问题类型使用对应 Checker Skill；基准版本威胁审计复用攻击模式引擎。已确认问题的跨版本匹配、对照版本新增或变化威胁的审计使用多版本审计能力。详见[多版本引擎](../deephole_client/vulnerability_mining/engines/multi_version/README.md)。

新建扫描优先选择 `opencode_lightweight_threat_analysis`。还可选择 Codex 轻量级方法或 DeepHole 原生方法，方法清单见[威胁分析方法](../deephole_client/threat_analysis/README.md)。

## 扫描流程与结果

静态分析需要的索引完成后，威胁分析与不依赖其产物的挖掘工作可以并行；`threat_pattern_audit` 和兼容的 `threat_audit` 等待威胁分析成功。漏洞验证与去误报按问题异步排队，有独立生命周期，不应把扫描主流程完成等同于复核、验证全部完成。

静态规则在独立进程中执行。单条规则失败时保留其它成功规则的候选，并记录 `checker_errors`；部分成功状态为 `partial`，所有规则失败时为 `error`。详情页会展示静态分析失败信息。

候选点通过稳定的 `idx` 保存审计状态和结果；同模式过滤也会形成明确的审计记录。匹配规则和边界见[Checker 开发参考](checker-development.md#候选去重与同模式过滤)，结果页面说明见[审计结果](audit_results.md)。

git 历史问题挖掘与同类变体排查当前不参与默认扫描链路，相关实现仅保留。内存 API 发现预处理也未接入当前静态扫描过程；配置或模块存在不代表会执行。

## 可选 MCP 与漏洞验证

### CodeGraph MCP

默认关闭。启用时选择本地或远端：本地使用固定的 `codegraph serve --mcp` 参数，远端填写 URL 和请求头。此配置与静态分析的 `code_index.db` 是两种能力。

「检测连接」在 Agent 上执行 MCP `initialize` 和 `list_tools`。运行时还会再次连接；准备或恢复失败时当前任务使用文件工具，不回退到其它扫描的 MCP。关闭、未传或历史 `null` 配置不会启动内置代码 MCP。

### 知识库

默认关闭。远程 URL、请求头、超时、`projects_tool` 和 `set_project_tool` 在服务端 `config.yaml` 的 `knowledge_base` 中配置。

启用后点击「检测并拉取项目」，Agent 调用 `projects_tool`；页面读取 `projects`、`currentProject` 和 `sessionProject`，用户选择一个项目。扫描固化连接及 `project_id` / `project_name`，后续任务继承快照。

运行时 OpenCode 原生 MCP 提供查询工具，受管 Hook 强制将查询的 `project_id` 绑定到扫描选择的项目。项目管理工具对模型隐藏，平台不调用 `set_project_tool`。连接或绑定失败时仅禁用该会话的知识库工具，扫描继续。

两种 MCP 的「底层能力」展示反映创建时的配置快照，并非实时连接成功状态；实际结果以任务日志为准。

### 漏洞验证

默认不启用。勾选后，页面按产品展示兼容方法，并依据 `validator.yaml` 的 `field` 生成参数表单。客户端验证策略、方法与参数在创建扫描时一起固化，之后修改配置只影响后续新扫描。

验证方法的 `run_command(..., timeout=...)` 使用命令自己的超时，不能把模型消息超时当作验证函数整体截止时间。方法开发见[漏洞验证文档](vulnerability_validation.md)。

## 停止与续扫

- **停止扫描**：向 Agent 发送取消信号，并取消属于本次扫描的排队或运行中模型任务；已持久化结果保留。当前实现不是“等待当前候选处理完再停止”。
- **续扫**：按持久化生命周期补跑失败、未完成或缺少合法结果的阶段及候选。成功的威胁分析、引擎任务和多版本检查点在满足校验时复用；索引按缓存条件复用，缺失或失效时仍可能重建。
- **威胁分析恢复**：先尝试复用阶段产物；明确失败且未取消时，可按编排规则归档后进行一次干净重跑。轻量级方法失败的 DeepHole 回退规则见[配置参考](configuration.md#轻量级威胁分析与回退)。
- **复核恢复**：续扫也会补跑未形成有效 TP/FP 结论的项目；已经全部完成的复核不会因此全量重跑。
- **配置更新**：正在执行的 OpenCode Session 不会因普通配置更新被强制中断；排队和后续任务按模型策略重新调度，Serve 重载等待安全的空闲边界。

Agent WebSocket 重连会携带仍活跃的扫描、复核与验证身份，服务端重新挂接。用户主动取消的任务不会仅因重连而自动恢复。

## 去误报与人工反馈

标准模式固定启用自动去误报并使用默认方法；自定义模式可以关闭自动复核或选择方法。方法目录由 `method.yaml` 声明名称、默认项、并发和阶段，创建后固化快照。

| 方法 | 阶段与并发 |
| --- | --- |
| `adversarial` | 默认方法，`prove-bug` → `prove-fp` → `final-judge`；方法最大并发 2 |
| `fp_check` | 主张重述、标准/深度验证与六道门；方法最大并发 4 |

对抗式复核中，`prove-bug` 返回 `confirmed=false` 时可直接形成误报结论，跳过后两阶段。结构化输出仍不合法时保留已有阶段证据并报告可重试错误，不伪造 TP/FP。

漏洞复核页提供统一操作：有未完成有效结论的项目时显示「启动复核」，只补跑这些项目；全部已有有效结论时显示「重新复核」，点击后全量重跑。每个方法一次处理一个漏洞，不生成跨漏洞批次攻击链汇总。

人工反馈支持“确认正报”“实为误报”“待分析”和取消标记。正报/误报生成的经验可用于后续选中的漏洞挖掘审计；“待分析”不进入经验库，也不阻止 AI 复核。取消标记会移除对应经验和扫描的反馈关联，使该项可以再次参与复核。

当前候选审计会将所选历史反馈附加到业务 Prompt；不依赖修改原始 Skill 文件。AI 去误报方法本身只读取当前漏洞报告及确有依赖的同轮阶段报告，不附加历史反馈。

## 导出、分享与统计

扫描详情的 ZIP 和 CSV 导出同一批具有有效 AI 复核 TP 最终结论的问题。单个问题也可导出 Markdown，其中包含所选复核方法的阶段证据。

| 格式 | API |
| --- | --- |
| 单项 Markdown | `GET /api/scan/{id}/vulnerability/{idx}/report` |
| CSV | `GET /api/scan/{id}/report` |
| ZIP | `GET /api/scan/{id}/report.zip` |

CSV 包含“文件、行号、函数、问题类型、问题描述、人工反馈、ZIP中的问题报告”七列，最后一列与 ZIP 内的 Markdown 文件对应。尚未完成复核或只做人工确认的项目，不因此自动满足 TP 导出条件。

分享链接和撤销机制见[扫描分享](scan-sharing.md)。所有登录用户均可查看「结果看板」；管理员统计全部扫描，普通用户统计自己创建的扫描。顶部 Token 总计按权限范围汇总并按 Agent 分组，不受产品筛选影响；单次扫描的任务和模型明细见[Token 分类统计](scan-token-categories.md)。

## Web 创建用户 Skill

1. 在「SKILL 市场」点击「在线创建」，填写标识、名称、描述、输入和单次运行超时。
2. 按需上传 `references/`、`scripts/`、`assets/`。
3. 生成并编辑 `SKILL.md` 和 `SCENARIOS.md` 草稿，确认后导入市场。
4. 在客户端 Checker 配置中选择是否启用；扫描创建时固化规则选择并同步资源。

标识用作 Checker 名称和目录名，允许字母、数字与下划线，以字母或下划线开头，最长 64 字符，不能与已有规则重名。文件保存在 `storage.user_skills_dir/<id>/checker.yaml` 与 `skills/<skill-name>/SKILL.md`；旧的平铺 `<id>/SKILL.md` 不自动发现。

用户 Skill 作为项目级候选进入当前审计管线，按统一 JSON Schema 返回一个权威结论。创建器仍保留 `result_mode: markdown_reports` 和 `REPORT_DIR` 模板说明，但当前候选审计器不会据此收集独立 Markdown 报告；输出契约以[候选审计组件](../deephole_client/vulnerability_mining/engines/static_candidate/candidate_audit/README.md)为准。

`SCENARIOS.md` 是辅助说明，不作为独立 Skill。创建者可删除自己的 Skill，管理员可删除任意用户 Skill，内置 Checker 不能通过 Web 删除。
