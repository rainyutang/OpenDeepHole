# DeepHole 2.0

基于 SKILL 的 C/C++ 源码白盒审计工具。核心漏洞挖掘在用户本地 Agent 上执行，源码不离开本机，结果汇报到 Web 服务器统一展示。

## 整体架构

```
[服务器端]
  FastAPI (port 8000)
  ├── Web UI（React + Tailwind CSS）
  ├── WebSocket /api/agent/ws 接受 Agent 连接
  ├── 通过 WS 下发扫描任务（task / stop / resume）
  ├── 接收 Agent 上报的扫描事件和漏洞结果（HTTP POST）
  ├── 存储扫描历史和误报反馈
  └── 提供 Agent 下载包

[用户本地]
  opendeephole-agent（守护进程，从 Web UI 下载）
  ├── 启动后主动向服务器发起 WebSocket 连接
  ├── 发送 hello 握手，接收 welcome 确认
  ├── 等待服务器通过 WS 推送扫描任务
  ├── 收到任务后：代码图谱构建 → 按选择运行分析与漏洞挖掘 → 验证/去误报
  └── 实时通过 HTTP POST 将事件和漏洞结果上报服务器
```

**交互流程：**

```
用户在 Web UI 点击「新建扫描」
  → 选择在线 Agent、填写代码路径（Agent 所在机器的路径）、选择检查项
  → 服务器通过 WebSocket 推送任务到 Agent
  → Agent 在本地执行完整扫描流程
  → 进度和结果实时显示在 Web UI
```

**源码不离开本地**：Agent 只上报漏洞分析结论，不上传源码文件。  
**误报反馈闭环**：用户在 Web UI 标记正报或误报后，选中的经验会注入 SKILL 中减少重复误判；也可将问题标为“待分析”作为人工待处理状态，该状态不进入经验库且仍可继续 AI 去误报复核；已标记问题也可以取消标记，取消后会移除该标记生成的经验并重新进入 AI 去误报候选。
**静态候选收敛、同类合并与同模式过滤**：DB 类 checker 会按本次 `code_scan_path` 在 SQL 层收敛函数范围；静态候选进入 AI 前会按 checker `family` 做函数级同类合并，并只向 OpenCode 提供“函数/变量或表达式/问题类型”的最小审计问题。AI 审计确认某个同模式代表点为非问题后，可通过 `pattern_filter` 自动过滤同 `vuln_type + subject + scope` 的后续候选。详细规则见下文“静态候选合并与同模式过滤”。
**扫描流程与威胁分析选择**：扫描详情固定展示静态分析、威胁分析、漏洞挖掘、漏洞验证和去误报，代码图谱构建作为底层能力单独显示。新建扫描通过 `threat_analysis_enabled` 独立选择威胁分析，并通过 `threat_analysis_method` 从 `deephole_client/threat_analysis/methods/` 自动发现的方法中选择一个；内置方法为“DeepHole威胁分析”。`mining_engines` 独立选择漏洞挖掘引擎；可以只运行威胁分析，但选择 `threat_audit` 时必须同时启用威胁分析。代码图谱完成后，静态分析和威胁分析可以并行，威胁审计等待威胁分析成功后再启动，验证与去误报继续按确认问题增量触发。
**git 历史问题挖掘 + 同类变体排查（当前硬禁用）**：默认扫描链路在完成代码索引和工作区准备后，会并行启动威胁分析和静态分析；静态分析完成后立即进入候选点 AI 审计，威胁分析结果生成后独立上报展示，并在扫描最终完成前收尾。git 历史问题挖掘及同类变体排查的实现代码仍保留，但当前版本不会执行该阶段，也不在客户端配置页面中暴露开关。

**AI 去误报（扫描级开关与目录化方法）**：新建扫描时可选择是否自动去误报，并从 `deephole_client/fp_review/methods/` 自动发现的方法目录中选择一种。每个方法都通过统一的 `async def run(**kwargs)` 入口一次处理一个漏洞，输入包含本次扫描代码路径、漏洞索引和单个漏洞对象；平台负责扫描级排队、方法并发、取消、补跑和持久化。内置 `adversarial` 保留 `history_match`、`prove-bug`、`prove-fp`、`final-judge` 流程，内置 `fp_check` 执行主张重述、标准/深度验证与六道门，最多并发四项。方法名称、默认项、最大并发、阶段和说明文档均来自各自的 `method.yaml`，扫描创建后会固化所选方法快照；方法不得生成跨漏洞批次汇总或修改其它漏洞结论。创建请求字段为 `auto_fp_review` 与 `fp_review_method`；前者省略时使用 `fp_review.auto_on_complete`，关闭时仍可手动启动单项复核，后者省略时使用目录清单声明的默认方法。
**漏洞报告导出**：对每一个 AI 判定为「是问题」的扫描项可单独导出 Markdown 报告，包含所选去误报方法的阶段证据；扫描详情页顶部「导出报告」会打包全部单项报告。对应端点 `GET /api/scan/{id}/vulnerability/{idx}/report` 与 `GET /api/scan/{id}/report.zip`。

### 静态候选合并与同模式过滤

静态扫描阶段的目标是先保留足够召回，再把重复审计成本压到 AI 调用前后两个位置：

- **Checker 内部去重**：各 analyzer 可先按自己的静态命中特征去重，例如同一 semgrep 命中、同一函数变量或同一资源表达式只产出一个 `Candidate`。公共扫描管线不依赖 analyzer 的内部规则，但要求 `Candidate.description` 保持中性、简短，`metadata.subject` 记录被审计的变量、表达式、函数或资源对象，`metadata.problem` 记录问题类型。
- **静态同类合并**：`static_dedup: true` 时，Agent 在所有静态候选和 git 同类变体候选汇总后，按 `(family, file, function)` 分组。`family` 来自 `checker.yaml`，未配置时使用 checker 名称；因此 `npd`、`mp_npd`、`npd_funcret` 等可配置成同一 `family`，在同一文件同一函数里只保留一个代表候选进入 AI。
- **代表点选择**：合并前会先按 checker 候选数量从少到多排序，同一 checker 内保持原有产出顺序；每个分组取排序后的第一个候选作为代表点。被合并候选的 `vuln_type`、`subject`、`file`、`line` 会写入代表点的 `metadata.merged_from`，所有非空 `subject` 会合并回代表点的 `metadata.subject`，并重写为最小化描述。
- **缓存与恢复边界**：合并后的候选会写回本次扫描工作目录的 `candidates.json`，后续函数源码快照、总候选数、断点恢复都以合并后的候选为准；重试未完成候选时不重新做静态同类合并。
- **同模式 key**：`pattern_filter.enabled: true` 时，AI 审计前为每个候选计算模式 key。只有存在 `metadata.subject` 的候选才可传播过滤；key 为 `(vuln_type, subject, scope)`。`scope` 由配置决定：`directory` 表示同目录（默认），`file` 表示同文件，`repo` 表示全仓。
- **代表点排除方式**：进入 AI 审计队列前会按模式 key 做轮转排序，尽量先让每种模式都有代表点被审计。某个候选实际调用 AI 后，只有结果为 `confirmed=false` 且 `ai_verdict == "not_confirmed"`，才把该模式加入已否决集合；超时、无结果、异常或确认存在问题都不会传播排除。
- **后续候选处理**：后续候选开始处理时，如果命中已否决模式，会跳过 LLM 调用，直接上报一条 `confirmed=false`、`ai_verdict="filtered_same_pattern"` 的结果，分析文本标记为“同模式代表点已被 AI 审计否决，自动过滤（未调用 LLM）”，并记录为已处理，保证进度和恢复状态一致。

内置 checker 当前的 `subject` 取值如下。只有“写入 `metadata.subject`”列为“是”的 checker，才会在 AI 否决后触发同模式过滤；其他 checker 即使描述里有类似 subject 的文本，也会被视为不可传播的独立候选。

| Checker | 写入 `metadata.subject` | 当前 subject 取值方式 |
|---------|--------------------------|------------------------|
| `npd` | 是 | 被解引用且缺少判空的变量名 `var_name` |
| `chain_npd` | 是 | 链式指针表达式 `expr_text`，例如 `ctx->a->b` |
| `oob` | 是 | 函数名 `func_name`，这是函数级 OOB 候选 |
| `sensitive_clear` | 是 | 疑似敏感变量名去重后用逗号拼接 |
| `safe_mem_oob` | 否 | 描述中使用 `call_name`，否则 `dst_expr`，否则“安全内存函数调用” |
| `loop_mut_idx_oob` | 否 | 描述中使用 copy_from_user 重点长度变量 `len_expr`/目标变量 `dst_expr`，或循环变化索引 `idx_expr`，否则“循环索引” |
| `bufoverflow` | 否 | 描述中依次取 `idx_expr`、`field_name`、`buf_name`、`ptr_name`、`type_name`，否则“缓冲区访问” |
| `intoverflow` | 否 | 描述中使用可疑整数运算 `arith_expr`，否则危险使用点 `sink_expr`，否则“整数运算” |
| `mp_npd` | 否 | 描述中使用多层指针 `ptr_expr`，否则 `root->field1`/`root`，否则“多层指针” |
| `npd_funcret` | 否 | 描述中使用接收返回值或输出参数赋值的指针 `ptr_name` |
| `memleak` | 否 | 函数级分组候选，描述中列出该函数内多个泄漏位置和变量 |
| `resleak` | 否 | 描述中使用 cppcheck 资源符号 `symbol`，或锁类资源类型 `res_types` |
| `multi_ptr_leak2` | 否 | 描述中使用释放调用点、释放实参、结构体和指针成员列表 |
| `mp_resouce_leak` | 否 | 描述中依次取多层成员 `field_expr`、资源获取 `acq`、根对象 `root`，否则“资源成员” |
| `double_free` | 否 | 描述中依次取 `ptr_name`、`obj_name->field_name`、`field_name`、`obj_name`，否则“指针/资源” |
| `inf_loop` | 否 | 描述中使用循环控制变量 `loop_var`；没有控制变量时只按函数/规则类别描述 |

## 快速开始

### 部署服务器

**Docker（推荐）：**

```bash
docker-compose up --build
```

访问 `http://localhost:8000`

| Checker | 说明 | 模式 | 静态分析器 |
|---------|------|------|-----------|
| `npd` | 空指针解引用 (NPD) | opencode | 有（tree-sitter AST 分析） |
| `oob` | 数组/缓冲区越界 (OOB) | opencode | 有 |
| `safe_mem_oob` | 安全内存函数越界 (SAFE_MEM_OOB) | opencode | 有（semgrep 高风险规则） |
| `loop_mut_idx_oob` | 循环索引/copy_from_user 累加长度越界 (LOOP_MUT_IDX_OOB) | opencode | 有（semgrep 宽召回规则） |
| `memleak` | 异常分支内存泄漏 (MEMLEAK) | opencode | 有（tree-sitter 路径分析） |
| `intoverflow` | 整数翻转/溢出 (INTOVFL) | opencode | 有（多阶段追踪） |
| `sensitive_clear` | 敏感信息未清零 (SENSITIVE_CLEAR) | opencode | 有（启发式敏感变量筛选，函数级审计） |
| `resleak` | 全类型资源泄露 (RESLEAK) | opencode | 有 |

**第 1 步：下载安装包**

打开 Web UI，点击右上角 **「下载 Agent」**，保存 `opendeephole-agent.zip`，解压到本地目录。

**第 2 步：配置 agent.yaml**

```yaml
server_url: "http://your-server:8000"
agent_name: "my-agent"
owner_token: ""
```

下载包会自动填入 `server_url` 和 `owner_token`。首次启动并连接后，在 Web UI 的 **「客户端配置」** 页面按机器名与 IP 选择客户端。页面只有「基础配置」和「高级配置」两个子页：基础配置包含基础参数与模型配置，高级配置包含威胁分析、产品信息、漏洞挖掘、去误报和漏洞验证。新注册客户端的模型列表固定为空；必须手动添加并启用至少一个明确的 `provider/model` 后才能创建或续建扫描。服务端会持久化配置并推送给在线客户端，已有稳定客户端重连时保留原配置，离线编辑会在重连后生效。

所有登录用户都可以打开 **「结果看板」**。管理员查看全部扫描，普通用户只汇总自己创建的扫描；看板顶部的 Token 总计覆盖当前权限范围内的全部扫描，按 Agent 分组且不受产品筛选影响。单次扫描的模型和任务 Token 明细仍保留在扫描详情中。

**「新建扫描」** 页面会直接读取当前代码仓 `deephole_client/vulnerability_mining/engines/` 中的引擎清单，可为一次扫描选择一个或多个引擎；这个选择与 Agent 无关，不需要等待 Agent 上报引擎。每个已选引擎还可独立配置其结果是否进入去误报，解析后的选择会随扫描固化。

**「新建扫描」** 页面的代码图谱 MCP 是可选项，默认关闭；未启用、未传或传入 `null` 时，模型任务只使用 `read`、`grep`、`glob` 等文件工具，不会启动或回退到内置代码 MCP。启用后可选择本地进程或远端服务，并配置启动参数、环境变量、请求头和 MCP 调用超时。`code_graph_mcp.timeout_seconds` 按秒填写，默认值 `300` 会在运行时转换为 OpenCode MCP 配置中的 `"enabled": true, "timeout": 300000`；该超时同时用于连接、工具发现和单次工具调用。启用的配置会作为扫描私有快照持久化，并在续扫、去误报和漏洞验证中继续使用；不同扫描不会共享代码图谱连接。

运行时会严格使用填写的 MCP 名称，不会追加扫描 ID、前缀或哈希。例如名称为 `static-mcp` 且服务提供 `static_read` 时，OpenCode 中的工具名就是 `static-mcp_static_read`；扫描 ID 仅用于内部连接隔离。

新建扫描页和产品信息配置区都提供手动 **「检测 MCP」**：检测只在 Agent 上执行 MCP `initialize` 和 `list_tools`，不会调用业务工具。扫描代码图谱的检测结果不写入 Agent 全局配置；运行时仍会再次连接，连接或初始化失败时继续扫描并只使用文件工具，不会回退到其它扫描或内置代码图谱。对于本地 `codegraph` CLI，项目 `.codegraph/codegraph.db` 是否就绪仍以扫描任务日志和产物为准。

仓库内置了用于联调的确定性假代码图谱 MCP，可直接运行
`python tests/fixtures/fake_code_graph_mcp.py --port 9010 --marker scan-a`，并在新建扫描中填写远端 URL `http://127.0.0.1:9010/mcp`。真实 OpenCode Serve 的双图谱连接与隔离回归可用
`python -m pytest -q tests/test_scan_code_graph_mcp_integration.py` 执行。

模型池必须至少包含一个已启用且填写明确 `provider/model` 的模型；不再支持“使用 CLI 默认模型”的配置行，没有显式模型时创建和续扫都会被拒绝。阶段级模型能力、模型调用超时和模型重试会覆盖具体模型行的超时/重试；漏洞验证 kwargs 中的 `run_command(..., timeout=...)` 仍只由该命令自己的超时控制，不受模型超时影响，也没有验证函数整体截止时间。

**第 3 步：确认代码索引工具**

代码索引依赖 Universal Ctags。Windows Agent 下载包已内置 `ctags-p6.2.20260517.0-x64/ctags.exe`，`run_agent.bat` 会优先使用包内版本；在 Git Bash/MSYS/Cygwin 中运行 `run_agent.sh` 时也会优先使用包内版本。缺少可用 `ctags` 或 `ctags` 不支持 JSON 输出时 Agent 会停止并提示处理方式，不会回退到旧索引方式。

Linux / macOS 仍需提前用系统包管理器安装 Universal Ctags：

```bash
# Debian / Ubuntu
sudo apt install universal-ctags

# macOS
brew install universal-ctags
```

**第 4 步：启动 Agent 守护进程**

```bash
# Linux / macOS
chmod +x run_agent.sh
./run_agent.sh

# Windows
run_agent.bat
```

启动成功后，终端输出类似：

```
DeepHole 2.0 Agent
  Name    : my-agent
  Server  : http://your-server:8000

  Connected via WebSocket, agent_id: a1b2c3d4...
```

Agent 通过 WebSocket 保持长连接，等待服务器推送任务。Agent 默认允许接收最大 64 MiB 的单条
WebSocket 消息，以支持大代码仓续扫时携带较多候选点；如续扫命令仍超过该限制，可设置正整数
环境变量 `OPENDEEPHOLE_WS_MAX_MESSAGE_MB` 后重启 Agent。
启动后的 Agent 支持任务执行前自动更新运行时代码。服务端更新 `deephole_client/`（包含各独立过程及其规则、技能和验证器）、`task_agent/`、`backend/`、`mcp_server/`、包内 Windows ctags 目录或 `requirements-agent.txt` 后，旧 Agent 会在下次启动扫描、恢复扫描、去误报或漏洞验证任务前下载最新 runtime 并重启后继续执行；runtime 更新包会携带快照 manifest，用于校验下载 zip 的文件集合和逐文件 hash。创建或恢复扫描时，选中的用户规则还会按 `static/` 与 `audit/` 两个根目录传输。如果更新了 `run_agent.sh` 或 `run_agent.bat`，需要重新下载 Agent 包。

验证方法的 manifest、kwargs、返回值和 OpenCode 调用约定见 [`docs/vulnerability_validation.md`](docs/vulnerability_validation.md)。

**第 4 步：在 Web UI 创建扫描任务**

1. 点击右上角「新建扫描」
2. 从下拉列表选择已在线的 Agent
3. 填写代码路径（Agent 所在机器上的绝对路径，如 `/home/user/myproject`）
4. 选择要运行的检查项，点击「开始扫描」
5. 扫描进度实时显示在当前页面

### Agent 启动参数

```
./run_agent.sh [选项]

选项：
  --server URL        覆盖 agent.yaml 中的 server_url
  --name NAME         覆盖 Agent 显示名称
  --config FILE       指定配置文件路径（默认 ./agent.yaml）
```

### 停止与恢复扫描

- **停止**：在扫描详情页点击「停止扫描」，服务器直接通知 Agent 停止。当前候选处理完成后立即停止，已处理的结果保留。
- **恢复**：在扫描列表页点击「恢复」，服务器通知 Agent 继续同一扫描任务，自动跳过已处理的候选，从断点继续。无需重新启动 Agent 或重新索引代码。
- **配置更新**：运行中的扫描收到新的客户端配置后，不会中断当前 OpenCode 任务；排队任务会按新模型配置重新调度，后续任务使用最新工具、模型池和代理绕过配置。

## 误报反馈机制

1. 在 Web UI 的漏洞列表或经验库中提交正报/误报反馈，或在漏洞列表中标记“待分析”
2. 经验库中打勾的反馈会记录到本次扫描的 `feedback_ids`
3. 已选反馈按漏洞类型注入到对应 SKILL 文件的「历史用户经验」章节
4. LLM 在分析同类候选时参考这些经验，校验并减少重复误判
5. “待分析”只保存为漏洞人工状态，不生成经验库反馈、不注入 SKILL，也不会阻止该问题继续进入 AI 去误报或续扫候选
6. 已人工标记的问题可单条或批量取消标记；取消后会删除该标记生成的反馈、从本次扫描的 `feedback_ids` 中移除，并在下次 AI 去误报时重新复核
7. 创建扫描时通过 `auto_fp_review` 决定是否自动复核，通过 `fp_review_method` 固定选择 `adversarial`（对抗式复核）或 `fp_check`（Trail of Bits fp-check 复核）；省略自动开关时才读取全局 `fp_review.auto_on_complete`
8. **正方早退**：`prove-bug` 最终 JSON 返回 `confirmed=false`（非问题）时正式早退，直接以正方理由记录"可能误报"最终结果并推送前端，跳过 `prove-fp` 和 `final-judge`；只有正方判定为真实问题时才进入后两个阶段，此时最终结论采用 `final-judge` 的最终 JSON
9. 对抗式复核继续逐项运行并保留原早退行为；Trail of Bits fp-check 对每个确认问题立即独立复核，扫描中也可手动补跑，单项并发上限为四
10. 每个阶段结束后页面实时展示对应中文 Markdown；结构化输出不完整时在同 Session 纠正，仍失败则明确结束为可重试错误并保留已有阶段证据，不生成 TP/FP。扫描完成后另行生成和导出批次攻击链汇总，旧成功汇总在更新失败时继续保留
11. **断线续挂**：Agent WebSocket 重连时会在 hello 中上报仍在运行的 FP 复核任务，后端重新挂接并恢复 running 状态；progress/result/stage-output 上报也会自动把因断连误标为 error 的复核任务恢复为 running

## 统一的 Checker 架构

内置 `static_candidate` 引擎将静态召回实现、候选点 AI 审计实现和规则统一放在引擎目录中。每条规则独占一个目录，静态文件与它使用的 Skill 一起维护：

```text
deephole_client/vulnerability_mining/engines/static_candidate/
├── static_analysis/          # 静态召回过程实现
├── candidate_audit/          # 候选点审计过程实现
└── rules/<name>/
    ├── checker.yaml          # 规则元数据（格式保持不变）
    ├── analyzer.py           # 可选：导出 Analyzer(BaseAnalyzer)
    ├── *.yml                 # 可选：Semgrep 等静态规则
    └── skills/<skill-name>/
        ├── SKILL.md          # AI 审计规则
        ├── SCENARIOS.md      # 可选
        └── references/       # 可选
```

后端只读取 Checker 元数据和构建传输包，不加载静态分析器，也不执行审计。源码和新 Agent 都使用统一规则树；传输包内部继续保留 `static/` 与 `audit/` 分区，以便滚动升级期间旧 Agent 仍能接收规则，新 Agent 解包后会还原为统一目录。

**checker.yaml 格式：**

```yaml
name: uaf
label: UAF
description: "Use-After-Free 检测"
enabled: true
visibility: public    # public: 所有用户可见；admin: 仅管理员测试可见
# family: uaf          # 可选，同类 checker 的跨规则去重家族；未配置时使用 name
# mode: opencode       # 可选；旧 api 值仅作 prompt.txt 兼容，不会直调 API
# skill_name: uaf-audit # 可选，自定义 OpenCode skill 名称
# model_capability: high # 可选，any/low/medium/high；未配置默认 any
```

新 Checker 应在 `skills/<skill-name>/SKILL.md` 提供 Skill，并使用默认 `mode: opencode`。Skill 的 YAML frontmatter `name` 必须与目录名一致；当一条规则包含多个 Skill 时，通过 `checker.yaml.skill_name` 选择。历史 `mode: api` checker 仍可读取 `prompt.txt`，但运行时会包装成临时 SKILL 后提交 OpenCode session。
同一 `family` 的候选会在静态阶段按同文件同函数做跨规则合并，只保留一个代表候选进入 AI 审计；代表点和同模式过滤规则见上文“静态候选合并与同模式过滤”。
新增或修改规则后无需重启后端；后端会在列表刷新和点击开始扫描时重新扫描元数据。测试阶段建议设置 `visibility: admin`，只有管理员能看到并启动该 Checker；测试完成后改为 `visibility: public` 即可对所有用户开放。

**内置 Checker：**

| Checker | 说明 |
|---------|------|
| `npd` | 空指针解引用 (Null Pointer Dereference) |
| `oob` | 数组/缓冲区越界 (Out-of-Bounds Access) |
| `safe_mem_oob` | 安全内存函数越界（dst/dstsz 不匹配） |
| `loop_mut_idx_oob` | 循环变化索引或 copy_from_user 累加长度导致的数组/指针越界 |
| `intoverflow` | 整数翻转/溢出 |
| `memleak` | 内存泄漏 |
| `sensitive_clear` | 敏感信息未清零（启发式筛选敏感变量所在函数，按函数审计生命周期清零状态） |
| `resleak` | 全类型资源泄露（文件/套接字/锁/内存映射等） |

### 在 Web UI 在线创建用户 SKILL

除直接在统一规则目录中开发内置 Checker 外，登录用户也可以在 Web UI 的 **SKILL 市场** 中创建项目级 SKILL。用户创建的规则会保存为 `storage.user_skills_dir/<id>/checker.yaml` 和 `storage.user_skills_dir/<id>/skills/<skill-name>/SKILL.md`，所有用户可在新建扫描页选择使用；服务端在传输时自动拆成静态和审计资源。旧的 `<id>/SKILL.md` 平铺格式不再参与自动发现，需要按新目录结构手动整理。

创建流程：

1. 打开「SKILL 市场」，点击「在线创建」
2. 填写 **标识**、名称、描述、输入和单次运行超时时间
3. 可选上传 `references/`、`scripts/`、`assets/` 资料
4. 点击「生成草稿」，检查并编辑生成的 `SKILL.md` 和 `SCENARIOS.md`
5. 点击「导入 SKILL 市场」，导入后即可在新建扫描页选择

用户填写的 **标识** 会作为 checker 名称和目录名，不再由系统自动分配 `skill-xx` 编号。标识只能包含字母、数字、下划线，必须以字母或下划线开头，最长 64 个字符，并且不能与现有内置 Checker 或用户 SKILL 重名。

用户创建的 SKILL 采用项目级审计模式：

- 后端会在导入时固定拼接 MCP 工具使用、Markdown 报告保存和写权限约束，用户主要维护审计目标、判断标准和场景说明
- 运行时 Agent 会把 SKILL 和上传资料同步到本次扫描的隔离工作区，项目源码保持只读
- SKILL 只能把 Markdown 报告写入指定 `REPORT_DIR`，扫描完成后报告会同步到服务端，并在扫描详情页的 SKILL 报告入口展示

权限和管理规则：

- SKILL 市场、新建扫描页会展示用户创建 SKILL 的创建者
- 创建者可以删除自己创建的 SKILL
- 管理员可以删除任意用户创建的 SKILL，包括历史上没有创建者字段的旧 SKILL
- 内置过程规则目录下的 Checker 不能通过 Web UI 删除

### 添加新 Checker

**第 1 步：创建目录和元数据**

```bash
mkdir -p deephole_client/vulnerability_mining/engines/static_candidate/rules/mycheck/skills/mycheck
```

`deephole_client/vulnerability_mining/engines/static_candidate/rules/mycheck/checker.yaml`：

```yaml
name: mycheck
label: MYCHECK
description: "我的自定义漏洞检测"
enabled: true
mode: "opencode"
```

**第 2 步：编写 SKILL.md**

在 `deephole_client/vulnerability_mining/engines/static_candidate/rules/mycheck/skills/mycheck/SKILL.md` 中定义审计步骤，并在 YAML frontmatter 中声明 `name: mycheck`；可参考同一规则树下的 `npd`。

**第 3 步（可选）：编写 analyzer.py**

```python
from __future__ import annotations
from pathlib import Path
from typing import TYPE_CHECKING
from ...static_analysis.base import BaseAnalyzer, Candidate, scoped_functions

if TYPE_CHECKING:
    from ...static_analysis.index_reader import CodeIndexReader


class Analyzer(BaseAnalyzer):
    vuln_type = "mycheck"  # 必须与 checker.yaml 的 name 一致

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeIndexReader | None" = None,
    ) -> list[Candidate]:
        if db is None:
            return []
        candidates = []
        functions = scoped_functions(db, project_path)
        total = len(functions)
        for idx, func in enumerate(functions):
            # 进度回调（可选，用于前端进度条）
            if self.on_file_progress:
                self.on_file_progress(idx + 1, total)
            body = func["body"] or ""
            if not body:
                continue
            # ... 分析逻辑 ...
            candidates.append(Candidate(
                file=func["file_path"],
                line=func["start_line"],
                function=func["name"],
                description=f"函数 `{func['name']}` 中变量/表达式 `target` 是否存在 XXX 问题，请审计确认。",
                vuln_type=self.vuln_type,
                metadata={"subject": "target", "problem": "XXX"},
            ))
        return candidates
```

**约定：**

- 类名**必须**是 `Analyzer`
- **必须**继承 `BaseAnalyzer`
- `vuln_type` **必须**与 `checker.yaml` 中的 `name` 字段一致
- `find_candidates()` 接收项目根目录路径，返回 `Iterable[Candidate]`（列表或 generator 均可）
- 规则分析器通过相对导入使用同一引擎的静态分析公共 API，例如 `from ...static_analysis.base import BaseAnalyzer, Candidate`
- 使用 DB 的 analyzer 应优先调用 `scoped_functions(db, project_path)`，让 `code_scan_path` 子目录扫描在 SQL 层收敛函数范围；无法判定范围时会自动退回全量。
- `Candidate.description` 应尽量只包含必要审计问题（函数、变量/表达式、问题类型），不要写静态分析规则、命中路径或工具细节；`metadata.subject` 用于跨规则合并和同模式过滤。

**内存 API 缓存：**

扫描管线已禁用内存 API 预处理，不再在 checker 静态分析前自动检查、生成或复用 `memory_api_pairs.json`。相关模块和配置仍保留，已有产物也仍可被内存类 checker 按需读取。

内存类 checker 可读取该文件中的 `allocators`、`deallocators` 和 `pairs` 来识别项目自定义的 malloc/free 薄封装；结构体/对象专用 destroy/free、复杂 cleanup/refcount 生命周期函数和文件/socket/mmap 等非堆资源不会作为底层内存 API 保留。

**第 4 步：本地测试 Checker（无需后端）**

```bash
# 只运行静态分析自测：校验 checker.yaml、Analyzer 加载、代码索引和候选点输出
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --min-candidates 1

# 关闭过程事件输出，只保留最终 JSON，便于在脚本或 CI 中断言
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --json

# 直接写入格式化 UTF-8 JSON 文件，中文 description 不会被转义成 \uXXXX
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --json-output /tmp/mycheck-candidates.json

# 精确断言候选点数量
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --expect-candidates 3

# 可选：对前 1 个候选点运行真实 AI 审计
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source \
  --audit --audit-limit 1 --task-agent-config ./task-agent.yaml

# 测试仓库外的统一规则树
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source \
  --rules-dir /path/to/rules
```

本地测试命令不依赖后端、Web UI 或在线 Agent。默认在临时工作目录构建并在退出时清理 `code_index.db`；可用 `--work-dir` 保留完整过程产物，或用 `--index-db /tmp/mycheck-code_index.db` 指定可复用索引。最终结果始终是 stdout 上的 JSON，过程事件默认写 stderr；`--json` 会关闭事件输出，`--json-output` 会把格式化 UTF-8 JSON 写入文件。代码图谱构建需要本机已安装 Universal Ctags。

开发阶段显式指定 Checker 名称时，即使 `checker.yaml` 中设置了 `enabled: false` 也会执行；线上扫描入口仍遵循 `enabled` 和 `visibility` 配置。`--audit` 会实际调用模型或 OpenCode，请先确认 `task-agent.yaml` 可用，并用 `--audit-limit` 控制成本。

新增规则目录或修改其中内容后无需重启后端；规则注册表、静态分析器和 Skill 会在后续列表刷新或扫描时自动发现。创建扫描时会把选中的静态资源和审计资源同步到客户端。

**CodeIndexReader API 参考（`deephole_client/vulnerability_mining/engines/static_candidate/static_analysis/index_reader.py`）：**

当 `db` 参数非 `None` 时，可通过以下方法查询预构建的代码索引。所有查询方法返回 `list[sqlite3.Row]`，通过 `row["field_name"]` 访问字段。

| 方法 | 说明 | 返回字段 |
|------|------|---------|
| `db.get_all_functions()` | 获取所有函数（按文件和行号排序） | function_id, name, signature, return_type, start_line, end_line, is_static, linkage, body, file_path |
| `db.get_functions_by_path_prefix(prefix)` | 获取指定索引相对路径前缀下的函数 | 同上 |
| `db.get_functions_by_name(name)` | 按名称精确匹配函数 | 同上 |
| `db.get_function_body(name)` | 获取第一个匹配函数的函数体 | 返回 `str \| None` |
| `db.get_calls_from_function(function_id)` | 查询指定函数发出的所有调用 | call_id, caller_function_id, callee_name, callee_function_id, line, column, file_path |
| `db.get_call_sites_by_name(callee_name)` | 查询指定函数名的所有被调用点 | 同上 + caller_name |
| `db.get_structs_by_name(name)` | 按名称查询结构体/类定义，短名可匹配 C++ 限定名 | struct_id, name, start_line, end_line, definition, file_path |
| `db.get_global_variables_by_name(name)` | 按名称查询全局变量 | global_var_id, name, start_line, end_line, is_extern, is_static, definition, file_path |
| `db.get_global_variable_reference_by_name(name)` | 查询全局变量的所有引用点 | reference_id, variable_name, function_id, line, column, context, access_type, file_path, function_name |

**tree-sitter 辅助工具（`deephole_client/vulnerability_mining/engines/static_candidate/static_analysis/code_utils.py`）：**

如需在 analyzer 中对函数体进行 AST 分析，可结合 tree-sitter 和以下辅助函数：

| 函数 | 说明 |
|------|------|
| `find_nodes_by_type(root_node, node_type, k=0)` | 递归查找所有指定类型的节点（DFS，最大深度 100） |
| `get_child_node_by_type(root_node, node_type: list)` | 返回第一个类型匹配的直接子节点 |
| `get_child_nodes_by_type(root_node, node_type: list)` | 返回所有类型匹配的直接子节点 |
| `get_child_field_text_by_type(root_node, field_name, node_type: list)` | 获取指定字段的文本（仅当字段节点类型匹配时） |
| `get_child_field_text(root_node, field_name)` | 获取指定字段的文本 |

使用示例：

```python
import tree_sitter_cpp
from tree_sitter import Language, Parser
from deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.code_utils import find_nodes_by_type

_CPP = Language(tree_sitter_cpp.language())
parser = Parser(_CPP)

tree = parser.parse(func_body.encode())
# 查找所有函数调用节点
for call in find_nodes_by_type(tree.root_node, "call_expression"):
    callee = call.child_by_field_name("function")
    if callee:
        print(callee.text.decode())
```

**常见模式：**

*1. 遍历所有函数并分析*

```python
from deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.base import scoped_functions

for func in scoped_functions(db, project_path):
    name = func["name"]
    body = func["body"] or ""
    file_path = func["file_path"]
    start_line = func["start_line"]
    # 对函数体进行模式匹配或 AST 分析...
```

*2. 查询调用关系*

```python
# 查找所有 malloc 调用点
for call in db.get_call_sites_by_name("malloc"):
    print(f"{call['file_path']}:{call['line']} — 调用者: {call['caller_name']}")

# 查找某函数内部调用的所有函数
for call in db.get_calls_from_function(func["function_id"]):
    print(f"  调用了 {call['callee_name']} at line {call['line']}")
```

*3. Generator 模式（流式产出）*

`find_candidates` 可返回 `Iterator[Candidate]`，通过 `yield` 流式产出候选项，让 LLM 提前开始处理：

```python
from collections.abc import Iterator

def find_candidates(self, project_path: Path, db=None) -> Iterator[Candidate]:
    if db is None:
        return
    for func in scoped_functions(db, project_path):
        # ... 分析 ...
        yield Candidate(file=func["file_path"], ...)
```

*4. 进度回调*

```python
functions = scoped_functions(db, project_path)
total = len(functions)
for idx, func in enumerate(functions):
    if self.on_file_progress and idx % 20 == 0:  # 每 20 个函数更新一次
        self.on_file_progress(idx + 1, total)
```

*5. 不依赖 db 的分析*

也可跳过 db，直接遍历文件系统进行自定义解析（如 memleak checker）：

```python
def find_candidates(self, project_path: Path, db=None) -> list[Candidate]:
    candidates = []
    for src in project_path.rglob("*.c"):
        source = src.read_bytes()
        tree = self._parser.parse(source)
        # 自定义 AST 分析...
    return candidates
```

**实现建议：**

- 推荐使用 `scoped_functions(db, project_path)` 查询而非直接遍历全量函数或文件系统（性能更好，且与 MCP Server 共享同一索引）
- Generator 模式适合耗时较长的分析器，可让 LLM 提前开始处理已发现的候选项
- `on_file_progress` 回调用于前端进度条显示，建议在循环中定期调用
- `description` 字段会作为初始 prompt 的一部分传递给 AI，应保持中性、简短，只描述需要审计确认的问题
- 新 checker 统一使用 `SKILL.md`；旧 `mode: api` + `prompt.txt` 仅作为迁移兼容，模型调用仍走 OpenCode
- 返回空列表是合法的，表示未找到候选点

### 服务端 config.yaml

```yaml
server:
  host: "0.0.0.0"
  port: 8000

storage:
  projects_dir: "../OpenDeepHoleData/projects"
  scans_dir: "../OpenDeepHoleData/scans"
  user_skills_dir: "../OpenDeepHoleData/user_skills"

logging:
  level: "INFO"
  file: "logs/opendeephole.log"
```

`storage` 中的相对路径会按 `config.yaml` 所在目录解析；默认会落到 DeepHole 2.0 项目上层的 `OpenDeepHoleData/`。

### Agent agent.yaml

```yaml
server_url: "http://your-server:8000"
agent_name: ""
owner_token: ""
checkers: []
schema_version: 4
base:
  tool: "nga"
  executable: "nga"
  no_proxy: "10.0.0.0/8"
  # null 时由 Agent 进程自动选择并复用一个空闲端口
  opencode_serve_port: null
model_pool:
  global_concurrency: 4
  models: []
```

`server_url`、`agent_name`、`owner_token` 和 `checkers` 是本机启动字段；其余 v4 字段由 Web **「客户端配置」** 页面管理并写回。完整模板见仓库根目录的 `agent.yaml`。配置以 `IP + machine_name` 形成稳定客户端身份，客户端离线或重连后仍使用同一份服务端配置。新客户端注册时服务端不会采用本地模板上报的模型，模型池保持为空，直到用户在 Web 中明确配置。威胁分析和漏洞挖掘引擎都不属于客户端配置，而是在新建扫描时分别选择；引擎清单直接来自当前代码仓。短暂使用过的 v5 配置会保留其它字段、移除 `mining_engines` 并归一为 v4。v2 及更早配置的阶段能力 `any`/`low` 与旧默认超时 `1200` 会分别一次性迁移为 `high` 和 `3600`；v3 中的全局代码图谱只作为旧集成请求的扫描级迁移输入，不再写回客户端配置。模型行能力标签、显式模型超时及其它自定义超时保持不变，升级后仍可手工配置 `low`。旧 Web `opencode_config` 字段与运行配置快照会在升级时清理，不再提供编辑或查看入口。

新增威胁分析方法只需创建方法目录并实现固定五参数入口，详见 [威胁分析方法扩展](deephole_client/threat_analysis/README.md)。
新增漏洞挖掘引擎只需创建独立目录并实现固定适配契约，详见 [漏洞挖掘引擎扩展](deephole_client/vulnerability_mining/README.md)。

模型的 `time_windows` 可配置多段，每段用 ISO 星期 `1..7` 表示周一至周日，并按 Agent 本地时间判断；各段取并集，未配置任何时间段表示全天可用。跨夜时间按当前星期判断，例如周一至周六 `22:00-06:00` 表示这些日期的 `00:00-06:00` 与 `22:00-24:00` 可用，周日不可用。旧配置未填写 `weekdays` 时继续按每天处理。

OpenCode 最终配置按“本机发现及显式指定的配置 < DeepHole 2.0 受管字段”合并，不再接受 Web 自定义 JSONC 层。受管字段包括 `$schema`、已启用的全局产品知识 MCP、公共技能路径和运行权限。产品知识 MCP 由客户端配置中的 `product_info` 管理，既写入受管 `opencode.json`，也会通过带目录上下文的 `/mcp` 接口热加载到已经使用过的 OpenCode 工作目录，并跨扫描、跨 Session 保持可用。扫描代码图谱 MCP 使用相同的底层配置格式和 `/mcp` 接口，但只按扫描快照临时连接，任务结束后释放。威胁分析方法的 Skill 不写入全局 workspace：平台只在运行时给当前所选方法绑定相邻 Skill 根，并在升级时清理旧版曾全局注入的四个受管 Skill，其它 workspace Skill 保持不变。产品 MCP 的 API Key、Token 等敏感值会以明文保存在服务端数据库、Agent 的 `agent.yaml` 和运行时文件中，应只在可信环境填写。

配置更新只会刷新独立的受管源并把 OpenCode serve 标记为待重载，不会提前改写正在运行的最终文件。serve 空闲后的下一次启动会原子写入 `~/.opendeephole/opencode_workspace/opencode.json`（POSIX 权限 `0600`），设置 `OPENCODE_CONFIG_DIR` 并显式清除 `OPENCODE_CONFIG_CONTENT`；存在活动 Session 时延迟到空闲边界，因此无需重启 Agent，也不会强制终止正在运行的 Session。

OpenCode 调用约定：

- `nga` / `opencode`：整个 Agent 固定使用 `~/.opendeephole/opencode_workspace`，扫描、复核和验证不再创建各自的配置 workspace，也不再向项目目录镜像运行配置。Agent 根据 Web 管理的基础工具和模型行生成 serve 配置。
- `nga` / `opencode` 只通过 serve API 调用。Agent 优先使用 `base.opencode_serve_port`，未配置时兼容 `OPENCODE_SERVE_PORT`，两者都没有时由操作系统分配一个空闲端口；自动端口在同一 Agent 进程内跨 Serve 重启复用，Agent 重启后重新选择。配置更新在活动 Session 结束后的安全重启边界生效。standalone `task-agent.yaml` 继续使用显式 `serve.port`（默认 `4096`）。组件只调用 `task_agent.run_opencode_task()`；真实项目目录和 `.opendeephole` 工作目录由执行上下文提供，不回退到当前目录。调用方不能传原生 permission，只能通过 `writable_paths` 显式增加路径级写权限。
- 文件、SKILL 与 `bash` 的稳定权限统一写入 Serve 实际使用的全局 `opencode.json`。项目目录作为 Session 工作目录保持可读；`~/.opendeephole/opencode_workspace/.opencode` 和最终配置注册的 SKILL 根只读，完整 Agent 的文件编辑工具可写 `~/.opendeephole/scans`、`fp_reviews`、`vulnerability_validation` 与 `skill_create`，其它源码目录保持只读且 `bash` 全面禁用。只有显式传入 `writable_paths` 时，额外动态路径才通过 Session `permission` 创建或 PATCH；省略时不改已有 Session 权限，显式空列表清空覆盖。脱离 Agent 运行时只从 `task-agent.yaml` 的 `serve.opencode_config.skills.paths` 加载 SKILL。
- `output_schema` 只用于本地 JSON 解析和校验，不发送 OpenCode 原生 `format`，也不修改首次用户 prompt；调用方需要自行把输出要求和 Schema 写入 prompt。最终文本 JSON 优先；若模型改用内置文件工具写 JSON，Task Agent 会从当前消息最后写入的合法文件填充 `structured`，但 `text` 仍保留 LLM 最后一次文本输出。确认由本条消息新建的临时文件在解析后自动删除；必须保留的文件或目录可传 `file_write_allowlist`，该白名单只控制清理且不能扩大 `work_dir` 写权限。JSON 仍不合规时默认在原 Session 追加 2 次包含 Schema 的中文纠正，也可通过 `invalid_json_retry_prompt` 提供原样发送的自定义纠正提示词；纠正耗尽或普通执行错误后，内部任务策略决定是否重新排队并创建新 Session。
- OpenCode/nga serve 会话会保留在真实项目目录下，便于用 `opencode session list` 查看历史；Agent 只在取消或超时时 abort session，不在正常完成后删除 session。
- 只有扫描显式启用的代码图谱 MCP 才会动态连接；空配置、历史 `null` 配置、去误报和漏洞验证均遵循同一文件工具模式，不会启动内置源码 MCP。
- 漏洞验证方法在 Agent 主进程中异步执行，直接调用同一个公共 OpenCode 接口，并继承扫描选择的代码图谱 MCP 或文件工具模式；验证方法直接执行 `nga`、`opencode`、`hac` 或 `claude` 会被拒绝。

内部 Python 调用统一使用自包含的 `task_agent` 组件。调用方不启动 CLI 或 Serve；首次 `run_opencode_task()` 会惰性创建任务服务和 Serve 管理单例，并在发送任务前完成 Serve 的启动、兼容进程复用或异常恢复：

```python
import json

from task_agent import run_opencode_task

RESULT_SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "string"}},
    "required": ["answer"],
    "additionalProperties": False,
}
prompt = (
    "审计目标代码并返回结论。"
    "\n\n请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(RESULT_SCHEMA, ensure_ascii=False, indent=2)
)
retry_prompt = (
    "上一次回复不符合要求，请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(RESULT_SCHEMA, ensure_ascii=False, indent=2)
)

result = await run_opencode_task(
    task_name="candidate-audit-example",
    task_type="vulnerability_mining",
    prompt=prompt,
    required_capability="high",
    output_schema=RESULT_SCHEMA,
    invalid_json_retry_count=2,
    invalid_json_retry_prompt=retry_prompt,
    writable_paths=["generated-reports"],
)

continued = await run_opencode_task(
    task_name="candidate-audit-example-follow-up",
    task_type="vulnerability_mining",
    prompt="...",
    required_capability="high",
    session_id=result.session_id,
)
```

`task_agent` 目录也可脱离 DeepHole 2.0 使用：将整个目录放到其它项目的 Python 导入根目录，或执行 `python -m pip install ./task_agent` 后，任意位置的业务代码都继续使用 `from task_agent import run_opencode_task`。未注册后端宿主绑定时，该函数会从显式 `config_path`、`TASK_AGENT_CONFIG` 或当前目录的 `task-agent.yaml` 读取固定项目/工作上下文、Serve 参数和模型池，然后惰性启动同一个 Serve 单例。格式模板见 `task_agent/task-agent.example.yaml`；首次配置在 `shutdown_opencode()` 前不可切换。

OpenCode 模型池统计：

- 漏洞挖掘、威胁分析、去误报和漏洞验证全部通过唯一公共接口，内部统一创建/续写 Session 并累计模型池统计。漏洞挖掘中的候选点审计、项目级审计和威胁审计共享 `task_type="vulnerability_mining"`，看板通过 `task_name` 区分具体子任务。
- 模型必须在 `model_pool.models[]` 中填写明确模型名并启用；不再接受默认模型行。没有显式模型时不能创建或恢复扫描。
- `model_pool.global_concurrency` 是所有模型合计运行数的硬上限；每个模型还会受自己的 `max_concurrency` 和 `time_windows` 限制。
- 配置页的每个模型可添加多段使用时间，每段独立选择周一至周日及起止时间；时间窗口只限制新取得的模型 Lease，不会中断已经运行的任务。
- 任务能力只分 `low`、`high`，各内置阶段默认并实际配置为 `high`；公开模型任务按类型自动使用固定优先级：漏洞验证 `90`、威胁分析 `75`、去误报复核 `60`、漏洞挖掘 `50`，同优先级按 FIFO 调度。v3/v4 中手工配置为低能力的阶段仍会优先使用最低足够能力模型。模型行本身仍可标记低/中/高能力。
- 模型调用默认超时为 `3600` 秒，只计算每条模型消息的执行阶段，不包含排队时间。超时、普通执行错误和同 Session JSON 纠正耗尽都会消费统一的新 Session 重试预算；默认重试 2 次，即最多 3 个 Session。新 Session 重试会释放并重新申请模型 Lease，最终超时保留最后 Session ID，模型池 completed-task 历史只记录一次最终状态。
- 扫描详情页点击「模型看板」可以查看每个模型的累计任务、成功/失败/超时/取消计数、平均耗时、当前运行数和当前排队数。
- Agent 会在模型池状态变化时上报快照，无变化时只保留低频心跳；服务端会保存到扫描记录中，页面刷新或重新进入扫描详情后会显示最近一次快照。

## 本地开发

框架整体流程、组件能力、输入输出契约和新增引擎、Checker、验证器的接入方法见
[框架开发指南](docs/framework_development.md)。

```bash
# 后端（含热重载）
pip install -r requirements.txt
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# 前端开发服务器（代理到 localhost:8000）
cd frontend
npm install
npm run dev

# 构建前端
npm run build

# 查看日志
tail -f logs/opendeephole.log
```

> **注意：** 客户端需要运行支持双根规则包的新版本。开始扫描时，后端会把选中的静态规则与审计规则分别同步；修改内置过程或产品验证方法后，下一项任务会先同步 `deephole_client` runtime 再执行。

## 数据存储位置

Agent 运行时会在以下位置产生数据：

| 位置 | 内容 | 生命周期 |
|------|------|---------|
| `<项目目录>/code_index.db` | tree-sitter 代码索引（函数/结构体/调用关系） | 持久保留，后续扫描复用 |
| `~/.opendeephole/scans/<scan_id>/` | 扫描工作目录（candidates.json、config.yaml、agent.log 等） | 扫描成功后自动删除；取消/出错时保留用于恢复 |
| `~/.opendeephole/fp_feedback.json` | 本地误报反馈缓存 | 持久保留 |
| `~/.opendeephole/fp_reviews/<review_id>/` | 误报复审临时目录 | 复审完成后自动删除 |

服务端数据：

| 位置 | 内容 |
|------|------|
| `../OpenDeepHoleData/scans/` | 扫描结果、兼容 submit sink 数据和 `scans.db` |
| `../OpenDeepHoleData/projects/` | 服务端上传扫描的项目缓存 |
| `logs/opendeephole.log` | 服务端日志（滚动，默认 10MB × 5 份） |

> **注意：** `code_index.db` 直接保存在被扫描的代码仓目录下。对于大型代码仓，该文件可能有几十到几百 MB。如需清理，直接删除项目目录下的 `code_index.db` 即可，下次扫描会自动重建。

## 项目结构

```
OpenDeepHole/
├── backend/                       # FastAPI 控制面、任务分发、持久化与实时事件
│   ├── api/
│   │   ├── agent.py               # Agent WebSocket、协议 v1/v2、命令与结果接收
│   │   ├── scan.py                # 扫描生命周期、游标分页详情、报告和验证 API
│   │   ├── integration.py         # 外部平台接入与公开扫描 API
│   │   ├── auth.py                # 登录、注册和密码管理
│   │   ├── admin.py               # 管理员接口与运行指标
│   │   ├── checkers.py            # Checker 目录接口
│   │   ├── skills.py              # 用户 SKILL 市场接口
│   │   ├── feedback.py            # 误报反馈 CRUD
│   │   └── announcements.py       # 首页公告 CRUD 与发布
│   ├── store/
│   │   ├── base.py                # 扫描、用户和运行状态的统一存储接口
│   │   ├── sqlite.py              # SQLite 单 Worker 兼容实现
│   │   ├── postgres.py            # PostgreSQL 多 Worker 生产实现
│   │   ├── async_ops.py           # 同步存储的有界异步执行边界
│   │   └── __init__.py            # 按 database_url 选择存储后端
│   ├── distributed.py             # 跨 Worker Agent 命令、RPC 与 SSE 扇出
│   ├── sse.py                     # 本地/分布式扫描事件发布与订阅
│   ├── pagination.py              # v2 API 稳定游标编码与解析
│   ├── runtime_metrics.py         # 请求、存储、事件循环和 SSE 队列指标
│   ├── registry.py                # Checker 元数据发现
│   ├── checker_sync.py            # 规则包构建与 Agent 同步
│   ├── validation_catalog.py      # 产品验证器目录
│   ├── models.py                  # 后端请求、响应和持久化模型
│   ├── config.py                  # 服务端配置加载
│   ├── main.py                    # FastAPI 入口与应用生命周期
│   ├── static/                    # Vite 构建后的前端静态文件
│   └── system_skills/             # 在线创建 SKILL 使用的系统 Skill
├── frontend/                      # React + TypeScript + Vite + Tailwind CSS
│   └── src/
│       ├── api/                    # 后端 API 客户端
│       ├── components/             # 扫描、Agent、Checker、反馈和管理页面
│       ├── features/threatAnalysis/ # 威胁分析结果查看器
│       ├── hooks/                  # SSE 等共享 React Hooks
│       ├── theme/                  # 深色/浅色主题
│       ├── types.ts                # 前端领域类型
│       └── App.tsx                 # 页面路由与应用入口
├── deephole_client/               # 本地 Agent、扫描协调器和独立业务过程
│   ├── code_graph_build/           # code_index.db 构建与缓存复用
│   ├── vulnerability_mining/
│   │   ├── engines/
│   │   │   ├── static_candidate/
│   │   │   │   ├── static_analysis/ # 静态候选召回过程
│   │   │   │   ├── candidate_audit/ # 候选点/项目级 AI 审计过程
│   │   │   │   ├── rules/           # analyzer、静态资源与嵌套 Skill
│   │   │   │   ├── engine.yaml
│   │   │   │   └── engine.py
│   │   │   └── threat_audit/       # 威胁审计引擎与完整过程实现
│   │   │       ├── runner.py       # 威胁任务派生、模型审计与结果汇总
│   │   │       ├── audit_schema.py # 专用结构化输出 Schema
│   │   │       ├── engine.yaml
│   │   │       └── engine.py       # 平台引擎适配器
│   │   ├── examples/               # 可复制的 Skill/外部 CLI 引擎示例
│   │   ├── runtime.py              # 引擎发现、加载、校验和执行
│   │   └── engine_report.py        # 引擎结构化结果转漏洞报告
│   ├── threat_analysis/            # 目录自动发现的威胁分析方法
│   │   ├── methods/
│   │   │   └── deephole_threat_analysis/ # DeepHole原生威胁分析及其 Skill
│   │   ├── runtime.py              # 方法发现、五参数签名校验与原包名加载
│   │   └── README.md              # method.yaml、入口和三份 JSON 契约
│   ├── threat_analysis_runner.py   # 威胁分析平台异步适配器
│   ├── fp_review/                  # 目录发现的单漏洞去误报方法框架
│   │   ├── methods/
│   │   │   ├── adversarial/       # 对抗式复核方法、清单和 Skill
│   │   │   └── fp_check/          # Trail of Bits fp-check 方法、清单和 Skill
│   │   └── runtime.py             # 方法发现、加载、校验和统一执行入口
│   ├── vulnerability_validation/   # 漏洞验证过程、SDK 与产品验证器
│   ├── scanner.py                  # 代码图谱、威胁分析和引擎并发协调
│   ├── reporter.py                 # 事件、批次、漏洞和最终状态上报
│   ├── server.py                   # Agent 任务/停止/恢复/复核/验证命令处理
│   ├── task_manager.py             # Agent 本地任务生命周期
│   ├── opencode_integration.py     # DeepHole 2.0 的 Task Agent 宿主适配
│   ├── updater.py                  # Agent 运行时同步与安全更新
│   ├── config.py                   # agent.yaml 配置加载
│   └── main.py                     # Agent 守护进程和自动重连入口
├── task_agent/                     # 可独立安装的模型任务、Session 与 Serve 框架
│   ├── api.py                      # run_opencode_task() 公共入口
│   ├── task_service.py             # 队列、权限、Session、纠错和重试
│   ├── model_pool.py               # 模型 Lease、并发、能力与健康调度
│   ├── serve_client.py             # OpenCode/nga Serve 生命周期与事件流
│   ├── host.py                     # 嵌入宿主上下文边界
│   ├── standalone.py               # 独立 YAML 自举与严格校验
│   ├── token_usage.py              # 模型 Token 用量归集
│   └── task-agent.example.yaml     # 独立组件配置模板
├── mcp_server/                     # 可独立启动的源码索引查询 MCP（Agent 默认不加载）
├── docs/
│   ├── framework_development.md    # 框架流程和组件接入指南
│   ├── opencode_task_service.md    # Task Agent 公共接口文档
│   ├── vulnerability_validation.md # 产品漏洞验证方法文档
│   └── production_scaling.md       # PostgreSQL、多 Worker、迁移和回滚指南
├── tools/
│   ├── checker_test.py             # Checker 静态召回/真实审计测试工具
│   └── external_platform_scan.py   # 外部平台扫描调用工具
├── scripts/
│   └── migrate_sqlite_to_postgres.py # SQLite 在线快照迁移工具
├── tests/                          # 后端、Agent、组件和规则的测试套件
├── agent.yaml                      # 客户端配置模板
├── requirements-agent.txt          # Agent 最小依赖
├── run_agent.sh                    # Agent 启动脚本（Linux/macOS）
├── run_agent.bat                   # Agent 启动脚本（Windows）
├── config.yaml                     # 服务端配置（含存储后端和连接池）
├── requirements.txt               # 服务端完整依赖
├── start.sh                        # 前端构建与后端 Worker 启动脚本
├── Dockerfile
└── docker-compose.yml             # DeepHole 2.0 + PostgreSQL 生产编排
```

## License

MIT
