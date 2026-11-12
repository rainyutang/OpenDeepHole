# 配置参考

[文档目录](README.md) · [部署与 Agent 安装](getting-started.md) · [模型任务接口](opencode_task_service.md)

## 配置入口

| 入口 | 管理内容 |
| --- | --- |
| 根目录 `config.yaml` | 服务端存储、认证、日志、知识库连接等 |
| Agent 的 `agent.yaml` | 本机服务地址、名称和用户令牌，以及服务端下发的配置副本 |
| Web「客户端配置」 | Agent 可执行文件、LLM API、模型池、各阶段策略和 Checker 选择 |
| 新建扫描表单 | 本次扫描的模式、引擎、方法、路径及 MCP/验证快照 |
| Agent 本机 OpenCode 配置 | Provider、模型定义、访问地址和凭据 |
| 独立 `task-agent.yaml` | 脱离平台使用 Task Agent 时的项目上下文、Serve 和模型池 |

## 服务端配置

配置加载顺序为显式 `load_config(config_path)` 参数、`CONFIG_PATH` 环境变量、当前目录 `config.yaml`。以下为最小字段示例，并非完整默认值：

```yaml
server:
  host: "0.0.0.0"
  port: 8000
storage:
  projects_dir: "../OpenDeepHoleData/projects"
  scans_dir: "../OpenDeepHoleData/scans"
  user_skills_dir: "../OpenDeepHoleData/user_skills"
  database_url: ""
logging:
  level: "INFO"
  file: "logs/opendeephole.log"
```

相对存储路径按配置文件所在目录解析。仓库实际模板将日志等级设为 `DEBUG`。Uvicorn 启动的监听地址与端口取决于命令行；`start.sh` 固定使用 8000。

| 环境变量 | 用途 |
| --- | --- |
| `CONFIG_PATH` | 服务端配置文件位置 |
| `OPENDEEPHOLE_DATABASE_URL` | 覆盖数据库连接串，PostgreSQL 使用 `postgresql://...` |
| `OPENDEEPHOLE_POSTGRES_POOL_MIN_SIZE` / `OPENDEEPHOLE_POSTGRES_POOL_MAX_SIZE` | 每 Worker 的数据库连接池范围 |
| `OPENDEEPHOLE_SERVER_WORKERS` | `start.sh` 使用的 Worker 数；多 Worker 要求 PostgreSQL 环境连接串 |
| `OPENDEEPHOLE_SERVER_WS_PING_INTERVAL` / `OPENDEEPHOLE_SERVER_WS_PING_TIMEOUT` | `start.sh` 的 WebSocket 心跳参数，默认 30/120 秒 |
| `NO_PROXY` | 覆盖服务端 `no_proxy` 配置 |

`OPENCODE_MODEL` 只覆盖兼容字段 `opencode.model`，不创建 Agent 模型池。`config.yaml` 中仍存在历史配置和注释，是否参与当前扫描以加载和执行代码为准；例如 git 历史挖掘与内存 API 预处理当前未接入扫描链路。

认证参数、首次管理员及固定 JWT 密钥见[部署文档](getting-started.md#从源码启动-web-服务)；数据库运维参数见[生产部署](production_scaling.md)。

## Agent 配置

根目录 [agent.yaml](../agent.yaml) 是 v11 模板。主要字段示例：

```yaml
server_url: "http://your-server:8000"
agent_name: ""
owner_token: ""
checkers: []
schema_version: 11
llm_providers: {}
base:
  tool: "opencode"
  executable: "opencode"
  no_proxy: "10.0.0.0/8"
  opencode_serve_port: null
model_pool:
  models: []
checker_selection:
  quick:
    disabled_checkers: ["sensitive_clear", "skill_only_project_audit"]
  standard:
    disabled_checkers: ["skill_only_project_audit"]
  custom:
    disabled_checkers: []
```

`server_url`、`agent_name`、`owner_token`、`checkers` 是本机启动字段，其余受管字段通过 Web 编辑并下发。客户端以 IP 和机器名形成稳定身份，重连保留已有配置；离线编辑在重连后生效。新注册客户端的模型列表为空，不采用启动模板上报的模型。

基础配置管理程序和模型池；高级配置管理威胁分析、漏洞挖掘、去误报和漏洞验证。各模式通过 Checker 排除列表表达选择，未被排除且当前启用、对用户可见的新增规则会进入后续新扫描。

兼容迁移包括：v5→v6 固定 `base.tool=opencode` 并保留可执行文件；v6→v7 将旧排除列表迁移到自定义模式；v7→v8 将旧默认威胁分析超时 3600 秒迁移为 7200 秒；v8→v9 将各阶段原默认总超时升级为 10800 秒，补充无新内容超时 1200 秒。v9→v10 细分任务超时：旧默认值按下表更新，原阶段自定义总超时保留并继承到该阶段新增的任务和纠正重试项。判定使用原始版本及原始值，v10 中用户修改的值不再迁移。历史 `full` / `threat_analysis_only` 的组件上下文按兼容规则处理，不批量重写历史记录。

### 模型池与阶段策略

- 模型必须启用并填写明确的 `provider/model`；没有显式模型不能创建或续扫。`base.executable` 对整个 Agent 生效，模型行不能覆盖程序。
- 总容量为有效启用模型的 `max_concurrency` 之和，各扫描共享额度；旧 `global_concurrency` / `opencode_concurrency` 不再构成独立全局上限。
- 模型能力可标记低/中/高，任务要求归一为 `low` 或 `high`。阶段级能力、超时和重试策略优先于模型行的相应覆盖。
- 模型 `time_windows` 按 Agent 本地时间判断，ISO 星期 `1..7` 为周一至周日；多段取并集，未设置时全天可用。跨夜窗口按当前日期判断，例如周一至周六 `22:00–06:00` 包括这些日期的凌晨与晚间，不包含周日。
- 时间窗口只限制取得新模型 Lease，不会打断已运行任务。一般阶段按启动时派生容量创建工作协程；去误报在每次补位时重新读取容量，降低上限不打断在途复核。
- 模型消息超时不包含排队时间。四个阶段分别配置总超时和 `idle_timeout_seconds`（默认 1200 秒/20 分钟）；各类总超时见下表。新文本、推理及工具进展刷新无新内容计时；心跳和重试状态不刷新。同 Session 的 JSON 纠正、产物及必需命令校验重试共用本次业务尝试的剩余时间，新 Session 业务重试重新计时，默认新 Session 重试 2 次；根目录 `agent.yaml` 的威胁分析模板写的是 5 次，实际运行应以 Web 保存并下发的值为准。
- 工具参数生成（`pending`）期间暂停无新内容检测，总时限及主动取消仍生效；当前调用和关联子 Session 的全部待生成参数完成后，恢复完整的无新内容计时。此阶段真正停滞也由总时限终止，工具进入 `running` 后继续按原有进展规则检测。
- 任务类型固定优先级：漏洞验证 90、去误报 80、威胁分析与挖掘 50；相同优先级按 FIFO 调度，不抢占已运行任务。

| 位置 / 字段 | 用途 | 默认秒数 |
| --- | --- | ---: |
| `threat_analysis.model_policy.timeout_seconds` | 威胁分析 | 10800 |
| `vulnerability_mining.threat_audit_timeout_seconds` | 威胁审计 | 10800 |
| `vulnerability_mining.candidate_audit_timeout_seconds` | 候选点审计，含该引擎内项目级审计 | 3600 |
| `false_positive.timeout_seconds` | 去误报 | 3600 |
| `vulnerability_mining.vulnerability_dedup_timeout_seconds` | 漏洞去重 | 1800 |
| 各阶段策略的 `json_correction_timeout_seconds` | 独立 JSON 格式修复 Session | 1800 |
| 各阶段策略的 `validation_retry_timeout_seconds` | 已弃用，仅兼容读取和保存；运行时忽略 | — |

漏洞挖掘的 `timeout_seconds` 用于其它挖掘任务，漏洞验证业务调用继续使用 `model_policy.timeout_seconds`，两者默认 10800 秒。模型能力、调用重试次数及无新内容超时仍由所属阶段配置。首次业务执行、同 Session 修复及宿主复验累计消耗业务预算；例如 3 小时任务已用 2 小时 50 分钟，所有同 Session 修复共剩 10 分钟。独立 JSON 格式修复及模型排队期间暂停原业务预算，返回原 Session 后继续使用离开前剩余的时间；新 Session 重新执行业务任务时恢复完整业务时限。本地产物校验脚本原有的 60 秒限制保持不变。已有验证任务仍从自身策略快照读取业务与独立格式修复时限，后续 Agent 配置修改不影响它。旧快照缺失的纠正字段沿用原兼容补齐规则：10800 秒采用 1800 秒，其它自定义值继承。`validation_retry_timeout_seconds` 的旧值保留，但不再控制运行计时，也不在 Web 配置页提供编辑。此次计时规则无需配置版本或数据库迁移，不回写历史任务。

模型看板展示任务状态、并发与 Token 用量。任务重试可关联多个 Session，但逻辑任务保持统一身份；完整统计口径见[Token 分类](scan-token-categories.md)。

## OpenCode 运行配置

### 网页配置 LLM API

在客户端的「基础配置 → 模型配置」中统一管理模型，使用页面顶部的「保存配置」统一保存。每行最左侧提供「启用」复选框，折叠时即可切换，不会触发展开或收起；总并发随草稿实时更新，启停状态在保存后生效。OpenCode 模型展示 ID、名称；LLM API 展示 `Provider ID/模型名称`，两者均带来源标记。点击箭头展开连接参数及调度设置，字段说明通过鼠标悬停、键盘聚焦或触屏点击查看。顶部提供「从 opencode 读取」「手动添加 opencode 模型」「添加 LLM API」三个入口，读取已有模型后仍可勾选导入。

第一版固定使用 Chat Completions 兼容协议（`@ai-sdk/openai-compatible`）。每个 API 必须提供唯一的 Provider ID、完整 HTTP(S) Base URL 和至少一个模型名称；这里的模型名称就是接口请求中 `model` 字段的实际值，例如 `qwen3-coder`，可包含斜杠。Base URL 不自动补 `/v1`，调用时由协议追加 `/chat/completions`。API Key 选填。新添加的 API 模型自动加入模型池，默认启用、高能力、并发 1、权重 1；已有但未加入模型池的 API 模型以禁用状态展示，不会自动增加容量。

同一 Provider 下的模型共享 URL、API Key、Provider 请求头和超时，通过「添加同 API 模型」继续添加。每个模型保留独立的 Token 上限、模型请求头和调度设置；修改 Provider ID 或模型名称会自动更新完整引用，无需重复填写调度 ID 或完整模型名称。内部调度 ID 自动分配，已有 ID 保持不变；旧的显示别名数据保留，但不再提供编辑入口。OpenCode 模型仍可独立编辑模型池 ID 和完整模型名称。删除模型池中的一行只移除该行；最后一个引用删除后才移除相应 API 模型，最后一个模型删除后才移除 Provider。

模型的 `limit` 整组可选；填写时必须同时填写正整数 `context` 和 `output`，`input` 选填。不填写则沿用配置合并及下文的默认上限规则。Provider/模型 headers、请求超时和流式间隔超时位于「更多选项」。超时单位是毫秒，区别于任务的 Session 超时秒数。API Key 和请求头值保存后不回显，未修改会保留，替换或显式删除才更新。

展开 LLM API 模型后可点击「测试连接」，测试当前未保存的单个模型草稿，不受同 API 下其他未完成模型影响。后端校验权限并补齐已保存的密钥，由所选 Agent 直接发送一次短文本流式请求；浏览器和控制端不连接远端 LLM API。测试不保存配置、不创建 OpenCode Session、不占用业务模型池，也不触发重启。每个 Agent 同时只运行一个测试，总时限 30 秒（更短的 API 超时及流式间隔超时仍有效），最多请求 128 个输出 Token，配置的输出上限更小时按该上限请求。请求沿用 Serve 的直连和 TLS 行为；鉴权依次由 API Key、Provider 请求头、模型请求头覆盖。收到实际生成内容并正常结束才算成功。结果只展示状态、耗时和必要错误说明，不回传生成文本及凭证；修改相关草稿后旧结果失效。Agent 离线或版本不支持时无法测试，断线时自动取消正在执行的测试。

保存 Provider 或模型定义变更后，Agent 暂停尚未开始的业务任务。已有逻辑任务继续使用旧生效配置，其续聊、格式修复和重试仍可创建 Session；全部完成并清理后，Agent 发布受管配置并自动重启 Serve，检查健康状态和模型目录后恢复调度。排队等待不会消耗模型调用超时或重试次数，仍可取消任务。仅修改能力、并发和权重不重启 Serve。

模型配置标题旁区分等待上线、等待任务完成、正在应用、已生效及应用失败；失败时新任务保持排队，可修改后保存或点击「重试应用」。连续保存以最新配置为准。已生效表示 Serve 已加载配置；「测试连接」用于检查 API 的地址、凭证及所选模型当前可用性。等待期间从 opencode 读取的可能仍是旧目录，页面会提示。

配置按 Agent 保存，权限沿用所有者或管理员。v10 及更早配置自动迁移至 v11 的顶层 `llm_providers`，默认为空，不改变已有文件配置。网页配置作为受管层覆盖同名字段；删除网页项只撤销该层，原有本地同名 Provider 仍按合并规则参与配置。凭证仅用于 Agent 私有配置，不进入扫描运行配置或报告；POSIX 上含凭证的 Agent 配置与受管文件权限为 `0600`。旧 Agent 需更新后才能应用此功能。

### 发现与合并

Agent 按以下顺序合并配置，后面的受管项覆盖前面的对应字段：

```text
用户全局目录
→ 可执行文件相邻目录
→ 项目目录
→ opencode.config_paths
→ OPENCODE_CONFIG_PATH / OPENCODE_CONFIG / OPENCODE_CONFIG_DIR
→ OpenDeepHole 受管字段
```

可执行文件名为 `nga` 时兼容发现 `~/.config/nga`。全局及显式目录兼容旧版 `config.json`；自动发现的可执行文件相邻目录、项目目录只识别 `opencode.json` / `opencode.jsonc`，避免读取项目自身的通用配置。无效 JSON/JSONC 会警告并忽略。

受管字段包括技能路径、权限、Hook 与压缩策略 `auto: true`、`prune: true`、`reserved: 20000`。已有 Provider 模型缺少 `limit.context` 时补 131072，此时缺少 `limit.output` 则补 32768；不从平台模型池反向创建 Provider 模型定义。

完整 Agent 使用 `~/.opendeephole/opencode_workspace/opencode.json`，在安全的 Serve 启动边界原子发布最终配置，POSIX 文件权限为 `0600`。Web LLM API 变更由上述配置协调器等待已有逻辑任务结束后主动重启并检查；其它受管资源更新遵循各自的空闲重载规则。配置通过专用目录隔离，受管 Hook 追加到已有 Plugin 列表。

### Serve 生命周期与权限

平台只启动 `base.executable` 指定的程序，失败时不会改用另一套已安装 CLI。端口优先使用 `base.opencode_serve_port`，其次兼容 `OPENCODE_SERVE_PORT`，否则由系统分配空闲端口；自动端口在同一 Agent 进程内复用，重启 Agent 后重新选择。

自动端口遇到冲突时最多尝试 3 个端口；固定端口直接报告错误。Serve 管理器只回收能证明属于当前 Agent 的进程，不终止未知端口占用者。Windows 使用进程身份标记辅助异常退出后的恢复。存在活动 Session 时延后普通重载；HTTP 5xx 触发的异常恢复同样等待其它在途工作退出。

全局允许文件读取、列举、搜索和外部目录读取，范围是运行账户可读路径。编辑默认拒绝，任务工作目录与显式白名单提供写权限；`bash` 默认拒绝，个别任务只开放绑定的产物校验命令。项目源码与工作产物的权限边界不能仅由“Agent 本地执行”推断。

代码图谱和知识库按扫描配置动态连接并释放。CodeGraph 可在扫描信息页切换，Agent 按扫描保存配置版本，任务真正开始执行时读取最新设置并固定为该任务的快照；排队期间的变更会生效，运行中任务及其内部重试不受影响。知识库继续使用创建时快照。配置为空时不启动内置 MCP；知识库项目管理工具对模型隐藏，查询项目由 Hook 强制绑定。

### 组件调用与结果

业务组件通过 `from task_agent import run_opencode_task` 调用模型，不自行启动 Serve。`output_schema` 用于本地解析和校验，调用方仍需在 Prompt 中声明输出格式。结果不合法时由独立格式修复、原 Session 纠正和新 Session 重试处理；文本与结构化产物有各自的返回字段和清理规则。

Python 调用示例、`file_write_allowlist`、Session 续写、结构化文件清理及重试细节见[Task Agent 公共接口](opencode_task_service.md)。正常完成不删除 OpenCode Session；取消或超时会 abort，可用所配置程序的 `session list` 查看保留的历史。

脱离平台运行时可安装 `python -m pip install ./task_agent`，从显式 `config_path`、`TASK_AGENT_CONFIG` 或当前目录 `task-agent.yaml` 获取上下文。独立配置在关闭组件前不可切换；模板见 [task-agent.example.yaml](../task_agent/task-agent.example.yaml)。

## Codex 运行配置

以下描述 Agent 内置集成的行为，入口在 [codex_runtime.py](../deephole_client/codex_runtime.py)、[codex_profiles.py](../deephole_client/codex_profiles.py) 和 [codex_scan_config.py](../deephole_client/codex_scan_config.py)。

### CLI 准备与模型

Agent 连接服务端前检查一次 Codex CLI。找不到 `codex` 时，当前自动安装流程依次执行 `npm set strict-ssl false`、设置 Huawei npm registry、清缓存和全局安装 `@openai/codex`，共享 120 秒总超时。这会改变本机 npm 配置；已有可调用 CLI 时跳过安装。失败只告警并继续连接，下次 Agent 重启才再次尝试。

应用客户端配置时先读取 `$CODEX_HOME/config.toml`，未设置时使用 `~/.codex/config.toml`（Windows 为 `%USERPROFILE%\.codex\config.toml`）。用户已有非空顶层 `model` 时保留，不探测平台模型，也不改写 Provider。

没有用户默认模型时，Agent 按已启用的显式模型顺序向 Provider 的 `/v1/responses` 发送最小探测请求，以第一个合法 Responses 对象确定默认模型。地址、凭据和定义来自 Agent 同一份有效 OpenCode 合并配置，不由平台传输密钥。配置应用时固定选择，扫描期间不切换。

选定后维护以下资源：

- `config.toml` 开头的受管默认模型与 Provider，使用 `wire_api = "responses"`。
- 带所有权标记的 `opendeephole-model-catalog-*.json`，POSIX 权限 `0600`，模型 ID 使用 Provider 的原始 ID。
- 模型上下文取有效 `limit.context`，否则按 128000 回退；自动压缩阈值按 128K 对应 100K 的比例计算。用户自有 `model_catalog_json`、`model_context_window` 和 `model_auto_compact_token_limit` 保留。
- `$CODEX_HOME/.env` 的受管区，为选定 Provider 主机追加 `NO_PROXY` / `no_proxy`；该文件供 Codex 加载，不注入 Agent 进程环境。

配置更新只替换带所有权标记的内容，并按引用关系清理旧托管目录；用户模型和非托管配置保留。

### 信任路径与扫描 MCP

创建或续扫时，Agent 将项目总路径、`~/.opendeephole`、本次 `scans/<scan_id>/threat_analysis` 工作目录及内置参考资料/校验器路径加入全局受管 trusted-projects 区。用户已对同一路径声明不信任、配置无效或目标为符号链接时不强制覆盖，依赖阶段按失败/回退契约处理。

Windows 的项目 trust 不等于沙箱文件读取权限，集成还会维护顶层：

```toml
# BEGIN OpenDeepHole managed Codex sandbox permissions
sandbox_permissions = ["disk-full-read-access"]
# END OpenDeepHole managed Codex sandbox permissions
```

该权限是用户级磁盘读取权限，不按扫描隔离；产物写入仍以扫描工作目录为边界。用户已有 `sandbox_permissions` 时只在包含所需权限的情况下复用，不扩大用户值；不新增或修改用户的 `[windows] sandbox` 选择。Linux/macOS 不新增该权限键。

扫描显式启用且准备成功的 CodeGraph MCP 写入精确威胁分析工作目录下的 `.codex/config.toml`，不写入全局 MCP。目录和文件在支持权限位的平台使用 `0700` / `0600`；关闭或准备失败时清理自有配置并使用文件工具。

扫描运行期间切换 CodeGraph 时，在下一次 Codex 威胁分析方法启动前更新该配置；当前方法运行期间不改写文件，避免改变其内部续接和重试使用的工具。

## 轻量级威胁分析与回退

新建标准模式扫描固定使用 DeepHole精简威胁分析；快速模式和自定义模式未指定方法时仍优先 OpenCode 轻量级方法。OpenCode 与 Codex 轻量级方法共用业务 Prompt，但执行通道不同：

| 方法 | 执行通道 |
| --- | --- |
| `opencode_lightweight_threat_analysis` | `run_opencode_task(task_type="threat_analysis")`，复用 Agent 的阶段模型策略 |
| `opencode_coverage_guided_lightweight_threat_analysis` | OpenCode 轻量初轮后，按完整文件清单最多定向补查两次 |
| `codex_goal_threat_analysis` | Codex SDK，通过 `codex app-server --listen stdio://` 使用全局默认模型 |
| `deephole_threat_analysis` | DeepHole 原生威胁分析方法 |
| `deephole_compact_threat_analysis` | DeepHole 多阶段流程，使用 51 项精简模式库，并补齐每模块缺失的 15 项固定审计模式 |

OpenCode 轻量初轮由宿主在回复结束后校验实际产物；模型可执行绑定命令自检，但执行命令不是完成审计条件。校验失败先回传原 Session 修正，再沿用阶段重试。Codex Goal 则要求在 Goal 内执行校验命令并通过。轻量级方法初轮失败、Codex 不可用或产物无效时，外层编排在未取消的前提下自动且仅一次以干净模式回退到 `deephole_threat_analysis`；覆盖率引导方法的补查失败保留最近有效结果。用户主动取消不触发回退，显式选择原生或精简 DeepHole 方法时直接执行所选方法。

用户自有 Codex 默认模型运行失败时不覆盖配置换模型重试，而是按上述规则回退。完整原生输入输出契约见[威胁分析方法扩展](../deephole_client/threat_analysis/README.md)。
