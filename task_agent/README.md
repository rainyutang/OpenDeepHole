# Task Agent 组件

`task_agent` 是供 DeepHole 2.0 Agent 使用的、自包含任务管理框架。它负责驱动 OpenCode 兼容 Serve，并管理延迟初始化的 Serve 单例、任务队列、模型租约、会话续接、权限、重试、事件流和 JSON 结果校验；工具语义固定为 `opencode`，实际启动文件由全局 executable 配置决定，可使用 `opencode`、`nga` 或完整路径。它本身不实现 OpenCode，也不提供另一套 CLI。

该目录本身就是顶层 Python 包。在源码项目中可以直接把整个 `task_agent/` 放到项目根目录；也可以从其父目录执行 `python -m pip install ./task_agent`，安装后调用代码放在任何目录都继续使用同一个公开包名。

应用的各个阶段仅使用公开任务 API。`run_opencode_task()` 的所有参数都必须按关键字传入：

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
    "审计目标代码并给出结论。"
    "\n\n请只返回符合下方 JSON Schema 的 JSON，不要附加解释：\n"
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
    file_write_allowlist=None,
    writable_paths=None,
    session_id=None,
    config_path=None,
    output=None,
    cancel_event=None,
)
```

## 调用参数

| 参数 | 类型 | 必填/默认值 | 说明 |
| --- | --- | --- | --- |
| `task_name` | `str` | 必填 | 任务名称，去除首尾空白后不能为空。它会用于队列记录、日志、Serve 会话标题及看板中的细分任务识别。 |
| `task_type` | `str` | 必填 | 任务类型，用于选择对应的模型策略、调度优先级和超时配置；仅接受下文列出的值。 |
| `prompt` | `str` | 必填 | 发送给模型的任务提示词，不能是空字符串或只包含空白。组件会原样发送该字符串，不会因 `output_schema` 自动追加或改写内容。 |
| `required_capability` | `Literal["low", "high"]` | 必填 | 模型池所需的能力等级，只接受 `low` 或 `high`。 |
| `output_schema` | `dict[str, Any]` 或 `None` | `None` | 可选的 JSON Schema。传入后，组件会先解析模型最终文本，必要时再检查本次消息由内置文件工具写入的文件，并将匹配值写入 `result.structured`；它不会修改首次 `prompt`。不传时 `result.structured` 为 `None`。 |
| `invalid_json_retry_count` | `int` | `2` | 首次结果不符合 `output_schema` 时的恢复开关与原 Session 纠正上限，必须大于或等于 `0`。大于 `0` 时先新建一次低能力格式匹配任务，再最多在原 Session 追加该次数的纠正消息；`0` 同时关闭这两层恢复。该参数不控制 fresh Session 重试次数。 |
| `invalid_json_retry_prompt` | `str` 或 `None` | `None` | JSON 校验失败后的可选纠正提示词。传入非空字符串时，每次纠错都原样重复发送；`None` 使用组件当前包含完整 Schema 的中文默认提示词。 |
| `file_write_allowlist` | 单个路径、路径序列或 `None` | `None` | 本次 Session 额外允许写入并默认保留的文件或目录。相对路径以 `project_dir` 为基准，绝对路径可位于项目外；路径自身及所有后代会获得 `read`、`external_directory` 和 `edit` 权限。不允许通配符或文件系统根目录。 |
| `writable_paths` | 单个路径、路径序列或 `None` | `None` | `file_write_allowlist` 的兼容别名；两者同时传入时合并去重，并使用完全相同的写权限和保留语义。 |
| `session_id` | `str` 或 `None` | `None` | 传入已有 Serve 会话 ID 以续接会话；省略、传入 `None` 或空字符串时创建新会话。同一组件生命周期内，续接会话不能切换项目目录或可写工作目录。 |
| `config_path` | `str`、`PathLike[str]` 或 `None` | `None` | 独立运行时使用的 YAML 配置文件路径。未传入时依次读取 `TASK_AGENT_CONFIG` 和当前目录下的 `task-agent.yaml`。宿主配置已注册时不能再传入此参数。 |
| `output` | callable 或 `None` | 使用当前执行上下文 | 可选的本次调用输出覆盖；传 `None` 可关闭 Task Agent 控制台流。 |
| `cancel_event` | 提供 `is_set()` 的对象 | 使用当前执行上下文 | 可选的本次调用取消信号覆盖。 |

返回的 `OpenCodeResult` 包含 `session_id`、`status`、`text`、`structured`、`model` 和可直接 JSON 序列化的 `output_source`。即使 `structured` 来自文件，`text` 也始终是 LLM 最后一次文本输出，不会替换成文件内容。

已有业务实现若提供同步入口，不需要为了接入平台改成异步，也不要在同步代码里感知宿主事件
循环。外层异步门面使用 `await run_sync_component(sync_entry, **kwargs)` 即可；该桥会在独立
线程执行同步入口，并把入口内部对 `run_opencode_task()` 的调用调度回门面所属事件循环。这样
平台公开入口仍统一为 `async`，原实现及其同步任务提交器可以保持不变。

过程门面还可以通过 `opencode_task_context(..., config_path=..., skill_paths=[...])` 绑定独立
配置和临时 SKILL 根。绑定值会被内部 `run_opencode_task()` 继承，SKILL 路径仅合并到该
任务的 Serve 配置，不会修改宿主的持久受管 Skill 注册；Task Agent 会在最终
`opencode.json` 中从 `skills.paths` 和临时 `skill_paths` 推导显式 `read: allow` 与外部目录规则，使
`references/`、`assets/`、`scripts/` 等资源可读。standalone 默认仍只允许写 `work_dir`；
嵌入宿主可通过 `OpenCodeHostBindings.writable_roots` 声明额外稳定可写根。每次调用都会把
`work_dir` 与 `file_write_allowlist`、兼容参数 `writable_paths` 合并为当前 Session 的窄化
`permission` 覆盖，因此续接 Session 不会继承上一次调用未再次声明的额外路径。调用方不能传
原生权限规则，`project_dir` 默认只读，`bash` 始终保持禁用。

`output_schema` 只定义本地解析和校验规则。需要模型首次就按 Schema 输出时，调用方必须像上例一样把要求和 Schema 明确写入 `prompt`。自定义 `invalid_json_retry_prompt` 也不会被组件追加 Schema、重试序号或其它文字；若省略该参数，组件才会使用当前内置的中文纠错提示词。显式传入空字符串、纯空白或非字符串会在提交任务前报错。

传入 `output_schema` 后，每条消息仍以最终文本中的合法 JSON 为第一选择。文本不匹配时，组件会按实际成功写入顺序倒序检查当前消息的内置 `write`、`edit`、`apply_patch`/`patch` 文件，最后一个匹配 Schema 的文件作为 `structured`。Task Agent 会向受管 `opencode.json` 追加文件写入 Hook，并在消息结束后重新读取本轮新增的完整 assistant 历史，因此即使最终响应只返回文本、文件工具发生在中间 assistant 消息中，也能恢复写入记录。相对写入路径以 `project_dir` 为基准；只读取 `project_dir`、`work_dir` 或显式白名单路径内的文件。

`work_dir` 始终是隐式白名单；显式白名单及其后代也默认保留。本轮由受管文件工具确认新建、但位于有效白名单之外的文件会在任意位置删除，包括执行失败、取消或进入后续恢复时。若某个本轮新建文件被实际采用为符合 `output_schema` 的结构化结果，它会在解析后强制删除，即使位于白名单中；其它合法但未采用的文件仍按普通白名单处理。已有文件即使被修改或被采用为结果也不会删除或恢复。未传 Schema 时不解析文件 JSON，但仍跟踪和清理非白名单新文件；自定义 MCP 的未知文件副作用不纳入该机制。

若文本和文件仍不符合 Schema，且 `invalid_json_retry_count > 0`，组件先把最后写入的非空文件内容（没有时使用最终文本）交给一个全新、禁用全部工具的格式匹配 Session。该任务以 `required_capability="low"` 调度并优先选择满足要求的最低能力候选，因此允许使用配置为低能力的模型；候选始终来自当前已启用且处于生效时间窗的模型。提示词要求只修复格式、不得增删或改写业务内容；原文缺少必需语义、映射有歧义或与 Schema 完全无关时，必须返回固定非法值 `__OPENDEEPHOLE_JSON_FORMAT_UNRELATED__`，不能强制生成。格式匹配成功时只采用其 `structured`，公开结果继续保留原业务 Session、原文本和原模型。格式匹配失败后，组件才在原业务 Session 最多追加 `invalid_json_retry_count` 次纠正消息；仍失败则进入既有 fresh Session 业务重试。

`task_type` 是文档约定的字符串，而不是导出的枚举。面向业务调用者的稳定类型只有 `vulnerability_mining`、`threat_analysis`、`fp_review` 和 `vulnerability_validation`；未知值会在提交前被拒绝。Agent 自身使用的辅助任务类型属于内部实现，不作为公共调用指导的一部分。

任务优先级由 `task_type` 自动决定，数值越大越先取得模型 Lease：`vulnerability_validation=90`、`fp_review=60`、`threat_analysis=50`、`vulnerability_mining=50`。同优先级任务按进入队列的先后顺序执行，因此威胁分析和漏洞挖掘可以按实际入队顺序共享模型容量。

漏洞挖掘中的候选点审计、项目级审计、威胁审计和漏洞根因去重都传
`task_type="vulnerability_mining"`。内置调用分别使用 `candidate-audit-*`、
`project-audit-*`、`threat-audit-*` 和 `vulnerability-dedup-*` 任务名前缀，模型看板据此
显示具体子任务；漏洞去重不会计入候选点审计活动状态，自定义名称无法匹配这些前缀时统一
显示为“漏洞挖掘”。

嵌入 DeepHole 2.0 时，宿主会在启动期间注册一次 `OpenCodeHostBindings`。注册过程会提供后端配置、共享工作区、解析后的 Serve 进程设置以及可选的 MCP 选择；它不会实例化管理器或启动 Serve。首次调用 `run_opencode_task()` 时，系统会按需创建共享任务服务和 Serve 管理器。在发送提示词之前，该管理器会在 Serve 尚未运行时启动它、复用兼容的进程，或执行既有的重启与恢复逻辑。

未注册宿主时，同一函数会从组件自有的 YAML 文件完成初始化。可以传入 `config_path=...`、设置 `TASK_AGENT_CONFIG`，或将 `task-agent.yaml` 放在当前目录中。请复制 `task-agent.example.yaml` 作为起点。在单例的整个生命周期内，该配置会固定项目、可写工作目录、组件工作区、Serve 进程设置和显式模型池。只有执行 `await shutdown_opencode()` 后才能选择其他配置。

一次 `run_opencode_task()` 返回后不会立即关闭 Serve；只要 Python 宿主进程仍在运行，后续任务就会继续复用这个单例。调用 `await shutdown_opencode()` 会立即终止组件启动的 Serve 进程树。若调用方未显式 shutdown，组件也会在解释器正常退出以及收到 `SIGINT`（Ctrl-C）或 `SIGTERM` 时自动清理，并把信号继续交给宿主原有处理逻辑。POSIX 清理会先向已登记的独立进程组发送 `SIGTERM`，持续检查整个进程组和已确认归属的监听 PID，5 秒后仍未退出则使用 `SIGKILL`；Windows ownership marker 会保存旧端口、受管 PID 和进程创建标识，恢复时只对身份仍匹配的进程执行 `taskkill /T /F`，PID 已复用或属于未知进程时绝不终止。TCP、监听表和 `SO_EXCLUSIVEADDRUSE` 只用于描述端点及端口状态：旧进程已确认不存在时，即使旧端口仍因连接回收暂不可独占绑定，也会删除无效 marker；完整 Agent 的自动模式避开该端口继续启动，standalone 固定端口则报告绑定失败。只有旧受管进程仍存活或身份无法安全确认时才保留 marker 并阻止第二个 Serve。`SIGKILL` 和 `os._exit()` 无法执行 Python 清理；这类异常退出由下次启动时的归属标记恢复逻辑处理。

standalone 与完整 Agent 共用受控的 OpenCode 配置发现：依次合并当前用户的全局配置、所选可执行文件相邻配置、项目配置和 `OPENCODE_CONFIG_PATH` / `OPENCODE_CONFIG` / `OPENCODE_CONFIG_DIR` 显式配置。随后再合并 `serve.opencode_config`，因此 YAML 是 standalone 的最高优先级用户层；`model_pool.models[].model` 只选择 `provider/model`，对应 Provider 可以直接由用户全局配置提供。自动发现的可执行文件相邻目录和项目目录只读取 `opencode.json` / `opencode.jsonc`，不会误读通用 `config.json`；最终生成的 `workspace_dir/opencode.json` 也不会作为项目配置回灌。

OpenCode 的 YAML 内覆盖配置放在 `serve.opencode_config` 下，其中 MCP 配置使用 `serve.opencode_config.mcp`。示例文件同时给出了 `type: remote` 的 HTTP MCP 和 `type: local` 的进程 MCP；两项默认关闭，配置好 URL、请求头或启动命令后再将对应的 `enabled` 改为 `true`。MCP 的 `timeout` 单位为毫秒。外部配置无效时记录文件路径和警告后忽略；YAML 内配置无效时直接拒绝启动。配置在单例生命周期内固定，执行 `await shutdown_opencode()` 后才会重新发现磁盘配置。

独立运行时，组件按 `[<stage>][<session_id>][task|session|tool|skill]` 打印结构化进度并立即刷新。`vulnerability_validation` 的 stage 固定为 `validation`，其它任务使用原始 `task_type`；Session 创建前使用 `pending`。`task` 记录排队、模型选择、Serve 和最终状态，`session` 明确标记当前消息执行的 `START`/`STOP`、Provider 重试、新 Session `RETRY`、格式匹配 `JSON_FORMAT_RETRY`/`JSON_FORMAT_RECOVERED`/`JSON_FORMAT_FAILED`、同 Session `JSON_RETRY` 及错误；`STOP status=success` 同时表示本次消息结束且执行成功。OpenCode 内部 step 不打印；Tool 和 SKILL 调用分别使用 `tool`、`skill`，每次调用只打印一行。常用内置 Tool 会追加定制摘要：`read` 打印路径及可选 offset/limit，`write` 打印路径和写入字符数，`edit` 打印路径、替换前后字符数及 replace-all 标志，`bash`/`shell` 完整打印经过单行 JSON 转义但不截断、不脱敏的命令及可选工作目录、超时和描述，`grep`/`glob`/`list` 打印各自的模式和目录；当前扫描实际选中的代码图谱 MCP 会打印实际工具名及完整、无截断、无脱敏的单行 `input` JSON，其它未识别的 Tool 与 MCP Tool 仍只打印名称。成功不追加完成行，失败才追加脱敏 `ERROR`。模型 text、reasoning、write/edit 正文及工具返回正文不写入控制台，但最终 text 仍正常返回并参与 JSON 解析。Bash 命令和代码图谱 MCP 输入中的 Token、密码、请求头或其它敏感值会原样进入日志，调用方应避免在这些参数中嵌入不应留存的凭据。一次消息执行结束的 `STOP ... retained=true` 不会删除可续写的 Session。宿主模式继承宿主绑定的输出回调，不会额外重复打印；嵌套 `opencode_task_context(...)` 只有显式传入 `output=None` 才会关闭该回调。

`serve.timeout` 是一次模型请求的总超时，默认 `3600` 秒。模型 Provider 无法连接时，OpenCode 自身的 `busy`、`retry` 和 `error` 会出现在上述实时输出中；达到总超时后，组件会 abort 当前 Session 请求、回收请求与事件任务，并按 `serve.max_retries` 重新排队到全新 Session，预算耗尽后才返回 `timeout`。fresh Session 重试会记住本次逻辑任务已经尝试过的模型：只要还有满足能力与时间窗的未尝试模型，就排除已经尝试的模型；即使替代模型的并发容量暂满也会等待，而不会立即回到原模型。只有单模型可用或所有合格模型都已尝试后，才允许按当前有效权重回退选择。结构化失败先尝试独立低能力格式匹配，再在原业务 Session 纠正；两者都失败后创建 fresh Session 时也遵循相同的换模规则。主动取消仍会立即停止当前请求及后续重试。Serve 子进程不会继承或接受 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 及其小写形式；`serve.environment` 的其它 Provider 环境变量保持不变，代理相关变量仅允许 `NO_PROXY`/`no_proxy` 绕过列表。

同步消息接口若返回 HTTP 成功但正文为空或不是 JSON，组件会按发送前的消息基线从同一 Session 恢复本次新增且已完成的 assistant 消息，并输出不含模型正文的 `RESPONSE_RECOVERED`。无法安全恢复时不会复用旧回复，而是报告仅含状态码、Content-Type、响应字节数和失败类别的协议错误，按健康中性失败换模重试且不降低模型权重；原始响应正文和底层 JSON 解码异常不会进入控制台错误。

模型配置中的 `weight` 始终是不会被运行时改写的基础权重。Task Agent 只在当前进程内维护健康惩罚等级，并以 `基础权重 × max(10%, 0.5^惩罚等级)` 计算有效权重；等级范围为 `0..4`，对应系数 `100%`、`50%`、`25%`、`12.5%` 和 `10%`。只有已经进入模型消息请求后的 Provider/Auth/API 失败或超时才会增加一级惩罚；Serve 启动、配置、MCP、回调、主动取消、无可用模型、上下文/输出长度错误以及 JSON/结构化输出失败都不会降权。其中已实际执行消息的健康中性失败仍会换模重试。一次最终成功，或连续 10 分钟没有新的模型消息请求故障，会恢复一级；JSON 纠错耗尽会换模重试，但本身既不降权也不恢复。基础权重和有效权重会分别出现在模型池运行状态中；健康状态不持久化，Agent/Task Agent 进程重启后恢复为健康基础权重。

此目录不会从 DeepHole 2.0 的 `deephole_client`、`backend` 或 `mcp_server` 包中导入任何内容。如需提取给其它平台，请复制整个目录并将其放到平台的 Python 导入根目录，或直接安装该目录；依赖会由包元数据安装。随后提供 `task-agent.yaml`，并让所有调用点继续使用上文所示的公开导入方式。已有自身配置系统的应用也可以改为注册 `OpenCodeHostBindings`；宿主绑定的优先级始终高于独立配置文件发现机制。
