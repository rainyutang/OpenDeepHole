# Task Agent 公共任务接口

DeepHole 2.0 中所有模型任务统一调用 `task_agent.run_opencode_task()`。业务组件不直接启动 CLI，不访问任务队列，也不自行创建、查询、取消或删除 OpenCode Session。

> 模型任务只使用 OpenCode 兼容 serve 与 OpenCode Session，没有 LLM API 降级路径。

Agent 启动时只注册一次 DeepHole 2.0 的后端配置、workspace 与 MCP/SKILL 适配，不创建 Serve 进程。首次 `run_opencode_task()` 会惰性创建共享任务服务和 Serve 管理单例；组件在真正发送 prompt 前检查 Serve，按现有规则启动、复用兼容进程或恢复异常进程。没有后端宿主绑定时，公共函数改从组件自己的 YAML 配置自举，仍不存在额外的组件 CLI。

## 唯一调用接口

```python
import json

from task_agent import run_opencode_task

prompt = (
    "使用 `npd` 技能审计指定候选点。"
    "\n\n请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(RESULT_SCHEMA, ensure_ascii=False, indent=2)
)
retry_prompt = (
    "上一次回复不符合要求，请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(RESULT_SCHEMA, ensure_ascii=False, indent=2)
)

result = await run_opencode_task(
    task_name="candidate-audit-npd",
    task_type="vulnerability_mining",
    prompt=prompt,
    required_capability="high",
    output_schema=RESULT_SCHEMA,
    invalid_json_retry_count=2,
    invalid_json_retry_prompt=retry_prompt,
    file_write_allowlist=None,
    writable_paths=None,
    session_id=None,
    output=None,
    cancel_event=None,
)
```

参数只有以下十三个：

| 参数 | 类型 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `task_name` | `str` | 必填 | 逻辑任务名及新 Session 标题；模型看板也使用它识别漏洞挖掘的具体子任务 |
| `task_type` | `str` | 必填 | 文档约束的任务类型字符串，用于选择内部策略和看板元数据 |
| `prompt` | `str` | 必填 | 本次原样发送给模型的提示词；服务不会根据 Schema 追加或改写内容 |
| `required_capability` | `"low" \| "high"` | 必填 | 调用方声明的能力；嵌入 Agent 时，已分类阶段由 Web 阶段策略覆盖 |
| `output_schema` | `dict \| None` | `None` | 最终文本或本次消息所写文件中的 JSON 必须匹配的 JSON Schema；只用于本地解析和校验 |
| `invalid_json_retry_count` | `int` | `2` | JSON 非法时在原 Session 追加纠正提示的次数 |
| `invalid_json_retry_prompt` | `str \| None` | `None` | 自定义 JSON 纠正提示词；非空字符串会原样重复发送，`None` 使用内置中文默认值 |
| `file_write_allowlist` | 路径序列或 `None` | `None` | 需要保留的模型写入文件或目录；仅在传入 `output_schema` 时参与自动清理，不增加写权限 |
| `writable_paths` | 路径序列或 `None` | `None` | 为本次 Session 额外开放内置文件修改工具的文件或目录；相对路径以 `project_dir` 为基准，绝对路径可位于项目外 |
| `session_id` | `str \| None` | `None` | 为空时创建 Session；非空时续写已有 Session |
| `config_path` | `str \| PathLike \| None` | `None` | 仅独立模式使用的组件 YAML 路径；后端模式禁止覆盖宿主配置 |
| `output` | callable 或 `None` | 当前执行上下文 | 覆盖本次任务的流式输出回调；显式 `None` 表示关闭 |
| `cancel_event` | 提供 `is_set()` 的对象 | 当前执行上下文 | 覆盖本次任务的取消信号 |

不再接受 `directory`、workspace、timeout、priority、attempt、MCP、SKILL、原生 permission 或 CLI 配置对象等参数。`writable_paths` 是唯一公开的额外写权限入口；它只生成路径级 `read`、`external_directory` 和 `edit` 放行规则，不能启用 `bash` 或改变其它权限。`file_write_allowlist` 只决定本次新建文件是否在 JSON 检查后保留。后端模式由 Agent 执行上下文和内部任务策略统一提供；独立模式由 `config_path` 指向的组件配置统一提供。业务过程可通过 `output` 和 `cancel_event` 对单次调用做局部覆盖。

返回的 `OpenCodeResult.output_source` 是可 JSON 序列化的 dict，用于由客户端协调器原样上报实际模型和 Session 来源。

`task_type` 直接传字符串，不提供枚举。面向业务调用者的稳定类型如下；其它公共调用值会立即抛出 `ValueError`：

| 字符串 | 用途 |
| --- | --- |
| `vulnerability_mining` | 漏洞挖掘，包括候选点审计、项目级审计和威胁审计 |
| `threat_analysis` | 威胁分析 |
| `fp_review` | 去误报复核 |
| `vulnerability_validation` | 漏洞验证 |

任务优先级由 `task_type` 自动决定，数值越大越先取得模型 Lease：

| `task_type` | 优先级 |
| --- | ---: |
| `vulnerability_validation` | 90 |
| `threat_analysis` | 75 |
| `fp_review` | 60 |
| `vulnerability_mining` | 50 |

Agent 内部辅助任务继续使用各自既有策略，但不属于公共调用指导。同优先级任务按进入队列的先后顺序执行；优先级不会抢占已经取得 Lease 的任务。

漏洞挖掘子任务不再拆分 `task_type`。内置调用分别使用 `candidate-audit-*`、`project-audit-*` 和 `threat-audit-*` 任务名前缀；模型看板以完整引擎名称作为主标签，并追加候选点审计、项目级审计或威胁审计作为子任务说明，其它任务名回退显示“漏洞挖掘”。

任务策略页只配置 `low`、`high` 两档，v3 默认全部为 `high`。v2 及更早配置中的阶段级 `any`/`low` 会一次性迁移为 `high`，旧默认超时 `1200` 会迁移为 `3600`；升级到 v3 后仍可手工改回 `low` 或填写自定义超时。模型行自身的能力标签和显式超时不会迁移。

## 独立组件配置

未注册 `OpenCodeHostBindings` 时，配置按以下顺序发现：

1. `run_opencode_task(config_path=...)`；
2. `TASK_AGENT_CONFIG` 环境变量；
3. 当前目录的 `task-agent.yaml`。

格式模板位于 `task_agent/task-agent.example.yaml`。下面的配置包含 Task Agent 自己识别的全部字段；除透传的 `serve.opencode_config` 和由调度器解析的 `time_windows` 项外，顶层、固定分区和模型行都是严格白名单，拼错或加入未知字段会在加载时直接报错：

```yaml
schema_version: 2

context:
  # OpenCode Session 的真实源码目录；该目录必须已经存在。
  project_dir: /absolute/path/to/source
  # 模型文件工具唯一允许写入的任务目录；不存在时自动创建。
  work_dir: /absolute/path/to/task-work
  # Serve 启动、opencode.json 和共享 Skill 所在的稳定组件目录。
  workspace_dir: /absolute/path/to/opencode-workspace

serve:
  # Task Agent 的实现固定为 OpenCode；这里只能填写 opencode。
  tool: opencode
  # 实际启动文件名或路径，可填写 opencode、nga 或完整路径。
  executable: opencode
  port: 4096
  # 单次模型消息从开始执行到完成的默认超时，单位为秒，不包含排队时间。
  timeout: 3600
  # 超时、普通执行错误或 JSON 纠正耗尽后，创建全新 Session 的重试次数。
  max_retries: 2
  # 传给 Serve 子进程的环境变量。实际代理变量会被清除，只保留绕过列表。
  environment:
    NO_PROXY: 127.0.0.1,localhost
    no_proxy: 127.0.0.1,localhost

  # 这里是原样交给 OpenCode 的原生配置对象，不属于 Task Agent 固定 Schema。
  opencode_config:
    $schema: https://opencode.ai/config.json
    # 推荐将 standalone 共享 Skill 放在 workspace_dir 下，并显式注册绝对路径。
    skills:
      paths:
        - /absolute/path/to/opencode-workspace/.opencode/skills
    mcp:
      remote-example:
        type: remote
        url: http://127.0.0.1:9123/mcp
        enabled: false
        timeout: 30000
        oauth: false
        headers:
          Authorization: "Bearer replace-me"
      local-example:
        type: local
        command:
          - python3
          - -m
          - your_mcp_server
        environment:
          PROJECT_DIR: /absolute/path/to/source
        enabled: false
        timeout: 30000

model_pool:
  # 所有模型合计正在执行的任务数硬上限。
  global_concurrency: 2
  models:
    - id: deepseek-pro
      # OpenCode 使用的 provider/model；use_default_model=false 时必须非空。
      model: deepseek/deepseek-v4-pro
      use_default_model: false
      capability: high
      weight: 1
      max_concurrency: 2
      enabled: true
      # 以下两项均为模型行覆盖；省略时继承 serve 设置。
      timeout: 3600
      max_retries: 2
      # 使用运行 Task Agent 的机器本地时间；多段时间窗取并集。
      time_windows:
        - weekdays: [1, 2, 3, 4, 5]
          start: "09:00"
          end: "18:00"
```

### 顶层和目录参数

| 参数 | 必填/默认值 | 含义 |
| --- | --- | --- |
| `schema_version` | 必填，当前为 `2` | standalone YAML 的 Schema 版本。v1 会按下述兼容规则迁移；其它版本拒绝加载。 |
| `context` | 必填 | 固定本次 standalone 组件生命周期使用的目录上下文。 |
| `serve` | 必填 | Serve 进程、默认执行策略和原生 OpenCode 配置。 |
| `model_pool` | 必填 | 显式模型列表及全局调度上限。 |
| `context.project_dir` | 必填，必须是已有目录 | OpenCode Session 的 `directory`，也是真实源码根目录。模型可读取该目录，但 Task Agent 不允许文件编辑工具写入。 |
| `context.work_dir` | 必填，不存在时创建 | 本次独立组件固定的可写任务目录。模型生成的补丁、PoC、报告等任务产物应写在这里。 |
| `context.workspace_dir` | 必填，不存在时创建 | Serve 的稳定启动目录和组件 workspace。运行时会在这里生成 `opencode.json`，也适合保存共享 Skill；不要把每次任务的业务产物写在这里。 |

三个路径都支持 `~`。绝对路径直接使用；相对路径以 `task-agent.yaml` 所在目录为基准，而不是以启动 Python 的当前目录为基准。`project_dir` 必须预先存在；`work_dir` 和 `workspace_dir` 会自动递归创建。standalone 的最终 `workspace_dir/opencode.json` 允许读取项目工作目录、`work_dir`、`workspace_dir/.opencode` 和已注册的 Skill 根；文件编辑工具只能写 `work_dir`，`bash` 始终禁用。

v1 兼容迁移会把 `serve.tool: nga` 规范为 `tool: opencode`，并在未显式填写 `serve.executable` 时继续使用 `nga`；旧模型行里的 `tool` 和 `executable` 会被忽略。v2 只接受 `serve.tool: opencode`，并拒绝模型行工具或可执行文件覆盖，确保所有模型共用 `serve.executable`。

嵌入完整 Agent 时，所有已知动态 `work_dir` 都位于四个稳定根目录下：`~/.opendeephole/scans`、`fp_reviews`、`vulnerability_validation` 和 `skill_create`。Task Agent 在 Serve 启动前把这些根目录及 `~/.opendeephole/opencode_workspace/.opencode` 的权限写入最终全局 `opencode.json`；前四个目录可读写，`.opencode` 及其中的 Skill/reference 只读，scans 之外的 `project_dir` 保持只读。Windows 下同时生成原生反斜杠和正斜杠兼容规则，`bash` 始终禁用。只有显式传入 `writable_paths` 时，额外动态路径才通过 Session 权限覆盖下发，不进入 Serve 配置哈希。

`workspace_dir` 中生成的 `opencode.json` 包含 `serve.opencode_config` 的实际内容，可能带有 Provider Key、MCP Header 等敏感值；运行时在 POSIX 系统上以 `0600` 权限写入，但该目录仍应只对可信用户开放。Serve 子进程使用 `workspace_dir` 下的独立 `XDG_CONFIG_HOME`，把 `OPENCODE_CONFIG_DIR` 指向该已解析配置，并清除继承的 `OPENCODE_CONFIG`、`OPENCODE_CONFIG_PATH` 和 `OPENCODE_CONFIG_CONTENT`，避免 OpenCode 再合并调用者机器上的环境配置。standalone 只以 YAML 中的 `serve.opencode_config` 为用户配置源；完整 Agent 则在进入 Task Agent 前按受控顺序合并已发现的全局、可执行文件目录、项目和显式配置。用户全局目录及显式配置目录兼容旧版 `config.json`，但自动发现的可执行文件相邻目录和项目目录只接受 `opencode.json` / `opencode.jsonc`；通用 `config.json` 可能属于安装器、启动器或项目自身，不能作为 OpenCode 配置源。

### Serve 参数

| 参数 | 必填/默认值 | 含义 |
| --- | --- | --- |
| `serve.tool` | 默认且只能为 `opencode` | 固定的 OpenCode Serve 实现标识，不用于选择磁盘上的文件。 |
| `serve.executable` | 默认 `opencode` | 实际启动 Serve 的可执行文件名或完整路径；可使用 `opencode`、`nga` 或其它兼容程序。配置哪个就启动哪个，不做名称回退。 |
| `serve.port` | 默认 `4096`，范围 `1..65535` | 本机 Serve 固定监听端口。该值会成为最终的 `OPENCODE_SERVE_PORT`，覆盖 `serve.environment` 中的同名值；standalone 不会自动改号。 |
| `serve.timeout` | 默认 `3600`，最小 `1` | 默认单次模型消息执行超时，单位为秒；排队等待模型 Lease 的时间不计入。 |
| `serve.max_retries` | 默认 `2`，最小 `0` | 首次 Session 之外最多创建多少个全新 Session 进行重试；不等同于同 Session 的 JSON 纠正次数。 |
| `serve.environment` | 默认 `{}` | 附加或覆盖到 Serve 子进程的环境变量。键转为字符串，值必须是标量并会转为字符串；`HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 及其小写形式会被忽略并从父进程环境清除，只允许 `NO_PROXY`/`no_proxy` 代理绕过变量。 |
| `serve.opencode_config` | 默认 `{}` | 必须是可 JSON 序列化的映射；运行时与 Task Agent 受管权限合并后写入 `workspace_dir/opencode.json` 并交给 OpenCode。 |

`serve.opencode_config` 可以包含 OpenCode 当前版本支持的 `$schema`、Provider、Agent、MCP、Skill 等原生配置。Task Agent 不校验这些子字段，也不保证不同 OpenCode 版本的原生字段兼容；最终配置中的 `read`、`list`、`glob`、`grep`、`external_directory`、`edit`、`bash` 和 `skill` 会由 Task Agent 覆盖为受管边界，不能依赖这里的 `permission` 放宽任务边界。

MCP 直接写在 `serve.opencode_config.mcp` 下。远程 MCP 通常使用 `type: remote`、`url`、`headers` 和 `oauth`；本地 MCP 使用 `type: local`、命令数组 `command` 以及可选的 `environment`。两种 MCP 的 `timeout` 都由 OpenCode 解释，单位为毫秒；这与 `serve.timeout` 的秒不同。扫描级代码图谱 MCP 对外使用 `code_graph_mcp.timeout_seconds`，运行时乘以 `1000` 写入 OpenCode 配置，例如 `300` 秒生成 `"enabled": true, "timeout": 300000`。

### Skill 放置和注册

单个 Skill 至少使用以下目录结构：

```text
<skill-root>/
└── my-skill/
    ├── SKILL.md
    ├── references/       # 可选
    ├── scripts/          # 可选
    └── assets/           # 可选
```

Skill 有两种常用放置方式：

1. 项目专用 Skill 放在 `<project_dir>/.opencode/skills/<skill-name>/SKILL.md`，由以 `project_dir` 为 Session 目录的 OpenCode 按项目发现。
2. 多个任务共享的 standalone Skill 推荐放在 `<workspace_dir>/.opencode/skills/<skill-name>/SKILL.md`，并将 `<workspace_dir>/.opencode/skills` 的绝对路径写入 `serve.opencode_config.skills.paths`。

standalone 加载器只负责创建 `workspace_dir`，不会自动创建、复制或注册任何 Skill，也不会把 `context.workspace_dir` 变量插值到 `skills.paths`。因此两处路径应手工保持一致，推荐都填写绝对路径；Task Agent 会从最终生效的 `skills.paths` 推导全局配置中的显式读取和外部目录权限，使 Skill 内的 `references/`、`assets/`、`scripts/` 一并可读。嵌入完整 DeepHole 2.0 Agent 时，威胁分析适配器会把当前所选方法相邻 `skills/` 中的 Skill 根作为任务级 `skill_paths` 绑定；它们不会复制到全局 workspace，其它威胁分析方法的 Skill 也不会注册到当前任务。升级时只会清理旧版曾全局注入的四个受管 Skill，不删除其它 workspace Skill。

### 模型池参数

`model_pool.models` 必须是列表，并且至少包含一个已启用且填写了 `model` 的模型，或者一个已启用且显式设置 `use_default_model: true` 的默认模型行。

| 参数 | 必填/默认值 | 含义 |
| --- | --- | --- |
| `model_pool.global_concurrency` | 默认 `1`，范围 `1..64` | 所有模型合计正在执行的任务数硬上限。 |
| `models[].id` | 默认取 `model`，默认模型行为 `default` | 模型池内部稳定标识，用于 Lease、日志和统计；不同模型行应使用不同 ID。 |
| `models[].model` | 条件必填 | OpenCode 的 `provider/model`。要让该行进入可调度模型池，当 `use_default_model` 为 `false` 时必须非空。 |
| `models[].use_default_model` | 默认 `false` | 为 `true` 时忽略 `model`，让 Serve 使用自己的默认模型。 |
| `models[].capability` | 默认 `high` | 模型能力，可为 `low`、`medium`、`high`。公共任务只请求 `low` 或 `high`；高能力任务只使用高档模型，低能力任务在当前负载和有效权重相同时优先选择满足条件的较低档模型。 |
| `models[].weight` | 默认 `1`，最小 `0.01` | 多个可用且能力合适的模型之间的基础调度权重；运行时健康降级不会改写该配置值。 |
| `models[].max_concurrency` | 默认 `1`，最小 `1` | 该模型行允许同时持有的 Lease 数量。 |
| `models[].enabled` | 默认 `true` | 是否将该模型加入可调度模型池。 |
| `models[].timeout` | 默认继承 `serve.timeout`，最小 `1` | 该模型单次消息执行超时，单位为秒。 |
| `models[].max_retries` | 默认继承 `serve.max_retries`，最小 `0` | 该模型在超时或其它可重试失败后采用的新 Session 重试次数。 |
| `models[].time_windows` | 默认 `[]` | 模型允许获得新 Lease 的本地时间窗口；空列表表示全天可用。 |

实际并发数同时受全局和模型行限制。对于当前满足能力、已启用且处于可用时间窗内的模型，可近似理解为：

```text
实际并发容量 = min(
    model_pool.global_concurrency,
    所有合格模型的 max_concurrency 之和,
)
```

例如全局并发为 `2`，但唯一高能力模型的 `max_concurrency` 为 `1` 时，两个 `high` 任务会同时进入队列，却仍然只能串行执行。要让它们同时运行，需要把该模型的 `max_concurrency` 提高到 `2`，或者再配置一个当前可用的高能力模型。

模型池在当前 Agent/Task Agent 进程内为每个实际模型身份维护 `0..4` 级健康惩罚，调度使用的有效权重为：

```text
有效权重 = 基础权重 × max(10%, 0.5 ^ 健康惩罚等级)
```

五个状态的权重系数依次为 `100%`、`50%`、`25%`、`12.5%` 和 `10%`。模型池状态会分别暴露基础权重、有效权重、当前惩罚等级以及最近一次健康故障的时间和类型；配置中的 `models[].weight` 始终保持不变。

只有已经进入模型消息请求后的 Provider/Auth/API 执行失败或总超时才会增加一级惩罚；即使消息接口返回 HTTP 200，assistant `info.error` 中的这类 Provider 执行错误也按真实请求失败处理。`ContextOverflowError`、`MessageOutputLengthError`、`StructuredOutputError` 和非主动取消产生的 `MessageAbortedError` 会让当前任务换模重试，但不会降权。Serve 启动或配置失败、MCP/回调故障、主动取消、没有可用模型，以及返回内容未通过 JSON Schema 校验，也都不属于模型健康故障。一次最终成功会恢复一级；没有新模型消息请求故障满 10 分钟也会恢复一级。JSON 纠错耗尽后仍会进入 fresh Session 换模重试，但该 JSON 失败本身既不降权也不恢复健康；若纠错消息请求本身超时或发生 Provider/Auth/API 执行失败，仍按真实请求故障处理。

健康状态不会写回配置或跨进程持久化，Agent/Task Agent 进程重启后从零惩罚和基础权重重新开始。运行中只修改基础权重、并发数或时间窗时继续沿用同一实际模型身份的健康状态；模型 ID 对应的真实模型、默认模型标记或全局可执行文件变化时视为新身份。

每个 `time_windows` 项支持以下字段：

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `weekdays` | `[1, 2, 3, 4, 5, 6, 7]` | ISO 星期，`1` 为周一、`7` 为周日。 |
| `start` | 必填 | `HH:MM` 起始时间，包含该分钟。 |
| `end` | 必填 | `HH:MM` 结束时间，不包含该分钟；不能与 `start` 相同。 |

时间窗口使用运行 Task Agent 的机器本地时间，多段取并集。`start < end` 表示同日区间；`start > end` 表示跨夜区间，并按“当前日期的星期”判断。例如周一的 `22:00-06:00` 包含周一 `00:00-06:00` 和 `22:00-24:00`，不会自动把周二凌晨视作周一的延续。时间窗只限制新 Lease，不中断已经运行的任务。

`time_windows` 本身必须是映射列表，但每个窗口中的未知字段不会触发严格 Schema 错误；调度器只读取 `weekdays`、`start`、`end`。时间格式非法、星期为空或超出 `1..7`、起止时间相同的窗口会被忽略。如果一行模型的所有窗口都被忽略，最终等同于没有有效时间窗，该模型会全天可用，因此应特别检查拼写和时间格式。

### 配置校验和生命周期

- 顶层只允许 `schema_version`、`context`、`serve`、`model_pool`；`context`、`serve`、`model_pool.models[]` 也会拒绝未知字段。
- `project_dir` 不存在、模型列表不是数组、没有任何可用模型、端口或数值超出范围、环境变量值不是标量时，首次调用会立即失败。
- 首个独立调用会锁定配置路径，并在同一进程内复用同一个任务服务和 Serve 单例。同一路径可重复传入；若要切换 YAML，必须先执行 `await shutdown_opencode()`。
- 单个任务返回不会停止 Serve；这是同一 Python 进程内跨阶段、跨任务复用的基础。显式调用 `await shutdown_opencode()` 会终止组件实际启动的 Serve 进程树并清除单例。
- standalone 的 `serve.port` 是显式固定端口，占用时会报告外部监听 PID，无监听却绑定失败时会提示 Windows 排除/保留端口或端点安全软件，不会换号或终止未证明属于本组件的进程。完整 Agent 在未配置端口时才使用自动模式：最多尝试 3 个端口，并只对一次无明确原因的 `Error: Unexpected error` 早退作恢复性换号。
- 未显式 shutdown 时，组件会登记自己通过 `Popen` 启动的精确 PID，在解释器正常退出、`SIGINT`（Ctrl-C）或 `SIGTERM` 时同步清理该进程树，再恢复或转交宿主原有信号处理器；退出清理不会根据端口终止未知进程，也只会删除 PID 仍匹配的归属标记。
- 启动失败会同时报告固定/自动端口模式、已尝试端口和可执行文件版本，并附上脱敏后的启动日志尾部。`OPENCODE_SERVER_PASSWORD is not set` 是 Agent 仅监听 `127.0.0.1` 时的预期警告，日志会明确说明它不是 Serve 退出原因。
- `SIGKILL` 和 `os._exit()` 不运行 Python 的信号处理器或 `atexit` 回调，无法保证当场清理；下次启动会继续使用既有归属标记和端口恢复逻辑回收残留 Serve。
- 若应用已经注册后端宿主绑定，则完全使用宿主配置，不读取独立 YAML；此时再传 `config_path` 会报冲突。

## 控制台日志

Task Agent 的进度行统一使用下面三个头字段：

```text
[<stage>][<session_id>][task|session|tool|skill] <event>
```

- `vulnerability_validation` 映射为 stage `validation`；其它任务直接使用 `task_type`。Session 尚未创建时第二段为 `pending`，创建或续写后改为真实 Session ID。
- 第三段只会是 `task`、`session`、`tool` 或 `skill`：`task` 覆盖排队、模型 Lease、Serve 准备和任务终态；`session` 覆盖当前消息执行的启动、停止、Provider 重试、新 Session `RETRY`、同 Session `JSON_RETRY`、错误及工具发现；`tool`、`skill` 分别表示一次真实工具调用或 SKILL 读取。OpenCode 内部 step 的 START、STOP 和 FAIL 不打印。
- 每次消息执行都会打印 `session START` 和 `session STOP`。`STOP status=success retained=true` 同时表示本次消息结束且成功，Session 本身仍保留并可续写；超时和取消分别标记 `status=timeout`、`status=cancelled`。
- assistant text 和 reasoning 不打印到控制台，仍在内部聚合并作为最终 `text` 返回或用于 JSON 校验。Tool/SKILL 调用每次只打印一行：`read` 打印 `path` 及可选 `offset`/`limit`，`write` 打印 `path`/`content_chars`，`edit` 打印 `path`/`old_chars`/`new_chars` 及可选 `replace_all`，`bash`/`shell` 打印完整 `command` 及可选 `workdir`/`timeout`/`description`，`grep`/`glob`/`list` 打印各自的模式与目录；当前扫描实际选中的代码图谱 MCP 打印实际工具名及完整、无截断、无脱敏的单行 `input` JSON，其它未识别的 Tool 和 MCP Tool 仍只打印名称。Bash 命令与代码图谱 MCP 输入使用 JSON 转义保持单行，其中的 Token、密码、请求头或其它敏感值会原样进入日志。成功不追加完成行，调用失败才在同一类别下追加脱敏 `ERROR`；write/edit 正文、其它未列出的调用参数和工具返回正文仍不打印。嵌套 `opencode_task_context(...)` 省略 `output` 时继承宿主回调，只有显式传入 `output=None` 才关闭输出。

独立模式直接把这些行打印到终端；宿主模式只交给宿主绑定的输出回调。宿主添加本地时间戳时会保留上述三个头字段，不再叠加旧的阶段或模型前缀；扫描器转发结构化 Task Agent 行时也不会重复添加进程阶段前缀。

## 返回值

接口只返回以下字段：

| 字段 | 含义 |
| --- | --- |
| `session_id` | 最终实际使用的 Session ID |
| `status` | 仅为 `success`、`failure` 或 `timeout` |
| `text` | 成功时始终为 LLM 最后一次文本输出，即使 `structured` 来自文件也不会替换为文件内容；失败或超时时为可直接展示的原因 |
| `structured` | 匹配 `output_schema` 的解析值；未传 Schema 或未成功时固定为 `None` |
| `model` | 最终实际响应的 `provider/model` |

```python
if result.status == "success":
    payload = result.structured
else:
    raise RuntimeError(result.text)
```

公共结果中没有 `cancelled`。主动取消会传播 `asyncio.CancelledError`，不会生成一个还需要业务方继续处理的取消结果。

## 目录与权限

Agent 在扫描、去误报、漏洞验证或其它组件的执行边界绑定运行上下文：

- `project_dir`：真实项目目录，只允许 `read`、`list`、`glob`、`grep`。
- `work_dir`：当前任务所属的 `.opendeephole` 隔离工作目录，允许文件编辑工具写入。
- `writable_paths`：调用方显式授权的额外文件或目录；相对路径以 `project_dir` 为基准，绝对路径允许位于项目外，但不接受 `*`、`?` 或文件系统根目录。
- `scan_id`、任务元数据、输出回调和取消事件：由编排层绑定并在异步任务树中自动继承。
- `config_path`：独立过程可绑定自己的 Task Agent YAML；其中的 `serve.opencode_config.skills.paths` 是 standalone Skill 的唯一显式注册来源。
- `skill_paths`：为确实需要临时 Skill 根的过程提供任务级注册；威胁分析只绑定当前所选方法的 Skill 根，不把方法目录写入全局运行配置。

后端模式没有绑定 `project_dir` 或 `work_dir` 时，调用会立即失败，不会回退到进程当前目录。独立模式始终使用 YAML 中固定的两个目录，因此 Session continuation 不会改变权限边界。

内部服务会在 Serve 启动前把受管边界写入最终全局 `opencode.json`：

- 允许读取项目工作目录、当前工作目录和全局 workspace 的 `.opencode`；最终配置的 `skills.paths` 以及通用过程显式绑定的临时 `skill_paths` 都会获得完整子路径的 `read: allow` 与外部目录规则，使 `references/`、`assets/`、`scripts/` 等资源可读。
- 先拒绝所有 `edit`，再允许宿主声明的稳定可写根。完整 Agent 允许写四个 `.opendeephole` 任务根，standalone 允许写固定 `work_dir`；通用嵌入宿主若没有声明覆盖当前 `work_dir` 的稳定根，Task Agent 会把该目录加入本次最终配置。
- 拒绝所有 `bash`，避免通过 shell 绕过项目只读和工作目录写边界。
- 允许加载最终配置注册的 SKILL，以及通用过程通过 `skill_paths` 绑定的临时 SKILL；注册 Skill 本身不会授予编辑权限，是否可写仍只取决于它是否落在 `work_dir` 或宿主可写根内，MCP 可见性继续由受管配置决定。

原生权限规则仍是内部实现细节，组件和 validator 不能直接传 `permission`。`writable_paths=None` 时 Task Agent 不在 `POST /session` 或 `PATCH /session/{sessionID}` 中发送权限，因此续接已有 Session 会保留其权限；显式序列会用本次生成的路径规则替换 Session 权限覆盖，显式 `[]` 清空覆盖并回落到全局配置。新 Session 重试会重新应用相同路径，同 Session JSON 纠正不会重复 PATCH。同步过程可以由异步门面通过 `run_sync_component()` 执行；同步实现内部调用 `run_opencode_task()` 时会回到门面所属事件循环，并继续继承同一目录、权限和私有 SKILL 上下文。

## JSON 自动纠正和新 Session 重试

只有传入 `output_schema` 时才解析结构化结果。服务不使用 OpenCode 原生 `format=json_schema`，也不再把 Schema 或任何输出要求追加到首次用户 prompt；调用方传入什么字符串，首次消息和任务队列历史就保存并发送什么字符串，`prompt_length` 也按该原文计算。需要模型首次就输出 JSON 时，调用方必须像上文示例一样显式组装最终 prompt。

服务先解析 LLM 的最终文本；文本中的 JSON 合法时始终优先采用。若文本不匹配 Schema，服务会检查当前这条消息中成功完成的内置 `write`、`edit`、`apply_patch`/`patch` 调用，按实际写入顺序从后向前读取文件，最后一个匹配 Schema 的文件成为 `structured`。这不会改变 `OpenCodeResult.text`，它仍是 LLM 最后一次文本输出。自定义 MCP 工具的未知文件副作用不在跟踪范围内。

每次消息完成后，服务会删除确认由该消息新建、且未被 `file_write_allowlist` 匹配的文件；无论 JSON 来自文本还是文件、消息执行失败，或即将进入同 Session 纠错，都会执行该清理。已存在但被修改的文件不会删除，也不会恢复旧内容。白名单中的相对路径以当前 `work_dir` 为基准；绝对路径必须位于 `work_dir` 内；文件项匹配自身，目录项匹配自身和所有后代。`writable_paths` 只授予修改权限，不会自动保留新文件；`file_write_allowlist` 只控制保留且不会扩大写权限。

若文本和已写文件都没有符合 Schema 的 JSON，服务会在原 Session 最多追加 `invalid_json_retry_count` 次纠正消息；这些消息复用同一 Session、同一模型 Lease，不重新排队。`invalid_json_retry_prompt=None` 时使用当前包含完整 Schema 的中文默认提示词；传入非空字符串时，每次都原样发送该字符串，不追加 Schema、重试序号或其它内容。空字符串、纯空白和非字符串会在提交任务前报错。未传 `output_schema` 时完全不启用文件跟踪、文件 JSON 回退或自动清理；纠错次数为 `0` 时不会发送纠正消息。

若同 Session 纠正耗尽，内部服务会按对应任务策略的 `max_retries` 释放 Lease、重新排队并创建全新 Session。模型消息超时和其它可重试执行错误也使用同一预算；`max_retries=2` 表示首次 Session 之外最多再创建 2 个 Session，即最多执行 3 次。业务方不再传 `attempt`。

创建新 Session 或更新续写 Session 的权限返回 HTTP 5xx 时，Task Agent 会把共享 Serve 标记为异常，而不让后续重试继续复用同一个进程。发生并发任务时，下一次 Session 获取会等待所有已获取 Session 释放，在空闲边界停止并重启 Serve、重新生成最终 `opencode.json`；等待中的其它重试随后复用这个新进程，因此同一轮异常只触发一次安全重启。HTTP 4xx 仍按请求或配置错误直接上报，不触发 Serve 重启。

OpenCode 同步消息接口若在 HTTP 成功后返回空正文或非 JSON，Task Agent 会查询同一 Session 的消息历史，只接受相对于发送前基线新增且已经完成的 assistant 消息，并将其送回正常的错误、模型、Token、文本和文件写入处理链；恢复成功时控制台输出 `RESPONSE_RECOVERED reason=empty_body|invalid_json source=session_messages`。续写 Session 无法取得发送前基线时不会用历史消息兜底，避免把上一轮结果误认为本轮成功。若没有可确认的新消息，则错误只包含状态码、Content-Type、响应字节数和恢复失败类别，不包含响应正文或模型文本，并作为健康中性失败进入 fresh Session 换模重试，不降低模型权重。

fresh Session 重试会累计本次逻辑任务已经尝试过的实际模型身份。只要还存在满足能力与当前时间窗的未尝试模型，调度器就排除已经尝试的模型；即使未尝试模型的并发容量暂满，也继续排队等待它，而不是立即回到刚失败的模型。只有单模型可用，或所有合格模型都已经尝试后，才重新允许全部候选按当前有效权重竞争 Lease。该换模规则同样适用于 JSON 纠错耗尽，但 JSON 校验失败和纠错耗尽本身不触发健康降权。

只有预算耗尽后的超时、主动取消和没有可用模型会成为终止结果：

- 最后一次仍超时时返回 `status="timeout"`，原因位于 `text`，并保留最后创建的 Session ID。
- 最终失败返回 `status="failure"`，原因位于 `text`。
- 主动取消传播 `asyncio.CancelledError`，并停止排队、当前请求、JSON 纠正及后续新 Session 重试。

## Session 续写

将上次返回的 `session_id` 传回同一接口即可续写：

```python
follow_up_prompt = (
    "基于已有上下文补充证据并重新输出 JSON。"
    "\n\n请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(RESULT_SCHEMA, ensure_ascii=False, indent=2)
)

continued = await run_opencode_task(
    task_name="candidate-audit-npd-follow-up",
    task_type="vulnerability_mining",
    prompt=follow_up_prompt,
    required_capability="high",
    output_schema=RESULT_SCHEMA,
    session_id=result.session_id,
)
```

续写约束：

- 同一 Session 的 `project_dir` 和 `work_dir` 都不能改变。
- 同一 Session 的消息在 Agent 进程内串行执行。
- 正常完成后 Session 保留，供后续续写和 OpenCode 历史查看。
- 若续写执行或 JSON 纠正最终需要新 Session 重试，返回值中的 `session_id` 是最后的权威 Session ID。

## 并发调用

独立任务可直接用 `asyncio.gather()` 并发；它们各自创建 Session，并受同一个模型池限制：

```python
code_prompt += (
    "\n\n请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(CODE_SCHEMA, ensure_ascii=False, indent=2)
)
exploit_prompt += (
    "\n\n请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(EXPLOIT_SCHEMA, ensure_ascii=False, indent=2)
)

code_result, exploit_result = await asyncio.gather(
    run_opencode_task(
        task_name="代码可达性分析",
        task_type="vulnerability_validation",
        prompt=code_prompt,
        required_capability="high",
        output_schema=CODE_SCHEMA,
    ),
    run_opencode_task(
        task_name="利用条件分析",
        task_type="vulnerability_validation",
        prompt=exploit_prompt,
        required_capability="high",
        output_schema=EXPLOIT_SCHEMA,
    ),
)
```

不要并发续写同一个 `session_id`；按顺序 `await`，以保持消息顺序明确。

## Validator 约定

validator 直接导入公共接口；验证运行时已经绑定项目目录、漏洞工作目录、输出回调和取消事件：

```python
import json

from task_agent import run_opencode_task

prompt = (
    kwargs["report_markdown"]
    + "\n\n请只返回符合下方 JSON Schema 的 JSON：\n"
    + json.dumps(RESULT_SCHEMA, ensure_ascii=False, indent=2)
)

result = await run_opencode_task(
    task_name="PoC 设计",
    task_type="vulnerability_validation",
    prompt=prompt,
    required_capability=kwargs["required_capability"],
    output_schema=RESULT_SCHEMA,
)
```

validator 不创建 OpenCode workspace、MCP Server 或 CLI 子进程，也不直接执行 `nga`、`opencode`、`hac` 或 `claude`。OpenCode 的结构化任务、Session、工具和 SKILL 进度只进入 Agent 控制台，模型 text/reasoning 不打印；需要在验证页面展示的内容应显式调用 `await kwargs["emit_stdout"](...)`。

## 内部职责

- `task_agent/api.py`：唯一公共调用与精简结果契约。
- `task_agent/task_service.py`：内部队列、模型调度、权限、Session、JSON 纠正和重试。
- `task_agent/model_pool.py`：模型 Lease、全局并发、能力匹配、时间窗和统计。
- `task_agent/serve_client.py`：Serve 生命周期、Session API、事件与消息流。
- `task_agent/host.py`：自包含组件与宿主之间的最小配置回调边界。
- `task_agent/standalone.py`：独立 YAML 的校验、发现、宿主适配和一次性自举。
- `deephole_client/opencode_integration.py`：DeepHole 2.0 全局 workspace、SKILL、MCP 与运行配置适配。
- `deephole_client/<process>/`：DeepHole 2.0 各业务过程的独立目录；过程只通过公开的 `run_opencode_task()` 调用 Task Agent。

`task_agent/` 内不导入 DeepHole 2.0 的 `deephole_client`、`backend` 或 `mcp_server` 模块。单独复制该目录后，可以放到目标项目的 Python 导入根目录，或执行 `python -m pip install ./task_agent`；两种方式都使用 `from task_agent import run_opencode_task`，不因业务代码所在目录变化而改名。组件提供独立配置即可运行，也可由其它应用注册自己的 `OpenCodeHostBindings`。DeepHole 2.0 业务阶段只能从 `task_agent` 导入公共类型和函数，不应直接依赖 `task_service.py` 中的内部任务记录、句柄或 Session 管理方法。
