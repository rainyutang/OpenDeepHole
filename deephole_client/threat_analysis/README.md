# 威胁分析方法扩展

威胁分析按目录自动发现。每个方法占用
`deephole_client/threat_analysis/methods/<method_id>/` 一个目录；新建扫描时用户只能选择其中
一个方法，扫描创建后会固化方法 ID、名称和说明快照。原生方法 ID 是
`deephole_threat_analysis`，界面名称是“DeepHole威胁分析”；Web 新建扫描默认优先
`opencode_lightweight_threat_analysis`。

`deephole_compact_threat_analysis`，界面名称“DeepHole精简威胁分析”，完整复制 DeepHole
多阶段方法，保留四类价值资产与五类高风险模块的并行识别、合并和逐资产攻击树分析。
攻击树阶段将原方法的 1,355 项攻击模式替换为现有轻量级库的 51 项：C/C++ 11 项、协议 14 项、
密码学 11 项、系统边界 15 项。完整复制
`methods/codex_goal_threat_analysis/references/attack_mode.json` 到新方法攻击树 Skill 的
`references/attack_mode.json`，作为独立随包资源，保留编号、名称、描述和顺序。
按每条攻击路径分析全部实际适用模式，数量要求与轻量级方法一致：有足够适用模式时至少输出 10 个，
确实不足 10 个时输出全部实际适用模式，不为凑数关联缺乏依据的模式；无合理匹配时输出空数组。
此要求仅约束提示词，不增加数量硬校验或额外排序要求。资产与高风险模块的识别规则保持原样，Web 类模块仍参与识别，
精简库的范围仅限制攻击模式关联。四个 Skill 均使用 `deephole-compact-` 前缀，以便在 Agent 的
统一 Skill 目录中与原方法共存。`attack_modes` 参数仍保留原 DeepHole 的预留语义，不用于替换候选库。

精简方法的高风险模块识别（map）和合并（merge）任务均由模型将 JSON 数组写入指定文件，
通过方法目录中的 `validate_high_risk_modules.py --output <文件>` 检查原有高风险模块 Schema。
两个阶段都允许 `[]`；字段、类型、必填项及额外字段限制沿用原契约，不增加模块语义判断。
模型调用使用 `output_schema=None`，宿主只读取已通过文件校验的结果，不消费聊天或结构化回复中的 JSON。
模型可运行任务绑定的精确命令自检，宿主在回复结束后必须独立校验；首次失败回传原 Session 纠正一次，
仍失败则进入现有重试策略。续扫逐份校验 map 与 merge 缓存；任一 map 需要重跑时，merge 也重新执行，
避免旧合并结果遗漏重建后的候选。价值资产阶段保持原有处理，不批量迁移已完成扫描。

精简方法目录作为 Agent 的稳定只读资源写入 OpenCode 配置，并保留每任务的只读授权，
使校验脚本、Schema 与 Skill 资源可被读取；旧配置缺少这些规则时自动刷新。产物写权限复用
扫描产物目录及当前分析工作目录的既有规则，源码和方法资源不增加写权限。Shell 仍默认禁止，
仅当前任务的精确 Python 校验命令通过 `allowed_bash_commands` 与 `bound_python_script` 绑定。
需更新并重启 Agent 及其受管 Serve，无需前端变更或数据库迁移。

精简方法的逐资产攻击树任务由模型直接写入指定 raw JSON 文件，宿主保存本次动态 Schema，
并通过方法目录中的 `validate_attack_tree.py --output <文件> --schema <Schema文件>` 校验实际产物。
校验保留既有结构及 `module_id` 约束，严格要求每个 `pattern_id` 与 `pattern_name` 配对匹配私有
51 项模式库，同时拒绝同一路径内重复模式；空 `attack_patterns` 仍合法。首次生成及现有节点纠正
均修改同一文件，宿主不再从最终聊天回复或结构化回复补写、覆盖攻击树文件。

执行方式与 OpenCode 轻量级一致：模型可以运行 runtime 提供的精确命令辅助自检，是否执行
不作为完成条件；宿主在 Session 回复结束后使用当前 Python 解释器独立校验，最多等待 60 秒，
并支持取消。首次失败将文件、字段及编号/名称等具体错误回传原 Session，允许纠正一次，仍失败时
进入现有威胁分析重试策略；校验通过前不记录任务成功、不合并攻击树。节点规范化及非外部暴露叶子的
现有修正规则保持不变，不增加轻量级的其他建模约束。续扫复用 raw 攻击树前执行相同校验，不合法时
只重跑对应攻击树任务，保留其他合法缓存。合并及固定模式补充后再次核对模式合法性。
本次校验修复需更新并重启 Agent，无需前端变更或数据库迁移，不批量改写已完成历史扫描。

仅精简方法在高风险模块合并后、生成攻击树前，将模块路径与所选扫描文件/目录求交。
无交集或没有有效路径的模块被排除，部分相交仅保留交集，并记录范围诊断。
原始 `high-risk-module-merge.json` 保留，裁剪结果另存为 `high-risk-modules-scoped.json`，
攻击树及返回的 `high_risk_modules_path` 使用同一裁剪结果；原生路径仍相对扫描工作目录，
平台适配层再转换为项目相对路径。恢复原生流程时，扫描范围和裁剪后模块内容的变化只使
攻击树缓存失效，前序合法产物仍可复用。没有外部暴露高风险模块时不强制生成攻击树，
保留范围内内部模块及其固定审计记录。其他威胁分析方法保持原有处理。

精简方法在 AI 分析完成、攻击树合并后，由程序为每个范围内高风险模块补齐以下 15 项固定审计模式：

| 编号 | 模式 |
| --- | --- |
| ODH-NATIVE-01 | 越界写入破坏内存状态 |
| ODH-NATIVE-02 | 越界读取泄露或干扰处理 |
| ODH-NATIVE-03 | 失效对象继续使用 |
| ODH-NATIVE-04 | 重复或非法释放内存 |
| ODH-NATIVE-05 | 整数溢出截断与符号混淆 |
| ODH-NATIVE-06 | 外部格式串解释 |
| ODH-NATIVE-07 | 未初始化内存或结构填充泄露 |
| ODH-NATIVE-08 | 类型与对象布局混淆 |
| ODH-NATIVE-09 | 字符串终止与长度单位混淆 |
| ODH-NATIVE-10 | 竞态条件与检查使用时差 |
| ODH-NATIVE-11 | 空指针无效指针或失效句柄解引用 |
| ODH-SYS-08 | 日志错误与崩溃产物泄露敏感信息 |
| ODH-SYS-09 | 不受控资源消耗与复杂度攻击 |
| ODH-SYS-12 | 外部输入触发致命错误与进程终止 |
| ODH-SYS-13 | 死锁活锁与执行资源饥饿 |

程序先按原有路径关联规则计算全局“模块 + 模式 ID”，仅补缺失项；名称和描述来自精简方法私有目录。
同一模块只在首次出现的高风险节点所属树中添加一次 `module_pattern_baselines`，每条记录包含
`module_name`、`node_id`、`source: "compact_baseline"` 和 `attack_patterns`。未进入任何树的模块
存入产物顶层的 `unassigned_module_pattern_baselines`，`node_id` 为 `null`，在攻击树页单独显示
“未关联攻击路径的高风险模块”。AI 原始节点、边和路径保持原有含义，原始任务 Schema 不接受程序补充字段；
最终产物另行校验，并支持没有资产树但有模块补充项的结果。

攻击模式引擎和覆盖图读取同一份补充记录，按模块与模式合并去重。固定模式表示必须检查的范围，
并不表示该模块已存在漏洞；模式不适用或无法确认真实漏洞时，审计正常返回 `[]`。
这会增加缺失组合的审计任务数，最多为每模块 15 个；AI 已选的其他模式仍参与审计。
任务 ID 和成功结果复用规则保持不变，重复处理不会累积补充项。已有扫描不迁移、不安排补审；
旧产物缺少新字段时继续按原逻辑读取。其他方法与新建扫描默认方法保持不变。
上线需更新后端、前端和 Agent 运行包并重启 Agent，无需数据库迁移。

仓库还提供三个轻量级方法：

- `codex_goal_threat_analysis`，界面名称“轻量级威胁分析（Codex）”，通过
  `codex_sdk` 启动可恢复 Goal。
- `opencode_lightweight_threat_analysis`，界面名称“轻量级威胁分析（OpenCode）”，通过一次
  逻辑上的 `run_opencode_task(task_type="threat_analysis")` 执行；这是新建扫描的默认选择。
- `opencode_coverage_guided_lightweight_threat_analysis`，界面名称
  “覆盖率引导的轻量级威胁分析（OpenCode）”，初轮沿用 OpenCode 轻量级流程，随后根据文件清单
  最多定向补查两次，每次最多五个未覆盖路径。独立增量通过脚本试合并校验后由代码合入累计结果；
  每次补查作为独立计划任务显示在扫描队列中。原默认方法不变。

三个方法调用 `lightweight_contract.py` 中同一个 Prompt 构造函数，因此相同源码、上下文、参考资料
和输出路径共享字节级一致的分析主体；只有完成条件按校验责任方区分。提示词不超过 4000 字符，
只携带路径和关键约束；覆盖率引导方法的补查使用单独的增量 Prompt。完整
接口契约与三份字段 Schema 都来自 Codex 方法目录下的只读 `references/*.json`，校验器也继续位于
该目录，以保持 Prompt 中的既有路径不变。完整 Agent 会把这个精确方法目录作为稳定只读根写入
OpenCode 的受管 Serve 配置，并声明当前 Session 的只读资源意图。当前文件读取全局允许访问运行账户可读路径，
这些资源声明不构成读取沙箱；方法资源不获得写权限。
缺少该规则的旧受管配置会在下次准备 workspace 时自动重写。OpenCode 方法复用 Agent 当前
`threat_analysis.model_policy` 的超时和全新 Session 重试；Task Agent 只开放 Prompt 内精确的
校验命令，但不要求 OpenCode 执行它，也不会产生“未执行校验命令”的完成失败。每次 Session 消息
完整结束后，宿主使用实际 `sys.executable` argv 校验三类产物；首次失败会把校验诊断追加到原
Session，要求修正产物并执行当前已绑定的校验命令，通过后再结束回复；第二次仍失败才进入阶段策略已有的 fresh Session
重试。命令执行本身不加入必需命令审计，最终仍以宿主复验为准。OpenCode 在非 Windows 上使用宿主 Python
绝对路径；Windows 使用 `python`，参数使用双引号，Session 的 `PATH` 临时前置当前 Python 目录。宿主校验不经 shell。Codex Goal 仍要求在 Goal 内执行同一条
提示命令并通过。标准重试耗尽后，外层扫描编排归档失败产物并仅 clean 执行一次
`deephole_threat_analysis`；取消不重试也不回退，历史扫描不迁移方法选择。

## 目录约定

```text
threat_analysis/
├── runtime.py
├── README.md
└── methods/
    ├── deephole_threat_analysis/
    │   ├── method.yaml
    │   ├── __init__.py
    │   ├── threat_analysis.py
    │   ├── pipeline.py
    │   ├── stages/
    │   └── skills/                 # 可选
    └── my_method/
        ├── method.yaml
        ├── __init__.py
        └── threat_analysis.py
```

目录名就是 `method_id`，首字符必须是字母或数字，后续只能包含字母、数字、点、下划线和
连字符，总长度不超过 128 个字符。隐藏目录、下划线开头目录和符号链接不会被发现；不完整或
清单非法的方法会进入目录接口的 `errors`，不会影响其它有效方法。

`method.yaml` 只接受两个必填字段：

```yaml
label: 我的威胁分析
description: 生成价值资产、高风险模块和攻击树。
```

方法 ID 已由目录名唯一确定，因此不需要 `package_name`。清单不需要 `default`：新建扫描由后端与
前端优先选择 `opencode_lightweight_threat_analysis`，而运行时在调用方没有显式传入方法时仍以
`deephole_threat_analysis` 作为安全兜底。未知字段会使当前方法无效。

## 唯一原生入口

每个方法必须在 `threat_analysis.py` 中定义下面的同步函数，并在 `__init__.py` 中原样导出：

```python
from .threat_analysis import run_threat_analysis

__all__ = ["run_threat_analysis"]
```

新方法应使用以下签名；历史五参数入口仍只兼容单目录，详见末尾的范围兼容说明：

```python
def run_threat_analysis(
    code_path,
    output_path,
    is_resume=False,
    product_mcp=None,
    attack_modes=None,
    code_paths=None,
) -> dict:
    ...
```

| 参数 | 必填/默认值 | 含义 |
| --- | --- | --- |
| `code_path` | 必填 | 本次扫描的只读代码目录，传入值为已解析的 `Path` |
| `output_path` | 必填 | 当前方法的可写产物目录，平台会提前创建 |
| `is_resume` | `False` | 是否允许方法复用自己在 `output_path` 中保存的阶段产物 |
| `product_mcp` | `None` | 本次扫描启用的知识库 MCP 名称；方法不使用时可以忽略 |
| `attack_modes` | `None` | 预留的攻击模式映射；方法不使用时可以忽略 |
| `code_paths` | `None` | 可选的绝对文件/目录列表；目录包含子树，文件仅包含自身。工作目录 `code_path` 为这些目标的最小公共父目录，所有产物相对路径以该目录为基准 |

`project_path`、`scan_mode`、`task_agent_config`、`output`、`cancel_event`、方法 ID 等属于外层平台参数，
不会传给原生入口。
需要模型的方法可以像内置实现一样调用 `task_agent.run_opencode_task()`；平台把当前所选方法的 Skill 根声明到任务上下文。独立模式据此注册路径；完整 Agent 已统一安装
全部业务 Skill，任务上下文仅检查所需名称，不按方法切换全局 Skill 目录。

## 返回值和三类 JSON 产物

成功必须返回：

```python
return {
    "result": True,
    "value_asset_path": str(output_path / "final/value-assets.json"),
    "attack_tree_path": str(output_path / "final/attack_trees.json"),
    "high_risk_modules_path": str(output_path / "final/high-risk-modules.json"),
}
```

三类产物都必须位于 `output_path` 内并可读取。价值资产与模块是 UTF-8 JSON 文件，攻击树也支持目录：

| 返回字段 | JSON 顶层结构 | 用途 |
| --- | --- | --- |
| `value_asset_path` | 数组 | 价值资产列表 |
| `attack_tree_path` | 单文件：对象中 `attack_trees` 为数组；目录：`index.json` 加逐树 JSON | 攻击树列表及其节点、边和攻击路径 |
| `high_risk_modules_path` | 数组 | 高风险模块列表 |

扩展方法应尽可能沿用内置方法的字段结构，因为当前详情页和 `threat_audit` 引擎直接消费这三类
产物。平台会拒绝缺少路径、路径越出方法输出目录、文件不存在、JSON 非法或顶层结构不一致的
成功结果。OpenCode 轻量与覆盖率引导方法使用目录形式；上传包保留合并后的 `content` 及清单/树文件的 `files` 快照，续扫还原同一布局，不要求额外生成合并文件。

失败必须返回可直接展示给用户的非空原因：

```python
return {
    "result": False,
    "reason": "无法连接威胁建模服务",
}
```

也可以抛出异常。平台会把 `reason` 或异常消息写入独立的威胁分析运行状态，通过 SSE 和刷新
持久展示在扫描详情；取消状态单独记录，不作为普通错误。不要在 `reason` 中返回完整堆栈、
模型正文、密钥或其它敏感内部信息。

## 续扫与失败恢复

首次扫描调用原生入口时传入 `is_resume=False`。扫描成功后，平台把三类产物的 JSON 内容、相对路径和
扫描范围作为不透明结果包保存到服务端。用户续扫时，如果威胁分析已经成功，Agent 会先按同一
`scan_id` 取回结果包，校验扫描范围、必需产物、JSON 顶层结构和相对路径安全性，再原子恢复到
当前扫描目录并直接提供给依赖引擎；这一过程不会注册模型任务、上报 `running` 或重置成功状态。
历史结果包没有可选范围字段时，仍按不可变的扫描 ID 兼容复用。

只有服务端结果缺失、损坏或范围不匹配时，平台才调用原生入口。轻量级方法在续扫时会收到
`is_resume=True`，但该参数只允许它们识别已经完整且带成功标记的本地产物；如果上次任务失败、
取消、超时或产物不完整，方法会先清除残留，再创建全新 Session/线程从头执行，不会续写失败
Session。其它方法直接以 `is_resume=False` 新建任务，业务层也不再先做一次失败 Session 的增量恢复。
轻量级方法失败时仍保留一次 clean DeepHole 方法回退：失败产物会归档到同级
`threat_analysis_failed/<UTC-attempt-id>/`，OpenCode 在 Windows 上遇到文件锁时降级复制诊断并
尽力清空原目录。取消不回退，DeepHole 回退失败时会同时保留主错误、归档警告和回退错误。

多版本引擎内部的基准威胁分析不上传为扫描级结果，而是在本地保存同等的结构化产物检查点。
它会以 `is_resume=True` 识别升级前已经完整且校验通过的本地产物；如果没有成功产物，OpenCode
轻量级方法会清除残留文件并创建新 Session，不会使用状态文件中的失败 Session ID。

该恢复策略属于平台协调逻辑，不要求方法感知扫描整体状态，也不修改
`methods/deephole_threat_analysis/` 内的原生实现。威胁分析失败只会阻塞消费其结果的
`threat_audit` 和 `threat_pattern_audit`；其它漏洞挖掘引擎按各自生命周期独立运行和续扫。

## 从现有 ThreatAnalysis 工程迁移内置方法

若外部 `ThreatAnalysis/src/threat_analysis_harness` 实现符合当前入口与产物契约，可将其作为迁移来源，
保留平台的 `method.yaml`。该工程不随本仓库分发；复制前核对版本、`code_paths` 支持和随包资源，
复制后执行方法契约与扫描范围测试，不能假定任意上游版本可直接覆盖：

```bash
cp -a ThreatAnalysis/src/threat_analysis_harness/. \
  deephole_client/threat_analysis/methods/deephole_threat_analysis/
```

原生实现中的 `from threat_analysis_harness...` 绝对导入无需修改。运行时会在选中方法执行期间
把该目录按原包名 `threat_analysis_harness` 加载，并串行保护同一进程内不同方法的包别名。

若要以它为基础新增方法，把目录复制成新的 `<method_id>`，再添加只含 `label` 和
`description` 的 `method.yaml` 即可；无需修改中央注册表或前端代码。

## 平台异步入口

平台和独立调用者使用外层入口：

```python
from deephole_client.threat_analysis_runner import run_threat_analysis

result = await run_threat_analysis(
    method_id="deephole_threat_analysis",
    project_path="/src/project",
    code_path="/src/project/services/api",
    output_path="/tmp/threat-analysis",
    is_resume=True,
    product_mcp=None,
    attack_modes=None,
    task_agent_config="./task-agent.yaml",
    output=print,
    cancel_event=None,
)
```

外层入口是 `async def run_threat_analysis(**kwargs)`，负责选择方法、校验参数和返回契约、绑定
Task Agent 上下文、转发事件与取消信号；它不会把平台参数混入原生方法签名。`project_path`
表示项目总路径，省略时默认等于 `code_path`；`code_path` 始终表示本次扫描路径，并且只有威胁
分析方法内部创建的 OpenCode Session 会把它作为项目目录。扫描器外层上下文和其它业务过程
仍使用项目总路径。

当 `code_path` 是项目子目录时，原生方法继续在自己的产物中保存扫描路径相对的高风险模块，
外层另行生成 `output_path/platform/high-risk-modules.json`，把每个 `代码目录` 转换为项目根
相对路径后提供给平台和威胁审计。适配时以真实文件为依据纠正重复的完整扫描目录前缀，
保留合法的同名嵌套目录；重复适配已生成的平台文件时按项目相对路径解释。原生产物不会被
改写，续扫时不会重复添加扫描目录前缀。扫描整个项目时也会纠正可确认的重复前缀；无需
纠正时直接复用原文件。

页面的高风险模块表格与覆盖图共用独立覆盖接口的扫描相对路径投影（扫描根目录为 `.`），
不改变这些内部产物及审计路径的基准。历史产物只读兼容，重复前缀必须能够通过完整文件
清单唯一确认才会纠正；不能定位的路径保留诊断，不计入覆盖。

所有内置方法支持 `code_paths`。历史五参数方法仍可用于单目录；选择单文件或多个路径时，框架拒绝不支持列表的方法，避免静默扩大扫描范围。轻量级方法在 `scan-context.json.source.paths` 记录列表，多阶段方法通过 `input_files` 传入列表。
