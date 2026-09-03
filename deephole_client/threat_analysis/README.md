# 威胁分析方法扩展

威胁分析按目录自动发现。每个方法占用
`deephole_client/threat_analysis/methods/<method_id>/` 一个目录；新建扫描时用户只能选择其中
一个方法，扫描创建后会固化方法 ID、名称和说明快照。内置方法 ID 是
`deephole_threat_analysis`，界面名称是“DeepHole威胁分析”。

仓库还提供两个运行时可区分的轻量级方法：

- `codex_goal_threat_analysis`，界面名称“轻量级威胁分析（Codex）”，通过
  `codex_sdk` 启动可恢复 Goal。
- `opencode_lightweight_threat_analysis`，界面名称“轻量级威胁分析（OpenCode）”，通过一次
  逻辑上的 `run_opencode_task(task_type="threat_analysis")` 执行；这是新建扫描的默认选择。

两个方法调用 `lightweight_contract.py` 中同一个 Prompt 构造函数，因此相同源码、上下文、参考资料
和输出路径共享字节级一致的分析主体；只有完成条件按校验责任方区分。提示词不超过 4000 字符，
只携带路径和关键约束；完整
接口契约与三份字段 Schema 都来自 Codex 方法目录下的只读 `references/*.json`，校验器也继续位于
该目录，以保持 Prompt 中的既有路径不变。完整 Agent 会把这个精确方法目录作为稳定只读根写入
OpenCode 的受管 Serve 配置，同时保留当前 Session 的窄化只读授权；因此主 Agent 可以读取
`analysis-guidance.json`、攻击模式和三份 Schema，但不能编辑该目录，也不会连带开放整个 Agent。
缺少该规则的旧受管配置会在下次准备 workspace 时自动重写。OpenCode 方法复用 Agent 当前
`threat_analysis.model_policy` 的超时和全新 Session 重试；Task Agent 只开放 Prompt 内精确的
校验命令，但不要求 OpenCode 执行它，也不会产生“未执行校验命令”的完成失败。每次 Session 消息
完整结束后，宿主使用实际 `sys.executable` argv 校验三份产物；首次失败会把校验诊断追加到原
Session，要求修正产物但不要求模型自行运行命令，第二次仍失败才进入阶段策略已有的 fresh Session
重试。Prompt 中的命令在所有平台都直接以 `python` 开头；Windows 参数继续使用双引号，Session 的
`PATH` 临时前置当前 Python 目录，而宿主校验不经 shell。Codex Goal 仍要求在 Goal 内执行同一条
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

函数签名必须完全一致：

```python
def run_threat_analysis(
    code_path,
    output_path,
    is_resume=False,
    product_mcp=None,
    attack_modes=None,
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

`project_path`、`scan_mode`、`task_agent_config`、`output`、`cancel_event`、方法 ID 等属于外层平台参数，
不会传给原生入口。
需要模型的方法可以像内置实现一样调用 `task_agent.run_opencode_task()`；平台会把当前所选方法
`skills/` 下所有包含 `SKILL.md` 的 Skill 根仅注册到本方法的任务上下文，不再全局注入其它
威胁分析方法的 Skill。

## 返回值和三份 JSON 产物

成功必须返回：

```python
return {
    "result": True,
    "value_asset_path": str(output_path / "final/value-assets.json"),
    "attack_tree_path": str(output_path / "final/attack_trees.json"),
    "high_risk_modules_path": str(output_path / "final/high-risk-modules.json"),
}
```

三个路径都必须指向 `output_path` 内已存在、可读取的 UTF-8 JSON 文件：

| 返回字段 | JSON 顶层结构 | 用途 |
| --- | --- | --- |
| `value_asset_path` | 数组 | 价值资产列表 |
| `attack_tree_path` | 对象，且 `attack_trees` 为数组 | 攻击树列表及其节点、边和攻击路径 |
| `high_risk_modules_path` | 数组 | 高风险模块列表 |

扩展方法应尽可能沿用内置方法的字段结构，因为当前详情页和 `threat_audit` 引擎直接消费这三份
产物。平台会拒绝缺少路径、路径越出方法输出目录、文件不存在、JSON 非法或顶层结构不一致的
成功结果。

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

首次扫描调用原生入口时传入 `is_resume=False`；用户续扫失败扫描时，平台只在威胁分析生命周期
不是 `success`，或依赖它的威胁审计仍有未完成任务时重新启动该过程，并先传入
`is_resume=True`。方法可以自行验证和复用 `output_path` 中已经完成的阶段产物。

如果普通方法的这次增量恢复明确返回 `result=False` 且任务没有被取消，外层扫描协调器会把当前
`threat_analysis` 目录原子移动到同级 `threat_analysis_failed/<UTC-attempt-id>/`，创建新的空
输出目录，然后只再调用一次原生入口并传入 `is_resume=False`。第二次仍失败时本次续扫立即
停止威胁分析且不循环重试；扫描整体状态仍按其它独立引擎的结果收敛。取消或外层适配器异常
也不会触发干净回退。归档只保留在 Agent 本地，便于排查且不会上传原生任务或模型明细。

两个轻量级方法使用更严格的恢复边界：Codex 失败，或 OpenCode 在当前威胁分析阶段策略配置的
fresh Session 重试全部耗尽后，直接归档并 clean 执行一次 DeepHole 方法，不再先 clean 重跑同一个
轻量级方法。OpenCode 轻量级失败归档在 Windows 上会先短暂重试原子移动；若目录仍被文件句柄、
ACL 或安全软件锁定，则复制一份诊断归档并尽力清空原目录，归档警告不会阻止这一次 DeepHole 回退。
DeepHole 回退失败时会同时保留轻量级主错误、归档警告和回退错误。

该恢复策略属于平台协调逻辑，不要求方法感知扫描整体状态，也不修改
`methods/deephole_threat_analysis/` 内的原生实现。威胁分析失败只会阻塞消费其结果的
`threat_audit`；其它漏洞挖掘引擎按各自生命周期独立运行和续扫。

## 从现有 ThreatAnalysis 工程覆盖内置方法

`ThreatAnalysis/src/threat_analysis_harness` 已经包含符合上述约定的 `__init__.py`、
`threat_analysis.py`、阶段代码和 Skill。迁移后可直接把其内容复制到内置方法目录，保留平台
自有的 `method.yaml`：

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
相对路径后提供给平台和威胁审计。原生产物不会被改写，续扫时不会重复添加扫描目录前缀。
