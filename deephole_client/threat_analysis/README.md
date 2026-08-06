# 威胁分析方法扩展

威胁分析按目录自动发现。每个方法占用
`deephole_client/threat_analysis/methods/<method_id>/` 一个目录；新建扫描时用户只能选择其中
一个方法，扫描创建后会固化方法 ID、名称和说明快照。内置方法 ID 是
`deephole_threat_analysis`，界面名称是“DeepHole威胁分析”。

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

方法 ID 已由目录名唯一确定，因此不需要 `package_name`。默认方法由平台常量
`deephole_threat_analysis` 确定，因此清单也不需要 `default`。未知字段会使当前方法无效。

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

`task_agent_config`、`output`、`cancel_event`、方法 ID 等属于外层平台参数，不会传给原生入口。
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

如果这次增量恢复明确返回 `result=False` 且任务没有被取消，外层扫描协调器会把当前
`threat_analysis` 目录原子移动到同级 `threat_analysis_failed/<UTC-attempt-id>/`，创建新的空
输出目录，然后只再调用一次原生入口并传入 `is_resume=False`。第二次仍失败时本次续扫立即
停止威胁分析且不循环重试；扫描整体状态仍按其它独立引擎的结果收敛。取消或外层适配器异常
也不会触发干净回退。归档只保留在 Agent 本地，便于排查且不会上传原生任务或模型明细。

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
    code_path="/src/project",
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
Task Agent 上下文、转发事件与取消信号；它不会把平台参数混入原生方法签名。
