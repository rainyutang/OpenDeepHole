# Checker 开发参考

[文档目录](README.md) · [框架扩展](framework_development.md#6-新增-static_candidate-checker) · [扫描使用指南](usage.md)

## 规则目录与发现

`static_candidate` 将静态召回、候选审计和规则放在同一个引擎目录：

```text
deephole_client/vulnerability_mining/engines/static_candidate/
├── static_analysis/          # 静态分析公共 API 与执行器
├── candidate_audit/          # 候选点 AI 审计
└── rules/<name>/
    ├── checker.yaml          # 规则元数据
    ├── analyzer.py           # 可选，导出 Analyzer(BaseAnalyzer)
    ├── *.yml                 # 可选，Semgrep 等规则资源
    └── skills/<skill-name>/
        ├── SKILL.md
        ├── SCENARIOS.md      # 可选辅助说明，不是独立 Skill
        └── references/
```

后端读取元数据并构建传输包，不运行静态分析器。传输包保留 `static/` 与 `audit/` 分区以兼容滚动升级，新 Agent 解包后还原统一目录。

当前规则以 [rules 目录](../deephole_client/vulnerability_mining/engines/static_candidate/rules/)及 Web「SKILL 市场」为准。目录存在不等于面向所有用户启用：例如 `oob` 和 `resleak` 当前为 `enabled: false`，`npd` 和 `skill_only_project_audit` 仅管理员可见；新扫描还应用各模式的排除列表。

新增规则无需手工注册，后续列表刷新或创建扫描会重新发现元数据。测试阶段可设 `visibility: admin`，准备公开后再改为 `public`。

## 编写规则

### 1. 创建清单与 Skill

```bash
mkdir -p deephole_client/vulnerability_mining/engines/static_candidate/rules/mycheck/skills/mycheck
```

`rules/mycheck/checker.yaml` 示例：

```yaml
name: mycheck
label: MYCHECK
description: "我的自定义漏洞检测"
enabled: true
visibility: admin
mode: opencode
skill_name: mycheck
```

在 `rules/mycheck/skills/mycheck/SKILL.md` 中写审计目标、证据要求与判定步骤，YAML frontmatter 必须声明 `name: mycheck`，与 Skill 目录名一致。一条规则有多个 Skill 时用 `skill_name` 指定入口。

`family` 是可选元数据，默认可回退到规则名，但当前静态执行器不会据它跨 Checker 合并候选，详见[去重规则](#候选去重与同模式过滤)。旧 `mode: api` 的 `prompt.txt` 仍有兼容读取路径，实际模型调用仍通过 OpenCode；新规则使用嵌套 Skill 目录。

### 2. 添加静态 Analyzer

以下为接口骨架，实际规则应在筛选到待审计模式后才创建候选：

```python
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ...static_analysis.base import BaseAnalyzer, Candidate, scoped_functions

if TYPE_CHECKING:
    from ...static_analysis.index_reader import CodeIndexReader


class Analyzer(BaseAnalyzer):
    vuln_type = "mycheck"

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeIndexReader | None" = None,
    ) -> list[Candidate]:
        if db is None:
            return []
        functions = scoped_functions(db, project_path)
        candidates = []
        for index, function in enumerate(functions):
            if self.on_file_progress:
                self.on_file_progress(index + 1, len(functions))
            body = function["body"] or ""
            if not body:
                continue
            # 在此实现静态筛选，并向 candidates 添加 Candidate。
        return candidates
```

命中后使用的候选结构：

```python
candidate = Candidate(
    file=function["file_path"],
    line=function["start_line"],
    function=function["name"],
    description=f"函数 {function['name']} 中的 target 是否存在目标问题，请审计确认。",
    vuln_type="mycheck",
    metadata={"subject": "target", "problem": "目标问题"},
)
```

接口约定：

- 类名为 `Analyzer`，继承 `BaseAnalyzer`，`vuln_type` 与清单 `name` 一致。
- `find_candidates(project_path, db=None)` 返回 `Iterable[Candidate]`，列表和 generator 均可；空结果合法。
- 使用 `scoped_functions(db, project_path)` 将函数查询限制在扫描范围，无法判断范围时回退全量查询。直接读取文件的规则自行遵守扫描范围。
- 描述应中性、简短，说明函数、变量或表达式及待确认问题，不把静态命中直接写成已确认漏洞。
- `metadata.subject` 为审计 Prompt 提供相关变量或表达式；不要把它当作当前同模式过滤键的一部分。
- `on_file_progress` 用于过程进度，可定期调用。generator 支持流式产出静态结果，但内置引擎仍先完成静态收集再开始 AI 审计。

只有 Skill、没有 Analyzer 的规则可以用于项目级审计，完整返回契约见[候选审计组件](../deephole_client/vulnerability_mining/engines/static_candidate/candidate_audit/README.md)。

## 本地测试

在仓库根目录安装 Agent 依赖并准备 Universal Ctags 后，可不启动后端和在线 Agent 直接测试：

```bash
# 静态自测，并断言至少一个候选
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --min-candidates 1

# stdout 只输出最终 JSON
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --json

# 将格式化 UTF-8 JSON 写入文件
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --json-output /tmp/mycheck-candidates.json

# 精确断言候选数量
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source --expect-candidates 3

# 调用真实模型审计一个候选，需要有效 Task Agent 配置
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source \
  --audit --audit-limit 1 --task-agent-config ./task-agent.yaml

# 使用仓库外的规则树
PYTHONPATH=. python3 tools/checker_test.py mycheck /path/to/source \
  --rules-dir /path/to/rules
```

默认在临时工作目录构建索引，退出时清理该临时目录；`--work-dir` 保留产物，`--index-db` 指定可复用索引。最终 JSON 写 stdout，过程事件默认写 stderr；`--json` 关闭事件输出，`--json-output` 保存中文不转义的 JSON。

显式指定规则名的本地自测可以执行 `enabled: false` 的规则，线上入口仍遵循启用与可见性。`--audit` 会实际消耗模型调用，请配置合适的 `--audit-limit`。

## 代码索引 API

实现位于 [index_reader.py](../deephole_client/vulnerability_mining/engines/static_candidate/static_analysis/index_reader.py)。多数查询返回 `list[sqlite3.Row]`，使用 `row["field"]` 访问字段；函数体与按位置查询是例外。

| 方法 | 结果与语义 |
| --- | --- |
| `get_all_functions()` | 全部函数，按文件和行号排序 |
| `get_functions_by_path_prefix(prefix)` | 索引相对路径范围内的函数 |
| `get_functions_by_name(name, file_path=None)` | 名称及可选文件匹配，包含 C++ 限定名/短名兼容 |
| `get_function_by_location(file_path, line)` | 包含该位置的单个函数行，未命中为 `None` |
| `get_function_body(name)` | 第一个匹配函数的 `str` 函数体，未命中为 `None` |
| `get_calls_from_function(function_id)` | 函数发出的调用 |
| `get_call_sites_by_name(callee_name)` | 被调用点，包含 `caller_name` |
| `get_structs_by_name(name)` | 结构体/类定义，短名兼容 C++ 限定名 |
| `get_global_variables_by_name(name)` | 全局变量定义 |
| `get_global_variable_reference_by_name(name)` | 变量引用位置、函数、上下文与访问类型 |

函数行常用字段为 `function_id`、`name`、`signature`、`return_type`、`start_line`、`end_line`、`body`、`file_path`。调用行包含 `callee_name`、`caller_function_id`、`line`、`column`、`file_path`。

[code_utils.py](../deephole_client/vulnerability_mining/engines/static_candidate/static_analysis/code_utils.py) 提供 tree-sitter 辅助函数：

| 函数 | 用途 |
| --- | --- |
| `find_nodes_by_type(root, node_type, k=0)` | 深度优先查找指定类型节点，递归深度受限 |
| `get_child_node_by_type(root, node_types)` | 第一个类型匹配的直接子节点 |
| `get_child_nodes_by_type(root, node_types)` | 所有类型匹配的直接子节点 |
| `get_child_field_text_by_type(root, field, node_types)` | 类型匹配字段的原始文本字节 |
| `get_child_field_text(root, field)` | 字段的原始文本字节 |

例如解析函数体中的调用：

```python
import tree_sitter_cpp
from tree_sitter import Language, Parser
from deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.code_utils import find_nodes_by_type

parser = Parser(Language(tree_sitter_cpp.language()))
tree = parser.parse(body.encode("utf-8"))
for call in find_nodes_by_type(tree.root_node, "call_expression"):
    callee = call.child_by_field_name("function")
    if callee is not None:
        print(callee.text.decode("utf-8"))
```

内存类规则仍可按需读取既有 `memory_api_pairs.json` 中的分配/释放信息，但当前管线不自动发现或生成该文件。

## 候选去重与同模式过滤

当前规则以[静态执行器](../deephole_client/vulnerability_mining/engines/static_candidate/static_analysis/runner.py)和[候选审计器](../deephole_client/vulnerability_mining/engines/static_candidate/candidate_audit/runner.py)为准：

1. **规则内部去重**由各 Analyzer 自己实现，例如按函数或资源表达式聚合命中。
2. **公共静态去重**在 `static_dedup` 开启时按 `(file, line, function, vuln_type)` 保留首项。当前不按 `family` 跨规则合并，不生成旧 README 描述的 `metadata.merged_from`。
3. **审计排序**由内置引擎优先安排 `memleak`，其它规则按候选数量从少到多排列，同规则保持原有产出顺序。没有旧说明中的“按模式 key 轮转”。
4. **缓存与身份**：静态结果写入扫描目录 `candidates.json`，提交候选时分配稳定 `idx`。定向续扫使用原候选索引，不用待重试子集替换完整列表。

启用 `pattern_filter` 时，[内置引擎适配器](../deephole_client/vulnerability_mining/engines/static_candidate/engine.py)先转换配置，再调用审计器：

| `pattern_filter.scope` 配置 | 传入审计器的 scope | 当前匹配 key |
| --- | --- | --- |
| `file` | `file` | `(vuln_type, file)` |
| `repo` | `global` | `(vuln_type,)` |
| 其它值，包括模板默认 `directory` | `function` | `(vuln_type, function)` |

独立调用候选审计组件时，`pattern_filter_scope` 可直接传入 `file` 或 `global`，其它值使用函数键。当前过滤不要求 `metadata.subject`；函数键也不包含文件名，模板默认 `directory` 不能理解成严格的同目录匹配。

只有实际审计返回 `confirmed=false` 且 `ai_verdict="not_confirmed"` 的结果才加入本轮已否决集合。之后尚未开始且命中该键的候选可跳过模型调用，写入 `filtered_same_pattern`，页面显示“候选点去重：同模式代表点已被 AI 审计为非问题，本候选未再次调用模型。”。超时、无结果、错误和确认问题都不传播否决；规则特有的过滤豁免以审计器为准。

每个候选只保存一份权威 `audit_state` / `audit_result`，漏洞列表保留被下游接受的投影。单条报告可描述多个相关表现，不意味着为同一候选创建多个权威结果。详见[审计结果](audit_results.md)。

## 规则失败隔离

每个 Checker 使用独立的 `spawn` 工作进程，原生崩溃或异常不会终止后续规则。成功规则的候选保留，错误记录在 `checker_errors`；至少一个规则成功时可返回 `partial`，全部失败时返回 `error`。新规则应验证正例、反例和异常路径，不能把部分规则失败后的扫描完成当作所有规则均成功。
