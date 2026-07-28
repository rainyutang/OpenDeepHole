# 候选点审计过程

公开入口是异步函数 `run_candidate_audit(**kwargs)`，输入和输出都是整批数据。

| key | 必填 | 类型 | 说明 |
|---|---:|---|---|
| `project_path` | 是 | path | 项目根目录 |
| `work_dir` | 是 | path | 过程工作目录 |
| `scan_id` | 是 | str | 扫描标识 |
| `candidates` | 是 | `list[dict]` | 静态候选点 |
| `checker_dirs` | 否 | `list[path]` | 审计规则根目录，默认本目录 `rules/` |
| `index_db_path` | 是 | path | 代码索引路径 |
| `checker_names` | 否 | `list[str]` | 只审计指定 checker |
| `concurrency` | 否 | int | 并发数，默认 1 |
| `required_capability` | 否 | `low\|high` | 默认 `high` |
| `pattern_filter_enabled` | 否 | bool | 启用同模式过滤 |
| `pattern_filter_scope` | 否 | str | `function`、`file` 或 `global` |
| `feedback_entries` | 否 | `list[dict]` | 历史人工反馈 |
| `audit_index_offset` | 否 | int | 审计序号偏移 |
| `task_agent_config` | 否 | path | 独立 Task Agent 配置 |
| `output` | 否 | callable | 同步或异步事件回调 |
| `on_candidate_result` | 否 | callable | 单个候选进入终态后的同步或异步结果回调 |
| `cancel_event` | 否 | event | 提供 `is_set()` 的取消信号 |

每个 checker 的 `SKILL.md` 必须在 YAML frontmatter 中声明 `name`。过程会把
`checker_dirs` 作为本次任务专属的 Skill 路径注册给 Task Agent，并以
`/<name>` 作为 Prompt 首行加载 Skill；`SKILL.md` 正文不会拼接进 Prompt。

普通候选点的单次模型任务直接返回一个漏洞对象；`function="__project__"` 的项目级
审计返回裸 JSON List，每个独立问题一个元素。项目级未发现问题时返回仅包含一个
`confirmed=false` 结论的 List。两种模式共用
`task_agent.audit_schema.VULNERABILITY_ITEM_SCHEMA`，字段包括：

- 始终必填：`confirmed`、`severity`、`file`、`function`、`line`、`description`
- 确认问题时必填：`vuln_type`、`impact`、`vulnerable_code`、`call_chain`、
  `attack_entry`、`root_cause`、`trigger_conditions`
- `severity` 仅允许 `critical`、`high`、`medium`、`low`；非问题固定为 `low`

模型不再生成 `ai_analysis`、`ai_verdict`、`vulnerability_report` 或
`markdown_reports`。`ai_verdict` 由过程根据 `confirmed` 派生，最终 Markdown 报告
由平台使用结构化字段生成。

`on_candidate_result` 会在每个候选完成后立即收到一个字典，其中包含
`audit_index`、`checker_name`、原始 `candidate`、本候选的
`vulnerabilities`、`skill_reports` 和 `processed_key`。正常结果、空结果、
失败/超时和同模式过滤都会各调用一次；`skill_reports` 作为兼容字段保留为空列表。
过程仍会等待整批结束，
并返回完整的 `vulnerabilities`、`skill_reports` 和 `processed_keys`，便于独立调用方
继续按批处理结果。

```bash
python -m deephole_client.candidate_audit --project-path /src/project \
  --work-dir /tmp/audit --candidates candidates.json \
  --checker-dir ./rules --index-db-path code_index.db \
  --task-agent-config ./task-agent.yaml
```
