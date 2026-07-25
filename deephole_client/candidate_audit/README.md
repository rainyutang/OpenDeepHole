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

`on_candidate_result` 会在每个候选完成后立即收到一个字典，其中包含
`audit_index`、`checker_name`、原始 `candidate`、本候选的
`vulnerabilities`、`skill_reports` 和 `processed_key`。正常结果、空结果、
失败/超时、同模式过滤和只生成报告的候选都会各调用一次。过程仍会等待整批结束，
并返回完整的 `vulnerabilities`、`skill_reports` 和 `processed_keys`，便于独立调用方
继续按批处理结果。

```bash
python -m deephole_client.candidate_audit --project-path /src/project \
  --work-dir /tmp/audit --candidates candidates.json \
  --checker-dir ./rules --index-db-path code_index.db \
  --task-agent-config ./task-agent.yaml
```
