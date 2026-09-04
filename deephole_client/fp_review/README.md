# 去误报方法

去误报与漏洞挖掘引擎采用相同的目录归属方式：每种方法位于
`methods/<method_id>/`，必须同时提供 `method.py` 与 `method.yaml`。运行时自动发现目录，
后端目录接口、Agent 调度并发度、Skill 路径及前端阶段展示均由清单驱动。

## 方法契约

`method.py` 只公开一个入口：

```python
async def run(**kwargs) -> dict:
    ...
```

入口一次只处理一个漏洞。平台负责扫描级队列、并发、取消、重试、进度和持久化；方法不得执行
批次汇总或修改其它漏洞的结论。统一门面为 `deephole_client.fp_review.run_fp_review(**kwargs)`。

启用自动去误报后，每个新确认的问题都会独立进入队列。单项返回 `error`、抛出异常或在没有
人工停止信号时意外取消，只会让该项保持为未形成有效结论，不得终止或清空后续项目；扫描完成
或用户手动补跑时，平台会再次排队这些未完成项。只有用户明确调用停止接口时，扫描级任务才
进入持续的 `cancelled` 状态。

| key | 必填 | 类型 | 说明 |
|---|---:|---|---|
| `method_id` | 是 | str | `methods/` 下的方法目录名 |
| `project_path` | 是 | path | 项目根目录 |
| `code_scan_path` | 是 | path | 本次漏洞扫描的代码目录，与漏洞验证粒度一致 |
| `work_dir` | 是 | path | 当前漏洞独立工作目录 |
| `scan_id` | 是 | str | 扫描标识 |
| `scan_mode` | 否 | str | 扫描模式：`quick`、`standard` 或 `custom` |
| `review_id` | 是 | str | 本轮去误报标识 |
| `vuln_index` | 是 | int | 漏洞在扫描结果中的索引 |
| `vulnerability` | 是 | dict | 单个漏洞对象 |
| `feedback_entries` | 否 | `list[dict]` | 兼容输入；内置方法不传入模型 Prompt |
| `history` | 否 | `list[dict]` | 兼容输入；内置方法不传入模型 Prompt |
| `required_capability` | 否 | `low\|high` | 默认 `high` |
| `invalid_json_retry_count` | 否 | int | 结构化输出重试次数，默认 `2` |
| `task_agent_config` | 否 | path | 独立 Task Agent 配置 |
| `output` | 否 | callable | 同步或异步事件回调 |
| `cancel_event` | 否 | event | 提供 `is_set()` 的取消信号 |

成功返回必须包含 `status=success`、二元 `verdict`（`true_positive` 或
`false_positive`）及非空 `reason`。阶段输出只能使用 `method.yaml` 声明的 key。

## 模型 Prompt 合同

平台方法入口仍接收完整 `vulnerability` 对象用于索引、调度和结果回传，但内置方法不得直接把
该对象序列化给模型。首轮业务 Prompt 固定使用 `/{skill_name}`、简短阶段任务、完整
`vulnerability_report` 和当前阶段 JSON Schema；旧记录报告为空时使用统一引擎报告构造器生成
Markdown fallback。
后续阶段只允许追加确有依赖的 `stage_markdown`（为空时回退 `reason`），不得内联人工反馈、
历史模式、`prior_stages` JSON 或 Skill 正文。同一 Schema 也必须通过公共 Task Agent 参数传入：
Prompt 负责首轮模型输出约束，`output_schema` 负责程序侧解析、校验与失败纠正。
每个阶段的业务 Prompt 都必须在 JSON Schema 之后以“请使用中文输出”结尾。

内置 `adversarial` 依次使用 `/prove-bug`、`/prove-fp` 和 `/final-judge`；正方判定误报时仍
直接早退，否则最终裁决只接收原始、正方和反方三份 Markdown 报告。内置 `fp_check` 的所有阶段
使用 `/fp-check`，每个后续阶段按执行顺序接收已经完成的阶段报告。

## 清单

`method.yaml` 严格接受 `label`、`description`、`default`、`max_concurrency`、`stages`
和 `documents`。仓库内必须恰好有一个可用方法设置 `default: true`。`documents` 用于扫描详情页
展示方法说明；方法目录中的 `skills/<skill-name>/SKILL.md` 会自动加入该任务的 Skill 搜索路径，
业务 Prompt 应通过 `/<skill-name>` 调用，不应读取后再拼接 Skill 正文。

```bash
python -m deephole_client.fp_review --method adversarial \
  --project-path /src/project --code-scan-path /src/project/src \
  --work-dir /tmp/fp/vuln-7 --scan-id scan-1 --review-id review-1 \
  --vuln-index 7 --vulnerability vulnerability.json
```
