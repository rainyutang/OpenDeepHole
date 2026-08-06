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
| `review_id` | 是 | str | 本轮去误报标识 |
| `vuln_index` | 是 | int | 漏洞在扫描结果中的索引 |
| `vulnerability` | 是 | dict | 单个漏洞对象 |
| `feedback_entries` | 否 | `list[dict]` | 人工反馈 |
| `history` | 否 | `list[dict]` | 历史问题模式 |
| `required_capability` | 否 | `low\|high` | 默认 `high` |
| `invalid_json_retry_count` | 否 | int | 结构化输出重试次数，默认 `2` |
| `task_agent_config` | 否 | path | 独立 Task Agent 配置 |
| `output` | 否 | callable | 同步或异步事件回调 |
| `cancel_event` | 否 | event | 提供 `is_set()` 的取消信号 |

成功返回必须包含 `status=success`、二元 `verdict`（`true_positive` 或
`false_positive`）及非空 `reason`。阶段输出只能使用 `method.yaml` 声明的 key。

## 清单

`method.yaml` 严格接受 `label`、`description`、`default`、`max_concurrency`、`stages`
和 `documents`。仓库内必须恰好有一个可用方法设置 `default: true`。`documents` 用于扫描详情页
展示方法说明；方法目录中的 `skills/` 会自动加入该任务的 Skill 搜索路径。

```bash
python -m deephole_client.fp_review --method adversarial \
  --project-path /src/project --code-scan-path /src/project/src \
  --work-dir /tmp/fp/vuln-7 --scan-id scan-1 --review-id review-1 \
  --vuln-index 7 --vulnerability vulnerability.json
```
