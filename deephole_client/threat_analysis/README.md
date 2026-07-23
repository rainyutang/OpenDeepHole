# 威胁分析过程

公开入口是异步函数 `run_threat_analysis(**kwargs)`，不连接后端。

| key | 必填 | 类型 | 说明 |
|---|---:|---|---|
| `project_path` | 是 | path | 项目根目录 |
| `work_dir` | 是 | path | 过程工作目录，不存在时创建 |
| `code_scan_path` | 否 | path | 扫描子目录，默认项目根目录 |
| `scan_id` | 否 | str | 任务标识 |
| `product` | 否 | str | 产品上下文 |
| `reuse_cache` | 否 | bool | 复用结果文件，默认 `true` |
| `result_path` | 否 | path | 结果文件，默认 `<project_path>/res.json` |
| `required_capability` | 否 | `low\|high` | 模型能力，默认 `high` |
| `timeout_seconds` | 否 | int | 单阶段超时秒数，默认 `1200` |
| `max_retries` | 否 | int | 阶段失败重试次数，默认 `3` |
| `task_agent_config` | 否 | path | 独立运行使用的 Task Agent YAML |
| `opencode_config_path` | 否 | path | 独立工作区使用的 OpenCode 配置文件 |
| `configured_mcp_names` | 否 | `list[str]` | 当前可用 MCP 名称，用于产品信息能力判定 |
| `product_mcp_name` | 否 | str | 产品信息 MCP 名称，默认 `product-info` |
| `product_mcp_detection_timeout_seconds` | 否 | int | 产品 MCP 判定超时，默认 `60` |
| `mock` | 否 | bool | 不调用模型的本地冒烟模式，默认 `false` |
| `output` | 否 | callable | 同步或异步结构化事件回调 |
| `cancel_event` | 否 | event | 提供 `is_set()` 的取消信号 |

```bash
python -m deephole_client.threat_analysis \
  --project-path /src/project --work-dir /tmp/ta \
  --task-agent-config ./task-agent.yaml
```

事件写 stderr，最终 JSON 写 stdout；`--output-file` 可另存结果。
