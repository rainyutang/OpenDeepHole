# 代码图谱构建过程

公开入口是异步函数 `run_code_graph_build(**kwargs)`。该目录负责构建本地
`code_index.db`，不负责运行静态规则，也不连接后端。

| key | 必填 | 类型 | 默认值 | 说明 |
|---|---:|---|---|---|
| `project_path` | 是 | path | - | 项目根目录 |
| `work_dir` | 是 | path | - | 原子建库使用的工作目录 |
| `code_scan_path` | 否 | path | `project_path` | 校验并记录的扫描范围 |
| `index_db_path` | 否 | path | `<project_path>/code_index.db` | 最终索引文件 |
| `reuse_cache` | 否 | bool | `true` | 复用版本匹配且完整的索引 |
| `ctags_executable` | 否 | str | `ctags` | Universal Ctags 可执行文件 |
| `output` | 否 | callable | `None` | 同步或异步结构化事件回调 |
| `cancel_event` | 否 | event | `None` | 提供 `is_set()` 的取消信号 |

返回值包含 `status`、`index_db_path`、`cache_hit`、`stats` 和
`indexer_version`。取消或失败不会用半成品覆盖已有索引。

```bash
python -m deephole_client.code_graph_build \
  --project-path /src/project \
  --work-dir /tmp/code-graph
```

单独复制本目录并将其父目录加入 `PYTHONPATH` 后，也可以执行
`python -m code_graph_build`。
