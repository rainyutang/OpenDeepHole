# 代码图谱构建过程

公开入口是异步函数 `run_code_graph_build(**kwargs)`。该目录负责构建本地
`code_index.db`，不负责运行静态规则，也不连接后端。

| key | 必填 | 类型 | 默认值 | 说明 |
|---|---:|---|---|---|
| `project_path` | 是 | path | - | 项目根目录 |
| `scan_mode` | 否 | str | `custom` | 扫描模式：`quick`、`standard` 或 `custom` |
| `work_dir` | 是 | path | - | 过程工作目录；SQLite 发布临时库固定与最终索引同目录 |
| `code_scan_path` | 否 | path | `project_path` | 实际建立索引的源码范围，必须位于项目内 |
| `index_db_path` | 否 | path | `<code_scan_path>/code_index.db` | 最终索引文件 |
| `reuse_cache` | 否 | bool | `true` | 复用版本匹配且完整的索引 |
| `ctags_executable` | 否 | str | `ctags` | Universal Ctags 可执行文件 |
| `output` | 否 | callable | `None` | 同步或异步结构化事件回调 |
| `cancel_event` | 否 | event | `None` | 提供 `is_set()` 的取消信号 |

返回值包含 `status`、`index_db_path`、`cache_hit`、`stats` 和
`indexer_version`，以及 `skipped_files`（跳过的文件数量）和
`coverage_complete`（源码覆盖是否完整）。取消或失败不会用半成品覆盖已有索引。
Agent 扫描只在本轮选择静态分析消费者时调用本过程；扫描子目录时不会回退读取或删除
`<project_path>/code_index.db`。显式 `index_db_path` 仍供独立调用和测试覆盖输出位置，
但索引内容始终以 `code_scan_path` 为根。

Windows 源码遍历和读取使用扩展长度路径，支持盘符路径和 UNC；无需修改系统
长路径设置。达到 260 个 UTF-16 单元的源码路径会通过短文件名临时副本传给
Ctags，副本来自已读取内容，保留扩展名、内容和行号。Ctags 输出映射回原源码
相对路径后才写入索引，不会将临时名称或扩展路径前缀作为索引键。
优先使用源码目录内的临时目录；目录本身过长时转用系统短临时目录，无法获得
可用短目录则明确失败。此回退下 Ctags 的工作目录也随之改变，项目工作目录内
的 Ctags 配置可能不再被自动加载。`oh_modules` 保持纳入扫描。

缺失、断链或无权限读取的单个源码文件会跳过，并通过 `warning` 事件报告路径
和原因；目录遍历失败也会报告覆盖缺口。Ctags 退出码为零时的输入读取警告同样
处理，工具或临时副本故障仍会使构建失败。合法空文件或无符号文件不会被误判。
发现源码但全部无法读取时失败，原索引保持不变；真正没有源码的目录可完成空索引。

部分文件跳过后，索引仍可供本轮静态分析和 MCP 查询使用。元数据 `status=complete`
表示构建过程结束，`coverage_complete=false` 表示源码覆盖存在缺口；同时记录
`skipped_files` 数量。目录无法遍历时无法确定其中的文件数，因此数量不包含这些
未枚举文件。有覆盖缺口的索引下次自动重建，避免修复后的文件被缓存遗漏；兼容
已有不含覆盖元数据的完整索引，无需数据库迁移。更新并重启 Agent 后重新执行
失败扫描即可使用修复，历史扫描结果不会回写。

```bash
python -m deephole_client.code_graph_build \
  --project-path /src/project \
  --work-dir /tmp/code-graph
```

单独复制本目录并将其父目录加入 `PYTHONPATH` 后，也可以执行
`python -m code_graph_build`。
