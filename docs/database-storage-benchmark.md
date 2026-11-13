# 扫描存储查询基准

## 2026-11-13：任务队列类型筛选

在临时 SQLite 3.42.0、PostgreSQL 16.15 数据库中，用 Python 3.10.12 测量单扫描 5,000 条历史，每条含 16 KiB 重复字符模拟正文；预热一次，再取 5 次 `perf_counter` 耗时中位数。旧查询使用 `1d6f3ae` 的未筛选 SQL 并解析返回的 50 条摘要；新查询调用完整 `list_task_page`，包括历史版本检查。未连接生产数据库，未模拟并发写入、网络或浏览器渲染。

| 数据库 / 历史数据 | 原未筛选查询（ms） | 新未筛选列表（ms） | 新类型筛选（ms） |
| --- | ---: | ---: | ---: |
| SQLite / 有分类投影 | 29.74 | 30.80 | 23.98 |
| SQLite / 旧记录无类型字段 | 25.12 | 27.95 | 123.03 |
| SQLite / 旧类型及名称只在正文上下文 | 32.19 | 31.48 | 161.01 |
| PostgreSQL / 有分类投影 | 47.64 | 48.27 | 38.21 |
| PostgreSQL / 旧记录无类型字段 | 34.88 | 39.01 | 41.55 |
| PostgreSQL / 旧类型及名称只在正文上下文 | 35.36 | 38.15 | 114.36 |

筛选条件为 `threat_pattern_audit`：有投影场景匹配一半记录，上下文场景全部匹配，无类型场景没有匹配。筛选与默认查询返回的集合不同，不能据此计算提速比例。旧记录筛选仍可能解析本扫描的正文上下文，成本随记录数及正文大小增长；旧快照 `history_version=0` 继续沿用完整快照兼容读取，不在本表语料范围内。

实现不增加表、列、索引或历史回填，只在新写入的 `metadata_json` 中增加分类以及缺失的类型/名称投影。本已有类型和名称的样本增加约 20–45 UTF-8 字节/条；二者都缺失的样本增加 64 字节，上下文样本增加 106 字节，后者随字段长度变化。这是 JSON 内容增量，不代表数据库文件或 WAL 的实际增量。

查询在单扫描范围内筛选、排序后取一页，不额外执行 `COUNT`；普通列表在 LIMIT 后才为本页补旧字段，正文不进入列表响应。SQLite `EXPLAIN QUERY PLAN` 确认使用 `scan_task_current` 的扫描复合主键及版本记录主键，分页后再按版本主键补字段。SQL 内部仍需处理本扫描的候选行，不能将此描述为恒定成本；本次未单独采集 PostgreSQL 执行计划。新投影的正文短路、扫描索引和分页前筛选由存储回归测试覆盖。

## 2026-09-07：扫描存储改造

2026-09-07，在同一台开发机器的临时 PostgreSQL 16.15 上，使用两个独立数据库比较 `57c1f35` 与本次变更。数据全为脚本生成，未连接生产电脑。

- 10000 条扫描、100000 条任务，其中一个扫描包含 10000 条任务。
- 每条任务有 1024 字节模拟 Prompt 和一个 Session 记录；未加入漏洞/复核/验证正文，也未模拟并发 Agent 写入。
- 同一 PostgreSQL 进程，双方关闭可选 JIT，采用默认数据库存储设置；未使用应用层压缩。
- Python 调用真实 store/统计构建函数，包含查询与反序列化，不包含 HTTP、浏览器渲染、网络跨机器延迟。
- 预热一次，通常测量 11 次；旧统计面板因单次耗时较长测量 5 次。p95 用最近秩法，样本较少，只作为本地回归证据。

| 操作 | 优化前 p95（ms） | 优化后 p95（ms） | 优化后 Python CPU 中位数（ms） |
| --- | ---: | ---: | ---: |
| 扫描首屏 50 条 | 5.56 | 4.02 | 0.99 |
| 含 10000 条任务的扫描概览 | 115.5 | 1.54 | 0.47 |
| 任务队列首屏 | 111.9 | 1.18 | 0.42 |
| 检查器统计面板 | 43122.68 | 82.36 | 18.67 |

任务队列的旧路径读取完整扫描及任务正文，新路径只读取首屏 50 条元数据；两者都是对应版本展示队列的取数方式。统计面板旧路径逐扫描装载详情，新路径聚合 SQL 汇总并单独分页读取扫描。

本样本的新查询达到首屏/概览 p95 小于 500ms 的本地目标。生产机的硬件、磁盘、正文分布、未回填扫描占比和并发度都不同，不能用此结果替代生产演练或容量规划。

## 空间与写入范围

本次一次性 SQL 装载后（没有手动 vacuum、没有模拟旧版重复接收正文），旧库约 205.1 MiB，新库约 385.2 MiB；装载阶段 WAL 增量分别约 27.1 MiB、210.1 MiB。这组数字**不证明空间减少或写入更快**：独立任务行、元数据和索引有固定开销，原生 PostgreSQL TOAST 对重复的模拟字符串也会产生不同效果。WAL 计数是该临时实例的装载窗口增量，并非每条业务报告的 WAL。

重复写入优化由单条报告/相同版本幂等、共享正文引用和增量输出的回归测试验证。真实生产收益应在备份演练库比较重复正文清理前后大小及持续上报负载，不能只看数据库文件大小。

## 复现

准备两个全新的专用测试数据库和一个基线代码目录。以下环境变量只能填写测试库地址：

```console
OPENDEEPHOLE_STORAGE_BENCHMARK_DSN='<空测试库A>' python scripts/benchmark_scan_storage.py --source '<基线目录>' --legacy --output before.json
OPENDEEPHOLE_STORAGE_BENCHMARK_DSN='<空测试库B>' python scripts/benchmark_scan_storage.py --output after.json
```

Windows PowerShell 先设置 `$env:OPENDEEPHOLE_STORAGE_BENCHMARK_DSN`，再运行后面的 Python 命令。脚本拒绝已存在业务表的目标，不清空已有数据库。输出 JSON 同时保存样本数、中位数、p95、客户端 CPU、数据规模及 PostgreSQL 版本。原始测量附后：

```json
{
  "before": {
    "version": "baseline",
    "postgres": "16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)",
    "scans": 10000,
    "tasks": 100000,
    "large_scan_tasks": 10000,
    "prompt_bytes_per_task": 1024,
    "database_bytes_after_seed": 215024143,
    "seed_wal_bytes": 28378568,
    "measurements": {
      "scan_first_page_50": {
        "samples": 11,
        "median_ms": 4.53,
        "p95_ms": 5.56,
        "client_cpu_median_ms": 2.79
      },
      "large_scan_overview": {
        "samples": 11,
        "median_ms": 97.77,
        "p95_ms": 115.5,
        "client_cpu_median_ms": 79.8
      },
      "task_first_page": {
        "samples": 11,
        "median_ms": 93.03,
        "p95_ms": 111.9,
        "client_cpu_median_ms": 71.73
      },
      "checker_dashboard": {
        "samples": 5,
        "median_ms": 42509.15,
        "p95_ms": 43122.68,
        "client_cpu_median_ms": 25044.36
      }
    }
  },
  "after": {
    "version": "optimized",
    "postgres": "16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)",
    "scans": 10000,
    "tasks": 100000,
    "large_scan_tasks": 10000,
    "prompt_bytes_per_task": 1024,
    "database_bytes_after_seed": 403890703,
    "seed_wal_bytes": 220289424,
    "measurements": {
      "scan_first_page_50": {
        "samples": 11,
        "median_ms": 2.88,
        "p95_ms": 4.02,
        "client_cpu_median_ms": 0.99
      },
      "large_scan_overview": {
        "samples": 11,
        "median_ms": 0.72,
        "p95_ms": 1.54,
        "client_cpu_median_ms": 0.47
      },
      "task_first_page": {
        "samples": 11,
        "median_ms": 0.83,
        "p95_ms": 1.18,
        "client_cpu_median_ms": 0.42
      },
      "checker_dashboard": {
        "samples": 11,
        "median_ms": 77.7,
        "p95_ms": 82.36,
        "client_cpu_median_ms": 18.67
      }
    }
  }
}
```
