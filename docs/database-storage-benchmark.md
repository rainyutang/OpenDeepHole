# 扫描存储查询基准

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
OPENDEEPHOLE_STORAGE_BENCHMARK_DSN=<空测试库A> python scripts/benchmark_scan_storage.py --source <基线目录> --legacy --output before.json
OPENDEEPHOLE_STORAGE_BENCHMARK_DSN=<空测试库B> python scripts/benchmark_scan_storage.py --output after.json
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
