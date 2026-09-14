# 复用本机 PostgreSQL 测试缓存

本机缓存目录为 `~/.cache/opendeephole-postgres`，可通过 `OPENDEEPHOLE_TEST_POSTGRES_HOME` 指向同样布局的其它目录。它独立于 Git 工作区和 `/tmp`，保留已下载的软件包、解包后的 PostgreSQL 16.15、Python 3.10 及测试依赖。`packages.json` 记录 Ubuntu 官方软件包来源、版本及经过核对的 SHA-256。未修改系统 PostgreSQL 安装。

在仓库根目录执行续扫存储回归：

```bash
python3 scripts/run_postgres_tests.py
```

传入 pytest 参数可执行更多数据库测试：

```bash
python3 scripts/run_postgres_tests.py -q tests/test_scan_resume_postgres.py tests/test_postgres_store_integration.py tests/test_storage_postgres.py
```

脚本不访问网络、不重复下载。每次在 `/tmp/odh-pg-test-*` 创建新数据库，用专属 Unix socket 连接，不占用 TCP 端口；为测试进程设置 `OPENDEEPHOLE_TEST_POSTGRES_DSN`，退出后停止 PostgreSQL 并清理该次数据库。并行运行各自使用独立目录。正常输出以 `Using cached PostgreSQL: ...; database: /tmp/odh-pg-test-...` 开头，成功条件为 pytest 全部通过且退出码为 0。

缓存约定：`root/usr/lib/postgresql/16/bin/{initdb,pg_ctl,postgres}`、`root/usr/share/postgresql/16`、`root/usr/lib/x86_64-linux-gnu`、`python/bin/python3.10`。脚本只使用已有缓存；迁移到其它机器时需要先准备适用于目标系统的同样环境，缺失时会直接报出缓存路径。

当前沙箱禁止创建 Unix socket，运行数据库时需要允许此脚本在沙箱外执行；缓存仍然复用。仅执行不依赖数据库服务的 Python 测试时也可直接使用缓存解释器：

```bash
PYTHONPATH=. ~/.cache/opendeephole-postgres/python/bin/python3.10 -m pytest -q tests/test_scan_resume_execution.py
```
