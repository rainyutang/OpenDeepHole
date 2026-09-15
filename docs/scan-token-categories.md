# 扫描 Token 分类统计

扫描详情的“Token 统计”显示整个扫描生命周期内已采集的用量，包括续扫、重新去误报、失败或取消前已发生的调用。模型调用结束并完成采集后更新，不需要等待整个扫描结束。登录页面、公开扫描页面和可撤销分享页面使用相同统计。

分类表展示总 Token、占比、输入、输出、推理、缓存读取和缓存写入，按总量降序排列，“未分类”位于最后。各类别与“未分类”之和等于原扫描总量。模型统计和业务分类是同一总量的不同视角，两者不能再相加。

## 类别与归属

| 编码 | 页面名称 | 归属 |
| --- | --- | --- |
| `threat_analysis` | 威胁分析 | 独立威胁分析的全部阶段 |
| `threat_audit` | 基于威胁的审计 | `threat_audit` 引擎 |
| `static_candidate` | 基于候选点的审计 | 候选点引擎，包含项目级审计 |
| `fp_review` | 去误报 | 所有复核方法及其全部阶段 |
| `threat_pattern_audit` | 威胁模式审计 | 攻击模式引擎 |
| `multi_version` | 多版本审计 | 多版本引擎内部的威胁分析、审计和版本匹配 |
| `vulnerability_validation` | 漏洞验证 | 模型参与的漏洞验证 |
| `vulnerability_dedup` | 漏洞去重 | 跨引擎共享的模型去重 |
| `git_history` | Git 历史分析 | 已关联本扫描的历史分析调用 |
| `variant_hunt` | 同类漏洞挖掘 | 已关联本扫描的同类问题挖掘 |
| `memory_api_discovery` | 内存 API 发现 | 已关联本扫描的内存 API 分析 |
| `skill_create` | Skill 创建 | 仅统计关联本扫描的调用 |
| 自定义引擎 ID | 引擎名称 | 自定义挖掘引擎的模型调用 |
| `uncategorized` | 未分类 | 无法可靠确定业务归属的已记账用量 |

主会话、子会话、重试与 JSON 格式修正统一计入所属业务，不另算一次任务消耗。去重、去误报和漏洞验证按各自用途归类，避免被调用它们的引擎吞并。没有模型调用的静态分析不会凭空产生 Token。

## 接口与持久化

现有扫描概况、详情与 SSE 的 `opencode_pool.token_usage` 增加 `by_category` 数组，无新增 HTTP 路径。每项包含 `category`、`label`、`complete` 及既有六项 Token 字段。旧数据或旧 Agent 可以不携带该数组；已知总量的分类缺口显示为未分类。

`complete` 仍表示 Token 采集是否完整；“未分类”表示已有用量缺少归属，两者含义不同。没有任何原始 Token 总量的扫描显示“暂无已采集的 Token 用量”。

分类快照写入 `scan_opencode_category_token_usage`，唯一键为扫描、Agent 进程会话和类别，原生上报标记为 `reported`，历史恢复标记为 `history`。同一进程的累计快照替换更新，不重复叠加；不同进程求和。原生分类优先于同进程的历史恢复。总量与分类同事务写入，续扫过期轮次、旧时间戳和回退的累计值不能覆盖新用量。

历史回填只在显式迁移命令中执行，页面读取汇总。`scan_token_category_recovery` 保存回填所需的少量任务身份和计数，不复制任务正文；随扫描删除。回填优先采用持久任务上报，以任务 ID 和修订去重；旧快照只有在会话归属明确、累计值一致且能够排除会话重叠时才参与分类。不同实际修订的独立消耗保留。超出原进程已记账总量的历史分组不会被强行缩放，余额继续显示未分类。

## 部署与历史补全

更新后端、前端和 Agent，并重启 Agent。后端启动时按现有机制增量创建两张表，原 Token 表及总量保留。旧 Agent 仍能上传总量；新版 Agent 从新调用开始提供分类。

在**实际数据库所在环境**执行以下命令。PostgreSQL 示例使用环境变量 `OPENDEEPHOLE_DATABASE_URL` 中已有的连接配置，不把密码写到命令行。所有命令从仓库根目录运行。

先做只读检查，确认数据库类型及表状态：

```bash
python3 scripts/migrate_scan_storage.py --database-url-env OPENDEEPHOLE_DATABASE_URL check
python3 scripts/migrate_scan_storage.py --database-url-env OPENDEEPHOLE_DATABASE_URL status
```

`check` 输出应包含 `"database": "postgresql"`；新表对应 `rows` 值为数字，`null` 表示尚未建表。若后端尚未执行增量建表，可明确执行以下 DDL 步骤：

```bash
python3 scripts/migrate_scan_storage.py --database-url-env OPENDEEPHOLE_DATABASE_URL expand
```

然后执行**写入分类汇总的回填**：

```bash
python3 scripts/migrate_scan_storage.py --database-url-env OPENDEEPHOLE_DATABASE_URL backfill --phase token-categories --batch-rows 500 --until-complete
```

回填按任务上报、任务版本、旧扫描快照、历史归档和汇总阶段推进，每批限制源记录数量和正文读取大小。中断后运行同一命令会从数据库游标继续。某个源正文超过批次字节限制时命令报错并保留原文及已提交游标，不跳过原文后宣称完成。

最终输出示例：

```json
{"complete": true, "phase": "token-categories", "processed": 0}
```

只读校验汇总与页面快照：

```bash
python3 scripts/migrate_scan_storage.py --database-url-env OPENDEEPHOLE_DATABASE_URL verify --phase token-categories
```

完整历史的单扫描输出示例：

```json
{"errors": [], "ok": true, "scan_id": "example-scan", "total_tokens": 120, "tracked": true, "uncategorized_tokens": 0}
```

成功条件为命令退出码 `0`，末尾 `failed_scans` 为 `0`，各计数字段分类之和等于原始总量，页面重新加载后的分类一致。`uncategorized_tokens > 0` 可以是旧数据缺失的正常结果；回填完成不代表所有历史类别都可恢复。

旧 Agent 仍在运行、旧任务上报晚到或历史记录随后补全时，可针对一个扫描重新计算：

```bash
python3 scripts/migrate_scan_storage.py --database-url-env OPENDEEPHOLE_DATABASE_URL backfill --phase token-categories --scan-id example-scan --restart --until-complete
python3 scripts/migrate_scan_storage.py --database-url-env OPENDEEPHOLE_DATABASE_URL verify --phase token-categories --scan-id example-scan
```

重新计算替换派生的历史分类，不叠加旧回填值，不覆盖新版 Agent 的原生分类。省略 `--scan-id` 并添加 `--restart` 可重跑全部扫描。运行中的扫描仍按原上报节奏刷新；历史补全以本次读到的持久数据为准。

SQLite 使用显式数据库路径替换目标参数即可，例如：

```bash
python3 scripts/migrate_scan_storage.py --sqlite /path/to/scans.db backfill --phase token-categories --until-complete
python3 scripts/migrate_scan_storage.py --sqlite /path/to/scans.db verify --phase token-categories
```

本地代码和临时测试数据库通过验证，并不代表目标部署已更新或其历史已回填；以目标环境执行结果及扫描页面为准。
