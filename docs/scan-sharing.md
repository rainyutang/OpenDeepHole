# 扫描分享

扫描列表每行、扫描详情顶部均有“分享”按钮。点击后可复制链接，也可在弹窗中关闭分享。所有扫描状态都可以分享，链接访问的是当前数据，状态和问题标记会实时刷新。

接收者无需登录，可以查看本次扫描的状态、进度、问题、审计任务、复核与验证结果，下载单个问题 Markdown 报告、扫描 CSV 和 ZIP 报告。问题支持“确认正报 / 实为误报 / 待分析”、理由、工单信息，以及修改、取消和批量操作；标记保存到原扫描，其他打开的扫描页面会同步更新。等待引擎最终对账的临时漏洞沿用原有规则，暂不能标记。

分享页禁止停止、续扫、删除扫描，禁止触发或停止 AI 复核和漏洞验证，禁止修改扫描配置、反馈选择和管理反馈库。标记沿用原有反馈记录生成、更新及清理行为，不会额外将新反馈勾选到扫描配置中。

每个扫描只有一个当前有效的分享链接，长期有效。重复点击“分享”得到同一链接；所有者或管理员可以关闭分享，重新开启后生成新链接。关闭后的请求立即被拒绝；已经打开的实时连接通过撤销通知关闭，通知丢失时由最长 30 秒的心跳校验兜底。扫描进入删除流程后，分享同样失效。

## 接口

登录接口使用 `Authorization: Bearer <JWT>`：

| 方法 | 路径 | 功能 |
| --- | --- | --- |
| POST | `/api/scan/{scan_id}/share` | 创建或获取分享，返回 `{ "scan_id": "...", "token": "..." }` |
| DELETE | `/api/scan/{scan_id}/share` | 关闭分享，返回 `{ "ok": true }` |

网页使用浏览器当前站点地址生成 `#/shared-scan/{scan_id}?token=...` 链接。访问分享数据使用 `/api/shared/scans/{scan_id}` 前缀，携带 `?token=<分享令牌>`。令牌只能访问对应扫描，不接受登录 JWT 或外部集成令牌替代。

| 方法 | 后缀 | 功能 |
| --- | --- | --- |
| GET | `/overview` | 当前状态及汇总 |
| GET | `/events`、`/event-history` | SSE 实时通知、历史日志分页 |
| GET | `/candidates`、`/vulnerabilities`、`/threat-audit-tasks`、`/validations` | 当前扫描结果分页 |
| GET | `/details/{resource}/{index}` | 问题、候选、验证和复核正文 |
| GET | `/tasks`、`/tasks/{task_id}` | 执行任务分页及历史详情 |
| GET | `/fp-review/overview`、`/fp-review/results`、`/fp_review` | 复核状态和结果 |
| GET | `/candidate-audit-results`、`/threat-audit-results`、`/vulnerabilities/{idx}/audit-source` | 审计摘要及问题来源 |
| GET | `/threat-analysis`、`/git_history`、`/index-status` | 威胁分析、历史模式和索引状态 |
| GET | `/checkers`、`/skill/{vuln_type}`、`/fp-review/skill`、`/skill-reports` | 本次扫描的规则信息和报告 |
| GET | `/report`、`/report.zip`、`/vulnerability/{idx}/report` | CSV、ZIP、单个问题报告 |
| POST | `/mark`、`/unmark`、`/batch-mark`、`/batch-unmark` | 沿用登录扫描接口的人工标记请求和响应格式 |

分享不可用时返回 `403`，提示“分享已关闭或链接无效”。活动 SSE 在关闭前发出 `share_unavailable` 事件，网页停止刷新并提示失效；不会清除浏览器已有登录信息。允许操作的参数校验和结果不存在错误沿用原扫描接口。

扫描尚未创建去误报任务时，`/fp-review/overview` 返回 `404`、`detail: "No FP review found"`，表示暂无去误报任务。扫描仍在运行、未启用自动去误报或没有问题结果时都可能出现；分享页继续显示扫描详情并保持实时连接，后续创建任务后可通过同一链接查看。网页仅把扫描主概览 `/api/shared/scans/{scan_id}/overview` 的 `404` 判为分享不可用，子资源的 `404` 由对应页面处理。

## 部署与验证

更新后端和前端资源。后端启动时自动创建独立 `scan_shares` 表并接入扫描删除清理，支持 SQLite 和 PostgreSQL；历史扫描默认未分享。令牌不进入扫描状态快照，扫描进度写回、续扫和服务重启均不会重置分享。现有外部集成链接继续使用原有令牌和权限。

已部署分享功能的环境，去误报 `404` 误判修复只需更新前端资源，无需数据库迁移或重新生成分享链接。

在仓库根目录执行后端测试；PostgreSQL 命令复用已有缓存，为本次测试创建临时数据库：

```bash
PYTHONPATH=. python3 -m pytest -q tests/test_scan_sharing.py tests/test_external_integration_api.py tests/test_report_export.py
python3 scripts/run_postgres_tests.py -q tests/test_scan_sharing.py tests/test_storage_deletion.py
```

在 `frontend/` 执行 `npm run test:scan-sharing`、`npm run test:issue-loading` 和 `npm run build`。成功标准是匿名查看、人工标记及报告内容正确，暂无去误报任务时仍可访问且后续任务可在同一链接加载，越权请求被拒绝，关闭分享后 API 和活动 SSE 均失效，两种数据库测试通过。
