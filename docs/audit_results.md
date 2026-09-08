# 审计结果与问题报告定位

扫描详情中的威胁审计任务、静态分析候选点与问题报告支持双向定位：

- 威胁审计任务的每条最终确认结果都有“查看问题报告”按钮。
- 静态分析候选点在关联问题得到最终确认后显示“发现问题”，详情展示问题简介、位置和判定来源，并提供“查看问题报告”。
- 问题报告中的“查看威胁审计任务”或“查看静态候选点”会打开对应来源，自动调整筛选、分页并选中目标。

标签的判定顺序为明确人工判定优先，其次为扫描内最近一次有效去误报结论。仅有原始审计发现时不添加问题标签；新一轮复核未形成有效结论时，保留之前的有效结论。候选点重新进入待执行、排队或运行状态时，不沿用上次审计的问题标签。执行状态标签仍表示任务是否成功完成。

定向打开报告时，页面显示“当前定位：结果 #索引”。即使目标不属于默认问题列表，也能查看原始报告、复核内容和人工判定；“返回问题列表”恢复默认列表范围。

## 按需读取与接口

所有索引都属于当前扫描，不能使用数组位置或文件/行号/函数猜测关联。已加载且具有明确来源的目标直接使用页面缓存；缺少目标时才读取，单条目标的回填不推进正常分页游标。

| GET 接口（相对 `/api/v2/scans/{scan_id}`） | 用途 |
| --- | --- |
| `/threat-audit-results?task_ids=...` | 当前可见威胁任务及选中任务的结果摘要 |
| `/candidate-audit-results?candidate_indexes=...` | 当前可见候选点及选中候选点的结果摘要 |
| `/vulnerabilities/{idx}/audit-source` | 返回问题唯一对应的审计任务或候选点 |
| `/vulnerabilities?after={idx-1}&limit=1` | 补充尚未加载的指定问题；客户端严格核对返回索引 |
| `/tasks?task_name={name}` | 按精确任务名称分页读取历史摘要，选择最近一次执行 |
| `/tasks/{task_id}?record_id={record_id}` | 按需读取该次执行的完整 Prompt 和 Session 记录 |

两个摘要接口使用重复查询参数，每批最多 100 条；返回简介与最终结论，不加载报告正文。来源接口返回 `vuln_index`、`status`、`kind`、`threat_task` 和 `candidate`；`status` 为 `resolved`、`missing`、`ambiguous` 或 `unsupported`，成功时只携带一种来源记录。公开扫描通过 `/api/public/scans/{scan_id}` 下的对应接口和现有访问令牌访问。

历史威胁结果优先按 `source_task_id`、任务的 `result_vuln_indexes` 关联，缺少来源时再检查唯一的节点、模式和路径关系；只有这种历史查询需要读取扫描的任务关联元数据。候选点结果优先使用保存的 `vulnerability_idx`，旧记录只通过明确的 `audit_index` 恢复。来源任务缺失或存在多个匹配时，页面说明无法定位的原因。

读取不改写历史数据。结果随审计、复核、人工判定及重连刷新更新；连续刷新会合并请求，切换目标或扫描会取消过期请求。

存储优化后，候选来源通过保存的正文版本引用恢复完整审计结果，历史任务摘要仍不携带 Prompt 正文。候选和威胁任务详情优先使用当前队列中的 Prompt，缺少历史记录时按精确任务名称查询摘要后读取单条正文，支持加载失败重试。扫描概览的 `detail_counts.human_confirmed_issue_count` 直接返回有效去误报 TP 中人工确认的总数，不依赖已加载的漏洞页数；人工判定后刷新汇总。

## 回归验证

```bash
PYTHONPATH=. python3 -m pytest -q tests/test_threat_audit_results.py
```

在 `frontend/` 中运行 `npm run test:audit-navigation`、`npm run test:threat-audit`、`npm run test:static-audit`、`npm run test:scan-runtime` 和 `npm run build`。导航测试覆盖实际 React 组件的分页、筛选、选中状态、滚动定位、结果刷新和过期响应处理。PostgreSQL 回归通过 `OPENDEEPHOLE_TEST_POSTGRES_DSN` 显式启用。
