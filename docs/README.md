# OpenDeepHole 文档

[返回项目首页](../README.md)

## 入门与使用

| 文档 | 内容 |
| --- | --- |
| [部署与 Agent 安装](getting-started.md) | 环境要求、源码部署、Docker 限制、Agent 启动 |
| [扫描使用指南](usage.md) | 模式、MCP、停止续扫、复核、反馈、导出与用户 Skill |
| [配置参考](configuration.md) | 服务端与 Agent 配置、模型池、OpenCode 和 Codex 运行时 |
| [架构与数据存储](architecture.md) | 组件职责、通信、数据流和本地存储 |
| [审计结果](audit_results.md) | 候选点与威胁任务的权威结果、状态与页面入口 |
| [威胁分析覆盖率](threat-coverage.md) | 文件清单、覆盖口径与模块路径匹配 |
| [扫描分享](scan-sharing.md) | 分享链接、权限与撤销 |
| [Token 分类统计](scan-token-categories.md) | 扫描、模型和任务的 Token 统计口径 |

## 开发与扩展

| 文档 | 内容 |
| --- | --- |
| [开发指南](development.md) | 开发服务器、测试与贡献约定 |
| [框架开发指南](framework_development.md) | 扫描流程、组件边界和扩展类型选择 |
| [Checker 开发参考](checker-development.md) | 规则目录、Analyzer、测试工具、去重与过滤 |
| [Task Agent 公共接口](opencode_task_service.md) | 模型任务、Session、权限与重试 |
| [漏洞验证方法](vulnerability_validation.md) | 产品验证器的清单、入参和结果契约 |

实现目录中的接口说明：

- [Agent 过程总览](../deephole_client/README.md)
- [代码索引构建](../deephole_client/code_graph_build/README.md)
- [威胁分析方法](../deephole_client/threat_analysis/README.md)
- [漏洞挖掘引擎](../deephole_client/vulnerability_mining/README.md)
- [去误报方法](../deephole_client/fp_review/README.md)
- [独立 Task Agent](../task_agent/README.md)

## 部署与维护

- [生产环境扩展与迁移](production_scaling.md)：PostgreSQL、多 Worker、代理与运行指标。
- [扫描历史存储迁移](database-storage-migration.md)：存储升级、回填与回滚。
- [存储基准测试](database-storage-benchmark.md)：测试范围、命令和结果解释。
- [PostgreSQL 测试缓存](testing-postgres.md)：使用已有本机缓存运行数据库回归。
- [更新日志](../CHANGELOG.md)：按日期记录项目变化。

配置默认值以当前配置模型和各方法清单为准。页面可选规则还受 `enabled`、`visibility` 和客户端排除列表影响，不能仅凭规则目录存在判断其已启用。
