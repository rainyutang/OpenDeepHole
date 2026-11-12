# 前端模块与状态所有权

本轮重构将扫描详情、问题详情、表单、历史列表及威胁分析按领域组织，保留页面交互、URL、HTTP/SSE 协议和历史数据格式。只需重新构建、发布前端，不需要数据库迁移或客户端升级。

## 模块边界

| 层次 | 所有者 | 责任 |
| --- | --- | --- |
| HTTP 传输与访问策略 | `frontend/src/api/transport.ts`、`accessPolicy.ts` | 唯一 Axios 实例、凭据、分享访问限制、鉴权失效通知 |
| 领域请求与类型 | `api/`、`types/` | 扫描、审计、问题、Agent、配置及管理端点；保留快照请求去重 |
| 中性数据模型 | `scanRuntime/` | 输入归一化、稳定编号、执行版本、快照合并、模型池历史；不依赖 UI |
| SSE 生命周期 | `hooks/scanSSE/` | 协议校验、事件批处理、资源刷新协调、连接和可见性恢复 |
| 扫描详情 | `features/scanDetail/` | 页面装配、纯展示模型、业务面板、状态与操作 hook、领域事件处理 |
| 问题详情 | `features/issues/` | 筛选、分页、定位、反馈、复核、验证与报告展示 |
| 创建与配置 | `features/newScan/`、`features/agentConfig/` | 草稿、校验、请求转换、远程配置与异步能力查询 |
| 历史与威胁分析 | `features/scanHistory/`、`features/threatAnalysis/` | 列表加载与轮询、公告状态；产物适配、树及固定基线展示 |
| 模型池公共展示 | `features/modelPool/` | 扫描页与 Agent 配置页复用的展示和任务命名 |

兼容入口 `api/client.ts`、`types.ts`、`scanRuntime.ts`、`hooks/useScanSSE.ts`、`components/ScanStatus.tsx` 和 `components/VulnerabilityList.tsx` 保留原导出。组件兼容导出引用同一个实现，不增加包装组件或额外生命周期。新领域模块直接导入实际所有者，不通过兼容入口互相引用。

API 地址、请求参数、超时、返回值和 DTO 字段保持不变。所有请求继续使用同一个 `api` 对象，公开/分享访问状态及拦截器只安装一次。`setPublicScanAccess` 的生命周期继续由应用路由管理。

## 扫描详情的数据流

`useScanSnapshotState` 持有扫描、复核、索引、执行版本相关状态和稳定引用。页面组合以下独立职责：

- `useScanHydration` 负责首次加载和手动重试；`useScanCatalog` 加载检查器与引擎元数据。
- `useDetailResources` 管理分页请求、取消、资源代次、摘要刷新和去重；`useDetailPagination` 决定当前页面需要哪些资源，并推进问题及复核分页。
- `useScanEvents` 将生命周期、发现结果、威胁和复核事件处理器装配到唯一 SSE hook；各业务面板不建立独立订阅。
- `useScanActions` 管理停止、续扫、验证、复核和导出；`useScanArtifacts` 管理反馈选择、SKILL 预览和报告。
- `useScanNavigation` 管理路由、审计来源定位及侧栏；展示面板持有自己的筛选、展开与选择状态。

同一扫描、同一访问身份切换子页面复用扫描实例、连接和已加载状态。应用的实例标识仍包含访问类型、扫描 ID 和访问 token；身份改变时清理旧作用域。浏览器后退取消旧的审计定位请求。

`resourceCoordinator` 合并资源失效通知，分页加载与刷新通过资源代次避免迟到响应覆盖新状态。保留执行版本检查、显式 `null`、稳定 `vuln_index`、历史任务归并和未变化详情的引用。收到事件不会无条件刷新所有列表。

现有时序保持不变：日志事件 50 ms、状态事件 75 ms、资源失效合并 150 ms、SSE 后备轮询 30 秒、运行扫描进度摘要轮询 60 秒。隐藏页面积累失效通知，健康连接恢复可见时按既有规则补齐资源。

## 草稿和用户阅读状态

新建扫描使用 `ScanDraft` 表达草稿，纯模型完成默认值、复制初始化、校验及创建请求转换。知识库探测带请求代次；客户端或开关变化、组件卸载后，旧结果不能重新填入草稿。

Agent 远程配置用于初始化编辑草稿，保留客户端切换请求代次、编辑版本及保存期间继续编辑的保护。问题列表继续按稳定编号定位，普通及分享页面复用同一详情；反馈草稿、复核阶段和对话展开状态不因实时更新被重置。

历史列表分页/轮询、筛选与公告已读状态各自管理。威胁产物适配保留既有格式判断、产物字段处理和固定基线语义；Coverage 算法、资源 hook 和绘制架构沿用原实现。

## 验证与后续修改

在 `frontend/` 执行 `npm test` 运行所有 `test:*` 脚本；新增测试需登记到 `package.json`。`npm run build` 执行 TypeScript 检查和生产构建。`test:architecture` 检查运行时循环、反向兼容入口依赖和纯模型的传递依赖。

性能装置及本轮结果见 [前端重构验证报告](frontend-refactor-validation.md)。修改数据加载、批处理或派生模型时，应同时检查结果、请求数、连接数、组件开销与内存；文件变短本身不代表性能提升。
