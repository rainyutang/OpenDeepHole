# Threat Analysis Feature

威胁分析前端代码集中在本目录：

- `api.ts`：威胁分析结果请求，复用全局鉴权和公开扫描访问逻辑。
- `ThreatAnalysisPanel.tsx`：独立面板组件，通过 props 接收数据、所选方法名、错误信息和受控结果页签。
- `useThreatAnalysisResult.ts`：统一首屏、SSE 通知与轮询触发的产物加载，合并在途请求并在切换扫描时取消旧请求。
- `index.ts`：feature 对外出口。

面板直接读取后端保存的原生 artifact bundle，不再依赖旧版归一化
`ThreatAnalysis` Schema，也不在 `ScanStatus.tsx` 中复制实现专属字段。

独立使用：

```tsx
import {
  getThreatAnalysisResultCounts,
  ThreatAnalysisPanel,
  getScanThreatAnalysis,
} from "../features/threatAnalysis";
```

扫描页负责加载数据、处理 SSE，并控制当前结果页签；攻击树展示细节仍保留在本 feature 内。
`getThreatAnalysisResultCounts()` 统一计算价值资产、高风险模块、去重后的内部节点和攻击树数量，
供结果页与扫描流程图共用。
有效 artifact bundle 是结果已就绪的判据；没有有效结果且
`threat_analysis_run.status=error` 时，面板继续显示已持久化的 `error_message`。

v2 概况和由分页拼装的扫描快照不携带威胁分析正文，其中的 `threat_analysis: null`
不表示删除产物。扫描页与 SSE 重同步通过 `mergeScanSnapshot()` 保留同一扫描已加载的结果，
停止及继续扫描后的刷新也沿用此规则。

连接/重连、恢复页面可见和全量重同步会单独刷新产物；威胁分析资源通知即使与其它
资源通知合并，也会触发更新。成功状态通知会主动获取结果，漏收通知或请求失败由现有
30 秒轮询补拉；已加载的有效结果（包含合法空数组）无需在每次轮询时重取。
404 视为尚无产物，网络错误保留当前结果，不触发全量资源的循环刷新。
请求期间的新通知合并为一次后续读取，旧请求及其它扫描的迟到响应不能覆盖新结果。

验证：在 `frontend/` 运行 `npm run test:threat-analysis-loading`，覆盖真实扫描页面的数量、
产物表格、混合通知、失败恢复、请求竞争、公开扫描及停止/续扫刷新。
