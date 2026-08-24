# Threat Analysis Feature

威胁分析前端代码集中在本目录：

- `api.ts`：威胁分析结果请求，复用全局鉴权和公开扫描访问逻辑。
- `ThreatAnalysisPanel.tsx`：独立面板组件，通过 props 接收数据、所选方法名、错误信息和受控结果页签。
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
