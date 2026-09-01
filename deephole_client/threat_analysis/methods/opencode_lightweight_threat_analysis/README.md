# OpenCode 轻量级威胁分析

该方法通过一次逻辑上的 `run_opencode_task(task_type="threat_analysis")`
完成价值资产、高风险模块和攻击树分析。它与 Codex 轻量级方法调用同一个
Prompt 构造函数，因此相同输入与输出路径会得到完全一致的用户 Prompt。

Task Agent 只为本任务开放 Prompt 中的精确校验命令；命令必须在最终文件写入后
成功执行。任务沿用 Agent 的 `threat_analysis.model_policy` 超时和全新 Session
重试策略，重试耗尽后的 DeepHole 回退由扫描编排层负责。
