# 覆盖率引导的轻量级威胁分析（OpenCode）

初轮复用原 OpenCode 轻量级提示词和产物校验；之后使用同一扫描的完整文件清单，
最多补查两次，每次由代码选择五个以内的最浅未覆盖路径。第一次校验合并后重新选择目标。

补查使用简短任务提示词，读取已有资产、模块和树作为只读参考，输出自己的 `delta.json`
及 `attack-trees/` 目录。初轮和各次补查分别显示为扫描任务队列中的计划、排队、运行及终态，
原 Session 产物纠正仍归属对应任务。

## 输出规范

- `references/delta.schema.json`：路径判定、已有模块更新、新模块和新资产。
- `references/attack-tree-index.schema.json`：本轮树清单，允许空数组。
- 单树沿用 Codex 方法目录的 `references/attack-tree.schema.json`。
- `references/supplement-guidance.json`：简短任务和必要要求，引用原有建模规则和条目格式。

`module_updates` 按精确模块名追加 `add_code_paths`、更新 `set_fields`，保留名称和旧路径。
其他字段更新必须与旧攻击树兼容。新模块及资产沿用原有条目格式，路径判定需要真实文件和行号证据。

## 校验与合并

Task Agent 在回复结束后异步执行 `supplement.py --context <程序内部输入文件>`。
脚本检查本轮 Schema、真实路径和证据，再试合并验证原有全部跨产物规则。
每个完整判定至少包含一条实际选择范围内、且位于当前判定路径下的有效证据；可额外引用公共源码根内
的真实依赖文件，不要求额外证据都在清单内。清单外路径不增加覆盖计数。源码行号校验兼容 UTF-8、GBK 及带 BOM 的 Unicode 文本，
产物 JSON 仍须使用 UTF-8；校验脚本的中文诊断统一按 UTF-8 回传。
不合法时回传诊断，由同 Session 修正一次，之后沿用阶段新 Session 重试。
任务要求模型仅写本轮增量并把源码和旧轮产物作为只读参考。完整 Agent 的稳定产物根不隔离各轮
写权限，不能把该要求理解成文件系统沙箱。模型可通过 `allowed_bash_commands` 与
`bound_python_script` 执行本轮绑定校验命令，其它 Shell 命令仍被拒绝；Task Agent 在回复后独立复验。
程序在校验通过后发布累计快照，
旧树保留，新树分配唯一 ID 和文件名后追加；没有新增内容时允许空增量。

校验允许尾逗号，证据结束行超出文件时收敛到文件末行；无效区间不作为证据。模块覆盖及部分
建模关系差异只记录 `warnings`，必要字段、真实路径、范围、引用、图结构与模式合法性仍必须通过。
累计快照输出标准 JSON，合并与续扫使用相同规则，详见[覆盖说明](../../../../docs/threat-coverage.md#覆盖率引导方法的补查)。

## 检查点和范围报告

初轮原始结果保留在 `final/`；补查原始结果位于 `rounds/round-N/`；
代码生成的累计结果位于 `merged/round-N/`。`coverage-workflow-state.json` 保存有效检查点，
取消后的续扫不重跑初轮及已提交轮次，也不复用失败 Session。历史成功结果继续复用。

补查失败保留最近有效结果，清单不完整则跳过补查；初轮失败仍按原有规则回退。
`coverage_report_path` 随产物上传保存轮次、目标、判定、树 ID 映射和停止原因。
`remaining_uncovered_files` 是未被高风险范围覆盖的文件数，`pending_files` 进一步扣除已明确判为
非高风险的文件。非高风险判定不提高覆盖图的高风险覆盖率；未完成范围保留为缺口。

本方法需更新后端及 Agent 并重启，可在自定义模式显式选择；自定义模式的默认选择仍为原 OpenCode 轻量级方法。
