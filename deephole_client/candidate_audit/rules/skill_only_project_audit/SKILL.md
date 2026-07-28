---
name: skill_only_project_audit
description: 管理员测试用项目级 SKILL-only checker，用于验证无 analyzer.py 的 checker 可直接审计代码扫描路径并返回多个结果
---

# SKILL-only 项目级审计测试

你正在执行一个项目级审计测试任务。这个 checker 没有 `analyzer.py`，系统会自动生成一个项目级候选点，然后直接运行本 SKILL。

## 目标

验证你可以在目标代码目录中完成项目级审计并返回真实结果。

重点不是复核某个候选线索，而是主动阅读代码，寻找可能存在的真实安全问题。每个问题对应一个独立结果。

## 审计要求

1. 先理解代码扫描路径对应的代码范围。提示词中会给出代码扫描路径和 `project_id`。
2. 选择若干关键函数阅读源码，优先关注入口函数、解析函数、认证/权限判断函数、内存拷贝函数、资源释放函数。
3. 如果发现真实问题，每个问题都必须形成列表中的一个独立结果。
4. 每个真实问题必须填写：
   - `confirmed=true`
   - `severity` 为 `critical` / `high` / `medium` / `low`
   - `description` 简要说明漏洞位置、触发方式和结果
   - `file` 为真实问题所在文件路径
   - `line` 为真实问题所在行号
   - `function` 为真实问题所在函数名
   - `vuln_type` 填漏洞类型，可附带 CWE 编号
   - `impact` 分别说明机密性、完整性、可用性影响
   - `vulnerable_code` 包含证明问题所需的全部相关源码
   - `call_chain` 按攻击入口到漏洞函数顺序列出全部函数
   - `attack_entry`、`root_cause`、`trigger_conditions` 分别说明攻击入口、根因和触发条件
5. 如果没有发现真实问题，也必须返回一个结果：
   - `confirmed=false`
   - `severity="low"`
   - `description` 说明没有发现可确认问题
   - `file`、`line`、`function` 使用提示词中给出的项目级占位值

## 判定标准

确认真实问题需要满足：

- 能指出具体函数和具体行号
- 能说明问题如何被触发
- 能说明现有校验为什么不能阻止问题
- 能说明影响范围

以下情况不要确认：

- 只有代码风格问题，没有安全影响
- 缺少可达路径或触发条件
- 已有边界检查、权限检查或错误处理覆盖该路径
- 位于测试、mock、stub 或不可达代码中
