# Codex Goal 威胁分析

该方法保持平台规定的五参数同步入口，只调用一次 `CodexController.goal()` 完成威胁建模。

## 输入

| 参数 | 处理方式 |
| --- | --- |
| `code_path` | 必填、必须存在的源码目录；作为只读绝对路径交给 Goal |
| `output_path` | 必填；用于三份最终产物、Goal 状态、扫描上下文、提示词和日志 |
| `is_resume` | 已有产物有效时直接复用，否则按保存的 Thread ID 恢复 Goal |
| `product_mcp` | 写入运行上下文，供 Goal 判断是否使用产品知识 |
| `attack_modes` | 写入运行上下文，供 Goal 生成攻击模式关联 |

## 必须输出

成功时返回 `result=true`，以及下面三个位于 `output_path/final/` 的文件路径：

- `value_asset_path`：`value-assets.json`，顶层为价值资产数组。
- `high_risk_modules_path`：`high-risk-modules.json`，顶层为高风险模块数组。
- `attack_tree_path`：`attack-trees.json`，顶层对象必须包含 `attack_trees` 数组。

字段和嵌套结构由本方法 `references/` 下的三份独立 JSON Schema 定义；分析步骤、证据要求、
跨产物关系和完成检查由同目录的 `analysis-guidance.json` 定义。动态路径、续扫状态、产品 MCP
名称和攻击模式写入 `output_path/scan-context.json`。Goal 和返回前校验器读取相同的私有参考
文件，不依赖其它威胁分析方法。Goal 初始提示词运行时硬性限制为不超过 4000 字符，并另存为
`output_path/codex-goal-prompt.txt`。

## Codex 模型与认证

Agent 启动时会先检查/安装 Codex CLI，再把用户级 OpenCode
`opencode.json` / `opencode.jsonc` 中显式声明的 Provider 和模型转为
`$CODEX_HOME` 下的 OpenDeepHole 托管 profile。本方法不运行裸 `codex`，
而是用第一个同步成功的 profile 显式启动：

```text
codex --profile <opendeephole-profile> app-server --listen stdio://
```

profile 已包含模型、Responses API base URL 和 API key 来源，所以工具执行不需要
ChatGPT 交互登录。新 Goal 会把选中的 `provider/model` 与 profile 写入
`codex-goal-state.json`，续扫保持使用同一模型。没有可用托管 profile、已保存模型
被删除或 Codex CLI 不可用时，本方法直接返回配置错误，不会回退到需要登录的默认
OpenAI Provider。

用户级 OpenCode 配置的最小形式如下；推荐让 Agent 进程通过环境变量取得密钥：

```jsonc
{
  "provider": {
    "corp": {
      "options": {
        "baseURL": "https://models.example.com/v1",
        "apiKey": "{env:CORP_MODEL_API_KEY}"
      },
      "models": { "threat-model": {} }
    }
  }
}
```

这里会生成模型 ID `corp/threat-model`。平台 Web「客户端配置」中的模型池继续管理模型
ID、启用状态、权重和并发，但不会保存 API Key；因此 Codex profile 的 URL 和凭据来源
必须存在于 Agent 操作系统用户的 OpenCode 配置中。修改后重启 Agent，并确认启动日志出现
`Codex model profiles ready`。自定义 Provider 必须兼容 Responses API。

工具不修改用户的 `$CODEX_HOME/config.toml` 或 Codex 默认模型。因此用户在终端直接
运行不带 `--profile` 的 `codex` 时，仍可能看到登录提示；这与工具内 Goal 的
profile 执行路径相互独立。
