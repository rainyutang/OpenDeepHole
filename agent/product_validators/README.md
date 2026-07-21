# 产品漏洞验证方法

每个验证方法占一个一级目录，并包含：

```text
<method>/
├── validator.yaml
└── validator.py
```

平台入口固定为：

```python
async def validate(**kwargs) -> ValidationResult:
    ...
```

平台不会调用 `main()`。开发者可以在 `validator.py` 中自行增加 `main()`，通过 `agent.validation_debug.run_validator_debug(...)` 复用真实 `agent.yaml` 并直接调试同一个 `validate`。

完整的 manifest、kwargs、返回值、本地 `main()` 模板和运行命令见 [漏洞验证方法与本地调试](../../docs/vulnerability_validation.md)。
