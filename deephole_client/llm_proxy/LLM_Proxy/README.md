# LLM_Proxy 运行目录

将现有 `LLM_Proxy` 程序放在本目录，入口必须为 `main.py`，并保留程序需要的
`hooks/codemate_hook.py` 等文件。OpenDeepHole 不在这里实现协议转换代码。

Agent 会在模型配置同步时生成本目录下的 `config.yaml`，然后以当前 Python 解释器和本目录作为
工作目录运行 `main.py`。`config.yaml` 是客户端运行时文件，不应提交到版本库。
