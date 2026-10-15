# C/C++ 命令注入规则

## 文件与审计边界

规则目录为 `deephole_client/vulnerability_mining/engines/static_candidate/rules/command_injection/`：

- `checker.yaml`：规则注册信息；沿用现有自动发现、规则同步和独立 worker。
- `analyzer.py`：Tree-sitter 定位、有限符号解析、按函数聚合，不直接确认漏洞。
- `sink.json`：静态阶段专用的字面量词表，包含 109 个执行相关 API 名称及条件入口。
- `skills/command-injection-audit/SKILL.md`：精简审计要求，仅关注外部可达性、输入控制、过滤效果和实际执行语义。
- `skills/command-injection-audit/SCENARIOS.md`：规则市场说明，不安装到模型使用的 Skill 目录。

规则包将词表放入 `static/`，审计包只包含 Skill。审计沿用统一的 `/<skill-name>` Prompt，不增加命令注入专用 Prompt 或输出协议；传入文件、函数、行号及 `metadata.subject` 中的实际命中 API、类别、行列，不传完整词表、原始候选描述或完整元数据。

每个源码函数定义范围聚合所有位置，生成一个候选并审计一次。重载、成员限定符、同一行的不同定义及 Lambda 分别标识；Lambda 捕获初始化表达式归入外层函数。函数外的宏定义和全局初始化分别按源码块审计，不升级为全项目审计。

同函数的多个独立问题保存在一个报告的 `description` 中，按编号关联其余证据字段；严重度及主位置取最高风险问题。分点描述、保留各问题的位置、触发方和影响，以及多问题时不受“一句话”限制的要求，仅在命令注入 Skill 中定义；通用审计文案及 JSON Schema 保持原样，统计仍以报告条数计数。本规则不使用跨函数的同模式拒绝缓存，避免一个安全函数导致其他函数被跳过。

## 匹配范围

完整名称以 `sink.json` 为准，不使用名称子串、通配符或相似名称匹配。覆盖 C/C++ 源文件、头文件和内联文件，不依赖索引是否包含某个函数；沿用扫描目录排除策略。忽略注释、普通字符串、纯声明及类型名，但专门处理宏体和动态符号解析中的精确字符串。

词表包含 shell 执行与展开、POSIX/BSD/QNX 的 exec/spawn、GLib/GIO、Qt/KDE、Boost.Process、Poco、wxWidgets、libuv、APR、SDL、NSPR、libiberty、ACE、SSH 远程执行、Linux 用户态辅助程序及 macOS 授权执行接口。不包含 Windows 专用 API；跨平台库和 QNX 的无下划线 spawn 系列保留。[QNX 官方 exec/spawn 对照](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.getting_started/topic/s1_procs_Starting_with_exec_spawn.html)

条件入口如下，不将通用入口的所有调用都认定为命中：

- `syscall`：首参必须精确为 `SYS_execve`、`SYS_execveat`、`__NR_execve` 或 `__NR_execveat`。
- `dlsym`、`dlvsym`：符号字符串必须精确等于词表中的 C 函数名；标记为符号引用，而非证明已经执行。
- `std::make_unique`、`std::make_shared`：模板类型必须解析到词表中的执行类，并存在构造参数。

成员方法要求能够确定接收者类型，不能仅凭 `start`、`open`、`spawn` 等裸方法名判定。支持可确定的命名空间、类型/using 别名、函数指针、字段、继承、显式返回类型、常见智能指针和宏别名；头文件通过精确的相对路径、扫描根目录或根目录下 `include/` 路径关联，不做文件名模糊搜索。

调用、取地址和构造均只是审计入口。Qt 的 `startCommand` 会拆分程序与参数，不意味着自动进入 shell；`open` 也能启动已配置的程序。[Qt QProcess 官方文档](https://doc.qt.io/qt-6/qprocess.html) Boost 执行类还包含移动构造或关闭句柄等不启动进程的构造重载，静态阶段不推断所有重载语义，交由审计核实。[Boost.Process 官方文档](https://www.boost.org/doc/libs/latest/libs/process/doc/html/index.html)

## 已知限制

- 不是编译器级符号解析或跨过程数据流引擎：复杂模板推导、任意指针传播、动态生成的函数名、宏拼接不做猜测。
- 遍历条件编译分支，但不代替完整预处理器；不推断缺失的编译参数、外部 include 搜索路径或条件宏值。
- 无法确定的接收者、宏分支、构造形式及语法错误写入 `Analyzer.diagnostics`，日志输出原因计数和有限示例。不能据无候选结论声称不存在命令注入。
- 当前实现保留解析树和作用域用于头文件与别名关联，内存随扫描规模增长；该选择优化本任务的运行时间，不保证比 Semgrep 更省内存。

## 验证与性能复现

分析器测试覆盖词表所有名称、正反例、作用域、宏、源码坐标、聚合及解析限制；集成测试覆盖 worker、规则包、Skill 隔离、统一 Prompt 和报告保留。模型调用使用 Mock，验证一次调用及多问题字段不丢失，不代表已完成真实 LLM 的漏洞确认能力评估。

```bash
PYTHONPATH=. python3 -m pytest -q tests/test_command_injection_analyzer.py tests/test_command_injection_integration.py
PYTHONPATH=. python3 scripts/benchmark_command_injection.py --files 100 --functions 240 --repeat 3 --jobs 1
```

基准每个样本启动新进程。共同语料仅包含 `system`、`popen`、`execve`、`posix_spawnp` 的直接调用，两种实现都必须输出预期位置数且无诊断；稀疏集仅 10% 文件包含调用，密集集所有函数包含调用。完整规则语料增加取地址、指针别名调用、Qt 成员调用和 Boost 构造，仅单测 Tree-sitter 吞吐，不将不等价规则做性能对照。

`median_cold_seconds` 包含启动、导入、扫描和结果解析时间；这不是清空文件系统缓存后的冷盘测试。`peak_process_rss_kb` 是自身及子进程高水位的最大值，不是整个进程树的同时内存总和。脚本的 `--tree-only` 可跳过 Semgrep；Semgrep 可能需要写入用户目录设置。

### 本地对照结果

2026-10-14，Linux / Python 3.12.3，Tree-sitter 0.25.2、tree-sitter-cpp 0.23.4、Semgrep 1.163.0。每组 100 个文件、每文件 240 个函数，单 worker，独立进程重复 3 次取中位数。

| 语料 | 预期位置数 | Tree-sitter 耗时 | Semgrep 耗时 | Tree-sitter RSS | Semgrep RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| 稀疏直接调用，1,309,600 字节 | 2,400 | 2.116 s | 4.270 s | 215.0 MiB | 153.5 MiB |
| 密集直接调用，1,315,000 字节 | 24,000 | 3.109 s | 29.529 s | 279.3 MiB | 251.8 MiB |
| 完整规则语料，3,805,000 字节 | 96,000 | 7.981 s | 不作对照 | 587.7 MiB | 不作对照 |

RSS 列为各次样本进程高水位的中位数。两组共同语料的位置数一致、无诊断；Tree-sitter 用时分别约为 Semgrep 的 1/2.0 和 1/9.5，但内存更高。基于本任务的精确匹配、函数聚合、可复用语法解析依赖及该对照的耗时，选用 Tree-sitter；该合成测试不代表所有实际项目、并发配置或语义规则下的普遍优劣，也不测量 LLM 审计耗时。
