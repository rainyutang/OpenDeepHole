# 整数翻转/溢出 — 可检测场景

## 概述

本检测器识别 C/C++ 代码中因**外部输入缺乏校验**，经加减运算导致整数翻转/溢出，且结果被用于**危险操作**（数组下标、内存分配、memcpy 长度等）的漏洞。

检测策略：从危险使用点出发 → 追溯变量来自未守卫的算术 → 反向查调用链确认操作数可追溯到外部入口函数。

## 检测范围

### 危险使用点（Sink）

- **数组下标**: `a[expr]`
- **指针偏移**: `*(p + expr)`, `*(p - expr)`
- **内存函数参数**: `memcpy(dst, src, expr)`, `malloc(expr)`, `sprintf_s(buf, expr, ...)` 等
- **循环边界**: `for (i = 0; i < expr; i++)` 且循环体内有上述操作

### 算术操作

- 减法: `A - B`, `A -= B`
- 加法: `A + B`, `A += B`

### 守卫检测

- 包围式守卫: `if (var >= sub) { ... var - sub ... }`
- 前置 early return: `if (var < sub) return; ... var - sub ...`
- 三元表达式: `(var >= sub) ? (var - sub) : 0`
- 守卫不一致: `if (var >= 4) { var - 8; }` → 守卫值 < 减去值
- 安全整数 API: `__builtin_sub_overflow`, `SafeInt` 等

## 可检测的漏洞场景

### 场景一：外部长度参数减去头部大小，无下界检查

```c
// 入口函数
void HandleMessage(uint8_t *data, uint32_t len) {
    ParsePayload(data + HEADER_SIZE, len);
}

// 内部函数
void ParsePayload(uint8_t *payload, uint32_t total_len) {
    uint32_t body_len = total_len - HEADER_SIZE;  // 无守卫！
    memcpy(buffer, payload, body_len);             // 翻转后拷贝巨量数据
}
```

**检出路径**: `memcpy` 第 3 参数 `body_len` → 来自 `total_len - HEADER_SIZE`（无守卫）→ `total_len` 是参数 → 反向追溯到 `HandleMessage`（入口函数）

### 场景二：加法溢出用于内存分配

```c
void ProcessPacket(uint32_t headerLen, uint32_t bodyLen) {
    uint32_t totalLen = headerLen + bodyLen;  // 溢出后变为小值！
    char *buf = malloc(totalLen);             // 分配过小的缓冲区
    memcpy(buf, data, headerLen + bodyLen);   // 实际拷贝溢出
}
```

### 场景三：守卫不一致

```c
void DecodeField(uint8_t *data, uint32_t offset) {
    if (offset >= 4) {              // 只检查 >= 4
        uint32_t idx = offset - 8;  // 但减去了 8！offset 为 4-7 时翻转
        table[idx] = data[0];       // 越界写入
    }
}
```

### 场景四：循环边界导致越界

```c
void CopyItems(Item *dst, Item *src, uint32_t count) {
    uint32_t adjusted = count - 1;        // 无守卫
    for (uint32_t i = 0; i < adjusted; i++) {  // count=0 时翻转为 UINT32_MAX
        dst[i] = src[i];                  // 巨量越界
    }
}
```

## 不检出的场景

### 有完整守卫

```c
void Safe(uint32_t len) {
    if (len < HEADER_SIZE) return;         // 有效守卫
    uint32_t payload = len - HEADER_SIZE;  // 安全
    memcpy(buf, data, payload);
}
```

### 纯常量运算

```c
uint32_t x = MAX_SIZE - HEADER_SIZE;  // 两个常量/宏，跳过
```

### 追溯不到入口函数

```c
static void InternalHelper(uint32_t x) {
    uint32_t y = x - 1;
    arr[y] = 0;
}
// 如果 InternalHelper 不在任何入口函数的调用链上，则不报告
```

### 变量未用于危险操作

```c
void Log(uint32_t total, uint32_t used) {
    uint32_t free = total - used;  // 无守卫
    printf("Free: %u\n", free);    // 但只是打印，不危险
}
```

## 局限性

- 不追踪全局变量传递的污点
- 不分析函数指针调用（调用图可能缺失边）
- 不追踪函数返回值的污点（保守标记）
- 不区分有符号/无符号类型
- 无法看穿宏定义中的守卫检查
- 调用链追溯深度限制为 8 层
