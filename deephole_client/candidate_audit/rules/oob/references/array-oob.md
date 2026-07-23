# S5：数组索引越界

## 漏洞原理

当数组的下标表达式来自外部输入或未经充分校验的变量时，
访问 `arr[index]` 可能读写数组边界之外的内存。

这包括越界读（信息泄露）和越界写（内存破坏），两者都属于本审计的覆盖范围。

核心判断：**index 的取值范围是否完全落在 [0, array_size - 1] 内。**

---

## 高危模式

### 模式 1：外部输入直接做下标


```c
void GetItem(DWORD dwIndex) {
    return g_ItemTable[dwIndex];   // dwIndex 未校验 → 越界读
}
```



### 模式 2：校验不完整（只检查了上界或下界之一）


```c
if (nIndex < MAX_SIZE) {        // 缺少 nIndex >= 0 的检查（有符号类型）
    buf[nIndex] = val;          // nIndex 为负时越界写
}
```




```c
if (nIndex >= 0) {              // 缺少上界校验
    buf[nIndex] = val;          // nIndex >= ARRAY_SIZE 时越界
}
```



### 模式 3：校验条件与数组大小不匹配


```c
#define TABLE_A_SIZE 64
#define TABLE_B_SIZE 128
ST_ITEM g_TableA[TABLE_A_SIZE];

if (dwIndex < TABLE_B_SIZE) {     // 用了错误的宏
    g_TableA[dwIndex] = item;     // dwIndex 在 64-127 时越界
}
```



### 模式 4：下标经过算术运算


```c
DWORD dwPos = dwBase + dwOffset;
arr[dwPos] = val;   // dwBase 和 dwOffset 各自可能在范围内，但相加后可能越界
```



### 模式 5：枚举值/类型转换做下标


```c
void HandleMsg(int nMsgType) {
    g_MsgHandlers[nMsgType](pData);   // nMsgType 来自网络 → 可越界
}
```



### 模式 6：通过指针算术间接越界


```c
ST_ITEM* pItem = pArray + dwIndex;  // 等价于 pArray[dwIndex]
pItem->field = val;                 // dwIndex 越界则写到非法位置
```



---

## 分析流程

### 1. 识别数组/指针下标访问

在函数体内查找所有 `arr[expr]`、`ptr[expr]`、`*(ptr + expr)` 形式的访问。
过滤掉下标为编译期常量且明显在范围内的访问。

### 2. 确定数组/缓冲区的有效范围

调用 MCP 工具确定被访问对象的大小：
- 栈数组 → 声明中直接可见
- 全局数组 → `view_global_variable_definition`
- 结构体成员数组 → `view_struct_code`
- 动态分配 → 追踪 malloc/new 的参数
- 函数参数传入 → 追踪调用方（最多 2 层）

### 3. 确定下标的取值范围

- 下标是常量 → 直接对比
- 下标来自函数参数 → 检查函数内是否有范围校验
- 下标来自外部数据（网络/文件/IO） → 检查是否校验
- 下标经过运算 → 分析运算后的值域

### 4. 检查现有校验

在数组访问之前，是否存在 `if (index < SIZE)` 或 `if (index >= SIZE) return` 类型的校验？
校验中的 SIZE 是否与实际数组大小一致？

### 5. 对比判定

下标最大可能值 vs 数组有效下标上界（array_size - 1）。
下标最小可能值 vs 0（有符号类型需关注负值）。

---

## 豁免规则

**豁免 1：下标在访问前经过完备的范围校验**

```c
if (dwIndex >= TABLE_SIZE) return ERROR;
g_Table[dwIndex] = val;  // → 安全
```



**豁免 2：下标是编译期常量且在范围内**

```c
buf[0] = 'A';
buf[MAX_SIZE - 1] = '\0';  // MAX_SIZE = sizeof(buf) → 安全
```



**豁免 3：下标来自 % 取模运算且模数 <= 数组大小**

```c
buf[index % BUF_SIZE] = val;  // BUF_SIZE <= sizeof(buf) → 安全
```



---

## 判定标准

- 下标来自外部输入且无范围校验 → `confirmed=true`
- 校验条件中的上界与实际数组大小不匹配 → `confirmed=true`
- 有符号下标只检查了上界未检查 >= 0 → `confirmed=true`
- 下标经过运算后可能超出范围 → `confirmed=true`
- 下标在访问前有完备的范围校验 → `confirmed=false`

---

## ai_analysis 输出示例


```
场景：S5 数组索引越界
访问：g_ItemTable[dwIndex]
数组：g_ItemTable，类型 ST_ITEM[256]，有效下标 0-255。
下标：dwIndex 来自函数参数 ProcessItem(DWORD dwIndex)。
校验：函数内未发现 dwIndex 的范围校验。
判定：dwIndex 可能 >= 256，存在越界读取风险。
修复建议：访问前添加 if (dwIndex >= 256) return ERROR;
```
