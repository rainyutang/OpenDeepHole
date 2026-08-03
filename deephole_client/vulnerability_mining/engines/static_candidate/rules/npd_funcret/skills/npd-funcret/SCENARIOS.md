# 函数返回值/参数赋值空指针解引用检测 — 可扫描场景

## 检测规则概述

本检查器采用 **semgrep 初筛 + tree-sitter 跨函数分析** 的混合方案，检测 C/C++ 代码中：
1. 函数返回值赋值给指针后，未判空即解引用
2. 通过函数参数（传指针的指针 `&ptr`）赋值后，未判空即解引用

检测流程：
- **Phase 1（semgrep）**：匹配「赋值 → 未判空 → 解引用」的代码模式
- **Phase 2（tree-sitter）**：对返回值赋值场景，分析被调函数是否可能返回 NULL，过滤误报

---

## 正例场景（可检测到的 NPD 模式）

### 场景 1：malloc/calloc 返回值未判空直接解引用

```c
void process() {
    char *buf = (char *)malloc(1024);
    buf[0] = '\0';  // ← NPD：malloc 可能返回 NULL
    use(buf);
    free(buf);
}
```

**检测原理**：`buf` 通过 `malloc` 返回值赋值，`malloc` 在已知可返回 NULL 的函数列表中，赋值后未判空即通过 `buf[0]` 解引用。

### 场景 2：自定义函数返回值未判空（函数体中有 return NULL 路径）

```c
Node *find_node(List *list, int key) {
    for (Node *n = list->head; n; n = n->next) {
        if (n->key == key)
            return n;
    }
    return NULL;  // ← 可能返回 NULL
}

void update_value(List *list, int key, int val) {
    Node *node = find_node(list, key);
    node->value = val;  // ← NPD：find_node 可能返回 NULL
}
```

**检测原理**：tree-sitter 分析 `find_node` 函数体，发现存在 `return NULL` 语句，确认可能返回 NULL。

### 场景 3：带类型强转的函数返回值未判空

```c
void init_config() {
    MyStruct *cfg = (MyStruct *)get_config_data();
    cfg->timeout = 30;  // ← NPD：get_config_data 可能返回 NULL
    cfg->retries = 3;
}
```

**检测原理**：semgrep 匹配 `$P = ($TYPE *)$CALL(...)` 模式，tree-sitter 分析 `get_config_data` 是否可能返回 NULL。

### 场景 4：通过传指针的指针赋值后未判空

```c
int get_resource(Resource **out) {
    *out = lookup_resource();
    if (*out == NULL)
        return -1;
    return 0;
}

void use_resource() {
    Resource *res;
    get_resource(&res);  // ← res 通过参数被赋值
    res->data = 42;      // ← NPD：get_resource 可能失败，res 可能为 NULL
}
```

**检测原理**：semgrep 匹配 `$CALL(..., &$P, ...); ... $P->$F;` 模式。参数赋值场景不做 `_can_return_null` 过滤，直接作为候选项交给 AI 审计。

### 场景 5：声明时通过函数赋值后未判空

```c
void read_data(const char *filename) {
    FILE *fp = fopen(filename, "r");
    char buf[256];
    fread(buf, 1, sizeof(buf), fp);  // ← NPD：fp 未判空，fopen 可能失败
    fclose(fp);
}
```

**检测原理**：`fopen` 在已知可返回 NULL 的函数列表中，赋值后未判空即作为参数传递（隐含解引用）。

### 场景 6：函数返回值经多层函数调用传递（递归分析）

```c
char *safe_alloc(size_t size) {
    return malloc(size);  // ← 直接返回 malloc 的结果
}

char *create_buffer(int count) {
    return safe_alloc(count * sizeof(char));  // ← 返回 safe_alloc 的结果
}

void fill_buffer(int count) {
    char *buf = create_buffer(count);
    buf[0] = 'x';  // ← NPD：create_buffer → safe_alloc → malloc，可能返回 NULL
}
```

**检测原理**：tree-sitter 递归分析（最多 3 层）：`create_buffer` 返回 `safe_alloc()` 的调用结果 → `safe_alloc` 返回 `malloc()` 的调用结果 → `malloc` 在已知可返回 NULL 列表中。

### 场景 7：条件表达式中返回 NULL

```c
Item *get_item(Cache *cache, int id) {
    return cache->enabled ? cache->items[id] : NULL;
}

void process_item(Cache *cache, int id) {
    Item *item = get_item(cache, id);
    item->process();  // ← NPD：get_item 在 cache 未启用时返回 NULL
}
```

**检测原理**：tree-sitter 分析 `get_item` 的 `return` 语句为条件表达式，其 `alternative` 分支为 `NULL`。

---

## 反例场景（不会误报的情况）

### 反例 1：赋值后有判空检查

```c
void safe_process() {
    char *buf = (char *)malloc(1024);
    if (buf == NULL) {
        log_error("malloc failed");
        return;
    }
    buf[0] = '\0';  // ← 安全：已判空
    free(buf);
}
```

**排除方式**：semgrep `pattern-not` 排除了 `if ($P == NULL)` 模式。

### 反例 2：被调函数不可能返回 NULL

```c
void copy_data(char *dst, const char *src) {
    char *result = strcpy(dst, src);
    result[0] = 'x';  // ← 安全：strcpy 不可能返回 NULL
}
```

**排除方式**：`strcpy` 在已知不返回 NULL 的函数列表中，Phase 2 过滤掉。

### 反例 3：在 if (ptr) 块内解引用

```c
void safe_use() {
    Node *node = find_node(list, key);
    if (node) {
        node->value = 42;  // ← 安全：在判空块内
    }
}
```

**排除方式**：semgrep `pattern-not-inside` 排除了 `if ($P) { ... }` 模式。

### 反例 4：判空后 return 再解引用

```c
void safe_read() {
    FILE *fp = fopen("data.txt", "r");
    if (!fp)
        return;
    fread(buf, 1, size, fp);  // ← 安全：已有 if (!fp) return
    fclose(fp);
}
```

**排除方式**：semgrep `pattern-not` 排除了 `if (!$P) return ...;` 模式。

---

## 不支持的场景（超出静态分析能力，需 LLM 辅助判断）

- **同一表达式内的链式解引用**：`func()->field` — semgrep 的 `...` 操作符要求跨语句匹配
- **C++ 异常路径导致的 NPD**：函数通过异常而非返回值表示失败
- **通过全局变量传递的指针**：指针赋值和解引用在不同函数中通过全局变量关联
- **多线程环境下的竞态 NPD**：指针在另一线程中被置为 NULL
- **复杂控制流**：指针赋值和解引用跨越多层 if/switch/loop 且判空逻辑嵌套在宏中
- **C++ 传引用赋值**：`func(ptr)` 其中参数类型为 `T*&` — 需要类型信息，semgrep 社区版不支持

这些场景可能被静态分析漏报或误报，AI 复审阶段会做进一步判断。
