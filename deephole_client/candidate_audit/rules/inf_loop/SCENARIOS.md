# 死循环检测 — 可扫描场景

## 检测规则概述

本检查器使用 semgrep 扫描 C/C++ 代码中的 CWE-835（死循环）模式，共 15 条规则，覆盖四大类：

1. **continue 路径未推进循环变量**：while / for / do-while 循环中，某条 continue 路径未更新控制变量
2. **zero-step 步进**：步进量在运行时可能为 0，循环无法前进
3. **C++ 迭代器失效**：erase/insert 后未更新迭代器，或 continue 前未推进迭代器
4. **其他无进展模式**：string::find 位置未推进、lower_bound key 未推进、worklist 重复入队等

---

## 正例场景（工具可检测并确认的死循环）

### 场景 1：while 循环局部变量在 continue 前未更新

```c
int parse_packet(const uint8_t *buf, int len) {
    int i = 0;
    while (i < len) {
        if (buf[i] == 0xFF) {
            log_error("bad byte");
            continue;   // ← i 未 ++，下次仍判断同一字节，死循环
        }
        process(buf[i]);
        i++;
    }
    return 0;
}
```

**规则**：`local-while-continue-no-progress`

---

### 场景 2：while 循环函数参数在 continue 前未更新（外部输入可触发，高危）

```c
void parse_stream(const uint8_t *ptr, const uint8_t *end) {
    while (ptr < end) {
        uint8_t type = *ptr;
        if (type == TYPE_UNKNOWN) {
            continue;   // ← ptr 未推进，死循环
        }
        ptr += record_size(type);
    }
}
```

**规则**：`param-while-continue-no-progress`（severity=ERROR）  
**LLM 分析**：追溯调用链，确认 `ptr` 来自网络数据，`TYPE_UNKNOWN` 可由攻击者构造触发，判定为高危 DoS。

---

### 场景 3：for 循环 increment 为空，continue 跳过更新

```c
int scan_fields(Record *recs, int count) {
    for (int i = 0; i < count; /* 空 */) {
        if (recs[i].flags & FLAG_SKIP) {
            continue;       // ← continue 跳回 condition，不经过 increment，i 未更新
        }
        process(&recs[i]);
        i++;
    }
    return 0;
}
```

**规则**：`for-empty-update-continue-no-progress-local`（confidence=HIGH）

---

### 场景 4：do-while 循环 continue 前未更新状态

```c
void drain_queue(Queue *q) {
    Item *item;
    do {
        item = queue_peek(q);
        if (item->state == PENDING) {
            continue;   // ← 未改变 state 也未弹出队列，死循环
        }
        queue_pop(q);
        handle(item);
    } while (!queue_empty(q));
}
```

**规则**：`do-while-continue-no-progress`

---

### 场景 5：步进量可能为零（zero-step，需 LLM 追溯调用链）

```c
void walk_buffer(uint8_t *buf, int len, int step) {
    int i = 0;
    while (i < len) {
        process(buf + i);
        i += step;   // ← step 若为 0，永远循环
    }
}

// 调用方
void handle_request(Request *req) {
    walk_buffer(req->data, req->len, req->step_size);  // step_size 来自网络包
}
```

**规则**：`unchecked-zero-step-add-assign`  
**LLM 分析**：查看调用方，确认 `step` 来自外部输入且无非零校验，判定为高危。

---

### 场景 6：C++ 迭代器 erase 后未更新迭代器

```cpp
void remove_invalid(std::vector<Item> &items) {
    for (auto it = items.begin(); it != items.end(); ++it) {
        if (!it->valid()) {
            items.erase(it);   // ← 未用返回值更新 it，迭代器失效后 ++it 导致 UB
        }
    }
}
```

**规则**：`erase-without-reassign-in-loop`（severity=ERROR）

---

### 场景 7：string::find 循环位置未推进

```cpp
void find_all(const std::string &s, const std::string &pat) {
    size_t pos = 0;
    while ((pos = s.find(pat, pos)) != std::string::npos) {
        handle(pos);
        // ← pos 未 += pat.size()，永远匹配同一位置
    }
}
```

**规则**：`string-find-without-position-advance`

---

### 场景 8：worklist 重复入队，状态未改变

```cpp
void propagate(std::queue<Node*> &worklist) {
    while (!worklist.empty()) {
        Node *n = worklist.front();
        worklist.pop();
        if (needs_update(n)) {
            worklist.push(n);   // ← n 状态未变，下次仍 needs_update，无限入队
        }
    }
}
```

**规则**：`worklist-reenqueue-same-item-without-state-change`

---

### 场景 9：宏展开内隐藏更新（需 LLM 查看宏定义确认）

```c
#define NEXT_RECORD(p)  /* 展开为: p = p->next */ do { (p) = (p)->next; } while(0)

void walk_list(Node *p) {
    while (p != NULL) {
        if (p->skip) {
            NEXT_RECORD(p);
            continue;   // semgrep 看不到宏内的 p=p->next，报告此处
        }
        process(p);
        NEXT_RECORD(p);
    }
}
```

**LLM 分析**：查看 `NEXT_RECORD` 宏定义，确认已推进指针，判定为误报。

---

### 场景 10：子函数内部推进循环变量（需 LLM 查看子函数确认）

```c
void scan(Parser *p) {
    while (p->pos < p->len) {
        if (is_whitespace(p->buf[p->pos])) {
            skip_whitespace(p);   // semgrep 不知道此函数内部推进了 p->pos
            continue;
        }
        parse_token(p);
    }
}
```

**LLM 分析**：查看 `skip_whitespace` 函数体，确认其内部执行了 `p->pos++`，判定为误报（或确认推进逻辑缺失则为真实漏洞）。

---

## 反例场景（semgrep 检出但工具正确过滤的误报）

### 反例 1：continue 前已显式更新循环变量

```c
while (i < len) {
    if (buf[i] == 0xFF) {
        i++;        // 先更新
        continue;   // semgrep 有 pattern-not 排除，不报告
    }
    process(buf[i++]);
}
```

### 反例 2：continue 分支中有 break/return

```c
while (ptr < end) {
    if (*ptr == SENTINEL) {
        break;      // semgrep 的 pattern-not 排除，不报告
    }
    ptr++;
}
```

### 反例 3：for 循环有正常 increment（非空）

```cpp
for (auto it = v.begin(); it != v.end(); ++it) {
    if (skip(*it)) continue;   // increment 在 for 头，continue 后仍执行，不报告
}
```

### 反例 4：erase 返回值正确赋回迭代器

```cpp
for (auto it = items.begin(); it != items.end(); ) {
    if (!it->valid())
        it = items.erase(it);  // 正确用法，不报告
    else
        ++it;
}
```

### 反例 5：有意设计的服务主循环（LLM 识别为误报）

```c
void *server_thread(void *arg) {
    while (g_running) {           // 依赖外部 flag 退出
        int fd = epoll_wait(...); // 阻塞等待，有意无限运行
        if (fd < 0) continue;
        handle_event(fd);
    }
    return NULL;
}
```

**LLM 分析**：发现 `epoll_wait` 阻塞调用 + `g_running` 外部 flag，识别为有意设计的事件循环，判定为误报。

### 反例 6：zero-step 调用方保证非零（LLM 追溯调用链后过滤）

```c
// 调用方始终传入固定非零常量
walk_buffer(data, len, sizeof(Header));   // sizeof 不可能为 0
```

**LLM 分析**：追溯调用链，确认 step 为编译期常量，不可能为 0，判定为误报。

---

## 不支持的场景（超出工具检测范围）

- **无限递归**：函数直接或间接递归调用自身，无终止条件——semgrep 规则不覆盖递归模式
- **条件变量虚假唤醒导致的活锁**：`pthread_cond_wait` 被虚假唤醒，逻辑上循环不终止——属于并发语义，静态分析无法判断
- **循环条件依赖运行时浮点精度**：`while (x != 0.0)` 因浮点运算永不精确相等——语义分析超出范围
- **间接调用链中的无进展**：函数 A 调用 B 调用 C，C 内部无进展但 semgrep 的规则不匹配顶层循环结构
- **信号处理器或异步回调中的死循环**：循环逻辑在信号处理上下文中执行，semgrep 无法关联上下文
