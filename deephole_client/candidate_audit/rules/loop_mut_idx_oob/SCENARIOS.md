# Loop Mutated Index OOB / 循环变更索引越界

本 checker 使用 Semgrep 初筛循环中变化索引、循环累加指针和 `copy_from_user` 长度变量导致的潜在越界，再由 LLM 判断是否真实可达。

## 目标场景

- `$IDX` 在循环第三表达式或循环体内递增、递减或按步长变化
- `$IDX` 被用于 `arr[idx]`、`*(ptr + idx)`、`(ptr + idx)->field`、`&arr[idx]` 或内存函数参数
- 循环条件没有直接包含 `$IDX`
- `copy_from_user` 家族调用使用 `$LEN` 作为拷贝长度，同时目标 `$DST` 在循环内按 `$LEN` 累加或递减
- 命中点附近没有明显 `idx < bound`、fail-fast 或 assert/check 宏

## 典型真阳性

```c
void parse(char *dst, const char *src, unsigned byteNum, unsigned contentLen) {
    unsigned loop = 0;
    for (; byteNum != 0; byteNum -= contentLen, loop++) {
        dst[loop] = src[loop];
    }
}
```

这里循环由 `byteNum` 控制，但访问使用 `loop`。如果 `byteNum / contentLen` 可能超过 `dst` 容量，并且没有其他边界校验，可能形成真实越界。

```c
void fill(char *base, unsigned remain, unsigned step) {
    unsigned idx = 0;
    while (remain > 0) {
        char *p = base + idx;
        *p = 0;
        idx += step;
        remain -= step;
    }
}
```

如果 `remain` 不等价于 `base` 的容量，且 `idx` 没有被单独约束，派生指针可能越过目标缓冲区。

```c
int MC_EthBuildPayloadByFrag(uintptr_t vaPayloadAddr, FragInfo *fragInfo, unsigned fragNum) {
    unsigned char *fragPayload;
    void __user *fragPayloadFromUser;
    unsigned fragId;
    unsigned fragLen;
    fragPayload = (unsigned char *)((uintptr_t)(vaPayloadAddr));
    for (fragId = 0; fragId < fragNum; fragId++) {
        fragPayloadFromUser = (void __user *)(uintptr_t)(fragInfo[fragId].packet);
        fragLen = fragInfo[fragId].len;
        if (bspkern_copy_from_user(fragPayload, fragPayloadFromUser, fragLen) != 0) {
            return -1;
        }
        fragPayload += fragLen;
    }
    return 0;
}
```

这里 `fragLen` 决定每轮 `bspkern_copy_from_user` 的写入长度，`fragPayload` 又按 `fragLen` 累加。如果 `fragNum` 和各片段 `len` 来自用户或协议字段，且没有校验累计长度不超过 `vaPayloadAddr` 指向缓冲区的容量，就可能在某一轮触发越界写。

## 典型误报

```c
void safe(char *dst, unsigned len) {
    unsigned i = 0;
    while (len-- > 0) {
        if (i >= 64) {
            return;
        }
        dst[i++] = 0;
    }
}
```

访问前存在 fail-fast 检查，真实访问被约束。

```c
void safe_sync(char dst[16], unsigned remain) {
    unsigned i = 0;
    while (remain > 0) {
        dst[i] = 0;
        i++;
        remain--;
    }
}
```

如果调用契约或上游校验证明 `remain <= 16`，虽然循环条件没有直接包含 `i`，也应判为误报。

```c
void safe_copy(char *dst, const char *src, unsigned len, unsigned remaining) {
    if (len > remaining) {
        return;
    }
    copy_from_user(dst, src, len);
    dst += len;
}
```

拷贝前已经比较过 `len` 和剩余空间，真实写入被约束。若校验隐藏在宏、封装或上游调用中，仍由 LLM 复核时确认。

## LLM 复核重点

- `$IDX` 的初始值、变化方向和最大可能值
- 循环条件是否通过等价变量间接约束 `$IDX`
- `copy_from_user` 形态中的重点变量 `$LEN` 来源、单轮最大值和多轮累计值
- `$DST` 指向的目标缓冲区真实容量，以及每轮推进后的剩余空间
- 数组、指针或结构体成员的真实容量
- 访问前是否有宏、断言、fail-fast 或上游校验
- 触发路径是否受外部输入控制，以及需要怎样的输入关系才能越过边界
