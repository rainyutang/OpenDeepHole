from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from deephole_client.vulnerability_mining.engines.static_candidate.rules.loop_mut_idx_oob import analyzer as analyzer_module
from deephole_client.vulnerability_mining.engines.static_candidate.rules.loop_mut_idx_oob.analyzer import (
    Analyzer as LoopMutIdxOobAnalyzer,
)


pytestmark = pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="semgrep CLI is not installed",
)


@pytest.fixture(autouse=True)
def require_successful_semgrep(monkeypatch):
    run = analyzer_module.run_semgrep

    def checked_run(*args, **kwargs):
        result = run(*args, **kwargs)
        assert result is not None
        assert result.returncode in (0, 1), result.stderr
        assert json.loads(result.stdout).get("errors", []) == []
        return result

    monkeypatch.setattr(analyzer_module, "run_semgrep", checked_run)


def test_loop_mut_idx_oob_semgrep_rules_find_direct_patterns(tmp_path: Path) -> None:
    source = tmp_path / "unsafe_direct.c"
    source.write_text(
        """
typedef unsigned long size_t;
typedef struct {
    int value;
} Item;

void memcpy_s(void *dst, size_t dstsz, const void *src, size_t count);

void array_access(char *dst, char *src, unsigned remain) {
    unsigned idx = 0;
    while (remain > 0) {
        dst[idx] = src[idx];
        idx++;
        remain--;
    }
}

void pointer_deref(char *ptr, unsigned len) {
    unsigned idx = 0;
    for (; len != 0; len--, idx++) {
        *(ptr + idx) = 0;
    }
}

void field_access(Item *items, unsigned len) {
    unsigned idx = 0;
    while (len != 0) {
        (items + idx)->value = 1;
        idx++;
        len--;
    }
}

void memory_call(char *dst, char *src, unsigned remain) {
    unsigned idx = 0;
    while (remain > 0) {
        memcpy_s(dst + idx, 16, src, 1);
        idx++;
        remain--;
    }
}
""",
        encoding="utf-8",
    )

    candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path))
    descriptions = "\n".join(candidate.description for candidate in candidates)

    assert "越界访问问题" in descriptions
    for access in ["dst[idx]", "*(ptr + idx)", "(items + idx)->value", "memcpy_s(dst + idx, 16, src, 1)"]:
        assert access in descriptions


def test_loop_mut_idx_oob_semgrep_rules_find_taint_patterns(tmp_path: Path) -> None:
    source = tmp_path / "unsafe_taint.c"
    source.write_text(
        """
typedef unsigned long size_t;
void memcpy_s(void *dst, size_t dstsz, const void *src, size_t count);

void derived_deref(char *base, unsigned remain) {
    unsigned idx = 0;
    while (remain > 0) {
        char *tmp = base + idx;
        *tmp = 0;
        idx++;
        remain--;
    }
}

void derived_memfunc(char *base, char *src, unsigned remain) {
    unsigned idx = 0;
    while (remain > 0) {
        char *tmp = &base[idx];
        memcpy_s(tmp, 8, src, 1);
        idx++;
        remain--;
    }
}
""",
        encoding="utf-8",
    )

    candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path))
    descriptions = "\n".join(candidate.description for candidate in candidates)

    assert "越界访问问题" in descriptions
    assert "derived-pointer" not in descriptions
    assert "local memory sink" not in descriptions
    assert len(candidates) >= 2


def test_loop_mut_idx_oob_semgrep_rules_find_copy_from_user_length_patterns(tmp_path: Path) -> None:
    source = tmp_path / "copy_from_user_len.c"
    code = """
typedef unsigned long uintptr_t;

typedef struct {
    uintptr_t packet;
    unsigned len;
} FragInfo;

int bspkern_copy_from_user(void *dst, const void *src, unsigned len);

int MC_EthBuildPayloadByFrag(uintptr_t vaPayloadAddr, FragInfo *fragInfo, unsigned fragNum) {
    unsigned char *fragPayload;
    void *fragPayloadFromUser;
    unsigned fragId;
    unsigned fragLen;
    fragPayload = (unsigned char *)((uintptr_t)(vaPayloadAddr));
    for (fragId = 0; fragId < fragNum; fragId++) {
        fragPayloadFromUser = (void *)(uintptr_t)(fragInfo[fragId].packet);
        fragLen = fragInfo[fragId].len;
        if (bspkern_copy_from_user(fragPayload, fragPayloadFromUser, fragLen) != 0) {
            return -1;
        }
        fragPayload += fragLen;
    }
    return 0;
}

int raw_copy_from_user(void *dst, const void *src, unsigned len);

int while_copy(char *dst, const char *src, unsigned remain, unsigned step) {
    unsigned idx;
    idx = 0;
    while (remain > 0) {
        raw_copy_from_user(dst, src, step);
        dst = dst + step;
        remain -= step;
        idx++;
    }
    return 0;
}
"""
    source.write_text(code, encoding="utf-8")

    candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path))
    candidate_lines = {candidate.line for candidate in candidates}
    lines = code.splitlines()
    bsp_line = lines.index("        if (bspkern_copy_from_user(fragPayload, fragPayloadFromUser, fragLen) != 0) {") + 1
    raw_line = lines.index("        raw_copy_from_user(dst, src, step);") + 1

    assert bsp_line in candidate_lines
    assert raw_line in candidate_lines
    descriptions = "\n".join(candidate.description for candidate in candidates)
    assert "重点变量/拷贝长度: fragLen" in descriptions
    assert "目标指针/累加变量: fragPayload" in descriptions
    assert "重点变量/拷贝长度: step" in descriptions


def test_loop_mut_idx_oob_semgrep_rules_ignore_direct_loop_bound_access(tmp_path: Path) -> None:
    source = tmp_path / "direct_bound.c"
    code = """
typedef unsigned long uintptr_t;

typedef struct {
    uintptr_t packet;
    unsigned len;
} FragInfo;

void frag_access(FragInfo *fragInfo, unsigned fragNum) {
    unsigned fragId;
    for (fragId = 0; fragId < fragNum; fragId++) {
        (void)(uintptr_t)(fragInfo[fragId].packet);
        (void)fragInfo[fragId].len;
    }
}

void pointer_offset(char *ptr, unsigned count) {
    unsigned idx;
    for (idx = 0; idx < count; idx++) {
        *(ptr + idx) = 0;
    }
}
"""
    source.write_text(code, encoding="utf-8")

    candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path))
    candidate_lines = {candidate.line for candidate in candidates}
    lines = code.splitlines()
    direct_line = lines.index("        (void)(uintptr_t)(fragInfo[fragId].packet);") + 1
    len_line = lines.index("        (void)fragInfo[fragId].len;") + 1
    pointer_line = lines.index("        *(ptr + idx) = 0;") + 1

    assert direct_line not in candidate_lines
    assert len_line not in candidate_lines
    assert pointer_line not in candidate_lines


def test_loop_mut_idx_oob_semgrep_rules_ignore_basic_safe_shapes(tmp_path: Path) -> None:
    source = tmp_path / "safe.c"
    source.write_text(
        """
void direct_condition(char *dst, unsigned len, unsigned cap) {
    if (len > cap) {
        return;
    }
    for (unsigned idx = 0; idx < len; idx++) {
        dst[idx] = 0;
    }
}

void guarded(char *dst, unsigned remain, unsigned cap) {
    unsigned idx = 0;
    while (remain > 0) {
        if (idx < cap) {
            dst[idx] = 0;
        }
        idx++;
        remain--;
    }
}

void fail_fast(char *dst, unsigned remain, unsigned cap) {
    unsigned idx = 0;
    while (remain > 0) {
        if (idx >= cap) return;
        dst[idx] = 0;
        idx++;
        remain--;
    }
}

void macro_checked(char *dst, unsigned remain, unsigned cap) {
    unsigned idx = 0;
    while (remain > 0) {
        CHECK_RET(idx < cap, -1);
        dst[idx] = 0;
        idx++;
        remain--;
    }
}

int copy_from_user(void *dst, const void *src, unsigned len);
void memcpy(void *dst, const void *src, unsigned len);

void checked_copy_from_user(char *dst, const char *src, unsigned step, unsigned cap) {
    if (step > cap) return;
    while (cap > 0) {
        copy_from_user(dst, src, step);
        dst += step;
        cap -= step;
    }
}

""",
        encoding="utf-8",
    )

    candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path))

    assert candidates == []


_TYPES = """
typedef struct Item { unsigned idx; int value; char *p; } Item;
typedef union Slot { unsigned idx; long other; } Slot;
typedef struct State {
    unsigned idx, step;
    char *p;
    Item inner, *items;
    unsigned *positions;
    struct State *next;
    Slot slot;
} State;
void *memcpy(void *dst, const void *src, unsigned long len);
int copy_from_user(void *dst, const void *src, unsigned len);
"""
_PARAMS = "char *buf, char *src, unsigned remain, State *ctx, State *other, unsigned k, unsigned *idxp"
_UPDATES = [
    "{x}++", "++{x}", "{x}--", "--{x}",
    "{x} += ctx->step", "{x} -= ctx->step",
    "{x} = {x} + ctx->step", "{x} = ctx->step + {x}", "{x} = {x} - ctx->step",
]


def _scan_cases(tmp_path: Path, cases: dict[str, str], extension: str = "c"):
    expected = {}
    for name, body in cases.items():
        code = _TYPES + f"void test({_PARAMS}) {{\n" + body + "\n}\n"
        filename = f"{name}.{extension}"
        (tmp_path / filename).write_text(code, encoding="utf-8")
        expected[filename] = {
            lineno for lineno, line in enumerate(code.splitlines(), 1) if "// hit" in line
        }
    found = {filename: set() for filename in expected}
    candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path))
    for candidate in candidates:
        found[candidate.file].add(candidate.line)
    for filename, lines in expected.items():
        if lines:
            assert lines <= found[filename], (filename, lines, found[filename])
        else:
            assert not found[filename], (filename, found[filename])
    return candidates


@pytest.mark.parametrize("extension", ["c", "cpp"])
def test_member_update_operator_loop_and_sink_matrix(tmp_path: Path, extension: str) -> None:
    cases = {}
    accesses = {
        "array": "buf[ctx->idx] = 0; // hit",
        "pointer": "*(buf + ctx->idx) = 0; // hit",
        "field": "(ctx->items + ctx->idx)->value = 0; // hit",
        "memory": "memcpy(buf + ctx->idx, src, 1); // hit",
        "derived": "char *p = buf + ctx->idx;\n*p = 0; // hit",
        "cursor": "*ctx->p = 0; // hit",
    }
    for kind, access in accesses.items():
        for index, template in enumerate(_UPDATES):
            update = template.format(x="ctx->p" if kind == "cursor" else "ctx->idx")
            loops = {
                "while_after": f"while (remain > 0) {{\n{access}\n{update};\nremain--;\n}}",
                "while_before": f"while (remain > 0) {{\n{update};\n{access}\nremain--;\n}}",
                "do": f"do {{\n{access}\n{update};\n}} while (--remain);",
                "for_body": f"for (; remain > 0;) {{\n{access}\n{update};\nremain--;\n}}",
                "for_step": f"for (k = 0; remain > 0; {update}) {{\n{access}\nremain--;\n}}",
                "for_comma": f"for (; remain > 0; remain--, {update}, k++) {{\n{access}\n}}",
                "for_empty_cond": f"for (;; {update}) {{\n{access}\nif (--remain == 0) break;\n}}",
            }
            for loop, body in loops.items():
                cases[f"{kind}_{index}_{loop}"] = body
    _scan_cases(tmp_path, cases, extension)


@pytest.mark.parametrize("extension", ["c", "cpp"])
def test_lvalue_member_shapes(tmp_path: Path, extension: str) -> None:
    expressions = [
        "idx", "state.idx", "ctx->idx", "ctx->inner.idx", "ctx->next->idx",
        "(*ctx).idx", "ctx->items[k].idx", "ctx->positions[k]", "states[k].idx",
        "ctx->slot.idx", "*idxp",
    ]
    cases = {
        f"shape_{index}": (
            "unsigned idx; State state, states[4];\n"
            f"while (remain > 0) {{\nbuf[{expression}] = 0; // hit\n"
            f"({expression}) += ctx->step;\nremain--;\n}}"
        )
        for index, expression in enumerate(expressions)
    }
    candidates = _scan_cases(tmp_path, cases, extension)
    descriptions = "\n".join(c.description for c in candidates)
    for expression in expressions:
        assert expression in descriptions
    assert "索引步长/变化量: ctx->step" in descriptions


@pytest.mark.parametrize("extension", ["c", "cpp"])
def test_inline_member_updates_and_pointer_cursor_sinks(tmp_path: Path, extension: str) -> None:
    cases = {}
    for index, template in enumerate(_UPDATES):
        expression = template.format(x="ctx->idx")
        pointer = template.format(x="ctx->p")
        for kind, access in {
            "array": f"buf[({expression})] = 0; // hit",
            "pointer": f"*(buf + ({expression})) = 0; // hit",
            "field": f"(ctx->items + ({expression}))->value = 0; // hit",
            "memory": f"memcpy(buf + ({expression}), src, 1); // hit",
            "derived": f"char *p = buf + ({expression});\n*p = 0; // hit",
            "cursor": f"*({pointer}) = 0; // hit",
            "cursor_read": f"char byte = *({pointer}); // hit",
            "cursor_mem": f"memcpy(({pointer}), src, 1); // hit",
        }.items():
            cases[f"inline_{kind}_{index}"] = f"while (remain > 0) {{\n{access}\nremain--;\n}}"
    cases.update({
        "cursor_field": "while (remain > 0) {\nctx->items->value = 0; // hit\nctx->items++;\nremain--;\n}",
        "cursor_array": "while (remain > 0) {\nctx->p[2] = 0; // hit\nctx->p -= ctx->step;\nremain--;\n}",
        "cursor_plain_memcpy": "char *dst = buf;\nwhile (remain > 0) {\nmemcpy(dst, src, ctx->step); // hit\ndst += ctx->step;\nremain--;\n}",
    })
    _scan_cases(tmp_path, cases, extension)


def test_member_copy_length_and_destination(tmp_path: Path) -> None:
    cases = {}
    for index, update in enumerate(_UPDATES[4:]):
        statement = update.format(x="ctx->p")
        cases[f"copy_{index}"] = (
            "while (remain > 0) {\ncopy_from_user(ctx->p, src, ctx->step); // hit\n"
            f"{statement};\nremain--;\n}}"
        )
        cases[f"copy_inline_{index}"] = (
            f"while (remain > 0) {{\ncopy_from_user(({statement}), src, ctx->step); // hit\n"
            "remain--;\n}"
        )
    cases["copy_for_comma"] = "for (; remain > 0; ctx->p = ctx->step + ctx->p, remain--) {\ncopy_from_user(ctx->p, src, ctx->step); // hit\n}"
    cases["copy_do"] = "do {\ncopy_from_user(ctx->p, src, ctx->step); // hit\nctx->p -= ctx->step;\n} while (--remain);"
    cases["copy_length_mismatch"] = "while (remain > 0) {\ncopy_from_user(ctx->p, src, ctx->idx);\nctx->p += ctx->step;\nremain--;\n}"
    cases["copy_destination_mismatch"] = "while (remain > 0) {\ncopy_from_user(other->p, src, ctx->step);\nctx->p += ctx->step;\nremain--;\n}"
    cases["copy_nested"] = "while (remain > 0) {\ncopy_from_user(ctx->items[k].p, src, ctx->items[k].idx); // hit\nctx->items[k].p += ctx->items[k].idx;\nremain--;\n}"
    cases["copy_inline_mismatch"] = "while (remain > 0) {\ncopy_from_user((ctx->p += ctx->step), src, ctx->idx);\nremain--;\n}"
    candidates = _scan_cases(tmp_path, cases)
    for candidate in candidates:
        nested = candidate.file == "copy_nested.c"
        assert candidate.metadata["focus_variable"] == ("ctx->items[k].idx" if nested else "ctx->step")
        assert candidate.metadata["target_variable"] == ("ctx->items[k].p" if nested else "ctx->p")


def test_member_guards_and_receiver_identity(tmp_path: Path) -> None:
    cases = {
        "different_object": "while (remain > 0) {\nbuf[other->idx] = 0;\nctx->idx++;\nremain--;\n}",
        "different_field": "while (remain > 0) {\nbuf[ctx->step] = 0;\nctx->idx++;\nremain--;\n}",
        "unchanged_member": "while (remain > 0) {\nbuf[ctx->idx] = 0;\nremain--;\n}",
        "other_object_guard": "while (remain > 0) {\nif (other->idx < k) {\nbuf[ctx->idx] = 0; // hit\n}\nctx->idx++;\nremain--;\n}",
        "member_if_guard": "while (remain > 0) {\nif (ctx->idx < k) {\nbuf[ctx->idx] = 0;\n}\nctx->idx++;\nremain--;\n}",
        "member_fail_fast": "while (remain > 0) {\nif (ctx->idx >= k) return;\nbuf[ctx->idx] = 0;\nctx->idx++;\nremain--;\n}",
        "member_macro_guard": "while (remain > 0) {\nCHECK_RET(ctx->idx < k, -1);\nbuf[ctx->idx] = 0;\nctx->idx++;\nremain--;\n}",
        "member_while_bound": "while (ctx->idx < k) {\nbuf[ctx->idx] = 0;\nctx->idx++;\n}",
        "member_for_bound": "for (; ctx->idx < k; ctx->idx++) {\nbuf[ctx->idx] = 0;\n}",
        "member_for_empty_step": "for (; ctx->idx < k;) {\nbuf[ctx->idx] = 0;\nctx->idx++;\n}",
        "postfix_guard": "while (remain > 0) {\nif (ctx->idx < k) {\nbuf[ctx->idx++] = 0;\n}\nremain--;\n}",
        "prefix_old_guard": "while (remain > 0) {\nif (ctx->idx < k) {\nbuf[++ctx->idx] = 0; // hit\n}\nremain--;\n}",
        "assignment_old_guard": "while (remain > 0) {\nif (ctx->idx >= k) return;\nbuf[ctx->idx += ctx->step] = 0; // hit\nremain--;\n}",
        "copy_member_guard": "while (remain > 0) {\nif (ctx->step > k) return;\ncopy_from_user(ctx->p, src, ctx->step);\nctx->p += ctx->step;\nremain--;\n}",
        "cursor_guard": "while (ctx->p < buf + k) {\n*ctx->p = 0;\nctx->p++;\n}",
        "cursor_postfix_guard": "while (ctx->p < buf + k) {\n*ctx->p++ = 0;\n}",
        "cursor_prefix_guard": "while (ctx->p < buf + k) {\n*++ctx->p = 0; // hit\n}",
        "outside_loop": "buf[ctx->idx] = 0;\nctx->idx++;",
    }
    _scan_cases(tmp_path, cases)


def test_cpp_this_member_updates(tmp_path: Path) -> None:
    source = tmp_path / "this.cpp"
    source.write_text("""
class Cursor {
    unsigned idx, step;
    char *ptr;
    void fill(char *buf, unsigned remain) {
        while (remain > 0) {
            buf[this->idx] = 0;
            this->idx -= this->step;
            *this->ptr++ = 0;
            remain--;
        }
    }
};
""", encoding="utf-8")
    candidates = list(LoopMutIdxOobAnalyzer().find_candidates(tmp_path))
    assert {7, 9} <= {candidate.line for candidate in candidates}
    descriptions = "\n".join(candidate.description for candidate in candidates)
    assert "this->idx" in descriptions
    assert "this->ptr" in descriptions
