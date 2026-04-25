"""整数翻转检测器测试。

测试各模块的核心功能：
- SinkChecker: 危险使用点检测
- GuardChecker: 守卫检测 + 一致性
- ArithScanner: 算术操作检测 + 跳过规则
- VarTracer: 变量来源追溯
- 集成测试: 完整的 sink → arith → trace 流程
"""

from __future__ import annotations

import sys
from pathlib import Path

import tree_sitter_cpp
from tree_sitter import Language, Parser

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from checkers.intoverflow.arith_scanner import ArithScanner
from checkers.intoverflow.guard_checker import GuardChecker
from checkers.intoverflow.sink_checker import SinkChecker
from checkers.intoverflow.var_tracer import VarTracer
from code_parser.code_utils import find_nodes_by_type

_CPP_LANG = Language(tree_sitter_cpp.language())
_PARSER = Parser(_CPP_LANG)


def _parse(code: str):
    """解析 C 代码片段，返回 AST root。"""
    return _PARSER.parse(code.encode()).root_node


def _find_sub_node(root):
    """找到第一个减法 binary_expression 节点。"""
    for b in find_nodes_by_type(root, "binary_expression"):
        op = b.child_by_field_name("operator")
        if op and op.text == b"-":
            return b
    return None


def _find_add_node(root):
    """找到第一个加法 binary_expression 节点。"""
    for b in find_nodes_by_type(root, "binary_expression"):
        op = b.child_by_field_name("operator")
        if op and op.text == b"+":
            return b
    return None


# ============================================================
# SinkChecker 测试
# ============================================================

class TestSinkChecker:
    def setup_method(self):
        self.checker = SinkChecker()

    def test_array_subscript(self):
        root = _parse("void f() { arr[idx] = 1; }")
        sinks = self.checker.find_sinks(root)
        assert any(s.sink_type == "array_index" and s.var_name == "idx" for s in sinks)

    def test_array_subscript_constant_skipped(self):
        root = _parse("void f() { arr[0] = 1; }")
        sinks = self.checker.find_sinks(root)
        assert not any(s.sink_type == "array_index" for s in sinks)

    def test_ptr_offset(self):
        root = _parse("void f() { *(ptr + offset) = 1; }")
        sinks = self.checker.find_sinks(root)
        assert any(s.sink_type == "ptr_offset" for s in sinks)

    def test_memcpy_length(self):
        root = _parse("void f() { memcpy(dst, src, len); }")
        sinks = self.checker.find_sinks(root)
        assert any(
            s.sink_type == "mem_func_arg" and s.var_name == "len"
            for s in sinks
        )

    def test_malloc_size(self):
        root = _parse("void f() { malloc(size); }")
        sinks = self.checker.find_sinks(root)
        assert any(
            s.sink_type == "mem_func_arg" and s.var_name == "size"
            for s in sinks
        )

    def test_loop_bound_with_dangerous_body(self):
        root = _parse("""
        void f() {
            for (int i = 0; i < count; i++) {
                arr[i] = 0;
            }
        }
        """)
        sinks = self.checker.find_sinks(root)
        assert any(
            s.sink_type == "loop_bound" and s.var_name == "count"
            for s in sinks
        )

    def test_loop_bound_without_dangerous_body_skipped(self):
        root = _parse("""
        void f() {
            for (int i = 0; i < count; i++) {
                x = i + 1;
            }
        }
        """)
        sinks = self.checker.find_sinks(root)
        assert not any(s.sink_type == "loop_bound" for s in sinks)

    def test_memcpy_s(self):
        root = _parse("void f() { memcpy_s(dst, dstLen, src, srcLen); }")
        sinks = self.checker.find_sinks(root)
        vars_found = {s.var_name for s in sinks if s.sink_type == "mem_func_arg"}
        assert "dstLen" in vars_found
        assert "srcLen" in vars_found


# ============================================================
# GuardChecker 测试
# ============================================================

class TestGuardChecker:
    def setup_method(self):
        self.checker = GuardChecker()

    def test_enclosing_guard_consistent(self):
        root = _parse("""
        void f(uint32_t x) {
            if (x >= 8) {
                uint32_t y = x - 8;
            }
        }
        """)
        sub_node = _find_sub_node(root)
        assert sub_node is not None
        status, _ = self.checker.check_subtraction(sub_node, "x", "8", root)
        assert status == "guarded"

    def test_no_guard(self):
        root = _parse("""
        void f(uint32_t x) {
            uint32_t y = x - 8;
        }
        """)
        sub_node = _find_sub_node(root)
        assert sub_node is not None
        status, _ = self.checker.check_subtraction(sub_node, "x", "8", root)
        assert status == "none"

    def test_inconsistent_guard(self):
        root = _parse("""
        void f(uint32_t x) {
            if (x >= 4) {
                uint32_t y = x - 8;
            }
        }
        """)
        sub_node = _find_sub_node(root)
        assert sub_node is not None
        status, _ = self.checker.check_subtraction(sub_node, "x", "8", root)
        assert status == "inconsistent"

    def test_preceding_early_return_guard(self):
        root = _parse("""
        void f(uint32_t x) {
            if (x < 8) return;
            uint32_t y = x - 8;
        }
        """)
        sub_node = _find_sub_node(root)
        assert sub_node is not None
        status, _ = self.checker.check_subtraction(sub_node, "x", "8", root)
        assert status == "guarded"


# ============================================================
# ArithScanner 测试
# ============================================================

class TestArithScanner:
    def setup_method(self):
        self.scanner = ArithScanner()

    def test_unguarded_subtraction(self):
        root = _parse("""
        void f(uint32_t len) {
            uint32_t payload = len - 8;
            memcpy(dst, src, payload);
        }
        """)
        result = self.scanner.find_unguarded_arith_for_var(root, "payload", 99)
        assert result is not None
        assert result.op == "-"
        assert result.guard_status == "none"

    def test_guarded_subtraction_returns_none(self):
        root = _parse("""
        void f(uint32_t len) {
            if (len >= 8) {
                uint32_t payload = len - 8;
            }
        }
        """)
        result = self.scanner.find_unguarded_arith_for_var(root, "payload", 99)
        assert result is None

    def test_skip_pure_constants(self):
        root = _parse("""
        void f() {
            uint32_t x = MAX_SIZE - HEADER_SIZE;
            arr[x] = 0;
        }
        """)
        result = self.scanner.find_unguarded_arith_for_var(root, "x", 99)
        assert result is None

    def test_keep_variable_plus_macro(self):
        root = _parse("""
        void f(uint32_t len) {
            uint32_t x = len - HEADER_SIZE;
            arr[x] = 0;
        }
        """)
        # before_line must be after the assignment (line ~2-3 in parsed AST)
        result = self.scanner.find_unguarded_arith_for_var(root, "x", 99)
        assert result is not None


# ============================================================
# VarTracer 测试
# ============================================================

class TestVarTracer:
    def test_trace_to_parameter(self):
        root = _parse("""
        void f(uint32_t len) {
            uint32_t x = len;
        }
        """)
        tracer = VarTracer(["len"])
        origin = tracer.trace(root, "x", 99)
        assert origin.origin_type == "parameter"
        assert origin.param_index == 0

    def test_trace_literal(self):
        root = _parse("""
        void f() {
            uint32_t x = 42;
        }
        """)
        tracer = VarTracer([])
        origin = tracer.trace(root, "x", 99)
        assert origin.origin_type == "literal"

    def test_trace_through_assignment_chain(self):
        root = _parse("""
        void f(uint32_t data) {
            uint32_t a = data;
            uint32_t b = a;
        }
        """)
        tracer = VarTracer(["data"])
        origin = tracer.trace(root, "b", 99)
        assert origin.origin_type == "parameter"
        assert origin.param_index == 0

    def test_trace_function_return(self):
        root = _parse("""
        void f(uint8_t *buf) {
            uint32_t len = parseHeader(buf);
        }
        """)
        tracer = VarTracer(["buf"])
        origin = tracer.trace(root, "len", 99)
        assert origin.origin_type == "call_return"

    def test_trace_macro_constant(self):
        root = _parse("""
        void f() {
            uint32_t x = MAX_SIZE;
        }
        """)
        tracer = VarTracer([])
        origin = tracer.trace(root, "MAX_SIZE", 99)
        assert origin.origin_type == "literal"

    def test_parameter_direct(self):
        root = _parse("void f(uint32_t len) { }")
        tracer = VarTracer(["len"])
        origin = tracer.trace(root, "len", 99)
        assert origin.origin_type == "parameter"
        assert origin.param_index == 0


# ============================================================
# 集成测试
# ============================================================

class TestIntegration:
    """端到端测试：sink → arith → var_trace 完整流程。"""

    def test_full_pipeline_subtraction(self):
        """参数减常量无守卫，结果用于 memcpy → 应检出。"""
        root = _parse("""
        void ProcessPayload(uint8_t *data, uint32_t total_len) {
            uint32_t body_len = total_len - 8;
            memcpy(buffer, data, body_len);
        }
        """)
        sinks = SinkChecker().find_sinks(root)
        mem_sinks = [s for s in sinks if s.sink_type == "mem_func_arg" and s.var_name == "body_len"]
        assert len(mem_sinks) > 0, f"Expected mem_func_arg sink for body_len, got: {sinks}"

        sink = mem_sinks[0]
        arith = ArithScanner().find_unguarded_arith_for_var(root, sink.var_name, sink.line)
        assert arith is not None, "Expected unguarded arithmetic for body_len"
        assert arith.op == "-"
        assert arith.guard_status == "none"

        tracer = VarTracer(["data", "total_len"])
        for operand in arith.operands:
            origin = tracer.trace(root, operand, arith.line)
            if origin.origin_type == "parameter":
                assert origin.param_index == 1  # total_len
                break
        else:
            raise AssertionError("Expected operand traced to parameter")

    def test_full_pipeline_guarded_skipped(self):
        """有守卫的减法 → 不应检出。"""
        root = _parse("""
        void ProcessPayload(uint8_t *data, uint32_t total_len) {
            if (total_len < 8) return;
            uint32_t body_len = total_len - 8;
            memcpy(buffer, data, body_len);
        }
        """)
        sinks = SinkChecker().find_sinks(root)
        mem_sinks = [s for s in sinks if s.sink_type == "mem_func_arg" and s.var_name == "body_len"]
        assert len(mem_sinks) > 0

        sink = mem_sinks[0]
        arith = ArithScanner().find_unguarded_arith_for_var(root, sink.var_name, sink.line)
        assert arith is None, "Guarded subtraction should not be reported"

    def test_addition_overflow(self):
        """加法溢出，结果用于 malloc → 应检出。"""
        root = _parse("""
        void Alloc(uint32_t headerLen, uint32_t bodyLen) {
            uint32_t totalLen = headerLen + bodyLen;
            char *buf = malloc(totalLen);
        }
        """)
        sinks = SinkChecker().find_sinks(root)
        mem_sinks = [s for s in sinks if s.sink_type == "mem_func_arg" and s.var_name == "totalLen"]
        assert len(mem_sinks) > 0

        sink = mem_sinks[0]
        arith = ArithScanner().find_unguarded_arith_for_var(root, sink.var_name, sink.line)
        assert arith is not None
        assert arith.op == "+"
        assert arith.guard_status == "none"

    def test_constant_only_skipped(self):
        """纯常量减法 → 不应检出。"""
        root = _parse("""
        void f() {
            uint32_t x = MAX_SIZE - HEADER_SIZE;
            arr[x] = 0;
        }
        """)
        sinks = SinkChecker().find_sinks(root)
        arr_sinks = [s for s in sinks if s.var_name == "x"]
        if arr_sinks:
            sink = arr_sinks[0]
            arith = ArithScanner().find_unguarded_arith_for_var(root, sink.var_name, sink.line)
            assert arith is None, "Pure constant arithmetic should be skipped"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
