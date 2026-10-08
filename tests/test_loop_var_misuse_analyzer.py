from __future__ import annotations

from pathlib import Path

import pytest

from deephole_client.vulnerability_mining.engines.static_candidate.rules.loop_var_misuse.analyzer import Analyzer


def scan(tmp_path: Path, source: str, suffix: str = ".cpp"):
    (tmp_path / f"sample{suffix}").write_text(source, encoding="utf-8")
    return Analyzer().find_candidates(tmp_path)


def targets(candidates):
    return [
        variable["expression"]
        for candidate in candidates
        for loop in candidate.metadata["loops"]
        for variable in loop["unused_variables"]
    ]


@pytest.mark.parametrize("update", [
    "j++", "++j", "j--", "--j", "j += step", "j -= step",
    "j = j + step", "j = step + j", "j = j - step", "j = (j) + step",
])
@pytest.mark.parametrize("in_header", [True, False])
def test_all_add_subtract_forms_are_candidates_without_body_use(tmp_path, update, in_header):
    source = (
        f"void f() {{ for (int j = 0; j < m; {update}) work(); }}"
        if in_header else
        f"void f() {{ int j = 0; while (j < m) {{ {update}; work(); }} }}"
    )
    assert targets(scan(tmp_path, source)) == ["j"]


@pytest.mark.parametrize("target", [
    "ctx->idx", "obj.idx", "state.inner.idx", "slots[k].idx",
    "ctx->slots[k].idx", "state.positions[k]", "(*ctx).idx", "*cursor",
    "ctx->cursor", "ns::state.idx",
])
def test_member_array_and_dereference_targets(tmp_path, target):
    source = f"void f() {{ for ({target} = 0; {target} < n; ++({target})) work(); }}"
    assert targets(scan(tmp_path, source)) == [f"({target})"]


@pytest.mark.parametrize("source, expected", [
    ("void f() { while (j-- > 0) work(); }", ["j"]),
    ("void f() { do { work(); } while (--ctx->left); }", ["ctx->left"]),
    ("void f() { for (;;) { ctx->idx += 2; work(); } }", ["ctx->idx"]),
    ("void f() { for (p = begin; p != end; p = next(p)) work(); }", ["p"]),
    ("void f() { for (int i = 0; i < n; ++i) { out[0] = in[0]; } }", ["i"]),
    ("void f() { while (next_record()) { process(v); ctx->offset += ctx->stride; } }", ["ctx->offset"]),
    ("void f() { for (; j < m; ++j) { j = 0; } }", ["j"]),
    ("void f() { for (; j < m; ++j) { sizeof(j); alignof(j); } }", ["j"]),
    ("void f() { for (; j < m; ++j) { const char *s = \"j\"; /* use(j) */ } }", ["j"]),
    ("void f() { for (; j < m; ++j) { work(); } consume(j); }", ["j"]),
    ("void f() { for (int i = 0; i < n; ++i) for (int j = 0; j < m; ++j) a[i] = 1; }", ["j"]),
    ("void f() { for (ctx->row=0; ctx->row<rows; ++ctx->row) for (ctx->col=0; ctx->col<cols; ++ctx->col) a[ctx->row][ctx->row]=0; }", ["ctx->col"]),
])
def test_uniform_detection(tmp_path, source, expected):
    assert targets(scan(tmp_path, source)) == expected


@pytest.mark.parametrize("body", [
    "a[j] = value;", "consume(j);", "consume(&j);", "result = j;",
    "if (j) work();", "if (stop) { consume(j); }", "assert(j < limit);",
    "a[j++] = value;", "a[++j] = value;", "consume(j += step);",
    "consume(j -= step);", "consume(j = j + step);", "v = (j++, j);",
    "if (j++) work();", "j++ && work();", "consume((work(), j++));",
    "consume(j *= 2);", "consume(j |= mask);",
    "auto get = [j]() { return 0; };", "for (int k = j; k < n; ++k) consume(k);",
])
def test_explicit_body_reads_and_consumed_updates_suppress_candidate(tmp_path, body):
    assert scan(tmp_path, f"void f() {{ for (int j = 0; j < m; ++j) {{ {body} }} }}") == []


@pytest.mark.parametrize("body", [
    "j++;", "(j++);", "(void)j++;", "j++, work();", "work(), j++;",
    "flag ? j++ : j--;", "j = j + step;", "j = j + j;", "j += j;", "j -= j;",
    "auto get = [&]() { consume(j); };",
    "auto get = [j=0]() { consume(j); };", "static_cast<void>(j++);",
    "decltype(j) value;", "(j /* update */)++;",
])
def test_discarded_updates_and_deferred_lambda_body_are_not_usage(tmp_path, body):
    assert targets(scan(tmp_path, f"void f() {{ for (int j=0; j<m; ++j) {{ {body} }} }}")) == ["j"]


@pytest.mark.parametrize("target, body", [
    ("ctx->idx", "consume((*ctx).idx);"),
    ("(*ctx).idx", "consume(ctx->idx);"),
    ("slots[(k)].idx", "consume(slots[k].idx);"),
    ("ctx->idx", "consume(&ctx->idx);"),
    ("p", "consume(p->value);"),
    ("ctx->p", "ctx->p->value = v;"),
    ("*cursor", "consume(*cursor);"),
])
def test_member_equivalence_and_pointer_address_computation_are_uses(tmp_path, target, body):
    assert scan(tmp_path, f"void f() {{ while (next()) {{ ++({target}); {body} }} }}") == []


@pytest.mark.parametrize("target, body", [
    ("ctx->idx", "consume(ctx->other);"),
    ("left.idx", "consume(right.idx);"),
    ("slots[k].idx", "consume(slots[q].idx);"),
    ("ctx->idx", "ctx->idx = 0;"),
    ("ctx->idx", "consume(ctx->idx_extra);"),
])
def test_other_members_or_writes_do_not_satisfy_use(tmp_path, target, body):
    assert targets(scan(tmp_path, f"void f() {{ for (; ready; ++({target})) {{ {body} }} }}")) == [f"({target})"]


def test_class_and_union_members(tmp_path):
    result = scan(tmp_path, """
        union U { int idx; int value; } u;
        class C {
            int idx;
            void run() { for (this->idx=0; this->idx<n; ++this->idx) work(); }
        };
        void run_union() { for (u.idx=0; u.idx<n; ++u.idx) work(); }
    """)
    assert targets(result) == ["this->idx", "u.idx"]
    assert [candidate.function for candidate in result] == ["run", "run_union"]


def test_declared_implicit_members_match_explicit_this_and_respect_shadowing(tmp_path):
    result = scan(tmp_path, """
        class C {
            int idx;
            void used() { for (idx=0;idx<n;++idx) consume(this->idx); }
            void explicit_used() { for (this->idx=0;idx<n;++this->idx) consume(idx); }
            void shadowed() { for (idx=0;idx<n;++idx) { int idx=0; consume(idx); } }
        };
    """)
    assert [candidate.function for candidate in result] == ["shadowed"]
    assert targets(result) == ["idx"]


def test_comments_do_not_prevent_equivalent_parenthesized_member_matching(tmp_path):
    assert scan(tmp_path, "void f() { for(;ready;++(ctx /* pointer */)->idx) consume((*ctx).idx); }") == []


def test_same_name_shadowing_does_not_hide_unused_outer_variable(tmp_path):
    source = "void f() { for (int j=0; j<n; ++j) { for (int j=0; j<m; ++j) consume(j); } }"
    result = scan(tmp_path, source)
    assert targets(result) == ["j"]
    assert result[0].metadata["loops"][0]["column"] == source.index("for") + 1


def test_block_shadowing_and_lifetime(tmp_path):
    source = """
        void unused() {
            for (int j=0; j<n; ++j) { int j=0; consume(j); }
        }
        void used() {
            for (int j=0; j<n; ++j) { { int j=0; consume(j); } consume(j); }
        }
    """
    result = scan(tmp_path, source)
    assert [candidate.function for candidate in result] == ["unused"]


def test_member_roots_and_subscript_indices_respect_shadowing(tmp_path):
    result = scan(tmp_path, """
        void f(C *ctx, int k) {
            for (; ready; ++ctx->idx) { C *ctx = other; consume(ctx->idx); }
            for (; ready; ++slots[k].idx) { int k = 1; consume(slots[k].idx); }
        }
    """)
    assert targets(result) == ["ctx->idx", "slots[k].idx"]


def test_multiple_loop_evidence_survives_function_and_same_line_aggregation(tmp_path):
    source = "void f() { for(int i=0;i<n;++i) for(int j=0;j<m;++j) ping(); for(int k=0;k<q;++k) work(); }"
    result = scan(tmp_path, source)
    assert len(result) == 1
    assert targets(result) == ["i", "j", "k"]
    loops = result[0].metadata["loops"]
    assert len({loop["column"] for loop in loops}) == 3
    assert all(loop["line"] == 1 for loop in loops)
    assert result[0].metadata["subject"] == "i, j, k"
    assert all(f"`{name}`" in result[0].description for name in ("i", "j", "k"))


def test_deep_nesting_applies_same_rule_at_each_level(tmp_path):
    source = "void f() { " + " ".join(f"for(int i{k}=0;i{k}<n;++i{k})" for k in range(20)) + "consume(i0); }"
    assert targets(scan(tmp_path, source)) == [f"i{k}" for k in range(1, 20)]


def test_multiple_updates_do_not_duplicate_target_and_bounds_are_not_targets(tmp_path):
    result = scan(tmp_path, "void f() { for(int j=0; j<m; ++j) { j+=step; j=j+step; } }")
    assert targets(result) == ["j"]
    assert len(result[0].metadata["loops"][0]["unused_variables"][0]["updates"]) == 3


@pytest.mark.parametrize("call", ["process(ctx)", "process(*ctx)", "ctx->process()"])
def test_whole_object_calls_keep_candidate_and_record_indirect_use(tmp_path, call):
    result = scan(tmp_path, f"void f() {{ for (; ready; ++ctx->idx) {{ {call}; }} }}")
    assert targets(result) == ["ctx->idx"]
    indirect = result[0].metadata["loops"][0]["unused_variables"][0]["possible_indirect_uses"]
    assert indirect == [{"line": 1, "expression": call}]
    assert "间接使用" in result[0].description


def test_unrelated_member_call_does_not_claim_indirect_use(tmp_path):
    result = scan(tmp_path, "void f() { for (; ready; ++ctx->idx) process(ctx->other); }")
    assert result[0].metadata["loops"][0]["unused_variables"][0]["possible_indirect_uses"] == []


def test_incomplete_loop_is_skipped_with_diagnostic(tmp_path, caplog):
    result = scan(tmp_path, "void f() { for(int j=0;j<m;++j) { int x = ; } }")
    assert result == []
    assert "skipping incomplete loop" in caplog.text


def test_valid_loop_in_file_with_unrelated_parse_error_is_still_scanned(tmp_path):
    result = scan(tmp_path, "void bad() { int x = ; } void good() { for(int j=0;j<m;++j) work(); }")
    assert [candidate.function for candidate in result] == ["good"]


def test_source_filters_progress_c_support_and_requested_subtree(tmp_path):
    source = "void f() { for(int j=0;j<m;++j) work(); }"
    for directory in ("src", "vendor", ".opendeephole", "outside"):
        folder = tmp_path / directory
        folder.mkdir()
        (folder / "sample.c").write_text(source)
    analyzer = Analyzer()
    progress = []
    analyzer.on_file_progress = lambda current, total: progress.append((current, total))
    result = analyzer.find_candidates(tmp_path / "src", db=object())
    assert targets(result) == ["j"]
    assert result[0].file == "sample.c"
    assert progress == [(1, 1)]
    result = analyzer.find_candidates(tmp_path)
    assert {candidate.file for candidate in result} == {"src/sample.c", "outside/sample.c"}


def test_loops_in_lambda_are_analyzed_without_executing_body_in_parent(tmp_path):
    result = scan(tmp_path, "void f() { auto fn = []() { for(int j=0;j<m;++j) work(); }; }")
    assert targets(result) == ["j"]
    assert result[0].function.startswith("<lambda@")
