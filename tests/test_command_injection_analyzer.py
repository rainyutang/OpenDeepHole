import json
from pathlib import Path

import pytest

from deephole_client.vulnerability_mining.engines.static_candidate.rules.command_injection.analyzer import Analyzer


RULE = Path(__file__).resolve().parents[1] / "deephole_client/vulnerability_mining/engines/static_candidate/rules/command_injection"
CATALOG = json.loads((RULE / "sink.json").read_text())


def scan(tmp_path, source, filename="example.cpp"):
    (tmp_path / filename).write_text(source, encoding="utf-8")
    analyzer = Analyzer()
    return analyzer, analyzer.find_candidates(tmp_path)


def matches(candidates):
    return [match for candidate in candidates for match in candidate.metadata["matches"]]


def apis(candidates):
    return [match["api"] for match in matches(candidates)]


@pytest.mark.parametrize("api", CATALOG["functions"])
def test_every_exact_function(tmp_path, api):
    _, candidates = scan(tmp_path, f'void audit_target(char *command) {{ {api}(command); }}')
    assert apis(candidates) == [api]
    assert len(candidates) == 1


@pytest.mark.parametrize("api", CATALOG["methods"])
def test_every_typed_method(tmp_path, api):
    owner, method = api.rsplit("::", 1)
    _, candidates = scan(tmp_path, f'void audit_target(char *command) {{ {owner} process; process.{method}(command); }}')
    assert apis(candidates) == [api]


@pytest.mark.parametrize("api", CATALOG["constructors"])
@pytest.mark.parametrize("form", ['{api} child("program");', '{api} child{{"program"}};', 'new {api}("program");', '{api}("program");', 'std::make_unique<{api}>("program");', 'std::make_shared<{api}>("program");'])
def test_every_executing_constructor(tmp_path, api, form):
    _, candidates = scan(tmp_path, "void audit_target() { " + form.format(api=api) + " }")
    assert apis(candidates) == [api]
    assert matches(candidates)[0]["kind"] == "constructor"


@pytest.mark.parametrize("selector", CATALOG["conditional"]["syscall"])
def test_exact_syscall_selector(tmp_path, selector):
    _, candidates = scan(tmp_path, f'void audit_target() {{ syscall({selector}, program, arguments); }}')
    assert apis(candidates) == ["syscall"]


@pytest.mark.parametrize("lookup", CATALOG["conditional"]["symbol_lookup"])
def test_literal_symbol_lookup_and_subsequent_call(tmp_path, lookup):
    _, candidates = scan(tmp_path, f'void audit_target() {{ auto execute = (callback){lookup}(handle, "system", "version"); execute(command); }}')
    assert apis(candidates) == ["system", "system"]
    assert [match["kind"] for match in matches(candidates)] == ["symbol_lookup", "call"]


def test_catalog_is_literal_unique_and_complete(tmp_path):
    entries = CATALOG["functions"] + CATALOG["methods"] + CATALOG["constructors"]
    assert len(entries) == len(set(entries)) == 109
    assert all(not any(character in name for character in "*?[] ") for name in entries)
    assert not {"CreateProcess", "WinExec", "ShellExecute", "_popen", "_wsystem", "_execv"}.intersection(entries)


def test_no_fuzzy_matching_comments_strings_declarations_or_shadowed_values(tmp_path):
    source = '''
int system(const char *command);
void prototype(int system);
namespace application { void system(const char *command); }
using Alias = boost::process::child;
void audit_target() {
    // system(command); proc.start(command);
    const char *message = "system(command); popen(command)";
    const char *raw = R"marker(system(command);)marker";
    mysystem(command); System(command); system_wrapper(command);
    application::system(command); other::QProcess::start(command);
    CreateProcess(command); _popen(command); _wsystem(command);
    syscall(SYS_write, command); syscall(SYS_execve + 1, command);
    dlsym(handle, "mysystem"); dlsym(handle, symbol_name);
    std::make_unique<NotProcess>(command);
    boost::process::child function_declaration();
    boost::process::child *pointer;
    int system = 3;
    consume(system);
    auto execute = other;
    execute(command);
}
'''
    _, candidates = scan(tmp_path, source)
    assert candidates == []


def test_scope_aliases_and_reassignment(tmp_path):
    source = '''
namespace standard = std;
void audit_target(char *command) {
    auto execute = &standard::system;
    auto second = execute;
    (*second)(command);
    { auto second = unrelated; second(command); }
    second = unrelated;
    second(command);
    system(command);
}
'''
    _, candidates = scan(tmp_path, source)
    assert apis(candidates) == ["std::system", "std::system", "std::system", "system"]
    assert len(candidates) == 1
    assert "std::system" in candidates[0].metadata["subject"]


def test_conditional_assignment_does_not_prove_an_alias(tmp_path):
    _, candidates = scan(tmp_path, 'void audit_target() { auto execute = other; if (condition) execute = system; execute(command); }')
    assert apis(candidates) == ["system"]
    assert matches(candidates)[0]["kind"] == "reference"


def test_namespace_using_type_alias_and_exact_receiver(tmp_path):
    source = '''
namespace bp = boost::process;
using Process = QProcess;
typedef Process OtherProcess;
using std::system;
void audit_target(char *program) {
    OtherProcess *process;
    process->start(program);
    (*process).startCommand(program);
    auto smart = std::make_unique<QProcess>();
    smart->start(program);
    bp::child child(program);
    system(program);
}
'''
    _, candidates = scan(tmp_path, source)
    assert apis(candidates) == ["QProcess::start", "QProcess::startCommand", "QProcess::start", "boost::process::child", "std::system"]


def test_fields_inheritance_and_unknown_receivers(tmp_path):
    source = '''
struct Wrapper { QProcess process; };
class Derived : public QProcess {
    QProcess *member;
    void audit_target(char *command) { member->start(command); this->start(command); start(command); }
};
class Overrides : public QProcess { void start(); void safe() { start(); } };
void audit_other(Wrapper wrapper, Unknown unknown) {
    wrapper.process.start("program");
    unknown.start("program");
}
'''
    analyzer, candidates = scan(tmp_path, source)
    assert apis(candidates) == ["QProcess::start"] * 4
    assert len(candidates) == 2
    assert any(item["reason"] == "unknown_receiver" for item in analyzer.diagnostics)


def test_macros_continuations_aliases_inactive_branches_and_undef(tmp_path):
    source = '''#define RUN(command) system(command); \\
    popen(command, "r")
#define EXEC system
#define NEXT EXEC
#define TEXT "system(command)"
void audit_target(char *command) { RUN(command); NEXT(command); }
#undef NEXT
void after_undef() { NEXT(command); }
#if 0
void inactive() { execl(program, program, 0); }
#endif
'''
    _, candidates = scan(tmp_path, source)
    by_function = {candidate.function: candidate for candidate in candidates}
    target = next(candidate for candidate in candidates if candidate.function.startswith("audit_target("))
    assert apis([target]) == ["popen", "system", "system"]
    assert all(match["kind"] == "macro_call" for match in matches([target]))
    assert not any(name.startswith("after_undef") for name in by_function)
    assert not any("TEXT" in name for name in by_function)
    assert any(name.startswith("inactive") for name in by_function)
    assert {match["line"] for candidate in candidates if "RUN@" in candidate.function for match in matches([candidate])} == {1, 2}


def test_local_macro_merges_into_function(tmp_path):
    _, candidates = scan(tmp_path, 'void audit_target() {\n#define RUN system\nRUN(command);\n}\n')
    assert len(candidates) == 1
    assert apis(candidates) == ["system", "system"]


def test_exact_included_headers_resolve_types_macros_and_namespace_aliases(tmp_path):
    (tmp_path / "include").mkdir()
    (tmp_path / "include/api.h").write_text('namespace bp = boost::process; using Process = QProcess;\n#define RUN(command) system(command)\n')
    _, candidates = scan(tmp_path, '#include "api.h"\nvoid audit_target(char *command) { Process process; process.start(command); bp::spawn(command); RUN(command); }')
    target = next(candidate for candidate in candidates if candidate.file == "example.cpp")
    assert apis([target]) == ["QProcess::start", "boost::process::spawn", "system"]


def test_no_alias_leakage_from_unincluded_file(tmp_path):
    (tmp_path / "other.h").write_text('using Process = QProcess;\n#define RUN system\n')
    _, candidates = scan(tmp_path, 'void audit_target(Process process) { process.start(command); RUN(command); }')
    assert not any(candidate.file == "example.cpp" for candidate in candidates)


def test_all_functions_lambdas_and_global_blocks_are_distinct(tmp_path):
    source = 'int global_value = system("global");\nvoid target(int value) { system("one"); [] { popen("nested", "r"); }(); [] { system("other"); }(); } void target(double value) { system("two"); }'
    _, candidates = scan(tmp_path, source)
    assert len(candidates) == 5
    assert len({candidate.function for candidate in candidates}) == 5
    assert all(len(candidate.metadata["matches"]) == 1 for candidate in candidates)
    assert len({(candidate.file, tuple(candidate.metadata["function_range"].values())) for candidate in candidates}) == 5


def test_byte_coordinates_crlf_utf8_and_large_rows(tmp_path):
    source = b"\r\n" * 270 + 'void audit_target() { /* 中文 */ ::std /* gap */ ::system\r\n(command); }'.encode()
    (tmp_path / "coords.C").write_bytes(source)
    candidates = Analyzer().find_candidates(tmp_path)
    assert apis(candidates) == ["std::system"]
    match = matches(candidates)[0]
    assert match["line"] == 271
    assert match["column"] == len('void audit_target() { /* 中文 */ '.encode()) + 1
    assert match["end_line"] == 272
    assert match["expression"] == '::std /* gap */ ::system\r\n(command)'


@pytest.mark.parametrize("extension", ["c", "cc", "cpp", "cxx", "c++", "h", "hh", "hpp", "hxx", "h++", "inl", "ipp", "tpp", "C", "HPP"])
def test_source_extensions_and_default_exclusions(tmp_path, extension):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor/ignored.c").write_text('void ignored() { system(command); }')
    _, candidates = scan(tmp_path, 'void audit_target() { system(command); }', f"target.{extension}")
    assert [candidate.file for candidate in candidates] == [f"target.{extension}"]


def test_partial_parse_preserves_other_execution_sites(tmp_path):
    analyzer, candidates = scan(tmp_path, '_Atomic(int) state;\nvoid audit_target() { system(command); }', "example.c")
    assert apis(candidates) == ["system"]
    assert any(item["reason"] == "parse_error" for item in analyzer.diagnostics)


def test_function_prototype_parameters_do_not_shadow_calls(tmp_path):
    _, candidates = scan(tmp_path, 'void prototype(int system); void audit_target() { system(command); }')
    assert apis(candidates) == ["system"]


def test_using_namespaces_and_out_of_line_fields(tmp_path):
    source = '''
namespace bp = boost::process;
using namespace bp;
class Owner { QProcess process; void audit_target(); };
void Owner::audit_target() { process.start(command); spawn(command); }
'''
    analyzer, candidates = scan(tmp_path, source)
    assert apis(candidates) == ["QProcess::start", "boost::process::spawn"]
    assert not analyzer.diagnostics


def test_macro_forward_alias_and_redefinition_use_call_site_bindings(tmp_path):
    source = '''#define RUN EXEC
#define EXEC system
void first() { RUN(command); }
#undef EXEC
#define EXEC popen
void second() { RUN(command); }
'''
    _, candidates = scan(tmp_path, source)
    first = next(candidate for candidate in candidates if candidate.function.startswith("first"))
    second = next(candidate for candidate in candidates if candidate.function.startswith("second"))
    assert apis([first]) == ["system"]
    assert apis([second]) == ["popen"]


def test_macro_call_does_not_ignore_local_shadowing(tmp_path):
    source = '#define RUN(command) system(command)\nvoid safe() { auto system = unrelated; RUN(command); }'
    _, candidates = scan(tmp_path, source)
    assert not any(candidate.function.startswith("safe") for candidate in candidates)


def test_macro_parameter_is_not_an_api_name(tmp_path):
    _, candidates = scan(tmp_path, '#define APPLY(system) system(command)\nvoid safe() { APPLY(other); }')
    assert not candidates


def test_qualified_function_pointer_aliases(tmp_path):
    _, candidates = scan(tmp_path, 'namespace execution { auto run = system; } namespace alias = execution; void audit_target() { alias::run(command); ::execution::run(command); }')
    assert apis(candidates) == ["system", "system", "system"]


def test_shadowed_conditional_entrypoints_are_not_sinks(tmp_path):
    _, candidates = scan(tmp_path, 'void safe() { auto syscall = unrelated; auto dlsym = other; syscall(SYS_execve, command); dlsym(handle, "system"); }')
    assert not candidates


def test_qualified_using_declarations(tmp_path):
    _, candidates = scan(tmp_path, 'namespace standard { using std::system; } void audit_target(){ standard::system(command); }')
    assert apis(candidates) == ["std::system"]


def test_inherited_using_method(tmp_path):
    _, candidates = scan(tmp_path, 'class Derived: public QProcess { public: using QProcess::start; }; void audit_target(Derived process){ process.start(command); }')
    assert apis(candidates) == ["QProcess::start"]


@pytest.mark.parametrize("declaration,receiver", [
    ("std::unique_ptr<QProcess> process;", "process.get()"),
    ("auto process = std::make_shared<QProcess>();", "process.get()"),
    ("using Process = std::unique_ptr<QProcess>; Process process;", "process"),
])
def test_smart_pointer_types(tmp_path, declaration, receiver):
    _, candidates = scan(tmp_path, f'void audit_target() {{ {declaration} {receiver}->start(command); }}')
    assert apis(candidates) == ["QProcess::start"]


def test_explicit_return_type_resolves_receiver(tmp_path):
    _, candidates = scan(tmp_path, 'QProcess* get_process(); void audit_target(){ get_process()->start(command); }')
    assert apis(candidates) == ["QProcess::start"]


def test_member_and_temporary_construction(tmp_path):
    source = '''
class Owner {
    boost::process::child child;
    Owner(char* command): child(command) {}
};
void audit_target() { boost::process::child{command}; }
'''
    _, candidates = scan(tmp_path, source)
    assert apis(candidates) == ["boost::process::child", "boost::process::child"]
    assert len(candidates) == 2


def test_lambda_capture_executes_in_enclosing_function(tmp_path):
    _, candidates = scan(tmp_path, 'void audit_target() { auto task = [value = system(command)] { popen(command, "r"); }; }')
    assert len(candidates) == 2
    parent = next(candidate for candidate in candidates if candidate.function.startswith("audit_target"))
    closure = next(candidate for candidate in candidates if candidate.function.startswith("<lambda"))
    assert apis([parent]) == ["system"]
    assert apis([closure]) == ["popen"]


def test_capture_shadowing_and_function_alias(tmp_path):
    _, candidates = scan(tmp_path, 'void audit_target() { auto safe = [system = other] { system(command); }; auto task = [system = system] { system(command); }; }')
    assert apis(candidates) == ["system", "system"]
    assert len(candidates) == 2


def test_typed_pointer_to_member_invocation(tmp_path):
    _, candidates = scan(tmp_path, 'void audit_target(QProcess process) { auto method = &QProcess::start; (process.*method)(command); }')
    assert apis(candidates) == ["QProcess::start", "QProcess::start"]
