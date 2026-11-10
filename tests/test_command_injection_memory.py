"""Coverage and object-lifetime regressions for bounded static analysis."""

import gc
import weakref
from collections import Counter
from pathlib import Path

import pytest

from deephole_client.vulnerability_mining.engines.static_candidate.rules.command_injection import analyzer as command


def write_sources(root, sources):
    for name, source in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")


def file_apis(candidates, filename):
    return [
        match["api"]
        for candidate in candidates if candidate.file == filename
        for match in candidate.metadata["matches"]
    ]


@pytest.fixture
def automatic_gc_disabled():
    was_enabled = gc.isenabled()
    gc.collect()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()
        gc.collect()


def track_units(monkeypatch):
    references = []
    original_init = command._Unit.__init__

    def tracked_init(self, *args, **kwargs):
        references.append(weakref.ref(self))
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(command._Unit, "__init__", tracked_init)
    return references


def test_targets_load_only_exact_closure_with_shared_transitive_and_cyclic_headers(tmp_path, monkeypatch):
    write_sources(tmp_path, {
        "include/api.h": '#include "base.h"\nnamespace bp = boost::process;\n',
        "include/base.h": '#include "api.h"\nusing Process = QProcess;\n#define EXEC(command) system(command)\n',
        "src/first.cpp": (
            '#include "api.h"\nvoid first(char *command) { Process process; '
            'process.start(command); EXEC(command); bp::spawn(command); }\n'
        ),
        "src/second.cpp": '#include "api.h"\nvoid second(char *command) { EXEC(command); }\n',
        "unrelated.h": 'using Process = UnrelatedProcess;\n',
    })
    closures = []
    original_connect = command._Analysis.connect

    def record_closure(self):
        closures.append(frozenset(path.relative_to(tmp_path).as_posix() for path in self.units))
        return original_connect(self)

    monkeypatch.setattr(command._Analysis, "connect", record_closure)
    candidates = command.Analyzer().find_candidates(tmp_path)

    headers = {"include/api.h", "include/base.h"}
    assert Counter(closures) == Counter([
        frozenset(headers), frozenset(headers),
        frozenset(headers | {"src/first.cpp"}),
        frozenset(headers | {"src/second.cpp"}),
        frozenset({"unrelated.h"}),
    ])
    assert file_apis(candidates, "src/first.cpp") == ["QProcess::start", "system", "boost::process::spawn"]
    assert file_apis(candidates, "src/second.cpp") == ["system"]
    assert file_apis(candidates, "include/base.h") == ["system"]
    assert sum(candidate.file == "include/base.h" for candidate in candidates) == 1
    assert not file_apis(candidates, "unrelated.h")
    assert [candidate.file for candidate in candidates] == sorted(candidate.file for candidate in candidates)


@pytest.mark.parametrize("denied_count,expected_api", [(0, "system"), (1, "popen"), (2, "execve")])
def test_include_precedence_falls_back_after_read_errors(tmp_path, monkeypatch, denied_count, expected_api):
    write_sources(tmp_path, {
        "src/api.h": '#define RUN(command) system(command)\n',
        "api.h": '#define RUN(command) popen(command, "r")\n',
        "include/api.h": '#define RUN(command) execve(command, argv, envp)\n',
        "src/main.cpp": '#include "api.h"\nvoid target(char *command) { RUN(command); }\n',
    })
    denied = {tmp_path / name for name in ("src/api.h", "api.h")[:denied_count]}
    original_read = Path.read_bytes

    def read_bytes(path):
        if path in denied:
            raise PermissionError("simulated inaccessible header")
        return original_read(path)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    analyzer = command.Analyzer()
    candidates = analyzer.find_candidates(tmp_path)

    assert file_apis(candidates, "src/main.cpp") == [expected_api]
    errors = [item for item in analyzer.diagnostics if item["reason"] == "read_error"]
    assert Counter(item["file"] for item in errors) == Counter(path.relative_to(tmp_path).as_posix() for path in denied)


def test_unincluded_source_global_assignments_do_not_pollute_shared_header(tmp_path):
    write_sources(tmp_path, {
        "api.h": 'extern int (*execute)(const char *);\n',
        "a.cpp": '#include "api.h"\nint setup = ((execute = system), 0);\n',
        "b.cpp": '#include "api.h"\nint result = execute("command");\n',
        "unrelated.h": 'using Process = QProcess;\n#define RUN(command) system(command)\n',
        "c.cpp": 'void target(Process process, char *command) { process.start(command); RUN(command); }\n',
    })
    candidates = command.Analyzer().find_candidates(tmp_path)

    assert file_apis(candidates, "a.cpp") == ["system"]
    assert not file_apis(candidates, "b.cpp")
    assert not file_apis(candidates, "c.cpp")


def test_shared_header_diagnostics_are_reported_once(tmp_path):
    write_sources(tmp_path, {
        "api.h": '#define JOIN(a, b) a ## b\n',
        "a.cpp": '#include "api.h"\nvoid a() {}\n',
        "b.cpp": '#include "api.h"\nvoid b() {}\n',
    })
    analyzer = command.Analyzer()
    analyzer.find_candidates(tmp_path)

    diagnostics = analyzer.diagnostics
    assert sum(item["reason"] == "macro_token_paste" for item in diagnostics) == 1
    identities = [(item["file"], item.get("line"), item.get("column"), item["reason"]) for item in diagnostics]
    assert len(identities) == len(set(identities))


def test_units_are_released_before_next_target_without_automatic_gc(tmp_path, monkeypatch, automatic_gc_disabled):
    write_sources(tmp_path, {
        "api.h": '#define RUN(command) system(command)\n',
        "a.cpp": '#include "api.h"\nvoid a(char *command) { RUN(command); }\n',
        "b.cpp": '#include "api.h"\nvoid b(char *command) { RUN(command); }\n',
    })
    references = track_units(monkeypatch)
    progress = []
    analyzer = command.Analyzer()

    def on_progress(current, total):
        assert all(reference() is None for reference in references)
        progress.append((current, total))

    analyzer.on_file_progress = on_progress
    candidates = analyzer.find_candidates(tmp_path)

    assert len(candidates) == 3
    assert progress == [(1, 3), (2, 3), (3, 3)]
    assert references and all(reference() is None for reference in references)


def inject_memory_error(monkeypatch, stage):
    if stage == "read":
        original = Path.read_bytes

        def fail(path):
            if path.name == "z_fail.cpp":
                raise MemoryError("simulated allocation failure")
            return original(path)

        monkeypatch.setattr(Path, "read_bytes", fail)
    elif stage == "parse":
        original = command._Unit.__init__

        class AllocationFailureParser:
            def parse(self, source):
                raise MemoryError("simulated allocation failure")

        def fail(self, path, source, parser, **kwargs):
            if path.name == "z_fail.cpp":
                parser = AllocationFailureParser()
            original(self, path, source, parser, **kwargs)

        monkeypatch.setattr(command._Unit, "__init__", fail)
    elif stage == "index":
        original = command._Analysis.index

        def fail(self, unit):
            original(self, unit)
            if unit.path.name == "z_fail.cpp" and unit.origin is unit:
                raise MemoryError("simulated allocation failure")

        monkeypatch.setattr(command._Analysis, "index", fail)
    elif stage == "connect":
        original = command._Analysis.connect

        def fail(self):
            original(self)
            if any(path.name == "z_fail.cpp" for path in self.units):
                raise MemoryError("simulated allocation failure")

        monkeypatch.setattr(command._Analysis, "connect", fail)
    else:
        original = command._Analysis.match

        def fail(self, kind, node, scope, *args, **kwargs):
            if scope.unit.path.name == "z_fail.cpp":
                raise MemoryError("simulated allocation failure")
            return original(self, kind, node, scope, *args, **kwargs)

        monkeypatch.setattr(command._Analysis, "match", fail)


@pytest.mark.parametrize("stage", ["read", "parse", "index", "connect", "match"])
def test_memory_error_reports_context_and_never_returns_partial_results(tmp_path, monkeypatch, stage):
    write_sources(tmp_path, {
        "a_good.cpp": 'void good(char *command) { system(command); }\n',
        "z_fail.cpp": 'void bad(char *command) { system(command); }\n',
    })
    inject_memory_error(monkeypatch, stage)
    analyzer = command.Analyzer()
    progress = []
    analyzer.on_file_progress = lambda current, total: progress.append((current, total))

    with pytest.raises(MemoryError) as caught:
        analyzer.find_candidates(tmp_path)

    message = str(caught.value)
    assert "z_fail.cpp" in message
    assert stage in message.lower()
    assert progress == [(1, 2)]


@pytest.mark.parametrize("stage", ["parse", "index", "connect", "match"])
def test_failed_target_releases_units_without_automatic_gc(tmp_path, monkeypatch, automatic_gc_disabled, stage):
    write_sources(tmp_path, {
        "api.h": '#define RUN(command) system(command)\n',
        "a_good.cpp": '#include "api.h"\nvoid good(char *command) { RUN(command); }\n',
        "z_fail.cpp": '#include "api.h"\nvoid bad(char *command) { RUN(command); }\n',
    })
    references = track_units(monkeypatch)
    inject_memory_error(monkeypatch, stage)

    def run_without_retaining_traceback():
        try:
            command.Analyzer().find_candidates(tmp_path)
        except MemoryError:
            return
        pytest.fail("allocation failure unexpectedly produced a successful scan")

    run_without_retaining_traceback()
    assert references and all(reference() is None for reference in references)


def test_macro_parameter_allocation_failure_releases_unfinished_fragment(tmp_path, monkeypatch, automatic_gc_disabled):
    write_sources(tmp_path, {"macro.h": '#define RUN(ARG) system(ARG)\n'})
    references = track_units(monkeypatch)
    original_symbol = command._Symbol

    def fail_parameter(name, *args, **kwargs):
        if name == "ARG":
            raise MemoryError("simulated macro parameter allocation failure")
        return original_symbol(name, *args, **kwargs)

    monkeypatch.setattr(command, "_Symbol", fail_parameter)

    def run_without_retaining_traceback():
        try:
            command.Analyzer().find_candidates(tmp_path)
        except MemoryError as exc:
            return str(exc)
        pytest.fail("macro parameter allocation failure unexpectedly succeeded")

    message = run_without_retaining_traceback()
    assert "file=macro.h" in message and "phase=index" in message
    assert len(references) == 2  # The source unit and the partly initialized macro.
    assert all(reference() is None for reference in references)


def test_unit_registration_failure_releases_unregistered_unit(tmp_path, monkeypatch, automatic_gc_disabled):
    write_sources(tmp_path, {"source.cpp": 'void target() { system(command); }\n'})
    references = track_units(monkeypatch)
    original_init = command._Analysis.__init__

    class AllocationFailureDict(dict):
        def __setitem__(self, key, value):
            raise MemoryError("simulated unit registration allocation failure")

    def fail_registration(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self.units = AllocationFailureDict()

    monkeypatch.setattr(command._Analysis, "__init__", fail_registration)

    def run_without_retaining_traceback():
        try:
            command.Analyzer().find_candidates(tmp_path)
        except MemoryError as exc:
            return str(exc)
        pytest.fail("unit registration allocation failure unexpectedly succeeded")

    message = run_without_retaining_traceback()
    assert "file=source.cpp" in message
    assert len(references) == 1
    assert references[0]() is None


def test_dependency_memory_error_identifies_target_and_header(tmp_path, monkeypatch):
    write_sources(tmp_path, {
        "a.cpp": '#include "api.h"\nvoid target(char *command) { RUN(command); }\n',
        "include/api.h": '#define RUN(command) system(command)\n',
    })
    original_read = Path.read_bytes

    def fail(path):
        if path.name == "api.h":
            raise MemoryError("simulated allocation failure")
        return original_read(path)

    monkeypatch.setattr(Path, "read_bytes", fail)
    with pytest.raises(MemoryError) as caught:
        command.Analyzer().find_candidates(tmp_path)

    message = str(caught.value)
    assert "target=a.cpp" in message
    assert "file=include/api.h" in message
    assert "phase=read" in message
    assert f"size_bytes={(tmp_path / 'include/api.h').stat().st_size}" in message


@pytest.mark.parametrize("fail_second_scan", [False, True])
def test_reusing_analyzer_clears_previous_diagnostics(tmp_path, monkeypatch, fail_second_scan):
    source = tmp_path / "z_fail.cpp"
    source.write_text('void target() { unknown.start(command); }\n', encoding="utf-8")
    analyzer = command.Analyzer()
    analyzer.find_candidates(tmp_path)
    assert any(item["reason"] == "unknown_receiver" for item in analyzer.diagnostics)

    source.write_text('void target() {}\n', encoding="utf-8")
    if fail_second_scan:
        inject_memory_error(monkeypatch, "read")
        with pytest.raises(MemoryError):
            analyzer.find_candidates(tmp_path)
    else:
        assert analyzer.find_candidates(tmp_path) == []
    assert analyzer.diagnostics == []
