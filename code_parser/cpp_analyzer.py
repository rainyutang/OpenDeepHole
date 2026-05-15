"""C/C++ source code analyzer using tree-sitter.

Parses C/C++ source files and populates a CodeDatabase with:
- Function definitions (with bodies and internal call sites)
- Struct/class definitions
- Global variable declarations
- Global variable references (g_xxx naming convention + explicit globals)
"""

import os
import re
from pathlib import Path
from typing import Callable

import tree_sitter_cpp
from tree_sitter import Language, Parser

from .code_database import CodeDatabase
from .code_utils import (
    find_nodes_by_type,
    get_child_field_text,
    get_child_field_text_by_type,
    get_child_node_by_type,
    get_child_nodes_by_type,
)

CPP_LANGUAGE = Language(tree_sitter_cpp.language())

# File extensions to scan
_C_CPP_EXTS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh", ".hxx"}

# Directories to skip during indexing (vendor, build, VCS, etc.)
_SKIP_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "vendor", "third_party", "3rdparty", "thirdparty",
    "external", "extern", "deps",
    "build", "cmake-build-debug", "cmake-build-release",
    "out", "output", "_build", ".build",
    "__pycache__", ".venv", "venv",
}

# Batch commit interval (number of files per commit)
_COMMIT_BATCH = 50


class CppAnalyzer:
    def __init__(self, db: CodeDatabase) -> None:
        self.db = db
        self._parser = Parser(CPP_LANGUAGE)
        # name → function_id mapping (populated per-file)
        self._func_id_map: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_directory(
        self,
        directory: Path,
        on_progress: Callable[[int, int], None] | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> None:
        """Parse all C/C++ files under *directory* and populate the DB.

        Uses os.walk with directory pruning to skip vendor/build/VCS dirs.
        Commits in batches for better performance on large repos.
        If *cancel_check* returns True, indexing stops early.
        """
        # Collect all C/C++ files in one pass, pruning irrelevant dirs
        files: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(directory):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fname in filenames:
                if Path(fname).suffix in _C_CPP_EXTS:
                    files.append(Path(dirpath) / fname)

        total = len(files)
        for idx, filepath in enumerate(files):
            if cancel_check and cancel_check():
                break

            try:
                rel_path = str(filepath.relative_to(directory))
                source = filepath.read_bytes()
                self.analyze_file(rel_path, source)
            except Exception:
                pass  # skip unparseable files

            # Batch commit
            if (idx + 1) % _COMMIT_BATCH == 0 or idx == total - 1:
                self.db.commit()

            # Progress callback (every 10 files or last file)
            if on_progress and (idx % 10 == 0 or idx == total - 1):
                on_progress(idx + 1, total)

    def analyze_file(self, rel_path: str, source: bytes) -> None:
        """Parse a single file and write results to DB."""
        file_id = self.db.get_or_create_file(rel_path)
        tree = self._parser.parse(source)
        root = tree.root_node
        lines = source.decode("utf-8", errors="replace").splitlines()

        self._extract_functions(root, source, rel_path, file_id)
        self._extract_structs(root, source, file_id)
        self._extract_global_variables(root, source, lines, file_id)

    # ------------------------------------------------------------------
    # Function extraction
    # ------------------------------------------------------------------

    def _extract_functions(
        self, root, source: bytes, rel_path: str, file_id: int
    ) -> None:
        func_nodes = find_nodes_by_type(root, "function_definition")
        for node in func_nodes:
            try:
                self._process_function(node, source, rel_path, file_id)
            except Exception:
                pass

    def _process_function(self, node, source: bytes, rel_path: str, file_id: int) -> None:
        # Return type
        return_type_node = node.child_by_field_name("type")
        return_type = return_type_node.text.decode("utf-8", errors="replace") if return_type_node else ""

        # Declarator → function name + signature
        declarator = node.child_by_field_name("declarator")
        if not declarator:
            return

        name = self._extract_function_name(declarator)
        if not name:
            return

        signature = declarator.text.decode("utf-8", errors="replace")

        # Static / linkage
        is_static = False
        linkage = "extern"
        for child in node.children:
            if child.type == "storage_class_specifier":
                text = child.text.decode("utf-8", errors="replace")
                if text == "static":
                    is_static = True
                    linkage = "static"

        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        body = node.text.decode("utf-8", errors="replace")

        func_id = self.db.insert_function(
            name=name,
            signature=signature,
            return_type=return_type,
            file_id=file_id,
            start_line=start_line,
            end_line=end_line,
            is_static=is_static,
            linkage=linkage,
            body=body,
        )
        self._func_id_map[name] = func_id

        # Extract call sites within this function body
        body_node = node.child_by_field_name("body")
        if body_node:
            self._extract_calls(body_node, func_id, file_id)

    def _extract_function_name(self, declarator) -> str | None:
        """Recursively unwrap declarator to find the identifier (function name)."""
        if declarator.type == "identifier":
            return declarator.text.decode("utf-8", errors="replace")
        if declarator.type in ("function_declarator", "pointer_declarator",
                               "reference_declarator", "abstract_function_declarator"):
            inner = declarator.child_by_field_name("declarator")
            if inner:
                return self._extract_function_name(inner)
        # Fallback: look for any identifier child
        id_node = get_child_node_by_type(declarator, ["identifier"])
        if id_node:
            return id_node.text.decode("utf-8", errors="replace")
        return None

    # ------------------------------------------------------------------
    # Call site extraction
    # ------------------------------------------------------------------

    def _extract_calls(self, body_node, caller_func_id: int, file_id: int) -> None:
        call_nodes = find_nodes_by_type(body_node, "call_expression")
        for call_node in call_nodes:
            try:
                func_node = call_node.child_by_field_name("function")
                if not func_node:
                    continue
                callee_name = func_node.text.decode("utf-8", errors="replace").strip()
                # Strip pointer/member access qualifiers
                callee_name = callee_name.split("->")[-1].split(".")[-1].split("::")[-1]
                line = call_node.start_point[0] + 1
                col = call_node.start_point[1]
                callee_id = self._func_id_map.get(callee_name)
                self.db.insert_function_call(
                    caller_function_id=caller_func_id,
                    callee_name=callee_name,
                    file_id=file_id,
                    line=line,
                    column=col,
                    callee_function_id=callee_id,
                )
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Struct extraction
    # ------------------------------------------------------------------

    def _extract_structs(self, root, source: bytes, file_id: int) -> None:
        for node_type in ("struct_specifier", "class_specifier"):
            for node in find_nodes_by_type(root, node_type):
                try:
                    name_node = node.child_by_field_name("name")
                    definition = node.text.decode("utf-8", errors="replace")

                    if name_node:
                        # 普通具名 struct：struct Foo { ... }
                        name = name_node.text.decode("utf-8", errors="replace")
                    else:
                        # 匿名 struct，尝试从外层 type_definition 获取 typedef 名
                        # typedef struct { ... } Node;
                        # AST: type_definition → struct_specifier + type_declarator(type_identifier)
                        name = self._typedef_name_for(node)
                        if not name:
                            continue
                        # 用整个 type_definition 作为 definition（包含 typedef 关键字）
                        if node.parent and node.parent.type == "type_definition":
                            definition = node.parent.text.decode("utf-8", errors="replace")

                    self.db.insert_struct(
                        name=name,
                        file_id=file_id,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        definition=definition,
                    )
                except Exception:
                    pass

    def _typedef_name_for(self, struct_node) -> str | None:
        """从 type_definition 父节点中提取 typedef 名（type_identifier）。"""
        parent = struct_node.parent
        if parent is None or parent.type != "type_definition":
            return None
        for child in parent.children:
            if child.type == "type_identifier":
                return child.text.decode("utf-8", errors="replace")
        # 也可能包在 pointer_declarator 里：typedef struct{} *NodePtr;
        for child in parent.children:
            if child.type in ("pointer_declarator", "abstract_pointer_declarator"):
                id_node = get_child_node_by_type(child, ["type_identifier", "identifier"])
                if id_node:
                    return id_node.text.decode("utf-8", errors="replace")
        return None

    # ------------------------------------------------------------------
    # Global variable extraction
    # ------------------------------------------------------------------

    def _extract_global_variables(
        self, root, source: bytes, lines: list[str], file_id: int
    ) -> None:
        """Extract top-level declarations that look like global variables."""
        for node in root.children:
            if node.type != "declaration":
                continue
            try:
                self._process_global_declaration(node, source, lines, file_id)
            except Exception:
                pass

    def _process_global_declaration(
        self, node, source: bytes, lines: list[str], file_id: int
    ) -> None:
        is_extern = False
        is_static = False
        for child in node.children:
            if child.type == "storage_class_specifier":
                t = child.text.decode("utf-8", errors="replace")
                if t == "extern":
                    is_extern = True
                if t == "static":
                    is_static = True

        # Find all declarators (there may be multiple, e.g. int a, b;)
        declarators = get_child_nodes_by_type(
            node,
            ["init_declarator", "identifier", "pointer_declarator",
             "array_declarator", "function_declarator"],
        )
        if not declarators:
            return

        definition = node.text.decode("utf-8", errors="replace")

        for decl in declarators:
            name_node = get_child_node_by_type(decl, ["identifier"])
            if not name_node:
                if decl.type == "identifier":
                    name_node = decl
                else:
                    continue
            name = name_node.text.decode("utf-8", errors="replace")

            # Skip function declarations (they have a function_declarator child)
            if any(c.type == "function_declarator" for c in decl.children):
                continue

            gvar_id = self.db.insert_global_variable(
                name=name,
                file_id=file_id,
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                is_extern=is_extern,
                is_static=is_static,
                definition=definition,
            )

            # Find references to this global (g_xxx pattern)
            if name.startswith("g_"):
                self._find_global_references(name, gvar_id, file_id, lines)

    def _find_global_references(
        self,
        var_name: str,
        gvar_id: int,
        file_id: int,
        lines: list[str],
    ) -> None:
        """Scan all functions in DB for references to var_name."""
        pattern = re.compile(r"\b" + re.escape(var_name) + r"\b")
        for i, line_text in enumerate(lines, start=1):
            if pattern.search(line_text):
                col = line_text.find(var_name)
                access_type = "write" if re.search(
                    r"\b" + re.escape(var_name) + r"\s*(?:\[.*?\]\s*)?=(?!=)", line_text
                ) else "read"
                self.db.insert_global_variable_reference(
                    global_var_id=gvar_id,
                    variable_name=var_name,
                    file_id=file_id,
                    function_id=None,  # resolved separately if needed
                    line=i,
                    column=col,
                    context=line_text.strip(),
                    access_type=access_type,
                )
