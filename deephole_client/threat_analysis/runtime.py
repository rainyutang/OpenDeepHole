"""Discovery and loading for directory-based threat-analysis methods."""

from __future__ import annotations

import importlib.util
import inspect
import re
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Iterator

import yaml


THREAT_ANALYSIS_METHODS_DIR = Path(__file__).resolve().parent / "methods"
THREAT_ANALYSIS_METHOD_MANIFEST = "method.yaml"
THREAT_ANALYSIS_METHOD_ENTRY = "threat_analysis.py"
DEFAULT_THREAT_ANALYSIS_METHOD_ID = "deephole_threat_analysis"
NATIVE_THREAT_ANALYSIS_PACKAGE = "threat_analysis_harness"

_METHOD_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MANIFEST_KEYS = {"label", "description"}
_NATIVE_ENTRY_PARAMETERS = (
    "code_path",
    "output_path",
    "is_resume",
    "product_mcp",
    "attack_modes",
)
_IMPORT_LOCK = threading.RLock()


@dataclass(frozen=True)
class ThreatAnalysisMethodManifest:
    method_id: str
    label: str
    description: str
    directory: Path

    def catalog_dict(self) -> dict[str, str]:
        return {
            "method_id": self.method_id,
            "label": self.label,
            "description": self.description,
        }

    def skill_roots(self) -> tuple[Path, ...]:
        """Return roots whose direct children are method-owned Skills."""
        skills_dir = self.directory / "skills"
        if not skills_dir.is_dir() or skills_dir.is_symlink():
            return ()
        roots: set[Path] = set()
        for skill_file in skills_dir.rglob("SKILL.md"):
            if skill_file.is_symlink() or not skill_file.is_file():
                continue
            resolved = skill_file.resolve()
            try:
                resolved.relative_to(skills_dir.resolve())
            except ValueError:
                continue
            roots.add(resolved.parent.parent)
        return tuple(sorted(roots, key=lambda path: path.as_posix()))


def _non_empty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def _read_manifest(directory: Path) -> ThreatAnalysisMethodManifest:
    if not _METHOD_ID_RE.fullmatch(directory.name):
        raise ValueError(f"invalid method directory name: {directory.name}")
    manifest_path = directory / THREAT_ANALYSIS_METHOD_MANIFEST
    init_path = directory / "__init__.py"
    entry_path = directory / THREAT_ANALYSIS_METHOD_ENTRY
    if not manifest_path.is_file() or not init_path.is_file() or not entry_path.is_file():
        raise ValueError(
            "method directory requires method.yaml, __init__.py, and threat_analysis.py"
        )
    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("method.yaml must contain a mapping")
    unknown = sorted(set(raw) - _MANIFEST_KEYS)
    missing = sorted(_MANIFEST_KEYS - set(raw))
    if unknown:
        raise ValueError(
            "unknown method.yaml field(s): " + ", ".join(unknown)
        )
    if missing:
        raise ValueError(
            "missing method.yaml field(s): " + ", ".join(missing)
        )
    return ThreatAnalysisMethodManifest(
        method_id=directory.name,
        label=_non_empty_string(raw["label"], "label"),
        description=_non_empty_string(raw["description"], "description"),
        directory=directory.resolve(),
    )


def discover_threat_analysis_method_manifests(
    methods_dir: Path = THREAT_ANALYSIS_METHODS_DIR,
) -> tuple[list[ThreatAnalysisMethodManifest], list[str]]:
    root = Path(methods_dir).expanduser().resolve()
    if not root.is_dir():
        return [], [f"Threat-analysis methods directory not found: {root}"]
    manifests: list[ThreatAnalysisMethodManifest] = []
    errors: list[str] = []
    for directory in sorted(root.iterdir()):
        if (
            not directory.is_dir()
            or directory.is_symlink()
            or directory.name.startswith((".", "_"))
        ):
            continue
        try:
            manifests.append(_read_manifest(directory))
        except Exception as exc:
            errors.append(f"{directory.name}: {exc}")
    return manifests, errors


def build_threat_analysis_method_catalog(
    methods_dir: Path = THREAT_ANALYSIS_METHODS_DIR,
) -> dict[str, Any]:
    manifests, errors = discover_threat_analysis_method_manifests(methods_dir)
    return {
        "methods": [
            item.catalog_dict()
            for item in sorted(
                manifests,
                key=lambda item: (
                    item.method_id != DEFAULT_THREAT_ANALYSIS_METHOD_ID,
                    item.label.casefold(),
                    item.method_id,
                ),
            )
        ],
        "errors": errors,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def resolve_threat_analysis_method(
    method_id: str | None,
    methods_dir: Path = THREAT_ANALYSIS_METHODS_DIR,
) -> ThreatAnalysisMethodManifest:
    selected_id = str(method_id or "").strip() or DEFAULT_THREAT_ANALYSIS_METHOD_ID
    manifests, errors = discover_threat_analysis_method_manifests(methods_dir)
    for manifest in manifests:
        if manifest.method_id == selected_id:
            return manifest
    detail = f" ({'; '.join(errors)})" if errors else ""
    raise ValueError(f"Unknown threat-analysis method: {selected_id}{detail}")


def _validate_native_entry(value: Any) -> Callable[..., dict[str, Any]]:
    if not callable(value):
        raise TypeError("__init__.py must export run_threat_analysis")
    parameters = list(inspect.signature(value).parameters.values())
    if tuple(parameter.name for parameter in parameters) != _NATIVE_ENTRY_PARAMETERS:
        raise TypeError(
            "run_threat_analysis must accept exactly: "
            + ", ".join(_NATIVE_ENTRY_PARAMETERS)
        )
    if any(
        parameter.kind is not inspect.Parameter.POSITIONAL_OR_KEYWORD
        for parameter in parameters
    ):
        raise TypeError(
            "run_threat_analysis parameters must be positional-or-keyword"
        )
    if parameters[0].default is not inspect.Parameter.empty:
        raise TypeError("code_path must be required")
    if parameters[1].default is not inspect.Parameter.empty:
        raise TypeError("output_path must be required")
    expected_defaults = (False, None, None)
    actual_defaults = tuple(parameter.default for parameter in parameters[2:])
    if actual_defaults != expected_defaults:
        raise TypeError(
            "is_resume, product_mcp, and attack_modes must default to False, None, and None"
        )
    return value


def _loaded_native_package_path() -> Path | None:
    loaded = sys.modules.get(NATIVE_THREAT_ANALYSIS_PACKAGE)
    if loaded is None:
        return None
    raw = str(getattr(loaded, "__file__", "") or "")
    return Path(raw).resolve() if raw else None


def _clear_loaded_native_package() -> None:
    prefix = NATIVE_THREAT_ANALYSIS_PACKAGE + "."
    for name in list(sys.modules):
        if name == NATIVE_THREAT_ANALYSIS_PACKAGE or name.startswith(prefix):
            sys.modules.pop(name, None)


def load_threat_analysis_method_package(
    manifest: ThreatAnalysisMethodManifest,
) -> ModuleType:
    """Load one copied harness under its unchanged native package name."""
    expected_init = (manifest.directory / "__init__.py").resolve()
    with _IMPORT_LOCK:
        loaded = sys.modules.get(NATIVE_THREAT_ANALYSIS_PACKAGE)
        loaded_path = _loaded_native_package_path()
        if loaded is not None and loaded_path == expected_init:
            _validate_native_entry(getattr(loaded, "run_threat_analysis", None))
            return loaded
        if loaded is not None and loaded_path is not None:
            try:
                loaded_path.relative_to(THREAT_ANALYSIS_METHODS_DIR.resolve())
            except ValueError as exc:
                raise RuntimeError(
                    "A different threat_analysis_harness package is already loaded: "
                    f"{loaded_path}"
                ) from exc
        _clear_loaded_native_package()
        spec = importlib.util.spec_from_file_location(
            NATIVE_THREAT_ANALYSIS_PACKAGE,
            expected_init,
            submodule_search_locations=[str(manifest.directory)],
        )
        if spec is None or spec.loader is None:
            raise ImportError(
                f"Cannot load threat-analysis method: {expected_init}"
            )
        module = importlib.util.module_from_spec(spec)
        sys.modules[NATIVE_THREAT_ANALYSIS_PACKAGE] = module
        try:
            spec.loader.exec_module(module)
            _validate_native_entry(getattr(module, "run_threat_analysis", None))
        except BaseException:
            _clear_loaded_native_package()
            raise
        return module


@contextmanager
def threat_analysis_method_execution() -> Iterator[None]:
    """Serialize native-package aliasing for concurrent in-process scans."""
    with _IMPORT_LOCK:
        yield


__all__ = [
    "DEFAULT_THREAT_ANALYSIS_METHOD_ID",
    "NATIVE_THREAT_ANALYSIS_PACKAGE",
    "THREAT_ANALYSIS_METHOD_ENTRY",
    "THREAT_ANALYSIS_METHOD_MANIFEST",
    "THREAT_ANALYSIS_METHODS_DIR",
    "ThreatAnalysisMethodManifest",
    "build_threat_analysis_method_catalog",
    "discover_threat_analysis_method_manifests",
    "load_threat_analysis_method_package",
    "resolve_threat_analysis_method",
    "threat_analysis_method_execution",
]
