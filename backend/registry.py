"""Checker registry — auto-discovers checker plugins from checkers/ directory."""

import importlib.util
import hashlib
import os
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from backend.analyzers.base import BaseAnalyzer
from backend.logger import get_logger

logger = get_logger(__name__)

CHECKERS_DIR = Path(__file__).resolve().parent.parent / "checkers"
CHECKERS_DIR_ENV = "OPENDEEPHOLE_CHECKERS_DIR"
CHECKER_VISIBILITY_PUBLIC = "public"
CHECKER_VISIBILITY_ADMIN = "admin"


@dataclass
class CheckerEntry:
    """A registered checker with its metadata, analyzer, and skill path."""
    name: str
    label: str
    description: str
    enabled: bool
    skill_path: Path
    analyzer: BaseAnalyzer | None = None
    directory: Path = field(default_factory=Path)
    single_pass: bool = False
    mode: str = "opencode"           # "api" | "opencode"
    prompt_path: Path | None = None  # prompt.txt for API mode
    skill_name: str | None = None    # custom skill name (default: {name}-analysis)
    visibility: str = CHECKER_VISIBILITY_PUBLIC  # "public" | "admin"


_registry: dict[str, CheckerEntry] | None = None
_registry_dir: Path | None = None


def current_checkers_dir() -> Path:
    """Return the checker root for the current process context."""
    override = os.environ.get(CHECKERS_DIR_ENV)
    if override:
        return Path(override)
    return CHECKERS_DIR


def get_registry(checkers_dir: Path | None = None, *, refresh: bool = False) -> dict[str, CheckerEntry]:
    """Get the checker registry singleton, optionally forcing a rescan."""
    global _registry, _registry_dir
    target_dir = (checkers_dir or current_checkers_dir()).resolve()
    if refresh or _registry is None or _registry_dir != target_dir:
        _registry = discover_checkers(target_dir)
        _registry_dir = target_dir
    return _registry


def refresh_registry(checkers_dir: Path | None = None) -> dict[str, CheckerEntry]:
    """Rescan the checker directory and replace the cached registry."""
    return get_registry(checkers_dir=checkers_dir, refresh=True)


def discover_checkers(checkers_dir: Path) -> dict[str, CheckerEntry]:
    """Scan checkers/ directory and build the registry.

    Each subdirectory with a checker.yaml is registered as a checker.
    If analyzer.py exists, it's dynamically imported and its Analyzer class instantiated.
    """
    registry: dict[str, CheckerEntry] = {}

    if not checkers_dir.is_dir():
        logger.warning("Checkers directory not found: %s", checkers_dir)
        return registry

    for checker_dir in sorted(checkers_dir.iterdir()):
        if not checker_dir.is_dir():
            continue

        yaml_path = checker_dir / "checker.yaml"
        if not yaml_path.is_file():
            continue

        try:
            entry = _load_checker(checker_dir, yaml_path)
            if entry.enabled:
                registry[entry.name] = entry
                logger.info(
                    "Registered checker: %s (%s)%s",
                    entry.name,
                    entry.label,
                    " [with analyzer]" if entry.analyzer else "",
                )
            else:
                logger.debug("Skipping disabled checker: %s", entry.name)
        except Exception:
            logger.exception("Failed to load checker from %s", checker_dir)

    logger.info("Discovered %d checkers: %s", len(registry), list(registry.keys()))
    return registry


def _load_checker(checker_dir: Path, yaml_path: Path) -> CheckerEntry:
    """Load a single checker from its directory."""
    with open(yaml_path, encoding="utf-8") as f:
        meta = yaml.safe_load(f)

    name = meta["name"]
    mode = meta.get("mode", "opencode")
    skill_path = checker_dir / "SKILL.md"
    prompt_path: Path | None = None

    if mode == "api":
        prompt_path = checker_dir / "prompt.txt"
        if not prompt_path.is_file():
            raise FileNotFoundError(
                f"prompt.txt not found for API mode checker {name} in {checker_dir}"
            )
        # SKILL.md is optional for API mode checkers
    else:
        if not skill_path.is_file():
            raise FileNotFoundError(f"SKILL.md not found in {checker_dir}")

    analyzer = _load_analyzer(checker_dir, name)

    return CheckerEntry(
        name=name,
        label=meta.get("label", name.upper()),
        description=meta.get("description", ""),
        enabled=meta.get("enabled", True),
        skill_path=skill_path,
        analyzer=analyzer,
        directory=checker_dir,
        single_pass=meta.get("single_pass", False),
        mode=mode,
        prompt_path=prompt_path,
        skill_name=meta.get("skill_name"),
        visibility=_normalize_visibility(meta.get("visibility", CHECKER_VISIBILITY_PUBLIC)),
    )


def _normalize_visibility(value: object) -> str:
    visibility = str(value or CHECKER_VISIBILITY_PUBLIC).strip().lower()
    if visibility not in {CHECKER_VISIBILITY_PUBLIC, CHECKER_VISIBILITY_ADMIN}:
        logger.warning("Unknown checker visibility %r, falling back to public", value)
        return CHECKER_VISIBILITY_PUBLIC
    return visibility


def _load_analyzer(checker_dir: Path, checker_name: str) -> BaseAnalyzer | None:
    """Dynamically import analyzer.py from a checker directory, if it exists."""
    analyzer_path = checker_dir / "analyzer.py"
    if not analyzer_path.is_file():
        return None

    module_name = _analyzer_module_name(checker_dir, checker_name)
    spec = importlib.util.spec_from_file_location(module_name, analyzer_path)
    if spec is None or spec.loader is None:
        logger.warning("Could not load analyzer spec from %s", analyzer_path)
        return None

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    analyzer_cls = getattr(module, "Analyzer", None)
    if analyzer_cls is None:
        logger.warning("No Analyzer class found in %s", analyzer_path)
        return None

    return analyzer_cls()


def _analyzer_module_name(checker_dir: Path, checker_name: str) -> str:
    """Return an isolated module name that still supports checker-local imports."""
    checker_dir = checker_dir.resolve()
    package_root = checker_dir.parent
    digest = hashlib.sha1(str(package_root).encode("utf-8")).hexdigest()[:12]
    root_pkg = f"_opendeephole_checkers_{digest}"
    checker_pkg = f"{root_pkg}.{checker_name}"

    for name in list(sys.modules):
        if name == checker_pkg or name.startswith(checker_pkg + "."):
            sys.modules.pop(name, None)

    root_module = sys.modules.get(root_pkg)
    if root_module is None:
        root_module = types.ModuleType(root_pkg)
        root_module.__path__ = [str(package_root)]  # type: ignore[attr-defined]
        sys.modules[root_pkg] = root_module
    checker_module = types.ModuleType(checker_pkg)
    checker_module.__path__ = [str(checker_dir)]  # type: ignore[attr-defined]
    sys.modules[checker_pkg] = checker_module
    importlib.invalidate_caches()
    return f"{checker_pkg}.analyzer"
