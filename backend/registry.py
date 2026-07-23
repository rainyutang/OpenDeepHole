"""Metadata registry for the decoupled static and candidate-audit rules."""

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from backend.logger import get_logger

logger = get_logger(__name__)

_REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
CHECKERS_DIR = _REPOSITORY_ROOT / "deephole_client" / "candidate_audit" / "rules"
STATIC_CHECKERS_DIR = (
    _REPOSITORY_ROOT / "deephole_client" / "static_analysis" / "rules"
)
CHECKERS_DIR_ENV = "OPENDEEPHOLE_CHECKERS_DIR"
CHECKER_VISIBILITY_PUBLIC = "public"
CHECKER_VISIBILITY_ADMIN = "admin"
CHECKER_CATEGORY_RESOURCE_LEAK = "resource_leak"
CHECKER_CATEGORY_INFINITE_LOOP = "infinite_loop"
CHECKER_CATEGORY_ILLEGAL_MEMORY_USE = "illegal_memory_use"
CHECKER_CATEGORY_OUT_OF_BOUNDS = "out_of_bounds"
CHECKER_CATEGORY_AUTH_BYPASS = "auth_bypass"
CHECKER_CATEGORY_OTHER = "other"
CHECKER_CATEGORY_DEFAULT = CHECKER_CATEGORY_ILLEGAL_MEMORY_USE
CHECKER_CATEGORY_LABELS = {
    CHECKER_CATEGORY_RESOURCE_LEAK: "资源泄露",
    CHECKER_CATEGORY_INFINITE_LOOP: "死循环",
    CHECKER_CATEGORY_ILLEGAL_MEMORY_USE: "非法内存使用",
    CHECKER_CATEGORY_OUT_OF_BOUNDS: "读写越界",
    CHECKER_CATEGORY_AUTH_BYPASS: "认证绕过",
    CHECKER_CATEGORY_OTHER: "其他",
}


@dataclass
class CheckerEntry:
    """A registered checker with transport metadata and resource locations."""
    name: str
    label: str
    description: str
    enabled: bool
    skill_path: Path
    directory: Path = field(default_factory=Path)
    static_directory: Path = field(default_factory=Path)
    single_pass: bool = False
    mode: str = "opencode"           # "api" | "opencode"
    prompt_path: Path | None = None  # prompt.txt for API mode
    skill_name: str | None = None    # custom skill name (default: {name}-analysis)
    visibility: str = CHECKER_VISIBILITY_PUBLIC  # "public" | "admin"
    category: str = CHECKER_CATEGORY_DEFAULT
    category_label: str = CHECKER_CATEGORY_LABELS[CHECKER_CATEGORY_DEFAULT]
    family: str = ""
    modified_at: str = ""
    user_created: bool = False
    created_by_user_id: str = ""
    created_by_username: str = ""
    result_mode: str = "vulnerabilities"  # "vulnerabilities" | "markdown_reports"
    timeout_seconds: int | None = None
    model_capability: str = "any"  # "any" | "low" | "medium" | "high"


_registry: dict[str, CheckerEntry] | None = None
_registry_dirs: tuple[Path, ...] | None = None


def current_checkers_dir() -> Path:
    """Return the checker root for the current process context."""
    override = os.environ.get(CHECKERS_DIR_ENV)
    if override:
        return Path(override)
    return CHECKERS_DIR


def current_checker_dirs() -> list[Path]:
    """Return checker roots for the current process context."""
    override = os.environ.get(CHECKERS_DIR_ENV)
    if override:
        return [Path(override)]
    roots = [CHECKERS_DIR]
    try:
        from backend.config import get_config
        user_skills_dir = Path(get_config().storage.user_skills_dir)
        if user_skills_dir != CHECKERS_DIR:
            roots.append(user_skills_dir)
    except Exception:
        logger.debug("User skill directory is not available yet", exc_info=True)
    return roots


def get_registry(checkers_dir: Path | None = None, *, refresh: bool = False) -> dict[str, CheckerEntry]:
    """Get the checker registry singleton, optionally forcing a rescan."""
    global _registry, _registry_dirs
    target_dirs = (checkers_dir.resolve(),) if checkers_dir else tuple(
        root.resolve() for root in current_checker_dirs()
    )
    if refresh or _registry is None or _registry_dirs != target_dirs:
        _registry = discover_checkers_from_dirs(target_dirs)
        _registry_dirs = target_dirs
    return _registry


def refresh_registry(checkers_dir: Path | None = None) -> dict[str, CheckerEntry]:
    """Rescan the checker directory and replace the cached registry."""
    return get_registry(checkers_dir=checkers_dir, refresh=True)


def discover_checkers_from_dirs(checkers_dirs: tuple[Path, ...] | list[Path]) -> dict[str, CheckerEntry]:
    """Scan checker roots and merge entries by checker name."""
    registry: dict[str, CheckerEntry] = {}
    for checkers_dir in checkers_dirs:
        is_user_dir = checkers_dir.resolve() != CHECKERS_DIR.resolve()
        for name, entry in discover_checkers(checkers_dir, user_created=is_user_dir).items():
            if name in registry:
                logger.warning(
                    "Duplicate checker %s in %s; keeping first definition from %s",
                    name,
                    entry.directory,
                    registry[name].directory,
                )
                continue
            registry[name] = entry
    logger.info("Merged %d checkers from %d root(s)", len(registry), len(checkers_dirs))
    return registry


def discover_checkers(checkers_dir: Path, *, user_created: bool = False) -> dict[str, CheckerEntry]:
    """Scan one candidate-audit metadata directory and build the registry.

    Built-in audit resources and static rules live in separate roots. User
    checkers may still provide both kinds of files in one directory; packaging
    separates them before the client starts either process.
    """
    registry: dict[str, CheckerEntry] = {}

    if not checkers_dir.is_dir():
        logger.warning("Checkers directory not found: %s", checkers_dir)
        return registry

    for checker_dir in sorted(checkers_dir.iterdir()):
        if not checker_dir.is_dir():
            continue

        yaml_path = checker_manifest_path(checker_dir)
        if not yaml_path.is_file():
            continue

        try:
            entry = _load_checker(checker_dir, yaml_path, user_created=user_created)
            if entry.enabled:
                registry[entry.name] = entry
                logger.info(
                    "Registered checker metadata: %s (%s)",
                    entry.name,
                    entry.label,
                )
            else:
                logger.debug("Skipping disabled checker: %s", entry.name)
        except Exception:
            logger.exception("Failed to load checker from %s", checker_dir)

    logger.info("Discovered %d checkers: %s", len(registry), list(registry.keys()))
    return registry


def checker_manifest_path(checker_dir: Path) -> Path:
    """Resolve metadata without importing a static analyzer."""
    local = checker_dir / "checker.yaml"
    if local.is_file():
        return local
    return STATIC_CHECKERS_DIR / checker_dir.name / "checker.yaml"


def _load_checker(checker_dir: Path, yaml_path: Path, *, user_created: bool = False) -> CheckerEntry:
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

    category = normalize_checker_category(meta.get("category"))

    return CheckerEntry(
        name=name,
        label=meta.get("label", name.upper()),
        description=meta.get("description", ""),
        enabled=meta.get("enabled", True),
        skill_path=skill_path,
        directory=checker_dir,
        static_directory=yaml_path.parent,
        single_pass=meta.get("single_pass", False),
        mode=mode,
        prompt_path=prompt_path,
        skill_name=meta.get("skill_name"),
        visibility=_normalize_visibility(meta.get("visibility", CHECKER_VISIBILITY_PUBLIC)),
        category=category,
        category_label=checker_category_label(category),
        family=str(meta.get("family") or name).strip() or name,
        modified_at=str(meta.get("modified_at") or "").strip(),
        user_created=user_created,
        created_by_user_id=str(meta.get("created_by_user_id") or "").strip(),
        created_by_username=str(meta.get("created_by_username") or "").strip(),
        result_mode=_normalize_result_mode(meta.get("result_mode")),
        timeout_seconds=_normalize_timeout_seconds(meta.get("timeout_seconds")),
        model_capability=_normalize_model_capability(meta.get("model_capability")),
    )


def _normalize_visibility(value: object) -> str:
    visibility = str(value or CHECKER_VISIBILITY_PUBLIC).strip().lower()
    if visibility not in {CHECKER_VISIBILITY_PUBLIC, CHECKER_VISIBILITY_ADMIN}:
        logger.warning("Unknown checker visibility %r, falling back to public", value)
        return CHECKER_VISIBILITY_PUBLIC
    return visibility


def _normalize_result_mode(value: object) -> str:
    result_mode = str(value or "vulnerabilities").strip().lower()
    if result_mode not in {"vulnerabilities", "markdown_reports"}:
        logger.warning("Unknown checker result_mode %r, falling back to vulnerabilities", value)
        return "vulnerabilities"
    return result_mode


def _normalize_timeout_seconds(value: object) -> int | None:
    if value in (None, ""):
        return None
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        logger.warning("Invalid checker timeout_seconds %r, ignoring", value)
        return None
    if timeout <= 0:
        logger.warning("Invalid checker timeout_seconds %r, ignoring", value)
        return None
    return timeout


def _normalize_model_capability(value: object) -> str:
    capability = str(value or "any").strip().lower()
    if capability not in {"any", "low", "medium", "high"}:
        logger.warning("Unknown checker model_capability %r, falling back to any", value)
        return "any"
    return capability


def normalize_checker_category(value: object) -> str:
    """Return a supported checker category, defaulting to illegal memory use."""
    category = str(value or CHECKER_CATEGORY_DEFAULT).strip().lower()
    if category not in CHECKER_CATEGORY_LABELS:
        logger.warning("Unknown checker category %r, falling back to %s", value, CHECKER_CATEGORY_DEFAULT)
        return CHECKER_CATEGORY_DEFAULT
    return category


def checker_category_label(value: object) -> str:
    """Return the display label for a checker category."""
    return CHECKER_CATEGORY_LABELS[normalize_checker_category(value)]


def checker_modified_sort_key(modified_at: str) -> datetime:
    """Parse a checker modified timestamp for newest-first sorting."""
    value = str(modified_at or "").strip()
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        logger.warning("Invalid checker modified_at %r, sorting last", modified_at)
        return datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed
