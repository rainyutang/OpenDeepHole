"""Discovery and execution for directory-based false-positive review methods."""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Awaitable, Callable

import yaml


FP_REVIEW_METHODS_DIR = Path(__file__).resolve().parent / "methods"
METHOD_MANIFEST_NAME = "method.yaml"
METHOD_ENTRY_NAME = "method.py"
_METHOD_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_STAGE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MANIFEST_KEYS = {
    "label",
    "description",
    "default",
    "max_concurrency",
    "stages",
    "documents",
}
_STAGE_KEYS = {"key", "label"}
_DOCUMENT_KEYS = {"label", "path"}
_COMMON_REQUIRED_KEYS = {
    "method_id",
    "project_path",
    "code_scan_path",
    "work_dir",
    "scan_id",
    "review_id",
    "vuln_index",
    "vulnerability",
}
_COMMON_ALLOWED_KEYS = _COMMON_REQUIRED_KEYS | {
    "scan_mode",
    "feedback_entries",
    "history",
    "required_capability",
    "invalid_json_retry_count",
    "task_agent_config",
    "output",
    "cancel_event",
}
_STATUSES = {"success", "error", "cancelled"}
_VERDICTS = {"true_positive", "false_positive"}


@dataclass(frozen=True)
class FpReviewStage:
    key: str
    label: str

    def catalog_dict(self) -> dict[str, str]:
        return {"key": self.key, "label": self.label}


@dataclass(frozen=True)
class FpReviewDocument:
    label: str
    path: Path


@dataclass(frozen=True)
class FpReviewMethodManifest:
    method_id: str
    label: str
    description: str
    default: bool
    max_concurrency: int
    stages: tuple[FpReviewStage, ...]
    documents: tuple[FpReviewDocument, ...]
    directory: Path

    @property
    def stage_keys(self) -> tuple[str, ...]:
        return tuple(stage.key for stage in self.stages)

    @property
    def skill_paths(self) -> tuple[Path, ...]:
        skills = self.directory / "skills"
        if not skills.is_dir() or not any(skills.rglob("SKILL.md")):
            return ()
        return (skills.resolve(),)

    def catalog_dict(self) -> dict[str, Any]:
        return {
            "method_id": self.method_id,
            "label": self.label,
            "description": self.description,
            "default": self.default,
            "max_concurrency": self.max_concurrency,
            "stages": [stage.catalog_dict() for stage in self.stages],
        }


@dataclass(frozen=True)
class LoadedFpReviewMethod:
    manifest: FpReviewMethodManifest
    run: Callable[..., Awaitable[Any]]


class FpReviewMethodRegistry:
    def __init__(
        self,
        methods: list[LoadedFpReviewMethod] | None = None,
        errors: list[str] | None = None,
    ) -> None:
        self._methods = {
            item.manifest.method_id: item
            for item in methods or []
        }
        self.errors = list(errors or [])

    def get(self, method_id: str) -> LoadedFpReviewMethod | None:
        return self._methods.get(str(method_id or "").strip())

    def methods(self) -> list[LoadedFpReviewMethod]:
        return sorted(
            self._methods.values(),
            key=lambda item: (
                not item.manifest.default,
                item.manifest.label.casefold(),
                item.manifest.method_id,
            ),
        )

    def manifests(self) -> list[FpReviewMethodManifest]:
        return [item.manifest for item in self.methods()]

    def default(self) -> LoadedFpReviewMethod | None:
        defaults = [item for item in self.methods() if item.manifest.default]
        return defaults[0] if len(defaults) == 1 else None


def _non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _read_stages(value: Any) -> tuple[FpReviewStage, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError("stages must be a non-empty list")
    result: list[FpReviewStage] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValueError(f"stages[{index}] must be a mapping")
        unknown = sorted(set(raw) - _STAGE_KEYS)
        missing = sorted(_STAGE_KEYS - set(raw))
        if unknown:
            raise ValueError(
                f"stages[{index}] unknown field(s): {', '.join(unknown)}"
            )
        if missing:
            raise ValueError(
                f"stages[{index}] missing field(s): {', '.join(missing)}"
            )
        key = _non_empty_string(raw["key"], f"stages[{index}].key")
        if not _STAGE_KEY_RE.fullmatch(key):
            raise ValueError(f"stages[{index}].key is invalid")
        if key in seen:
            raise ValueError(f"duplicate stage key: {key}")
        seen.add(key)
        result.append(FpReviewStage(
            key=key,
            label=_non_empty_string(
                raw["label"],
                f"stages[{index}].label",
            ),
        ))
    return tuple(result)


def _read_documents(
    value: Any,
    directory: Path,
) -> tuple[FpReviewDocument, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError("documents must be a list")
    root = directory.resolve()
    result: list[FpReviewDocument] = []
    seen: set[Path] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValueError(f"documents[{index}] must be a mapping")
        unknown = sorted(set(raw) - _DOCUMENT_KEYS)
        missing = sorted(_DOCUMENT_KEYS - set(raw))
        if unknown:
            raise ValueError(
                f"documents[{index}] unknown field(s): {', '.join(unknown)}"
            )
        if missing:
            raise ValueError(
                f"documents[{index}] missing field(s): {', '.join(missing)}"
            )
        relative = Path(_non_empty_string(
            raw["path"],
            f"documents[{index}].path",
        ))
        if relative.is_absolute():
            raise ValueError(f"documents[{index}].path must be relative")
        path = (root / relative).resolve()
        if root not in path.parents or not path.is_file():
            raise ValueError(
                f"documents[{index}].path must reference an existing method file"
            )
        if path in seen:
            raise ValueError(f"duplicate document path: {relative.as_posix()}")
        seen.add(path)
        result.append(FpReviewDocument(
            label=_non_empty_string(
                raw["label"],
                f"documents[{index}].label",
            ),
            path=path,
        ))
    return tuple(result)


def _read_manifest(directory: Path) -> FpReviewMethodManifest:
    if not _METHOD_ID_RE.fullmatch(directory.name):
        raise ValueError(f"invalid method directory name: {directory.name}")
    manifest_path = directory / METHOD_MANIFEST_NAME
    entry_path = directory / METHOD_ENTRY_NAME
    if not manifest_path.is_file() or not entry_path.is_file():
        raise ValueError("method directory requires method.yaml and method.py")
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
    default = raw["default"]
    max_concurrency = raw["max_concurrency"]
    if not isinstance(default, bool):
        raise ValueError("default must be a boolean")
    if isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int):
        raise ValueError("max_concurrency must be a positive integer")
    if max_concurrency < 1:
        raise ValueError("max_concurrency must be a positive integer")
    return FpReviewMethodManifest(
        method_id=directory.name,
        label=_non_empty_string(raw["label"], "label"),
        description=_non_empty_string(raw["description"], "description"),
        default=default,
        max_concurrency=max_concurrency,
        stages=_read_stages(raw["stages"]),
        documents=_read_documents(raw["documents"], directory),
        directory=directory.resolve(),
    )


def discover_fp_review_method_manifests(
    methods_dir: Path = FP_REVIEW_METHODS_DIR,
) -> tuple[list[FpReviewMethodManifest], list[str]]:
    root = Path(methods_dir).expanduser().resolve()
    if not root.is_dir():
        return [], [f"FP review methods directory not found: {root}"]
    manifests: list[FpReviewMethodManifest] = []
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
    defaults = [item.method_id for item in manifests if item.default]
    if len(defaults) != 1:
        errors.append(
            "exactly one FP review method must set default=true"
            + (f": {', '.join(defaults)}" if defaults else "")
        )
    return manifests, errors


def _load_module(manifest: FpReviewMethodManifest) -> ModuleType:
    digest = hashlib.sha256(
        str(manifest.directory).encode("utf-8")
    ).hexdigest()[:16]
    package_name = f"{__package__}.methods._dynamic_{digest}"
    module_name = f"{package_name}.method"
    package = ModuleType(package_name)
    package.__path__ = [str(manifest.directory)]  # type: ignore[attr-defined]
    package.__package__ = package_name
    sys.modules[package_name] = package
    spec = importlib.util.spec_from_file_location(
        module_name,
        manifest.directory / METHOD_ENTRY_NAME,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to create FP review method module spec")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        sys.modules.pop(package_name, None)
        raise
    return module


def _validate_run(value: Any) -> None:
    if not inspect.iscoroutinefunction(value):
        raise TypeError("method.py must define async def run")
    parameters = list(inspect.signature(value).parameters.values())
    if (
        len(parameters) != 1
        or parameters[0].kind is not inspect.Parameter.VAR_KEYWORD
    ):
        raise TypeError("run must accept exactly one **kwargs parameter")


def load_fp_review_methods(
    methods_dir: Path = FP_REVIEW_METHODS_DIR,
) -> FpReviewMethodRegistry:
    manifests, errors = discover_fp_review_method_manifests(methods_dir)
    loaded: list[LoadedFpReviewMethod] = []
    for manifest in manifests:
        try:
            module = _load_module(manifest)
            run = getattr(module, "run", None)
            _validate_run(run)
            loaded.append(LoadedFpReviewMethod(manifest=manifest, run=run))
        except Exception as exc:
            errors.append(f"{manifest.method_id}: {exc}")
    loaded_defaults = [
        item.manifest.method_id
        for item in loaded
        if item.manifest.default
    ]
    if len(loaded_defaults) != 1:
        errors.append(
            "exactly one available FP review method must set default=true"
            + (f": {', '.join(loaded_defaults)}" if loaded_defaults else "")
        )
    return FpReviewMethodRegistry(loaded, errors)


def build_fp_review_method_catalog(
    methods_dir: Path = FP_REVIEW_METHODS_DIR,
) -> dict[str, Any]:
    registry = load_fp_review_methods(methods_dir)
    return {
        "methods": [
            item.manifest.catalog_dict()
            for item in registry.methods()
        ],
        "errors": registry.errors,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def _normalize_mapping(value: Any, field: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise TypeError(f"{field} must be a dict")
    return dict(value)


def _normalize_stage_outputs(
    method: LoadedFpReviewMethod,
    value: Any,
) -> dict[str, str]:
    raw = _normalize_mapping(value, "stage_outputs")
    unknown = sorted(set(raw) - set(method.manifest.stage_keys))
    if unknown:
        raise ValueError(
            f"{method.manifest.method_id}: undeclared stage output(s): "
            + ", ".join(unknown)
        )
    return {str(key): str(item or "") for key, item in raw.items()}


def normalize_fp_review_method_output(
    method: LoadedFpReviewMethod,
    output: Any,
) -> dict[str, Any]:
    if not isinstance(output, dict):
        raise TypeError(
            f"{method.manifest.method_id}: run() must return a dict"
        )
    status = str(output.get("status") or "").strip().lower()
    if status not in _STATUSES:
        raise ValueError(
            f"{method.manifest.method_id}: status must be success, error, or cancelled"
        )
    stage_outputs = _normalize_stage_outputs(
        method,
        output.get("stage_outputs"),
    )
    stage_sources = _normalize_mapping(
        output.get("stage_output_sources"),
        "stage_output_sources",
    )
    unknown_sources = sorted(set(stage_sources) - set(method.manifest.stage_keys))
    if unknown_sources:
        raise ValueError(
            f"{method.manifest.method_id}: undeclared stage source(s): "
            + ", ".join(unknown_sources)
        )
    normalized: dict[str, Any] = {
        "status": status,
        "method_id": method.manifest.method_id,
        "method_label": method.manifest.label,
        "stage_outputs": stage_outputs,
        "stage_output_sources": {
            str(key): _normalize_mapping(value, f"stage_output_sources.{key}")
            for key, value in stage_sources.items()
        },
        "output_source": _normalize_mapping(
            output.get("output_source"),
            "output_source",
        ),
        "error_message": str(output.get("error_message") or ""),
    }
    if status != "success":
        return normalized
    verdict = str(output.get("verdict") or "").strip().lower()
    reason = str(output.get("reason") or "").strip()
    if verdict not in _VERDICTS:
        raise ValueError(
            f"{method.manifest.method_id}: successful result requires "
            "verdict=true_positive or false_positive"
        )
    if not reason:
        raise ValueError(
            f"{method.manifest.method_id}: successful result requires a non-empty reason"
        )
    normalized.update({
        "verdict": verdict,
        "reason": reason,
        "revised_severity": str(output.get("revised_severity") or ""),
        "vulnerability_report": str(output.get("vulnerability_report") or ""),
        "match_type": str(output.get("match_type") or ""),
        "match_reference": str(output.get("match_reference") or ""),
    })
    return normalized


async def run_fp_review(**kwargs: Any) -> dict[str, Any]:
    """Run one configured method for exactly one vulnerability."""
    unknown = sorted(set(kwargs) - _COMMON_ALLOWED_KEYS)
    if unknown:
        raise TypeError(
            "run_fp_review() got unexpected key(s): " + ", ".join(unknown)
        )
    missing = sorted(
        key for key in _COMMON_REQUIRED_KEYS
        if kwargs.get(key) in (None, "")
    )
    if missing:
        raise TypeError(
            "run_fp_review() missing required key(s): " + ", ".join(missing)
        )
    try:
        vuln_index = int(kwargs["vuln_index"])
    except (TypeError, ValueError) as exc:
        raise TypeError("vuln_index must be a non-negative integer") from exc
    if vuln_index < 0:
        raise ValueError("vuln_index must be a non-negative integer")
    vulnerability = kwargs["vulnerability"]
    if hasattr(vulnerability, "model_dump"):
        vulnerability = vulnerability.model_dump(mode="json")
    if not isinstance(vulnerability, dict):
        raise TypeError("vulnerability must be a dict")

    registry = load_fp_review_methods()
    method_id = str(kwargs["method_id"]).strip()
    method = registry.get(method_id)
    if method is None:
        detail = "; ".join(registry.errors)
        raise LookupError(
            f"unknown or unavailable FP review method: {method_id}"
            + (f" ({detail})" if detail else "")
        )

    original_output = kwargs.get("output")
    if original_output is not None and not callable(original_output):
        raise TypeError("output must be callable or None")

    async def validated_output(event: Any) -> None:
        if not isinstance(event, dict):
            raise TypeError("FP review output event must be a dict")
        data = event.get("data")
        if event.get("kind") == "stage":
            if not isinstance(data, dict):
                raise TypeError("FP review stage event data must be a dict")
            stage = str(data.get("stage") or "")
            if stage not in method.manifest.stage_keys:
                raise ValueError(
                    f"{method_id}: emitted undeclared stage: {stage}"
                )
        if original_output is None:
            return
        value = original_output(event)
        if inspect.isawaitable(value):
            await value

    call_kwargs = dict(kwargs)
    call_kwargs.update({
        "method_id": method.manifest.method_id,
        "vuln_index": vuln_index,
        "vulnerability": dict(vulnerability),
        "output": validated_output if original_output is not None else None,
    })
    raw_output = await method.run(**call_kwargs)
    return normalize_fp_review_method_output(method, raw_output)


__all__ = [
    "FP_REVIEW_METHODS_DIR",
    "FpReviewMethodManifest",
    "FpReviewMethodRegistry",
    "LoadedFpReviewMethod",
    "build_fp_review_method_catalog",
    "discover_fp_review_method_manifests",
    "load_fp_review_methods",
    "normalize_fp_review_method_output",
    "run_fp_review",
]
