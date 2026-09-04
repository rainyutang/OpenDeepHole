"""Generic collection of JSON artifacts returned by independent processes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping


def collect_json_artifacts(
    result: Mapping[str, Any],
    *,
    output_root: str | Path,
) -> dict[str, Any]:
    """Load top-level ``*_path`` results without allowing output-root escapes."""
    if result.get("result") is not True:
        raise ValueError("cannot collect artifacts from an unsuccessful process result")
    root = Path(output_root).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"process output root is not a directory: {root}")

    entrypoint_result = dict(result)
    artifacts: dict[str, dict[str, Any]] = {}
    for key, raw_path in result.items():
        if not str(key).endswith("_path") or not isinstance(raw_path, (str, Path)):
            continue
        path = Path(raw_path).expanduser().resolve()
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                f"process artifact escapes output root: {key}={path}"
            ) from exc
        if not path.is_file():
            raise FileNotFoundError(f"process artifact is not a file: {key}={path}")
        try:
            content = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"process artifact is not valid JSON: {key}={path}") from exc
        relative_text = relative.as_posix()
        entrypoint_result[str(key)] = relative_text
        artifacts[str(key)] = {
            "path": relative_text,
            "content": content,
        }

    if not artifacts:
        raise ValueError("successful process result did not return any *_path artifacts")
    return {
        "entrypoint_result": entrypoint_result,
        "artifacts": artifacts,
    }


def restore_json_artifacts(
    bundle: Mapping[str, Any],
    *,
    output_root: str | Path,
    required_keys: Iterable[str] = (),
) -> dict[str, Any]:
    """Materialize a stored artifact bundle and restore native absolute paths."""
    entrypoint = bundle.get("entrypoint_result")
    artifacts = bundle.get("artifacts")
    if not isinstance(entrypoint, Mapping) or entrypoint.get("result") is not True:
        raise ValueError("stored process entrypoint_result is not successful")
    if not isinstance(artifacts, Mapping) or not artifacts:
        raise ValueError("stored process artifacts must be a non-empty mapping")

    required = tuple(str(key) for key in required_keys)
    missing = [
        key for key in required
        if key not in entrypoint or key not in artifacts
    ]
    if missing:
        raise ValueError(
            "stored process result is missing required artifact(s): "
            + ", ".join(missing)
        )

    root = Path(output_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    restored = dict(entrypoint)
    for raw_key, raw_artifact in artifacts.items():
        key = str(raw_key)
        if not key.endswith("_path"):
            raise ValueError(f"stored process artifact key is not a path: {key}")
        if not isinstance(raw_artifact, Mapping):
            raise TypeError(f"stored process artifact {key!r} must be a mapping")
        relative_text = raw_artifact.get("path")
        if not isinstance(relative_text, str) or not relative_text.strip():
            raise TypeError(f"stored process artifact {key!r} path must be a string")
        relative = Path(relative_text)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(
                f"stored process artifact escapes output root: {key}={relative_text}"
            )
        destination = (root / relative).resolve()
        try:
            destination.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                f"stored process artifact escapes output root: {key}={relative_text}"
            ) from exc
        entrypoint_path = entrypoint.get(key)
        if entrypoint_path != relative_text:
            raise ValueError(
                f"stored process artifact path mismatch: {key}="
                f"{entrypoint_path!r} != {relative_text!r}"
            )
        if "content" not in raw_artifact:
            raise ValueError(f"stored process artifact {key!r} is missing content")

        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".restore.tmp")
        temporary.write_text(
            json.dumps(raw_artifact["content"], ensure_ascii=False, indent=2)
            + "\n",
            encoding="utf-8",
        )
        temporary.replace(destination)
        restored[key] = str(destination)

    return restored


__all__ = ["collect_json_artifacts", "restore_json_artifacts"]
