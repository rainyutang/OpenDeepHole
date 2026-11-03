"""Materialize the currently selected review notes on the scanning Agent."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any


_LOCK = threading.RLock()
_FAILED_SYNCS: dict[str, int] = {}
_SCAN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_RESERVED = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.I)


def _paths(scan_id: str) -> tuple[Path, Path]:
    if not isinstance(scan_id, str) or not _SCAN_ID.fullmatch(scan_id):
        raise ValueError("Invalid review notes scan_id")
    root = (Path.home() / ".opendeephole" / "scans").resolve()
    scan_dir = root / scan_id
    directory = scan_dir / "review-notes"
    state = scan_dir / "review-notes-state.json"
    if any(path.is_symlink() for path in (scan_dir, directory, state)):
        raise ValueError("Review notes paths must not be symbolic links")
    return directory, state


def _read_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Invalid review notes state")
    return value


def _files_present(directory: Path, state: dict[str, Any]) -> bool:
    files = state.get("files")
    return directory.is_dir() and isinstance(files, list) and all(
        isinstance(name, str) and name not in {"", ".", ".."}
        and "/" not in name and "\\" not in name
        and (directory / name).is_file() and not (directory / name).is_symlink()
        for name in files
    )


def _write_atomic(path: Path, text: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".review-notes-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _file_stem(title: str) -> str:
    stem = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", title).strip(" .") or "note"
    if _RESERVED.match(stem):
        stem = "_" + stem
    # Leave room for .md and a collision suffix within common filename limits.
    while len(stem.encode("utf-8")) > 180:
        stem = stem[:-1]
    return stem.rstrip(" .") or "note"


def _files(payload: dict[str, Any]) -> dict[str, str]:
    entries = payload.get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("Review notes entries must be a list")
    selected = payload.get("note_ids", [])
    if not isinstance(selected, list) or not all(isinstance(item, str) for item in selected):
        raise ValueError("Review notes note_ids must be a list of strings")
    selected_ids = set(selected)
    normalized: list[tuple[str, str, str]] = []
    seen_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Invalid review note entry")
        note_id, title, content = (entry.get(key) for key in ("id", "title", "content"))
        if not all(isinstance(value, str) and value.strip() for value in (note_id, title, content)):
            raise ValueError("Review note id, title and content must be non-empty strings")
        if note_id in seen_ids:
            raise ValueError("Duplicate review note id")
        seen_ids.add(note_id)
        if note_id in selected_ids and payload.get("enabled"):
            normalized.append((note_id, title, content))
    if payload.get("enabled") and selected_ids - seen_ids:
        raise ValueError("Selected review notes are missing from entries")
    result: dict[str, str] = {}
    used: set[str] = set()
    for note_id, title, content in sorted(normalized):
        stem = _file_stem(title)
        filename = stem + ".md"
        if filename.casefold() in used:
            suffix = hashlib.sha256(note_id.encode("utf-8")).hexdigest()[:12]
            filename = f"{stem}-{suffix}.md"
            counter = 2
            while filename.casefold() in used:
                filename = f"{stem}-{suffix}-{counter}.md"
                counter += 1
        used.add(filename.casefold())
        result[filename] = f"# {title}\n\n{content}\n"
    return result


def sync_review_notes(payload: dict[str, Any]) -> int:
    """Replace current Markdown files; return the applied (or newer) revision."""
    scan_id = payload.get("scan_id") if isinstance(payload, dict) else None
    requested_revision = payload.get("revision") if isinstance(payload, dict) else None
    with _LOCK:
        try:
            revision = _sync_review_notes(payload)
        except Exception:
            if isinstance(scan_id, str) and _SCAN_ID.fullmatch(scan_id):
                failed_revision = (
                    requested_revision
                    if isinstance(requested_revision, int) and not isinstance(requested_revision, bool)
                    else 0
                )
                _FAILED_SYNCS[scan_id] = max(_FAILED_SYNCS.get(scan_id, 0), failed_revision)
            raise
        if revision >= _FAILED_SYNCS.get(scan_id, -1):
            _FAILED_SYNCS.pop(scan_id, None)
        return revision


def _sync_review_notes(payload: dict[str, Any]) -> int:
    if not isinstance(payload, dict):
        raise ValueError("Review notes payload must be an object")
    revision = payload.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise ValueError("Invalid review notes revision")
    if not isinstance(payload.get("enabled"), bool):
        raise ValueError("Review notes enabled must be a boolean")
    directory, state_path = _paths(payload.get("scan_id"))
    files = _files(payload)
    with _LOCK:
        try:
            previous = _read_state(state_path)
            previous_revision = int(previous.get("revision", -1))
        except (ValueError, TypeError):
            # A complete server payload can repair corrupt local metadata.
            previous, previous_revision = {}, -1
        if previous_revision > revision or (
            previous_revision == revision and previous.get("synced") is True
            and _files_present(directory, previous)
        ):
            if previous.get("synced") is not True or not _files_present(directory, previous):
                raise RuntimeError("A newer review notes update has not been synchronized")
            return previous_revision
        directory.mkdir(parents=True, exist_ok=True)
        state = {
            "revision": revision,
            "enabled": payload["enabled"],
            "note_ids": list(payload.get("note_ids", [])),
            "files": list(files),
            "synced": False,
        }
        _write_atomic(state_path, json.dumps(state, ensure_ascii=False))
        for filename, content in files.items():
            _write_atomic(directory / filename, content)
        for path in directory.iterdir():
            if path.name not in files and (path.is_file() or path.is_symlink()):
                path.unlink()
        state["synced"] = True
        _write_atomic(state_path, json.dumps(state, ensure_ascii=False))
    return revision


def get_review_notes_dir(scan_id: str) -> Path | None:
    """Read only local selection state when starting a vulnerability review."""
    directory, state_path = _paths(scan_id)
    with _LOCK:
        if scan_id in _FAILED_SYNCS:
            raise RuntimeError("问题判定依据尚未同步成功，请重试同步后再复核")
        state = _read_state(state_path)
        if not state:
            return None
        if state.get("synced") is not True:
            raise RuntimeError("问题判定依据尚未同步成功，请重试同步后再复核")
        if not state.get("enabled") or not state.get("files"):
            return None
        if not _files_present(directory, state):
            raise RuntimeError("问题判定依据文件缺失，请重新同步")
        return directory


def apply_command_review_notes(command: dict[str, Any]) -> None:
    payload = command.get("review_notes")
    if payload is None:
        return
    if not isinstance(payload, dict) or payload.get("scan_id") != command.get("scan_id"):
        raise ValueError("Review notes scan_id does not match command")
    sync_review_notes(payload)


def sync_welcome_review_notes(payloads: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Keep one inaccessible scan from interrupting the Agent reconnect."""
    failures: list[dict[str, str]] = []
    for payload in payloads:
        try:
            sync_review_notes(payload)
        except Exception as exc:
            failures.append({
                "scan_id": str(payload.get("scan_id", "")) if isinstance(payload, dict) else "",
                "error": str(exc),
            })
    return failures


def review_notes_revisions() -> dict[str, int]:
    """Report applied local versions so reconnect only transfers changed notes."""
    root = Path.home() / ".opendeephole" / "scans"
    revisions: dict[str, int] = {}
    with _LOCK:
        for path in root.glob("*/review-notes-state.json"):
            try:
                if path.parent.name in _FAILED_SYNCS:
                    continue
                directory, state_path = _paths(path.parent.name)
                state = _read_state(state_path)
                if state.get("synced") is True and _files_present(directory, state):
                    revisions[path.parent.name] = int(state["revision"])
            except (OSError, ValueError, KeyError, TypeError):
                continue
    return revisions
