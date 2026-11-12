"""Artifacts services for Agent-backed scans."""

from __future__ import annotations
from backend.agents import constants
from backend.application import (
    ApplicationError as HTTPException,
    DownloadArtifact as Response,
    get_runtime,
    get_scan_store,
    run_store_call,
)
from pathlib import Path
from backend.models import User
from backend.agents.schemas import _RuntimeDownload
import asyncio
import hashlib
import io
import secrets
import time
import zipfile
from backend.logger import get_logger
logger = get_logger(__name__)


def _purge_expired_runtime_downloads() -> None:
    now = time.time()
    expired = [
        token
        for token, download in get_runtime().agents.runtime_download_tokens.items()
        if download.expires_at <= now
    ]
    for token in expired:
        get_runtime().agents.runtime_download_tokens.pop(token, None)


def _agent_runtime_hash_scope() -> dict:
    return {
        "version": 4,
        "dirs": list(constants._AGENT_RUNTIME_DIRS),
        "tool_dirs": list(constants._AGENT_TOOL_DIRS),
        "root_files": list(constants._AGENT_RUNTIME_ROOT_FILES),
        "skip_dirs": sorted(constants._AGENT_RUNTIME_SKIP_DIRS),
        "skip_suffixes": sorted(constants._AGENT_SKIP_SUFFIXES),
    }


def _should_skip_agent_file(path: Path, skip_dirs: set[str]) -> bool:
    return path.suffix in constants._AGENT_SKIP_SUFFIXES or any(part in skip_dirs for part in path.parts)


def _iter_agent_runtime_files():
    for dir_name in [*constants._AGENT_RUNTIME_DIRS, *constants._AGENT_TOOL_DIRS]:
        dir_path = constants._PROJECT_ROOT / dir_name
        if not dir_path.is_dir():
            continue
        # Sort by POSIX arcname to ensure consistent ordering across platforms
        # (Windows Path sorting is case-insensitive, Linux is case-sensitive).
        entries = []
        for file_path in dir_path.rglob("*"):
            if file_path.is_file() and not _should_skip_agent_file(file_path, constants._AGENT_RUNTIME_SKIP_DIRS):
                arcname = file_path.relative_to(constants._PROJECT_ROOT).as_posix()
                entries.append((arcname, file_path))
        entries.sort(key=lambda e: e[0])
        yield from entries
    for filename in constants._AGENT_RUNTIME_ROOT_FILES:
        file_path = constants._PROJECT_ROOT / filename
        if file_path.is_file():
            yield filename, file_path


def _agent_runtime_hash() -> str:
    digest = hashlib.sha256()
    for arcname, file_path in _iter_agent_runtime_files():
        digest.update(arcname.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _agent_runtime_hash_for_files(files: list[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256()
    for arcname, content in files:
        digest.update(arcname.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def _agent_runtime_manifest_for_files(files: list[tuple[str, bytes]]) -> dict:
    return {
        "hash_scope": _agent_runtime_hash_scope(),
        "files": [
            {
                "path": arcname,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
            for arcname, content in files
        ],
    }


def _read_agent_runtime_files() -> list[tuple[str, bytes]]:
    return [(arcname, file_path.read_bytes()) for arcname, file_path in _iter_agent_runtime_files()]


def _build_agent_runtime_zip() -> bytes:
    return _build_agent_runtime_zip_from_files(_read_agent_runtime_files())


def _build_agent_runtime_zip_from_files(files: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, content in files:
            zf.writestr(arcname, content)
    return buf.getvalue()


def _build_agent_runtime_download() -> _RuntimeDownload:
    from backend.agents.schemas import _RuntimeDownload
    files = _read_agent_runtime_files()
    data = _build_agent_runtime_zip_from_files(files)
    runtime_hash = _agent_runtime_hash_for_files(files)
    manifest = _agent_runtime_manifest_for_files(files)
    manifest["runtime_hash"] = runtime_hash
    return _RuntimeDownload(
        runtime_hash=runtime_hash,
        archive_sha256=hashlib.sha256(data).hexdigest(),
        manifest=manifest,
        data=data,
        expires_at=time.time() + constants._RUNTIME_DOWNLOAD_TOKEN_TTL_SECONDS,
    )


def create_agent_runtime_update_payload(server_url: str) -> dict:
    _purge_expired_runtime_downloads()
    download = _build_agent_runtime_download()
    token = secrets.token_urlsafe(32)
    get_runtime().agents.runtime_download_tokens[token] = download
    return {
        "hash": download.runtime_hash,
        "archive_sha256": download.archive_sha256,
        "manifest": download.manifest,
        "hash_scope": download.manifest["hash_scope"],
        "download_url": f"{server_url.rstrip('/')}/api/agent/runtime/download",
        "token": token,
        "expires_at": int(download.expires_at),
    }


def create_agent_task_runtime_update_payload(server_url: str, agent_key: str) -> dict | None:
    """Keep ordinary tasks from bypassing a queued idle-only manual update."""
    from backend.agents.runtime_updates import _runtime_update_status
    normalized_key = str(agent_key or "").strip()
    if normalized_key:
        record = get_scan_store().get_agent_record(normalized_key)
        if _runtime_update_status(record) in constants._RUNTIME_UPDATE_ACTIVE_STATUSES:
            return None
    return create_agent_runtime_update_payload(server_url)


async def create_agent_task_runtime_update_payload_async(
    server_url: str,
    agent_key: str,
) -> dict | None:
    """Build the runtime archive off-loop after an async durable-state check."""
    from backend.agents.runtime_updates import _runtime_update_status
    normalized_key = str(agent_key or "").strip()
    if normalized_key:
        record = await run_store_call(
            get_scan_store(),
            "get_agent_record",
            normalized_key,
        )
        if _runtime_update_status(record) in constants._RUNTIME_UPDATE_ACTIVE_STATUSES:
            return None
    return await asyncio.to_thread(create_agent_runtime_update_payload, server_url)


def _build_agent_zip(server_url: str='', owner_token: str='') -> bytes:
    """Build the agent zip in-memory from the project source."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for dir_name in [*constants._AGENT_DIRS, *constants._AGENT_TOOL_DIRS]:
            dir_path = constants._PROJECT_ROOT / dir_name
            if not dir_path.is_dir():
                continue
            for file_path in dir_path.rglob("*"):
                if file_path.is_file() and not _should_skip_agent_file(file_path, constants._AGENT_DOWNLOAD_SKIP_DIRS):
                    arcname = str(file_path.relative_to(constants._PROJECT_ROOT))
                    zf.write(file_path, arcname)

        for filename in constants._AGENT_ROOT_FILES:
            file_path = constants._PROJECT_ROOT / filename
            if not file_path.is_file():
                continue
            if filename == "agent.yaml":
                content = file_path.read_text(encoding="utf-8")
                if server_url:
                    content = content.replace(
                        'server_url: "http://your-server:8000"',
                        f'server_url: "{server_url}"',
                    )
                if owner_token:
                    content = content.replace(
                        'owner_token: ""',
                        f'owner_token: "{owner_token}"',
                    )
                zf.writestr(filename, content.encode("utf-8"))
            else:
                zf.write(file_path, filename)

        zf.writestr("README.txt", constants._AGENT_README.encode("utf-8"))

    return buf.getvalue()


async def agent_download(server_url: str, current_user: User=None) -> Response:
    """Serve the agent package as a downloadable zip with server_url and owner_token pre-filled."""
    try:
        server_url = server_url
        data = await asyncio.to_thread(
            _build_agent_zip,
            server_url,
            current_user.agent_token,
        )
    except Exception as exc:
        logger.exception("Failed to build agent zip")
        raise HTTPException(status_code=500, detail=f"Failed to build agent package: {exc}")

    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="opendeephole-agent.zip"'},
    )


async def agent_runtime_manifest() -> dict:
    """Return the current server-side Agent runtime hash."""
    def build_manifest() -> dict:
        files = _read_agent_runtime_files()
        runtime_hash = _agent_runtime_hash_for_files(files)
        manifest = _agent_runtime_manifest_for_files(files)
        manifest["runtime_hash"] = runtime_hash
        return {
            "hash": runtime_hash,
            "hash_scope": manifest["hash_scope"],
            "manifest": manifest,
        }

    return await asyncio.to_thread(build_manifest)


async def agent_runtime_download(token: str) -> Response:
    """Serve a short-lived Agent runtime update archive."""
    _purge_expired_runtime_downloads()
    token = token
    download = get_runtime().agents.runtime_download_tokens.pop(token, None)
    if download is None:
        raise HTTPException(status_code=403, detail="Invalid or expired runtime update token")
    if time.time() > download.expires_at:
        raise HTTPException(status_code=403, detail="Runtime update token expired")

    return Response(
        content=download.data,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="opendeephole-agent-runtime.zip"'},
    )
