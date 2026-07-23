"""Upload API — handles source code zip file uploads."""

import json
import shutil
import uuid
import zipfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile

from backend.config import get_config
from backend.logger import get_logger
from backend.models import UploadResponse

router = APIRouter()
logger = get_logger(__name__)

CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB chunks


@router.get("/api/project/{project_id}/index-status")
async def get_index_status(project_id: str) -> dict:
    """Return the current code indexing progress for a project.

    For agent-based scans the project_id equals the scan_name; we check
    the in-memory agent index status store first so agent progress is
    visible through the same polling URL the frontend already uses.
    """
    from backend.api.agent import _scan_index_statuses
    from backend.api.scan import _running_scans

    # Agent scans: find a running scan whose project_id (scan_name) matches
    for scan_id, scan in _running_scans.items():
        if scan.project_id == project_id and scan_id in _scan_index_statuses:
            return _scan_index_statuses[scan_id]

    # Uploaded source is storage only. Code-graph construction is exclusively
    # coordinated by deephole_client, so the backend never executes a process.
    config = get_config()
    project_dir = Path(config.storage.projects_dir) / project_id
    status_path = project_dir / "parse_status.json"
    if not status_path.exists():
        return {"status": "not_started"}
    try:
        return json.loads(status_path.read_text())
    except Exception:
        return {"status": "unknown"}


@router.post("/api/upload", response_model=UploadResponse)
async def upload_source(file: UploadFile) -> UploadResponse:
    """Upload and extract a source-code zip without executing analysis.

    Accepts a .zip file, streams it to disk in chunks to avoid
    loading the entire file into memory, and returns a project_id
    for subsequent scan requests.
    """
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are accepted")

    config = get_config()
    max_bytes = config.storage.max_upload_size_mb * 1024 * 1024

    project_id = uuid.uuid4().hex
    project_dir = Path(config.storage.projects_dir) / project_id
    project_dir.mkdir(parents=True, exist_ok=True)

    zip_path = project_dir / "upload.zip"
    total_written = 0

    try:
        # Stream file to disk in chunks
        with open(zip_path, "wb") as f:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break
                total_written += len(chunk)
                if total_written > max_bytes:
                    f.close()
                    shutil.rmtree(project_dir)
                    raise HTTPException(
                        status_code=400,
                        detail=f"File too large. Max size: {config.storage.max_upload_size_mb}MB",
                    )
                f.write(chunk)

        # Extract zip
        with zipfile.ZipFile(zip_path, "r") as zf:
            # Security: check for path traversal in zip entries
            for name in zf.namelist():
                resolved = (project_dir / name).resolve()
                if not str(resolved).startswith(str(project_dir.resolve())):
                    shutil.rmtree(project_dir)
                    raise HTTPException(status_code=400, detail="Zip contains path traversal")
            zf.extractall(project_dir)

    except zipfile.BadZipFile:
        shutil.rmtree(project_dir)
        raise HTTPException(status_code=400, detail="Invalid zip file")
    except HTTPException:
        raise
    except Exception:
        shutil.rmtree(project_dir, ignore_errors=True)
        raise
    finally:
        zip_path.unlink(missing_ok=True)

    logger.info("Uploaded project %s (%d bytes)", project_id, total_written)
    return UploadResponse(project_id=project_id)
