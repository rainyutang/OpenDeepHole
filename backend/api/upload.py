"""Upload API — handles source code zip file uploads."""

import json
import shutil
import uuid
import zipfile
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, HTTPException, UploadFile

from backend.config import get_config
from backend.logger import get_logger
from backend.models import UploadResponse

router = APIRouter()
logger = get_logger(__name__)

CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB chunks


def _parse_project(project_id: str, project_dir: Path) -> None:
    """Background task: parse C/C++ source and populate code_index.db."""
    from code_parser import CodeDatabase, CppAnalyzer

    status_path = project_dir / "parse_status.json"
    db_path = project_dir / "code_index.db"

    status_path.write_text(json.dumps({"status": "parsing"}))
    try:
        db = CodeDatabase(db_path)
        analyzer = CppAnalyzer(db)
        analyzer.analyze_directory(project_dir)
        db.close()
        status_path.write_text(json.dumps({"status": "done"}))
        logger.info("Project %s: code index built at %s", project_id, db_path)
    except Exception as exc:
        logger.exception("Project %s: code indexing failed", project_id)
        status_path.write_text(json.dumps({"status": "error", "error": str(exc)}))


@router.post("/api/upload", response_model=UploadResponse)
async def upload_source(file: UploadFile, background_tasks: BackgroundTasks) -> UploadResponse:
    """Upload a source code zip file for analysis.

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
    background_tasks.add_task(_parse_project, project_id, project_dir)
    return UploadResponse(project_id=project_id)
