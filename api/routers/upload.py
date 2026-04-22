"""Upload router — handle file uploads."""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, UploadFile
from sqlalchemy.orm import Session

from api.auth import get_optional_user
from api.database.engine import get_db
from api.database.orm_models import Upload

router = APIRouter(tags=["upload"])

UPLOAD_DIR = Path("uploads")


@router.post("/upload")
async def upload_file(
    file: UploadFile,
    db: Session = Depends(get_db),
    current_user: dict | None = Depends(get_optional_user),
):
    """Upload a binary/pcap/firmware file for analysis."""
    upload_id = str(uuid.uuid4())
    upload_dir = UPLOAD_DIR / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)

    file_path = upload_dir / file.filename
    content = await file.read()
    file_path.write_bytes(content)

    from core.ingest.reader import triage_file
    file_info = triage_file(file_path)

    upload = Upload(
        id=upload_id,
        user_id=current_user["user_id"] if current_user else None,
        filename=file.filename,
        file_path=str(file_path),
        file_size=len(content),
        file_type=file_info.file_type.value,
        md5=file_info.md5,
        sha256=file_info.sha256,
    )
    db.add(upload)
    db.commit()

    return {
        "upload_id": upload_id,
        "filename": file.filename,
        "size": len(content),
        "file_type": file_info.file_type.value,
        "md5": file_info.md5,
        "sha256": file_info.sha256,
    }
