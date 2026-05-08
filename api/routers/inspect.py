"""Inspect router — live hex view + on-demand disassembly for the Cutter-like UI."""

from __future__ import annotations

import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.database.engine import get_db
from api.database.orm_models import Upload

router = APIRouter(tags=["inspect"])

# Sane caps to avoid huge responses
MAX_HEX_LENGTH = 4096
MAX_DISASM_LENGTH = 1024


@router.get("/samples/{upload_id}/hex")
def get_hex(
    upload_id: str,
    offset: int = Query(0, ge=0),
    length: int = Query(256, ge=1, le=MAX_HEX_LENGTH),
    db: Session = Depends(get_db),
):
    """Return a hex dump of bytes from a specific offset of the uploaded file."""
    upload = db.query(Upload).filter(Upload.id == upload_id).first()
    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")

    file_path = Path(upload.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found on disk")

    file_size = file_path.stat().st_size
    if offset >= file_size:
        raise HTTPException(status_code=400, detail=f"Offset beyond file size ({file_size})")

    actual_length = min(length, file_size - offset)

    with file_path.open("rb") as f:
        f.seek(offset)
        data = f.read(actual_length)

    # Build hex dump rows: 16 bytes per row
    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk)
        rows.append({
            "offset": offset + i,
            "hex": hex_str,
            "ascii": ascii_str,
        })

    return {
        "offset": offset,
        "length": actual_length,
        "file_size": file_size,
        "rows": rows,
    }


@router.get("/samples/{upload_id}/disasm")
def get_disasm(
    upload_id: str,
    offset: int = Query(..., ge=0, description="Address or file offset to disassemble"),
    length: int = Query(64, ge=1, le=MAX_DISASM_LENGTH, description="Bytes to disassemble"),
    use_address: bool = Query(False, description="If true, treat offset as virtual address"),
    db: Session = Depends(get_db),
):
    """Disassemble bytes via radare2."""
    upload = db.query(Upload).filter(Upload.id == upload_id).first()
    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")

    file_path = Path(upload.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found on disk")

    if not (shutil.which("radare2") or shutil.which("r2")):
        raise HTTPException(
            status_code=503,
            detail="radare2 not installed — install r2 + 'pip install r2pipe' for disassembly",
        )

    try:
        import r2pipe
    except ImportError:
        raise HTTPException(status_code=503, detail="r2pipe not installed (pip install r2pipe)")

    r2 = r2pipe.open(str(file_path), flags=["-2"])
    try:
        # Run basic analysis so r2 knows about functions at the requested address
        r2.cmd("aa")
        r2.cmd("aac")

        # Seek to the target
        seek_addr = hex(offset) if use_address else offset
        r2.cmd(f"s {seek_addr}")

        # Try to disassemble as a recognized function first (pdf = print disasm function).
        # This bounds the output to the actual function body, avoiding the trailing
        # garbage / padding ('ff ff ff' invalid bytes) that you get from a fixed-byte
        # disassembly walking past the end of the function into data.
        disasm_text = r2.cmd("pdf").strip()

        # If pdf returned nothing useful (no function defined at that address),
        # fall back to disassembling N instructions so users can still see something.
        if not disasm_text or disasm_text.startswith("ERROR") or "Cannot find function" in disasm_text:
            # Estimate ~4 bytes/instruction on x86, cap at 64 instructions
            n_instructions = min(64, max(8, length // 4))
            disasm_text = r2.cmd(f"pd {n_instructions}")

        # Try to detect function name at this address
        func_info = r2.cmd("afi.").strip()

        return {
            "offset": offset,
            "use_address": use_address,
            "function": func_info or None,
            "disassembly": disasm_text,
        }
    finally:
        r2.quit()


@router.get("/samples/{upload_id}/info")
def get_file_info(
    upload_id: str,
    db: Session = Depends(get_db),
):
    """Quick file metadata for the inspect view."""
    upload = db.query(Upload).filter(Upload.id == upload_id).first()
    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")

    return {
        "upload_id": upload.id,
        "filename": upload.filename,
        "file_size": upload.file_size,
        "file_type": upload.file_type,
        "md5": upload.md5,
        "sha256": upload.sha256,
    }
