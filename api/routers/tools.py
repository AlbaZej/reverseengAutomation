"""Tools router — run individual tools and utilities on demand."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.database.engine import get_db
from api.database.orm_models import Upload

router = APIRouter(tags=["tools"])


class DiffRequest(BaseModel):
    upload_id_1: str
    upload_id_2: str


class VTLookupRequest(BaseModel):
    hash: str | None = None
    upload_id: str | None = None


@router.post("/diff")
def diff_binaries(req: DiffRequest, db: Session = Depends(get_db)):
    """Compare two uploaded files."""
    upload1 = db.query(Upload).filter(Upload.id == req.upload_id_1).first()
    upload2 = db.query(Upload).filter(Upload.id == req.upload_id_2).first()

    if not upload1 or not upload2:
        raise HTTPException(status_code=404, detail="One or both uploads not found")

    from core.tools.diff_tool import DiffTool
    tool = DiffTool()
    result = tool._timed_run(Path(upload1.file_path), target2=upload2.file_path)

    if not result.success:
        raise HTTPException(status_code=500, detail=result.error)

    return {
        "success": True,
        "file1": upload1.filename,
        "file2": upload2.filename,
        "result": _serialize_diff(result.data),
    }


@router.post("/vt-lookup")
def vt_lookup(req: VTLookupRequest, db: Session = Depends(get_db)):
    """Look up a file hash on VirusTotal."""
    from core.tools.virustotal import VirusTotalTool
    tool = VirusTotalTool()

    if not tool.is_available():
        raise HTTPException(status_code=503, detail="VT_API_KEY not configured")

    if req.hash:
        result = tool.lookup_hash(req.hash)
    elif req.upload_id:
        upload = db.query(Upload).filter(Upload.id == req.upload_id).first()
        if not upload:
            raise HTTPException(status_code=404, detail="Upload not found")
        result = tool._timed_run(Path(upload.file_path))
    else:
        raise HTTPException(status_code=400, detail="Provide hash or upload_id")

    if not result.success:
        raise HTTPException(status_code=502, detail=result.error)

    return {"success": True, "result": result.data}


@router.get("/tools")
def list_tools():
    """List available analysis tools and their status."""
    from core.tools.binwalk_tool import BinwalkTool
    from core.tools.die_tool import DieTool
    from core.tools.diff_tool import DiffTool
    from core.tools.entropy_tool import EntropyTool
    from core.tools.frida_tool import FridaTool
    from core.tools.ghidra import GhidraTool
    from core.tools.radare2 import Radare2Tool
    from core.tools.strings_tool import StringsTool
    from core.tools.virustotal import VirusTotalTool
    from core.tools.yara_tool import YaraTool

    all_tools = [
        StringsTool(), EntropyTool(), YaraTool(), DieTool(),
        Radare2Tool(), GhidraTool(), FridaTool(), BinwalkTool(),
        VirusTotalTool(), DiffTool(),
    ]

    return {
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "available": t.is_available(),
                "supported_types": t.supported_types,
            }
            for t in all_tools
        ]
    }


def _serialize_diff(data: dict) -> dict:
    """Ensure diff data is JSON-serializable."""
    # Data is already primitive types from DiffTool
    return data
