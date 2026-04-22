"""AI router — AI-powered analysis interpretation."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.auth import get_current_user
from api.database.engine import get_db
from api.database.orm_models import AnalysisJob

router = APIRouter(tags=["ai"])


class AskRequest(BaseModel):
    job_id: str
    question: str


class ExplainFunctionRequest(BaseModel):
    code: str
    context: str = ""


@router.get("/ai/status")
def ai_status():
    """Check if AI features are available."""
    from core.ai.interpreter import is_ai_available
    return {"available": is_ai_available()}


@router.post("/ai/explain")
def explain_analysis(
    job_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get an AI explanation of analysis results."""
    from core.ai.interpreter import explain_report

    report = _load_report(job_id, db)
    result = explain_report(report)
    return result


@router.post("/ai/ask")
def ask_about_binary(
    req: AskRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Ask a question about an analyzed binary."""
    from core.ai.interpreter import ask_about_binary

    report = _load_report(req.job_id, db)
    result = ask_about_binary(report, req.question)
    return result


@router.post("/ai/explain-function")
def explain_function(
    req: ExplainFunctionRequest,
    current_user: dict = Depends(get_current_user),
):
    """Explain a decompiled function."""
    from core.ai.interpreter import explain_function

    result = explain_function(req.code, req.context)
    return result


@router.post("/ai/generate-yara")
def generate_yara(
    job_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate a YARA rule from analysis results."""
    from core.ai.interpreter import generate_yara_rule

    report = _load_report(job_id, db)
    result = generate_yara_rule(report)
    return result


def _load_report(job_id: str, db: Session):
    """Load an AnalysisReport from a job ID."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "completed" or not job.result_json:
        raise HTTPException(status_code=400, detail="Analysis not completed")

    # Reconstruct a minimal report object for the AI context builder
    # We pass the raw JSON data since the AI module just needs the text context
    from core.models import AnalysisReport, FileInfo, FileType, Architecture
    from pathlib import Path

    data = json.loads(job.result_json)
    fi_data = data.get("file_info", {})

    file_info = FileInfo(
        path=Path(fi_data.get("path", "unknown")),
        size=fi_data.get("size", 0),
        md5=fi_data.get("md5", ""),
        sha256=fi_data.get("sha256", ""),
        file_type=FileType(fi_data.get("file_type", "unknown")),
        mime_type=fi_data.get("mime_type", ""),
        architecture=Architecture(fi_data.get("architecture", "unknown")),
        is_packed=fi_data.get("is_packed", False),
        packer_name=fi_data.get("packer_name"),
        compiler=fi_data.get("compiler"),
    )

    report = AnalysisReport(file_info=file_info)
    report.verdict = data.get("verdict", "unknown")
    report.verdict_confidence = data.get("verdict_confidence", 0)

    # Reconstruct findings
    from core.models import Finding, SignalType
    for f in data.get("findings", []):
        report.findings.append(Finding(
            title=f["title"],
            description=f["description"],
            severity=SignalType(f["severity"]),
            source_tool=f["source_tool"],
            evidence=f.get("evidence", ""),
            mitre_ids=f.get("mitre_ids", []),
        ))

    # Reconstruct IOCs
    from core.models import IOC
    for i in data.get("iocs", []):
        report.iocs.append(IOC(
            type=i["type"],
            value=i["value"],
            context=i.get("context", ""),
        ))

    # Reconstruct strings
    from core.models import ExtractedString
    for s in data.get("strings", {}).get("interesting", []):
        report.strings.append(ExtractedString(
            value=s["value"],
            offset=s.get("offset", 0),
            encoding="ascii",
            category=s.get("category", "other"),
            is_interesting=True,
        ))

    return report
