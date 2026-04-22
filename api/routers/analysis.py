"""Analysis router — trigger and poll analysis jobs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.database.engine import get_db
from api.database.orm_models import AnalysisJob, Upload

router = APIRouter(tags=["analysis"])


class AnalyzeRequest(BaseModel):
    upload_id: str
    quick: bool = False


def _run_analysis(job_id: str, file_path: str, quick: bool):
    """Background task that runs the analysis pipeline."""
    from api.database.engine import SessionLocal
    from core.analyzers.auto_analyzer import auto_analyze
    from core.report.generator import to_json

    db = SessionLocal()
    try:
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        job.status = "running"
        db.commit()

        report = auto_analyze(Path(file_path), quick=quick)

        job.result_json = to_json(report)
        job.status = "completed"
        job.verdict = report.verdict
        job.verdict_confidence = report.verdict_confidence
        job.finding_count = len(report.findings)
        job.ioc_count = len(report.iocs)
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as e:
        job.status = "failed"
        job.error = str(e)
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()


@router.post("/analyze")
async def start_analysis(
    req: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Start an analysis job for an uploaded file."""
    upload = db.query(Upload).filter(Upload.id == req.upload_id).first()
    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")

    job = AnalysisJob(upload_id=req.upload_id)
    db.add(job)
    db.commit()
    db.refresh(job)

    background_tasks.add_task(_run_analysis, job.id, upload.file_path, req.quick)

    return {"job_id": job.id, "status": "pending"}


@router.get("/analysis/{job_id}")
def get_analysis(job_id: str, db: Session = Depends(get_db)):
    """Get the status and results of an analysis job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    result = {
        "job_id": job.id,
        "status": job.status,
        "verdict": job.verdict,
        "verdict_confidence": job.verdict_confidence,
        "finding_count": job.finding_count,
        "ioc_count": job.ioc_count,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }

    if job.status == "completed" and job.result_json:
        result["report"] = json.loads(job.result_json)
    elif job.status == "failed":
        result["error"] = job.error

    return result
