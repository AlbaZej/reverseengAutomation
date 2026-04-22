"""Export router — download analysis reports in various formats."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from api.database.engine import get_db
from api.database.orm_models import AnalysisJob

router = APIRouter(tags=["export"])


@router.get("/export/{job_id}/{format}")
def export_report(job_id: str, format: str, db: Session = Depends(get_db)):
    """Download an analysis report in the specified format.

    Formats: json, text
    """
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status != "completed" or not job.result_json:
        raise HTTPException(status_code=400, detail=f"Job is {job.status}, not completed")

    if format == "json":
        return PlainTextResponse(
            content=job.result_json,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=deshifro_report_{job_id[:8]}.json"},
        )

    if format == "text":
        # Parse JSON back, generate summary text
        report_data = json.loads(job.result_json)
        lines = [
            "=" * 60,
            "  DESHIFRO ANALYSIS REPORT",
            "=" * 60,
            "",
            f"  File:     {report_data['file_info']['path']}",
            f"  Type:     {report_data['file_info']['file_type']}",
            f"  SHA256:   {report_data['file_info']['sha256']}",
            f"  Verdict:  {report_data['verdict'].upper()} ({report_data['verdict_confidence']:.0%})",
            "",
        ]

        for f in report_data.get("findings", []):
            lines.append(f"  [{f['severity'].upper():8s}] {f['title']}")
            lines.append(f"             {f['description']}")
            lines.append("")

        text = "\n".join(lines)
        return PlainTextResponse(
            content=text,
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename=deshifro_report_{job_id[:8]}.txt"},
        )

    raise HTTPException(status_code=400, detail=f"Unsupported format: {format}. Use 'json' or 'text'.")
