"""Samples router — history, search, tags, annotations."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Session

from api.auth import get_current_user, get_optional_user
from api.database.engine import get_db
from api.database.orm_models import AnalysisJob, Annotation, Upload

router = APIRouter(tags=["samples"])


class TagRequest(BaseModel):
    tags: list[str]


class AnnotationRequest(BaseModel):
    content: str
    annotation_type: str = "note"  # note | label | verdict_override


@router.get("/samples")
def list_samples(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    search: str = Query(None, description="Search by filename, hash, or tag"),
    file_type: str = Query(None, description="Filter by file type: pe, elf, macho, pcap, firmware"),
    verdict: str = Query(None, description="Filter by verdict: clean, suspicious, malicious"),
    sort: str = Query("newest", description="Sort: newest, oldest, name, size"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List uploaded samples with search and filters."""
    query = db.query(Upload).filter(Upload.user_id == current_user["user_id"])

    # Search
    if search:
        search_term = f"%{search}%"
        query = query.filter(or_(
            Upload.filename.ilike(search_term),
            Upload.md5.ilike(search_term),
            Upload.sha256.ilike(search_term),
            Upload.tags.ilike(search_term),
        ))

    # Filters
    if file_type:
        query = query.filter(Upload.file_type == file_type)

    # Sort
    if sort == "oldest":
        query = query.order_by(Upload.created_at.asc())
    elif sort == "name":
        query = query.order_by(Upload.filename.asc())
    elif sort == "size":
        query = query.order_by(Upload.file_size.desc())
    else:
        query = query.order_by(Upload.created_at.desc())

    total = query.count()
    uploads = query.offset((page - 1) * per_page).limit(per_page).all()

    # Get latest job info for each upload
    samples = []
    for u in uploads:
        latest_job = db.query(AnalysisJob).filter(
            AnalysisJob.upload_id == u.id,
        ).order_by(AnalysisJob.created_at.desc()).first()

        samples.append({
            "id": u.id,
            "filename": u.filename,
            "file_size": u.file_size,
            "file_type": u.file_type,
            "md5": u.md5,
            "sha256": u.sha256,
            "tags": [t.strip() for t in u.tags.split(",") if t.strip()] if u.tags else [],
            "created_at": u.created_at.isoformat(),
            "analysis": {
                "job_id": latest_job.id if latest_job else None,
                "status": latest_job.status if latest_job else None,
                "verdict": latest_job.verdict if latest_job else None,
                "verdict_confidence": latest_job.verdict_confidence if latest_job else None,
                "finding_count": latest_job.finding_count if latest_job else 0,
                "ioc_count": latest_job.ioc_count if latest_job else 0,
            } if latest_job else None,
        })

    # Verdict filter (post-query since it's in AnalysisJob)
    if verdict:
        samples = [s for s in samples if s.get("analysis", {}).get("verdict") == verdict]

    return {
        "samples": samples,
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.get("/samples/{upload_id}")
def get_sample(
    upload_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get full details for a sample including all jobs and annotations."""
    upload = db.query(Upload).filter(
        Upload.id == upload_id,
        Upload.user_id == current_user["user_id"],
    ).first()
    if not upload:
        raise HTTPException(status_code=404, detail="Sample not found")

    jobs = db.query(AnalysisJob).filter(
        AnalysisJob.upload_id == upload_id,
    ).order_by(AnalysisJob.created_at.desc()).all()

    annotations = db.query(Annotation).filter(
        Annotation.upload_id == upload_id,
    ).order_by(Annotation.created_at.desc()).all()

    return {
        "id": upload.id,
        "filename": upload.filename,
        "file_size": upload.file_size,
        "file_type": upload.file_type,
        "md5": upload.md5,
        "sha256": upload.sha256,
        "tags": [t.strip() for t in upload.tags.split(",") if t.strip()] if upload.tags else [],
        "created_at": upload.created_at.isoformat(),
        "jobs": [
            {
                "id": j.id,
                "status": j.status,
                "verdict": j.verdict,
                "verdict_confidence": j.verdict_confidence,
                "finding_count": j.finding_count,
                "ioc_count": j.ioc_count,
                "created_at": j.created_at.isoformat(),
                "completed_at": j.completed_at.isoformat() if j.completed_at else None,
            }
            for j in jobs
        ],
        "annotations": [
            {
                "id": a.id,
                "content": a.content,
                "type": a.annotation_type,
                "created_at": a.created_at.isoformat(),
            }
            for a in annotations
        ],
    }


@router.put("/samples/{upload_id}/tags")
def update_tags(
    upload_id: str,
    req: TagRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Set tags on a sample."""
    upload = db.query(Upload).filter(
        Upload.id == upload_id,
        Upload.user_id == current_user["user_id"],
    ).first()
    if not upload:
        raise HTTPException(status_code=404, detail="Sample not found")

    upload.tags = ",".join(req.tags)
    db.commit()

    return {"tags": req.tags}


@router.post("/samples/{upload_id}/annotations")
def add_annotation(
    upload_id: str,
    req: AnnotationRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Add a note or label to a sample."""
    upload = db.query(Upload).filter(
        Upload.id == upload_id,
        Upload.user_id == current_user["user_id"],
    ).first()
    if not upload:
        raise HTTPException(status_code=404, detail="Sample not found")

    annotation = Annotation(
        upload_id=upload_id,
        user_id=current_user["user_id"],
        content=req.content,
        annotation_type=req.annotation_type,
    )
    db.add(annotation)
    db.commit()
    db.refresh(annotation)

    return {
        "id": annotation.id,
        "content": annotation.content,
        "type": annotation.annotation_type,
        "created_at": annotation.created_at.isoformat(),
    }


@router.delete("/samples/{upload_id}/annotations/{annotation_id}")
def delete_annotation(
    upload_id: str,
    annotation_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete an annotation."""
    annotation = db.query(Annotation).filter(
        Annotation.id == annotation_id,
        Annotation.upload_id == upload_id,
        Annotation.user_id == current_user["user_id"],
    ).first()
    if not annotation:
        raise HTTPException(status_code=404, detail="Annotation not found")

    db.delete(annotation)
    db.commit()
    return {"message": "Annotation deleted"}


@router.get("/dashboard/stats")
def dashboard_stats(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Dashboard statistics for the current user."""
    total_samples = db.query(Upload).filter(
        Upload.user_id == current_user["user_id"],
    ).count()

    total_jobs = db.query(AnalysisJob).join(Upload).filter(
        Upload.user_id == current_user["user_id"],
    ).count()

    completed_jobs = db.query(AnalysisJob).join(Upload).filter(
        Upload.user_id == current_user["user_id"],
        AnalysisJob.status == "completed",
    )

    verdicts = {"clean": 0, "suspicious": 0, "malicious": 0}
    for job in completed_jobs:
        if job.verdict in verdicts:
            verdicts[job.verdict] += 1

    # Recent file types
    type_counts = {}
    recent = db.query(Upload).filter(
        Upload.user_id == current_user["user_id"],
    ).order_by(Upload.created_at.desc()).limit(100).all()
    for u in recent:
        type_counts[u.file_type] = type_counts.get(u.file_type, 0) + 1

    return {
        "total_samples": total_samples,
        "total_analyses": total_jobs,
        "verdicts": verdicts,
        "file_types": type_counts,
    }
