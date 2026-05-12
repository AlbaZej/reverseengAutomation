"""FastAPI application for Deshifro."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.database.engine import init_db
from api.routers import ai_router, analysis, auth_router, diagnostics, export, inspect, samples, tools, upload

UPLOAD_DIR = Path("uploads")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown logic."""
    UPLOAD_DIR.mkdir(exist_ok=True)
    init_db()
    _recover_orphaned_jobs()
    _warm_ollama()
    yield


def _warm_ollama():
    """Send a tiny prompt to Ollama in a background thread so the model is
    loaded into RAM before the user's first click. The first-call cold load
    on Llama 3.1 8B is ~30s — by warming it at startup, the user always
    gets fast responses.
    """
    import threading

    def _warm():
        try:
            from core.ai.interpreter import is_ai_available, _call_ollama
            if not is_ai_available():
                return
            print("Warming Ollama (loading model into RAM)...")
            _call_ollama("", "Hi", max_tokens=5, timeout=120)
            print("Ollama warmed up — AI calls will now be fast")
        except Exception as e:
            print(f"Ollama warmup failed (will fall back to deterministic): {e}")

    threading.Thread(target=_warm, daemon=True).start()


def _recover_orphaned_jobs():
    """Mark any 'running' or 'pending' jobs as failed at startup.

    Jobs in those states were running in a BackgroundTask of a previous
    API process. When the API restarts, those tasks are gone but the DB
    rows are stuck — so the UI would show them as 'running' forever and
    AI calls on them would fail with 400. Mark them failed instead.
    """
    from datetime import datetime, timezone
    from api.database.engine import SessionLocal
    from api.database.orm_models import AnalysisJob

    db = SessionLocal()
    try:
        orphaned = db.query(AnalysisJob).filter(
            AnalysisJob.status.in_(("running", "pending"))
        ).all()
        for job in orphaned:
            job.status = "failed"
            job.error = "Job orphaned by API restart"
            job.completed_at = datetime.now(timezone.utc)
        if orphaned:
            print(f"Recovered {len(orphaned)} orphaned analysis job(s)")
        db.commit()
    finally:
        db.close()


app = FastAPI(
    title="Deshifro",
    description="Cybersecurity reverse engineering automation API",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Public routes (no auth required)
app.include_router(auth_router.router, prefix="/api")

# Protected routes
app.include_router(upload.router, prefix="/api")
app.include_router(analysis.router, prefix="/api")
app.include_router(export.router, prefix="/api")
app.include_router(tools.router, prefix="/api")
app.include_router(samples.router, prefix="/api")
app.include_router(ai_router.router, prefix="/api")
app.include_router(inspect.router, prefix="/api")
app.include_router(diagnostics.router, prefix="/api")


@app.get("/api/health")
def health():
    from core.ai.interpreter import is_ai_available
    return {
        "status": "ok",
        "version": "0.2.0",
        "ai_available": is_ai_available(),
    }
