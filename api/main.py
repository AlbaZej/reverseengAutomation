"""FastAPI application for Deshifro."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.database.engine import init_db
from api.routers import ai_router, analysis, auth_router, export, inspect, samples, tools, upload

UPLOAD_DIR = Path("uploads")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown logic."""
    UPLOAD_DIR.mkdir(exist_ok=True)
    init_db()
    yield


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


@app.get("/api/health")
def health():
    from core.ai.interpreter import is_ai_available
    return {
        "status": "ok",
        "version": "0.2.0",
        "ai_available": is_ai_available(),
    }
