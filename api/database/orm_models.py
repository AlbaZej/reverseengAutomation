"""SQLAlchemy ORM models for the API."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


# --- Auth ---

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    name = Column(String, default="")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    uploads = relationship("Upload", back_populates="user")
    api_keys = relationship("ApiKey", back_populates="user")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, default="default")
    key_hash = Column(String, nullable=False, unique=True, index=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_used_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="api_keys")


# --- Samples ---

class Upload(Base):
    __tablename__ = "uploads"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    filename = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    file_size = Column(Integer, nullable=False)
    file_type = Column(String, default="unknown")
    md5 = Column(String, index=True)
    sha256 = Column(String, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Tags for organization
    tags = Column(String, default="")  # comma-separated

    user = relationship("User", back_populates="uploads")
    jobs = relationship("AnalysisJob", back_populates="upload")
    annotations = relationship("Annotation", back_populates="upload")


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    upload_id = Column(String, ForeignKey("uploads.id"), nullable=False)
    status = Column(String, default="pending")  # pending | running | completed | failed
    result_json = Column(Text, nullable=True)
    error = Column(Text, nullable=True)
    verdict = Column(String, nullable=True)
    verdict_confidence = Column(Float, nullable=True)
    finding_count = Column(Integer, default=0)
    ioc_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)

    upload = relationship("Upload", back_populates="jobs")


# --- Annotations ---

class Annotation(Base):
    __tablename__ = "annotations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    upload_id = Column(String, ForeignKey("uploads.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    annotation_type = Column(String, default="note")  # note | label | verdict_override
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    upload = relationship("Upload", back_populates="annotations")
