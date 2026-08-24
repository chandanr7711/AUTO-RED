from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Enum, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./autored.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    DENIED = "denied"


def _uuid() -> str:
    return str(uuid.uuid4())


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(String, primary_key=True, default=_uuid)
    target = Column(String, nullable=False, index=True)
    scan_type = Column(String, nullable=False, default="recon")
    status = Column(Enum(ScanStatus), nullable=False, default=ScanStatus.PENDING)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    results_json = Column(Text, nullable=True)
    error = Column(Text, nullable=True)
    ai_summary = Column(Text, nullable=True)
    ai_status = Column(String, nullable=False, default="idle")  # idle | running | completed | failed
    ai_error = Column(Text, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(String, primary_key=True, default=_uuid)
    timestamp = Column(DateTime, nullable=False)
    target = Column(String, nullable=False)
    action = Column(String, nullable=False)
    authorized = Column(Boolean, nullable=False)
    reason = Column(Text, nullable=False)
    requested_by = Column(String, nullable=False, default="unknown")


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
