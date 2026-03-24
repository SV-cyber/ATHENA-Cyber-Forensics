"""
ATHENA database models and session management.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from .config import DatabaseConfig


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class EventRecord(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_uid: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    event_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    event_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    tactic: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    technique_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    tactic_encoded: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    severity_encoded: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    mcdm_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    threat_feed_hit: Mapped[bool] = mapped_column(Boolean, default=False)
    raw_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    detections: Mapped[list["DetectionResult"]] = relationship(back_populates="event", cascade="all, delete-orphan")


class DetectionResult(Base):
    __tablename__ = "detection_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    model_name: Mapped[str] = mapped_column(String(100))
    confidence_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    anomaly_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    is_true_positive: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    is_malicious_pred: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True, index=True)
    raw_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    event: Mapped[EventRecord] = relationship(back_populates="detections")


class CorrelationRecord(Base):
    __tablename__ = "correlations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chain_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    parent_event_id: Mapped[Optional[int]] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), nullable=True)
    child_event_id: Mapped[Optional[int]] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), nullable=True)
    correlation_type: Mapped[str] = mapped_column(String(100), index=True)
    strength: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    gap_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    chain_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    is_multi_stage: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    reasons: Mapped[Optional[list[Any]]] = mapped_column(JSON, nullable=True)
    raw_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


engine = create_engine(
    DatabaseConfig.connection_string(),
    future=True,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, class_=Session)


def ensure_schema() -> None:
    Base.metadata.create_all(bind=engine)


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def reset_pipeline_tables(session: Session) -> None:
    session.query(CorrelationRecord).delete()
    session.query(DetectionResult).delete()
    session.query(EventRecord).delete()
