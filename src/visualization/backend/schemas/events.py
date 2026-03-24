from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class EventCreate(BaseModel):
    event_id: Optional[str] = Field(default=None, description="External event UUID. Generated if omitted.")
    event_name: Optional[str] = None
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    event_type: Optional[str] = None
    tactic: Optional[str] = None
    technique_id: Optional[str] = None
    severity: Optional[str] = None
    is_malicious: bool = False
    tactic_encoded: Optional[int] = None
    severity_encoded: Optional[int] = None
    mcdm_score: Optional[float] = None
    threat_actor: Optional[str] = None
    threat_feed_hit: bool = False
    raw_data: Optional[Dict[str, Any]] = None


class EventResponse(BaseModel):
    db_id: int
    event_id: str
    event_name: Optional[str] = None
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    event_type: Optional[str] = None
    tactic: Optional[str] = None
    technique_id: Optional[str] = None
    severity: Optional[str] = None
    is_malicious: bool
    tactic_encoded: Optional[int] = None
    severity_encoded: Optional[int] = None
    mcdm_score: Optional[float] = None
    threat_actor: Optional[str] = None
    threat_feed_hit: bool = False
    tag: str = "normal"


class DetectionResultResponse(BaseModel):
    rule_name: str
    matched: bool
    confidence_score: float
    severity: str = "low"
    alert: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)


class EventIngestResponse(EventResponse):
    detections: List[DetectionResultResponse] = Field(default_factory=list)
    correlation: Optional[Dict[str, Any]] = None
    processing_mode: str = "sync"


class EventListResponse(BaseModel):
    count: int
    data: List[EventResponse]
