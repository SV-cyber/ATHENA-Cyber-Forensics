from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AlertCreate(BaseModel):
    alert_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    rule_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    ml_score: Optional[float] = None
    duplicate_count: int = 1
    status: str = "active"


class AlertResponse(BaseModel):
    id: int
    alert_id: str
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    rule_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    ml_score: Optional[float] = None
    duplicate_count: int = 1
    status: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class AlertListResponse(BaseModel):
    count: int
    data: List[AlertResponse]


class AlertStatsResponse(BaseModel):
    total: int
    last_hour: int
    last_day: int
    by_severity: Dict[str, int] = Field(default_factory=dict)
