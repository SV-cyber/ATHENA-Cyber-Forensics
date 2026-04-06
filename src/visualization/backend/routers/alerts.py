from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..dependencies import get_db
from ..schemas.alert import AlertListResponse, AlertResponse, AlertStatsResponse
from utils.database import Alert


router = APIRouter(tags=["alerts"])


def _serialize_alert(alert: Alert) -> Dict[str, Any]:
    return {
        "id": alert.id,
        "alert_id": alert.alert_id,
        "timestamp": alert.timestamp,
        "source_ip": str(alert.source_ip) if alert.source_ip else None,
        "event_type": alert.event_type,
        "severity": alert.severity,
        "rule_alerts": list(alert.rule_alerts or []),
        "ml_score": alert.ml_score,
        "duplicate_count": alert.duplicate_count,
        "status": alert.status,
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
    }


@router.get("/alerts/stats", response_model=AlertStatsResponse)
def alert_stats(db: Session = Depends(get_db)) -> AlertStatsResponse:
    now = datetime.now(timezone.utc)
    last_hour = now - timedelta(hours=1)
    last_day = now - timedelta(days=1)

    severity_rows = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    by_severity = {str(severity or "unknown"): int(count) for severity, count in severity_rows}

    return AlertStatsResponse(
        total=int(db.query(func.count(Alert.id)).scalar() or 0),
        last_hour=int(db.query(func.count(Alert.id)).filter(Alert.timestamp >= last_hour).scalar() or 0),
        last_day=int(db.query(func.count(Alert.id)).filter(Alert.timestamp >= last_day).scalar() or 0),
        by_severity=by_severity,
    )


@router.get("/alerts", response_model=AlertListResponse)
def list_alerts(
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    start_time: Optional[datetime] = Query(default=None),
    end_time: Optional[datetime] = Query(default=None),
    db: Session = Depends(get_db),
) -> AlertListResponse:
    query = db.query(Alert).order_by(Alert.timestamp.desc(), Alert.id.desc())
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if start_time:
        query = query.filter(Alert.timestamp >= start_time)
    if end_time:
        query = query.filter(Alert.timestamp <= end_time)

    rows = query.all()
    data = [AlertResponse.model_validate(_serialize_alert(row)) for row in rows]
    return AlertListResponse(count=len(data), data=data)


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: str, db: Session = Depends(get_db)) -> AlertResponse:
    row = db.query(Alert).filter(Alert.alert_id == alert_id).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertResponse.model_validate(_serialize_alert(row))


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertResponse)
def acknowledge_alert(alert_id: str, db: Session = Depends(get_db)) -> AlertResponse:
    row = db.query(Alert).filter(Alert.alert_id == alert_id).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    row.status = "acknowledged"
    row.updated_at = datetime.now(timezone.utc)
    db.add(row)
    db.commit()
    db.refresh(row)
    return AlertResponse.model_validate(_serialize_alert(row))


@router.post("/alerts/{alert_id}/resolve", response_model=AlertResponse)
def resolve_alert(alert_id: str, db: Session = Depends(get_db)) -> AlertResponse:
    row = db.query(Alert).filter(Alert.alert_id == alert_id).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    row.status = "resolved"
    row.updated_at = datetime.now(timezone.utc)
    db.add(row)
    db.commit()
    db.refresh(row)
    return AlertResponse.model_validate(_serialize_alert(row))
