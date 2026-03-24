from __future__ import annotations

from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..dependencies import get_db
from ..services.detection_engine import evaluate_event
from utils.database import Event


router = APIRouter(tags=["detections"])


@router.get("/detect")
def detect(limit: Optional[int] = Query(default=None, ge=1), db: Session = Depends(get_db)) -> Dict[str, List[Dict]]:
    query = db.query(Event).order_by(Event.timestamp.desc(), Event.id.desc())
    if limit is not None:
        query = query.limit(limit)

    events = list(reversed(query.all()))
    results: List[Dict] = []
    for event in events:
        detections = evaluate_event(db, event, persist=False)
        for detection in detections:
            if detection["matched"]:
                results.append(
                    {
                        "event_id": event.event_uid,
                        "event_name": event.event_name,
                        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                        "source_ip": event.source_ip,
                        "rule_name": detection["rule_name"],
                        "severity": detection["severity"],
                        "alert": detection["alert"],
                        "confidence_score": detection["confidence_score"],
                        "details": detection["details"],
                    }
                )

    return {"count": len(results), "data": results}
