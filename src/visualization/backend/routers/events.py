from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from sqlalchemy.orm import Session

from ..dependencies import get_db
from ..schemas.events import EventCreate, EventIngestResponse, EventListResponse, EventResponse
from ..services.events import create_event, list_events, normalize_event_payload, process_event_async
from utils.database import Event


router = APIRouter(tags=["events"])


@router.post("/events", response_model=EventIngestResponse, status_code=201)
def ingest_event(
    payload: EventCreate,
    background_tasks: BackgroundTasks,
    async_process: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> EventIngestResponse:
    if not async_process:
        return EventIngestResponse.model_validate(create_event(db, payload))

    normalized = normalize_event_payload(payload)
    event = Event(
        event_uid=normalized["event_id"],
        event_name=normalized["event_name"],
        timestamp=normalized["timestamp"],
        source_ip=normalized["source_ip"],
        destination_ip=normalized["destination_ip"],
        event_type=normalized["event_type"],
        tactic=normalized["tactic"],
        technique_id=normalized["technique_id"],
        severity=normalized["severity"],
        is_malicious=normalized["is_malicious"],
        tactic_encoded=normalized["tactic_encoded"],
        severity_encoded=normalized["severity_encoded"],
        mcdm_score=normalized["mcdm_score"],
        threat_actor=normalized["threat_actor"],
        threat_feed_hit=normalized["threat_feed_hit"],
        raw_data=normalized["raw_data"],
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    background_tasks.add_task(process_event_async, event.id)

    response = EventIngestResponse.model_validate(
        {
            **normalized["raw_data"],
            "db_id": event.id,
            "event_id": event.event_uid,
            "event_name": event.event_name,
            "timestamp": event.timestamp,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "event_type": event.event_type,
            "tactic": event.tactic,
            "technique_id": event.technique_id,
            "severity": event.severity,
            "is_malicious": event.is_malicious,
            "tactic_encoded": event.tactic_encoded,
            "severity_encoded": event.severity_encoded,
            "mcdm_score": event.mcdm_score,
            "threat_actor": event.threat_actor,
            "threat_feed_hit": event.threat_feed_hit,
            "tag": normalized["raw_data"].get("tag", "normal"),
            "detections": [],
            "correlation": None,
            "processing_mode": "background",
        }
    )
    return response


@router.get("/events", response_model=EventListResponse)
def get_events(db: Session = Depends(get_db)) -> EventListResponse:
    events = [EventResponse.model_validate(item) for item in list_events(db)]
    return EventListResponse(count=len(events), data=events)
