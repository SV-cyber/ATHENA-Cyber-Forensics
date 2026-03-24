from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from sqlalchemy.orm import Session

from utils.database import Event, SessionLocal
from ..schemas.events import EventCreate
from .detection_engine import evaluate_event
from .correlation_service import run_correlation
SUSPICIOUS_KEYWORDS = ("nmap", "hydra", "netcat", "nc ", "nc.exe", "masscan", "bruteforce", "portscan", "mimikatz")


def serialize_event(event: Event) -> Dict[str, Any]:
    raw = dict(event.raw_data or {})
    raw.update(
        {
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
            "tag": raw.get("tag", "normal"),
        }
    )
    return raw


def create_event(db: Session, payload: EventCreate) -> Dict[str, Any]:
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

    detections = evaluate_event(db, event)
    db.commit()

    correlation = run_correlation(db, event=event)
    result = serialize_event(event)
    result["detections"] = detections
    result["correlation"] = correlation
    return result


def process_event_async(event_id: int) -> None:
    db = SessionLocal()
    try:
        event = db.query(Event).filter(Event.id == event_id).one_or_none()
        if event is None:
            return
        evaluate_event(db, event)
        db.commit()
        run_correlation(db, event=event)
    finally:
        db.close()


def list_events(db: Session) -> List[Dict[str, Any]]:
    rows = db.query(Event).order_by(Event.timestamp.asc(), Event.id.asc()).all()
    return [serialize_event(row) for row in rows]


def normalize_event_payload(payload: EventCreate) -> Dict[str, Any]:
    raw_data = dict(payload.raw_data or {})
    if not raw_data:
        raw_data = payload.model_dump(exclude_none=True)

    timestamp = payload.timestamp or datetime.now(timezone.utc)
    source_ip = _normalize_ip(payload.source_ip)
    destination_ip = _normalize_ip(payload.destination_ip)
    event_type = _normalize_text(payload.event_type or raw_data.get("event_type"))
    event_name = _normalize_text(payload.event_name or event_type or payload.technique_id or payload.tactic)
    tactic = _normalize_text(payload.tactic)
    technique_id = _normalize_text(payload.technique_id)
    severity = _normalize_text(payload.severity) or "low"
    raw_data.update(
        {
            "event_id": payload.event_id or str(uuid4()),
            "event_name": event_name,
            "event_type": event_type,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "timestamp": timestamp.isoformat(),
            "severity": severity,
        }
    )

    suspicious_reasons = []
    if not event_type:
        suspicious_reasons.append("missing_event_type")
    if not source_ip:
        suspicious_reasons.append("missing_source_ip")
    if payload.source_ip and source_ip is None:
        suspicious_reasons.append("invalid_source_ip")
    if payload.destination_ip and destination_ip is None:
        suspicious_reasons.append("invalid_destination_ip")

    event_text = " ".join(
        [
            str(event_name or ""),
            str(event_type or ""),
            str(raw_data.get("message") or ""),
            str(raw_data.get("command") or ""),
            str(raw_data.get("process_name") or ""),
        ]
    ).lower()
    keyword_hits = [keyword.strip() for keyword in SUSPICIOUS_KEYWORDS if keyword in event_text]
    suspicious_reasons.extend(f"keyword:{keyword}" for keyword in keyword_hits)

    tag = "suspicious" if suspicious_reasons else "normal"
    raw_data["tag"] = tag
    raw_data["suspicious_reasons"] = suspicious_reasons

    return {
        "event_id": raw_data["event_id"],
        "event_name": event_name,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "event_type": event_type,
        "tactic": tactic,
        "technique_id": technique_id,
        "severity": severity,
        "is_malicious": payload.is_malicious,
        "tactic_encoded": payload.tactic_encoded,
        "severity_encoded": payload.severity_encoded,
        "mcdm_score": payload.mcdm_score,
        "threat_actor": payload.threat_actor,
        "threat_feed_hit": payload.threat_feed_hit,
        "raw_data": raw_data,
    }


def _normalize_ip(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _normalize_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text.lower().replace(" ", "_") if text else None
