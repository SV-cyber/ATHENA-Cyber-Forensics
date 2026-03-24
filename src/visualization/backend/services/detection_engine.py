from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from utils.database import DetectionResult, Event


LOGIN_FAILURE_KEYWORDS = ("login_failure", "failed_login", "authentication_failure", "invalid_password", "logon_failure")
PORT_SCAN_KEYWORDS = ("scan", "syn", "portscan", "recon")
SUSPICIOUS_PROCESS_KEYWORDS = ("nmap", "hydra", "netcat", "nc ", "nc.exe", "masscan")
ALERT_SEVERITIES = {"high", "critical"}


def evaluate_event(db: Session, event: Event, *, persist: bool = True) -> List[Dict[str, Any]]:
    detections = [
        _detect_brute_force(db, event),
        _detect_port_scan(db, event),
        _detect_suspicious_process(event),
    ]
    matched = [detection for detection in detections if detection["matched"]]
    if persist:
        _persist_detections(db, event, matched)
    return detections


def _persist_detections(db: Session, event: Event, detections: List[Dict[str, Any]]) -> None:
    for detection in detections:
        db.add(
            DetectionResult(
                event_id=event.id,
                model_name=detection["rule_name"],
                confidence_score=float(detection["confidence_score"]),
                anomaly_score=float(detection["confidence_score"]),
                is_true_positive=None,
                is_malicious_pred=bool(detection["alert"]),
                raw_data=detection,
            )
        )


def _detect_brute_force(db: Session, event: Event) -> Dict[str, Any]:
    raw_text = _event_text(event)
    if not any(keyword in raw_text for keyword in LOGIN_FAILURE_KEYWORDS):
        return _result("brute_force_detection", False, 0.0, reason="event_not_login_failure")

    if not event.source_ip:
        return _result("brute_force_detection", False, 0.0, reason="missing_source_ip")

    window_start = (event.timestamp or _utc_now()) - timedelta(minutes=10)
    recent_events = (
        db.query(Event)
        .filter(Event.source_ip == event.source_ip, Event.timestamp >= window_start, Event.timestamp <= event.timestamp)
        .all()
    )
    failure_count = sum(1 for row in recent_events if any(keyword in _event_text(row) for keyword in LOGIN_FAILURE_KEYWORDS))
    matched = failure_count >= 5
    confidence = min(1.0, failure_count / 10.0) if matched else min(0.4, failure_count / 10.0)
    return _result(
        "brute_force_detection",
        matched,
        confidence,
        severity="high" if matched else "low",
        source_ip=event.source_ip,
        failure_count=failure_count,
        window_minutes=10,
    )


def _detect_port_scan(db: Session, event: Event) -> Dict[str, Any]:
    if not event.source_ip:
        return _result("port_scan_detection", False, 0.0, reason="missing_source_ip")

    current_port = _extract_port(event.raw_data or {})
    raw_text = _event_text(event)
    if current_port is None and not any(keyword in raw_text for keyword in PORT_SCAN_KEYWORDS):
        return _result("port_scan_detection", False, 0.0, reason="no_scan_indicators")

    window_start = (event.timestamp or _utc_now()) - timedelta(minutes=5)
    recent_events = (
        db.query(Event)
        .filter(Event.source_ip == event.source_ip, Event.timestamp >= window_start, Event.timestamp <= event.timestamp)
        .all()
    )
    unique_ports = set()
    for row in recent_events:
        port = _extract_port(row.raw_data or {})
        if port is not None:
            unique_ports.add(port)

    matched = len(unique_ports) >= 10
    confidence = min(1.0, len(unique_ports) / 20.0) if matched else min(0.45, len(unique_ports) / 20.0)
    return _result(
        "port_scan_detection",
        matched,
        confidence,
        severity="medium" if matched else "low",
        source_ip=event.source_ip,
        unique_ports=len(unique_ports),
        ports=sorted(unique_ports)[:20],
        window_minutes=5,
    )


def _detect_suspicious_process(event: Event) -> Dict[str, Any]:
    raw_text = _event_text(event)
    matched_keywords = [keyword.strip() for keyword in SUSPICIOUS_PROCESS_KEYWORDS if keyword in raw_text]
    matched = bool(matched_keywords)
    confidence = 0.95 if matched else 0.0
    severity = "critical" if any(keyword in {"hydra", "masscan"} for keyword in matched_keywords) else "high"
    return _result(
        "suspicious_process_detection",
        matched,
        confidence,
        severity=severity if matched else "low",
        keywords=matched_keywords,
        process_name=(event.raw_data or {}).get("process_name"),
        command=(event.raw_data or {}).get("command"),
    )


def _extract_port(raw_data: Dict[str, Any]) -> int | None:
    for key in ("destination_port", "dest_port", "port", "target_port"):
        value = raw_data.get(key)
        try:
            if value is not None:
                return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _event_text(event: Event) -> str:
    raw = event.raw_data or {}
    parts = [
        str(event.event_name or ""),
        str(event.event_type or ""),
        str(raw.get("message") or ""),
        str(raw.get("command") or ""),
        str(raw.get("process_name") or ""),
        str(raw.get("status") or ""),
    ]
    return " ".join(parts).lower()


def _result(rule_name: str, matched: bool, confidence_score: float, severity: str = "low", **details: Any) -> Dict[str, Any]:
    return {
        "rule_name": rule_name,
        "matched": matched,
        "confidence_score": float(confidence_score),
        "severity": severity,
        "alert": severity in ALERT_SEVERITIES and matched,
        "details": details,
    }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
