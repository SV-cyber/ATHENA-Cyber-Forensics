from __future__ import annotations
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple
from uuid import uuid4

from sqlalchemy.orm import Session

from core.soar_actions import block_ip_via_firewall, isolate_host_via_api
from utils.database import Alert


logger = logging.getLogger("athena.alerts")
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class AlertManager:
    def __init__(self, redis_client: Any, db_session: Session):
        self.redis_client = redis_client
        self.db_session = db_session

    def create_alert(self, event: Any, rule_alerts: List[Dict[str, Any]], ml_score: float | None) -> Dict[str, Any]:
        source_ip = self._as_str(self._event_attr(event, "source_ip"))
        event_type = self._as_str(self._event_attr(event, "event_type")) or "unknown"
        timestamp = self._event_attr(event, "timestamp") or datetime.now(timezone.utc)
        severity = self._calculate_severity(rule_alerts, ml_score)
        should_create, duplicate_count = self._deduplicate(source_ip or "unknown", event_type)

        if not should_create:
            alert = (
                self.db_session.query(Alert)
                .filter(Alert.source_ip == source_ip, Alert.event_type == event_type)
                .order_by(Alert.updated_at.desc(), Alert.id.desc())
                .first()
            )
            if alert is not None:
                alert.duplicate_count = duplicate_count
                alert.severity = severity
                alert.rule_alerts = list(rule_alerts)
                alert.ml_score = float(ml_score or 0.0)
                alert.updated_at = datetime.now(timezone.utc)
                self.db_session.add(alert)
                self.db_session.commit()
                self.db_session.refresh(alert)
                return _serialize_alert(alert, actions_taken=[], deduplicated=True)

        status = "throttled" if duplicate_count > 5 else "active"
        alert = Alert(
            alert_id=f"ALT-{uuid4().hex[:12]}",
            timestamp=timestamp,
            source_ip=source_ip,
            event_type=event_type,
            severity=severity,
            rule_alerts=list(rule_alerts),
            ml_score=float(ml_score or 0.0),
            duplicate_count=duplicate_count,
            status=status,
        )
        self.db_session.add(alert)
        self.db_session.commit()
        self.db_session.refresh(alert)
        self._store_latest_alert_ref(source_ip or "unknown", event_type, alert.alert_id)
        return _serialize_alert(alert, actions_taken=[], deduplicated=False)

    def _deduplicate(self, source_ip: str, event_type: str, window_seconds: int = 300) -> Tuple[bool, int]:
        if self.redis_client is None:
            return True, 1

        key = f"alert:{source_ip}:{event_type}"
        now = datetime.now(timezone.utc)
        payload = self.redis_client.hgetall(key) or {}
        first_seen_raw = payload.get("first_seen")
        count = int(payload.get("count", 0) or 0)
        first_seen_value = now.isoformat()

        should_create = True
        if first_seen_raw:
            first_seen = datetime.fromisoformat(first_seen_raw)
            if now - first_seen <= timedelta(seconds=window_seconds):
                count += 1
                should_create = count == 1 or count > 5
                first_seen_value = first_seen_raw
            else:
                count = 1
        else:
            count = 1

        self.redis_client.hset(
            key,
            mapping={
                "count": count,
                "first_seen": first_seen_value,
            },
        )
        self.redis_client.expire(key, window_seconds)
        return should_create, count

    def _calculate_severity(self, rule_alerts: List[Dict[str, Any]], ml_score: float | None) -> str:
        severities = [str(alert.get("severity") or "low").lower() for alert in rule_alerts]
        rule_severity = max(severities, key=lambda item: SEVERITY_ORDER.get(item, 0), default="low")
        if ml_score is None:
            return rule_severity
        if ml_score >= 0.9:
            ml_severity = "critical"
        elif ml_score >= 0.75:
            ml_severity = "high"
        elif ml_score >= 0.5:
            ml_severity = "medium"
        else:
            ml_severity = "low"
        return max((rule_severity, ml_severity), key=lambda item: SEVERITY_ORDER.get(item, 0))

    def block_ip(self, ip: str, duration_minutes: int = 60) -> Dict[str, Any]:
        result = block_ip_via_firewall(ip)
        result["duration_minutes"] = duration_minutes
        return result

    def isolate_host(self, hostname: str) -> Dict[str, Any]:
        return isolate_host_via_api(hostname)

    def add_to_watchlist(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        logger.info("SOAR stub: add %s=%s to watchlist", indicator_type, indicator)
        return {
            "action": "add_to_watchlist",
            "indicator": indicator,
            "indicator_type": indicator_type,
            "success": True,
        }

    def _store_latest_alert_ref(self, source_ip: str, event_type: str, alert_id: str) -> None:
        if self.redis_client is None:
            return
        key = f"alert:{source_ip}:{event_type}"
        self.redis_client.hset(key, mapping={"latest_alert_id": alert_id})

    @staticmethod
    def _event_attr(event: Any, key: str) -> Any:
        if isinstance(event, dict):
            return event.get(key)
        return getattr(event, key, None)

    @staticmethod
    def _as_str(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None


def _serialize_alert(alert: Alert, *, actions_taken: List[Dict[str, Any]], deduplicated: bool) -> Dict[str, Any]:
    return {
        "alert_id": alert.alert_id,
        "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
        "source_ip": str(alert.source_ip) if alert.source_ip else None,
        "event_type": alert.event_type,
        "severity": alert.severity,
        "rule_alerts": list(alert.rule_alerts or []),
        "ml_score": alert.ml_score,
        "duplicate_count": alert.duplicate_count,
        "status": alert.status,
        "actions_taken": actions_taken,
        "deduplicated": deduplicated,
    }
