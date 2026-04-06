from __future__ import annotations

import logging
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from core.alert_manager import AlertManager
from core.redis_stream import RedisStream
from core.soar_actions import send_slack_alert
from utils.config import RedisConfig
from utils.database import Event, SessionLocal, ensure_schema
from visualization.backend.services.detection_engine import evaluate_event


logger = logging.getLogger("athena.siem.worker")
SIEM_CONSUMER_GROUP = os.getenv("REDIS_SIEM_CONSUMER_GROUP", "siem_workers")


def _setup_logger() -> logging.Logger:
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s - %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


class SIEMWorker:
    def __init__(self) -> None:
        _setup_logger()
        self.redis_stream = RedisStream(RedisConfig)
        self.stream_key = RedisConfig.STREAM_KEY
        self.consumer_group = SIEM_CONSUMER_GROUP
        self.consumer_name = f"{socket.gethostname()}-{os.getpid()}"
        self.redis_stream.create_consumer_group(self.stream_key, self.consumer_group)

    def process_once(self, batch_size: int = 10) -> int:
        events = self.redis_stream.consume(
            self.stream_key,
            self.consumer_group,
            self.consumer_name,
            batch_size=batch_size,
        )
        if not events:
            return 0

        processed = 0
        for payload in events:
            event_id = str(payload.get("_redis_event_id") or "")
            try:
                self._process_event(payload)
                if event_id:
                    self.redis_stream.ack(self.stream_key, self.consumer_group, event_id)
                processed += 1
            except Exception as exc:
                logger.exception("Failed processing stream event %s: %s", event_id, exc)
        return processed

    def run_forever(self, poll_interval_seconds: int = 2) -> None:
        ensure_schema()
        while True:
            processed = self.process_once()
            if processed == 0:
                time.sleep(poll_interval_seconds)

    def _process_event(self, payload: Dict[str, Any]) -> None:
        db = SessionLocal()
        try:
            event = self._get_event(db, payload)
            if event is None:
                logger.warning("Skipping stream payload; event not found for payload=%s", payload.get("event_id"))
                return

            detections = evaluate_event(db, event, persist=True)
            matched = [detection for detection in detections if detection.get("matched")]
            if not matched:
                db.commit()
                return

            ml_score = self._derive_ml_score(event, matched)
            manager = AlertManager(self.redis_stream.client, db)
            alert = manager.create_alert(event, matched, ml_score)

            actions_taken: List[Dict[str, Any]] = []
            if alert["severity"] in {"high", "critical"}:
                if event.source_ip:
                    actions_taken.append(manager.block_ip(str(event.source_ip)))
                    actions_taken.append(manager.add_to_watchlist(str(event.source_ip), "ip"))
                hostname = str((event.raw_data or {}).get("hostname") or "").strip()
                if hostname:
                    actions_taken.append(manager.isolate_host(hostname))
                actions_taken.append(
                    send_slack_alert(
                        f"ATHENA alert {alert['alert_id']} severity={alert['severity']} "
                        f"source_ip={alert['source_ip']} event_type={alert['event_type']}"
                    )
                )
            alert["actions_taken"] = actions_taken
            logger.info(
                "Processed alert %s severity=%s actions=%d",
                alert["alert_id"],
                alert["severity"],
                len(actions_taken),
            )
        finally:
            db.close()

    @staticmethod
    def _get_event(db: Any, payload: Dict[str, Any]) -> Optional[Event]:
        db_id = payload.get("db_id")
        if db_id is not None:
            event = db.query(Event).filter(Event.id == int(db_id)).one_or_none()
            if event is not None:
                return event
        event_uid = payload.get("event_id")
        if event_uid:
            return db.query(Event).filter(Event.event_uid == str(event_uid)).one_or_none()
        return None

    @staticmethod
    def _derive_ml_score(event: Event, detections: List[Dict[str, Any]]) -> float:
        if event.mcdm_score is not None:
            return float(event.mcdm_score)
        return max((float(item.get("confidence_score") or 0.0) for item in detections), default=0.0)


if __name__ == "__main__":
    SIEMWorker().run_forever()
