from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from utils.database import DetectionResult, Event


BASE_DIR = Path(__file__).resolve().parents[3]
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

CORRELATOR_PATH = BASE_DIR / "correlation-engine" / "attack_chain_builder.py"


def run_correlation(db: Session, event: Optional[Event] = None) -> Dict[str, Any] | None:
    from .events import serialize_event

    try:
        AttackChainBuilder = _load_attr_from_path(CORRELATOR_PATH, "AttackChainBuilder")
    except Exception:
        return None

    events = db.query(Event).order_by(Event.timestamp.asc(), Event.id.asc()).all()
    if len(events) < 2:
        return None

    event_payloads = [serialize_event(row) for row in events]
    prediction_payloads = _build_prediction_payloads(db, events)

    builder = AttackChainBuilder()
    result = builder.correlate_events(event_payloads, predictions=prediction_payloads)
    if event is None:
        return result

    for chain in result.get("attack_chains", []) or []:
        if event.event_uid in (chain.get("event_ids") or []):
            return chain
    return None


def _build_prediction_payloads(db: Session, events: List[Event]) -> List[Dict[str, Any]]:
    detections = (
        db.query(DetectionResult)
        .filter(DetectionResult.event_id.in_([event.id for event in events]))
        .all()
    )
    detection_by_event_id: Dict[int, List[DetectionResult]] = {}
    for detection in detections:
        detection_by_event_id.setdefault(detection.event_id, []).append(detection)

    payloads: List[Dict[str, Any]] = []
    for event in events:
        rows = detection_by_event_id.get(event.id, [])
        confidence = max((float(row.confidence_score or 0.0) for row in rows), default=0.0)
        payloads.append(
            {
                "p_malicious_lstm": confidence,
                "anomaly_score_iforest": confidence,
                "is_malicious_pred": 1 if rows else 0,
            }
        )
    return payloads


def _load_attr_from_path(py_path: Path, attr_name: str) -> Any:
    module_name = f"athena_dynamic_correlation_{py_path.stem}_{abs(hash(str(py_path)))}"
    spec = importlib.util.spec_from_file_location(module_name, str(py_path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load module spec for {py_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return getattr(module, attr_name)
