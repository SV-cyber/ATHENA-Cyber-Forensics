"""
ATHENA Backend - FastAPI Server

Database-backed API for running the ATHENA pipeline and retrieving results.
"""

from __future__ import annotations

import asyncio
import csv
import importlib.util
import io
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parents[2]  # /src
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from utils.database import CorrelationRecord, DetectionResult, Event, ensure_schema, session_scope
from visualization.backend.routers.detections import router as detections_router
from visualization.backend.routers.events import router as events_router
from visualization.backend.services.events import list_events, serialize_event


PIPELINE_PATH = BASE_DIR / "main_pipeline.py"


def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("athena.api")
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


logger = _setup_logger()


def _load_attr_from_path(py_path: Path, attr_name: str) -> Any:
    py_path = py_path.resolve()
    if not py_path.exists():
        raise FileNotFoundError(str(py_path))

    module_name = f"athena_dynamic_api_{py_path.stem}_{abs(hash(str(py_path)))}"
    spec = importlib.util.spec_from_file_location(module_name, str(py_path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load module spec for {py_path}")

    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]

    if not hasattr(mod, attr_name):
        raise AttributeError(f"{py_path} does not define {attr_name}")
    return getattr(mod, attr_name)


class HealthResponse(BaseModel):
    status: str = Field(..., examples=["ok"])
    timestamp: str


class PipelineRunResponse(BaseModel):
    total_events: int
    anomalies_detected: int
    attack_chains_found: int
    timestamp: str


app = FastAPI(
    title="ATHENA API",
    description="AI-Driven Threat Hunting & Adversary Emulation",
    version="0.3.0",
)
app.include_router(events_router)
app.include_router(detections_router)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_pipeline_summary(raw: Dict[str, Any]) -> Dict[str, int]:
    def pick_int(*keys: str, default: int = 0) -> int:
        for key in keys:
            value = raw.get(key)
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                return int(value)
        return default

    return {
        "total_events": pick_int("total_events", default=0),
        "anomalies_detected": pick_int("anomalies_detected", "anomalies", default=0),
        "attack_chains_found": pick_int("attack_chains_found", "attack_chains", default=0),
    }


def _serialize_detection(detection: DetectionResult, event_uid: str | None = None) -> Dict[str, Any]:
    raw = dict(detection.raw_data or {})
    raw.update(
        {
            "id": detection.id,
            "event_id": event_uid,
            "model_name": detection.model_name,
            "confidence_score": detection.confidence_score,
            "anomaly_score": detection.anomaly_score,
            "detected_at": detection.detected_at.isoformat() if detection.detected_at else None,
            "is_true_positive": detection.is_true_positive,
            "is_malicious_pred": detection.is_malicious_pred,
        }
    )
    return raw


def _build_attack_chain_payload() -> Dict[str, Any]:
    with session_scope() as session:
        summary_rows = (
            session.query(CorrelationRecord)
            .filter(CorrelationRecord.correlation_type == "chain_summary")
            .order_by(CorrelationRecord.chain_score.desc().nullslast(), CorrelationRecord.id.asc())
            .all()
        )
        edge_rows = (
            session.query(CorrelationRecord)
            .filter(CorrelationRecord.correlation_type == "event_edge")
            .order_by(CorrelationRecord.id.asc())
            .all()
        )
        events = session.query(Event).all()

    events_by_uid = {event.event_uid: serialize_event(event) for event in events}
    db_id_to_uid = {event["db_id"]: event["event_id"] for event in events_by_uid.values()}

    chains: Dict[str, List[Dict[str, Any]]] = {}
    attack_chains: List[Dict[str, Any]] = []

    for row in summary_rows:
        chain = dict(row.raw_data or {})
        chain_id = str(row.chain_id or chain.get("chain_id") or f"chain-{row.id}")
        event_ids = [str(event_id) for event_id in chain.get("event_ids", [])]
        chains[chain_id] = [events_by_uid[event_id] for event_id in event_ids if event_id in events_by_uid]
        chain["chain_id"] = chain_id
        chain["chain_score"] = row.chain_score if row.chain_score is not None else chain.get("chain_score")
        attack_chains.append(chain)

    graph_edges = []
    for row in edge_rows:
        graph_edges.append(
            {
                "source": db_id_to_uid.get(row.parent_event_id),
                "target": db_id_to_uid.get(row.child_event_id),
                "strength": row.strength,
                "gap_seconds": row.gap_seconds,
                "reasons": list(row.reasons or []),
                "chain_id": row.chain_id,
            }
        )

    return {
        "chains": chains,
        "attack_chains": attack_chains,
        "graph": {"edges": graph_edges},
        "count": len(attack_chains),
    }


def _get_events_payload() -> Dict[str, Any]:
    with session_scope() as session:
        data = list_events(session)
    return {"count": len(data), "data": data}


def _get_detections_payload() -> Dict[str, Any]:
    with session_scope() as session:
        rows = (
            session.query(DetectionResult, Event.event_uid)
            .join(Event, DetectionResult.event_id == Event.id)
            .order_by(DetectionResult.detected_at.asc(), DetectionResult.id.asc())
            .all()
        )

    data = [_serialize_detection(detection, event_uid=event_uid) for detection, event_uid in rows]
    return {"count": len(data), "data": data}


async def _run_pipeline_in_thread() -> Dict[str, Any]:
    AthenaPipeline = _load_attr_from_path(PIPELINE_PATH, "AthenaPipeline")
    PipelineConfig = _load_attr_from_path(PIPELINE_PATH, "PipelineConfig")

    def _runner() -> Dict[str, Any]:
        ensure_schema()
        pipeline = AthenaPipeline(config=PipelineConfig(threat_actor="APT28"))
        return pipeline.run_full_pipeline()

    return await asyncio.to_thread(_runner)


@app.on_event("startup")
def startup() -> None:
    ensure_schema()


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", timestamp=_utc_now_iso())


@app.post("/run-pipeline", response_model=PipelineRunResponse)
async def run_pipeline() -> PipelineRunResponse:
    try:
        logger.info("Pipeline run requested")
        raw_summary = await _run_pipeline_in_thread()
        if not isinstance(raw_summary, dict):
            raise RuntimeError("Pipeline returned non-dict summary")
        normalized = _normalize_pipeline_summary(raw_summary)
        return PipelineRunResponse(**normalized, timestamp=_utc_now_iso())
    except FileNotFoundError as exc:
        logger.exception("Pipeline file missing")
        raise HTTPException(status_code=500, detail=f"Pipeline file not found: {exc}") from exc
    except Exception as exc:
        logger.exception("Pipeline run failed")
        raise HTTPException(status_code=500, detail=f"Pipeline failed: {exc}") from exc


@app.get("/results")
async def results() -> Dict[str, Any]:
    # Backward-compatible alias for the existing frontend pages.
    return _get_events_payload()


@app.get("/detections")
async def detections() -> Dict[str, Any]:
    return _get_detections_payload()


@app.get("/attack-chains")
async def attack_chains() -> Dict[str, Any]:
    payload = _build_attack_chain_payload()
    if not payload["attack_chains"]:
        raise HTTPException(status_code=404, detail="No attack chains found. Run POST /run-pipeline first.")
    return payload


@app.get("/export-csv")
async def export_csv() -> StreamingResponse:
    payload = _get_events_payload()
    rows = payload["data"]
    if not rows:
        raise HTTPException(status_code=404, detail="No events found. Run POST /run-pipeline first.")

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    buffer.seek(0)

    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=athena_threat_intelligence.csv"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
