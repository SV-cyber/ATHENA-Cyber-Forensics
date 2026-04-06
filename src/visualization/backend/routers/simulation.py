from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..dependencies import get_db
from simulation.scenarios import ScenarioLibrary
from utils.database import Event, ScenarioExecution
from utils.event_bus import event_bus
from visualization.backend.services.events import serialize_event


router = APIRouter(tags=["simulation"])
library = ScenarioLibrary()


def _persist_simulation_events(db: Session, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    persisted: List[Dict[str, Any]] = []
    for item in events:
        raw_data = dict(item.get("raw_data") or {})
        raw_data.update(
            {
                "mitre_tactic": item.get("raw_data", {}).get("mitre_tactic"),
                "mitre_tactic_id": item.get("raw_data", {}).get("mitre_tactic_id"),
                "mitre_technique": item.get("raw_data", {}).get("mitre_technique"),
                "mitre_technique_id": item.get("raw_data", {}).get("mitre_technique_id"),
            }
        )
        event = Event(
            event_uid=str(item["event_id"]),
            event_name=str(item.get("event_name") or item.get("event_type") or ""),
            timestamp=item["timestamp"],
            source_ip=item.get("source_ip"),
            destination_ip=item.get("destination_ip"),
            event_type=item.get("event_type"),
            tactic=item.get("tactic"),
            technique_id=item.get("technique_id"),
            severity=item.get("severity"),
            is_malicious=bool(item.get("is_malicious", True)),
            tactic_encoded=item.get("tactic_encoded"),
            severity_encoded=item.get("severity_encoded"),
            mcdm_score=item.get("mcdm_score"),
            threat_actor=item.get("threat_actor"),
            threat_feed_hit=bool(item.get("threat_feed_hit", False)),
            raw_data=raw_data,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        payload = serialize_event(event)
        persisted.append(payload)
        event_bus.publish(payload)
    return persisted


@router.get("/simulation/scenarios")
def list_scenarios(db: Session = Depends(get_db)) -> Dict[str, Any]:
    library.sync_to_db(db)
    db.commit()
    scenarios = library.list_scenarios()
    return {"count": len(scenarios), "data": scenarios}


@router.post("/simulation/run/{scenario_name}")
def run_scenario(scenario_name: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    scenario = library.get_scenario(scenario_name)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    execution_id = f"SIM-{uuid4().hex[:12]}"
    execution = ScenarioExecution(
        execution_id=execution_id,
        scenario_name=scenario.name,
        started_at=datetime.now(timezone.utc),
        status="running",
        events_generated=0,
    )
    db.add(execution)
    db.commit()
    db.refresh(execution)

    try:
        events = library.generate_events(scenario_name, execution_id=execution_id)
        persisted = _persist_simulation_events(db, events)
        execution.status = "completed"
        execution.completed_at = datetime.now(timezone.utc)
        execution.events_generated = len(persisted)
        db.add(execution)
        db.commit()
        db.refresh(execution)
        return {
            "execution_id": execution.execution_id,
            "scenario_name": execution.scenario_name,
            "status": execution.status,
            "events_generated": execution.events_generated,
            "events": persisted,
        }
    except Exception as exc:
        execution.status = "failed"
        execution.completed_at = datetime.now(timezone.utc)
        db.add(execution)
        db.commit()
        raise HTTPException(status_code=500, detail=f"Scenario execution failed: {exc}") from exc


@router.get("/simulation/executions")
def list_executions(db: Session = Depends(get_db)) -> Dict[str, Any]:
    rows = db.query(ScenarioExecution).order_by(ScenarioExecution.started_at.desc(), ScenarioExecution.id.desc()).all()
    data = [
        {
            "execution_id": row.execution_id,
            "scenario_name": row.scenario_name,
            "started_at": row.started_at.isoformat() if row.started_at else None,
            "completed_at": row.completed_at.isoformat() if row.completed_at else None,
            "events_generated": row.events_generated,
            "status": row.status,
        }
        for row in rows
    ]
    return {"count": len(data), "data": data}


@router.get("/simulation/status/{execution_id}")
def execution_status(execution_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    row = db.query(ScenarioExecution).filter(ScenarioExecution.execution_id == execution_id).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Execution not found")
    return {
        "execution_id": row.execution_id,
        "scenario_name": row.scenario_name,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "events_generated": row.events_generated,
        "status": row.status,
    }
