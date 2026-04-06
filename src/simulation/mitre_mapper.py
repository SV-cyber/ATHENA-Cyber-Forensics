from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


TACTIC_ORDER = {
    "TA0043": 0,  # Reconnaissance
    "TA0001": 1,  # Initial Access
    "TA0002": 2,  # Execution
    "TA0003": 3,  # Persistence
    "TA0004": 4,  # Privilege Escalation
    "TA0005": 5,  # Defense Evasion
    "TA0006": 6,  # Credential Access
    "TA0007": 7,  # Discovery
    "TA0008": 8,  # Lateral Movement
    "TA0009": 9,  # Collection
    "TA0010": 10,  # Exfiltration
    "TA0011": 11,  # Command and Control
    "TA0040": 12,  # Impact
}

TACTIC_ID_BY_NAME = {
    "Reconnaissance": "TA0043",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Exfiltration": "TA0010",
    "Command and Control": "TA0011",
    "Impact": "TA0040",
}


class MITREAttackMapper:
    def __init__(self, data_path: Optional[Path] = None):
        self.data_path = data_path or Path(__file__).resolve().parents[2] / "data" / "mitre_techniques.json"
        self.techniques = self._load_techniques()
        self.techniques_by_id = {item["technique_id"]: item for item in self.techniques}

    def map_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(event)
        technique_id = str(
            payload.get("mitre_technique_id")
            or payload.get("technique_id")
            or ""
        ).strip()
        tactic = str(payload.get("mitre_tactic") or payload.get("tactic") or "").strip()

        record = self.techniques_by_id.get(technique_id)
        if record is None and tactic:
            tactic_id = TACTIC_ID_BY_NAME.get(tactic)
            record = {
                "tactic": tactic,
                "tactic_id": tactic_id,
                "technique": payload.get("technique_name"),
                "technique_id": technique_id or payload.get("technique_id"),
            }

        if record:
            payload["mitre_tactic"] = record.get("tactic") or tactic or payload.get("tactic")
            payload["mitre_tactic_id"] = record.get("tactic_id") or TACTIC_ID_BY_NAME.get(str(payload.get("mitre_tactic") or ""))
            payload["mitre_technique"] = record.get("technique") or payload.get("technique_name")
            payload["mitre_technique_id"] = record.get("technique_id") or technique_id or payload.get("technique_id")
        else:
            payload.setdefault("mitre_tactic", tactic or None)
            payload.setdefault("mitre_tactic_id", TACTIC_ID_BY_NAME.get(tactic))
            payload.setdefault("mitre_technique", payload.get("technique_name"))
            payload.setdefault("mitre_technique_id", technique_id or None)
        return payload

    def map_attack_chain(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        mapped: List[Dict[str, Any]] = []
        previous_order = -1
        for idx, event in enumerate(events, start=1):
            enriched = self.map_event(event)
            tactic_id = str(enriched.get("mitre_tactic_id") or "")
            current_order = TACTIC_ORDER.get(tactic_id, previous_order if previous_order >= 0 else 0)
            progression_valid = current_order >= previous_order
            enriched["mitre_chain_position"] = idx
            enriched["mitre_progression_valid"] = progression_valid
            enriched["mitre_stage_order"] = current_order
            if mapped:
                enriched["mitre_previous_tactic_id"] = mapped[-1].get("mitre_tactic_id")
            previous_order = current_order
            mapped.append(enriched)
        return mapped

    def _load_techniques(self) -> List[Dict[str, Any]]:
        with self.data_path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
        if isinstance(payload, dict):
            return list(payload.get("techniques", []))
        return list(payload)
