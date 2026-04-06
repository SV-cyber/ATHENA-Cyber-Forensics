"""
ATHENA Event Normalizer (Phase 2)

Purpose:
Convert raw mission logs (from CALDERA-style `operators.py`) into structured,
ML-ready security events.

Input:
    - mission_log: list of dict entries from AdversaryOperator.mission_log

Output:
    - normalized events list (JSON-serializable dicts)
    - pandas DataFrame export for downstream ML pipeline
"""

from __future__ import annotations

import random
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pandas as pd

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.append(str(SRC_ROOT))

from simulation.mitre_mapper import MITREAttackMapper


Severity = str


@dataclass(frozen=True)
class NormalizerConfig:
    """
    Configuration for normalization behavior.

    - Internal IP ranges are simulated (RFC1918).
    - Severity mapping is heuristic and can be tuned.
    """

    internal_networks: Tuple[str, ...] = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    seed: Optional[int] = None


class EventNormalizer:
    """
    Normalize mission logs into ML-ready events.

    Each normalized event includes:
        - event_id
        - timestamp
        - source_ip
        - destination_ip
        - event_type
        - tactic
        - technique_id
        - mitre_tactic
        - mitre_tactic_id
        - mitre_technique
        - mitre_technique_id
        - severity
        - is_malicious
    """

    # Stable categorical encoding for tactics (full lifecycle).
    TACTIC_ORDER: Sequence[str] = (
        "Reconnaissance",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Exfiltration",
        "Command and Control",
    )

    # Severity heuristic by tactic (can be tuned).
    TACTIC_SEVERITY: Dict[str, Severity] = {
        "Reconnaissance": "low",
        "Initial Access": "high",
        "Execution": "high",
        "Persistence": "high",
        "Privilege Escalation": "critical",
        "Defense Evasion": "high",
        "Credential Access": "critical",
        "Discovery": "medium",
        "Lateral Movement": "high",
        "Collection": "medium",
        "Exfiltration": "critical",
        "Command and Control": "critical",
    }

    SEVERITY_ENCODING: Dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    def __init__(self, mission_log: List[Dict[str, Any]], *, config: Optional[NormalizerConfig] = None) -> None:
        self.mission_log = mission_log or []
        self.config = config or NormalizerConfig()

        # Use a dedicated RNG for reproducibility (optional).
        self._rng = random.Random(self.config.seed)

        self._normalized_events: List[Dict[str, Any]] = []
        self._mitre_mapper = MITREAttackMapper()

        # Precompute tactic encoding.
        self._tactic_encoding: Dict[str, int] = {t: i for i, t in enumerate(self.TACTIC_ORDER)}

    def normalize_events(self) -> List[Dict[str, Any]]:
        """
        Convert mission logs into normalized events list.
        """
        normalized: List[Dict[str, Any]] = []

        for entry in self.mission_log:
            step: Dict[str, Any] = (entry.get("step") or {}) if isinstance(entry, dict) else {}
            tactic = str(step.get("tactic") or "Unknown")
            technique_id = str(step.get("technique_id") or "T0000")
            status = str(entry.get("status") or "unknown").lower()

            ts = self._normalize_timestamp(entry.get("timestamp"))
            src_ip, dst_ip = self._simulate_ips(step=step, entry=entry)

            severity = self._derive_severity(
                tactic=tactic, technique_id=technique_id, status=status, entry=entry, step=step
            )
            is_malicious = self._label_is_malicious(
                tactic=tactic, severity=severity, status=status, entry=entry, step=step
            )

            event: Dict[str, Any] = {
                "event_id": str(uuid.uuid4()),
                "timestamp": ts,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "event_type": self._derive_event_type(tactic=tactic, technique_id=technique_id, step=step),
                "tactic": tactic,
                "technique_id": technique_id,
                "severity": severity,
                "is_malicious": bool(is_malicious),
            }

            # Feature engineering for ML pipeline compatibility.
            event.update(self._engineer_features(event=event, entry=entry, step=step))
            event.update(
                {
                    "mitre_tactic": step.get("mitre_tactic"),
                    "mitre_tactic_id": step.get("mitre_tactic_id"),
                    "mitre_technique": step.get("mitre_technique") or step.get("technique_name"),
                    "mitre_technique_id": step.get("mitre_technique_id") or technique_id,
                }
            )
            event = self._mitre_mapper.map_event(event)

            normalized.append(event)

        self._normalized_events = normalized
        return normalized

    def export_to_dataframe(self) -> pd.DataFrame:
        """
        Export normalized events to a pandas DataFrame.

        If `normalize_events()` has not been called, this will call it first.
        """
        if not self._normalized_events:
            self.normalize_events()

        df = pd.DataFrame(self._normalized_events)

        # Ensure stable dtypes for ML pipeline.
        for col in (
            "event_id",
            "timestamp",
            "source_ip",
            "destination_ip",
            "event_type",
            "tactic",
            "technique_id",
            "mitre_tactic",
            "mitre_tactic_id",
            "mitre_technique",
            "mitre_technique_id",
            "severity",
        ):
            if col in df.columns:
                df[col] = df[col].astype("string")

        if "is_malicious" in df.columns:
            df["is_malicious"] = df["is_malicious"].astype("bool")

        # Common ML-friendly numeric columns.
        for col in ("tactic_encoded", "severity_encoded"):
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype("int64")

        return df

    # -----------------------
    # Internal helpers
    # -----------------------

    def _normalize_timestamp(self, value: Any) -> str:
        """
        Normalize timestamps to ISO-8601 UTC strings.
        """
        if isinstance(value, str) and value.strip():
            # operators.py already emits UTC ISO strings; keep as-is if parseable.
            try:
                dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc).isoformat()
            except ValueError:
                pass

        return datetime.now(timezone.utc).isoformat()

    def _simulate_ips(self, *, step: Dict[str, Any], entry: Dict[str, Any]) -> Tuple[str, str]:
        """
        Simulate internal source/destination IPs.

        - Recon/Discovery: tends to be host scanning -> multiple destinations; we keep a single representative.
        - Lateral Movement: destination is a server-ish IP.
        """
        tactic = str(step.get("tactic") or "")
        artifacts = (entry.get("artifacts") or {}) if isinstance(entry, dict) else {}
        domain = str(artifacts.get("domain") or "corp.local")

        # Keep deterministic-ish mapping by using a hash seed per tactic + domain.
        bias = abs(hash((tactic, domain))) % 250

        src = self._random_rfc1918_ip(offset=bias)

        if tactic in {"Lateral Movement", "Command and Control", "Exfiltration"}:
            dst = self._random_rfc1918_ip(offset=(bias + 50))
        else:
            dst = self._random_rfc1918_ip(offset=(bias + 20))

        return src, dst

    def _random_rfc1918_ip(self, *, offset: int = 0) -> str:
        """
        Generate a pseudo-random RFC1918 IP. Uses internal RNG (seedable).
        """
        choice = self._rng.choice([10, 172, 192])

        if choice == 10:
            # 10.0.0.0/8
            a = 10
            b = self._rng.randint(0, 255)
            c = (self._rng.randint(0, 255) + offset) % 256
            d = self._rng.randint(1, 254)
            return f"{a}.{b}.{c}.{d}"

        if choice == 172:
            # 172.16.0.0/12 -> 172.16-31.x.x
            a = 172
            b = self._rng.randint(16, 31)
            c = (self._rng.randint(0, 255) + offset) % 256
            d = self._rng.randint(1, 254)
            return f"{a}.{b}.{c}.{d}"

        # 192.168.0.0/16
        a = 192
        b = 168
        c = (self._rng.randint(0, 255) + offset) % 256
        d = self._rng.randint(1, 254)
        return f"{a}.{b}.{c}.{d}"

    def _derive_event_type(self, *, tactic: str, technique_id: str, step: Dict[str, Any]) -> str:
        """
        High-level event type for correlation/ML grouping.
        """
        # Prefer tactic as event_type (consistent with earlier pipeline), but add a hint.
        name = str(step.get("technique_name") or "")
        if name:
            return f"{tactic}:{technique_id}"
        return tactic

    def _derive_severity(
        self,
        *,
        tactic: str,
        technique_id: str,
        status: str,
        entry: Dict[str, Any],
        step: Dict[str, Any],
    ) -> Severity:
        base = self.TACTIC_SEVERITY.get(tactic, "medium")

        # If a step is failed/skipped, lower the severity slightly (still informative).
        if status in {"failed", "skipped"}:
            if base == "critical":
                return "high"
            if base == "high":
                return "medium"
            return base

        # If credential access or exfil succeeded, keep at critical.
        if tactic in {"Credential Access", "Exfiltration", "Command and Control"} and status == "success":
            return "critical"

        # If technique id indicates credential dumping, keep high/critical.
        if technique_id.startswith("T1003"):
            return "critical"

        return base

    def _label_is_malicious(
        self,
        *,
        tactic: str,
        severity: Severity,
        status: str,
        entry: Dict[str, Any],
        step: Dict[str, Any],
    ) -> bool:
        """
        Labeling logic for supervised learning.

        - Successful steps in the attack lifecycle are malicious.
        - Failed/skipped steps are typically non-malicious in terms of effect, but still adversarial intent.
          We label them as malicious if the tactic is high-risk even when blocked.
        """
        if status == "success":
            return True

        # High-risk intent: still label as malicious even if blocked.
        if tactic in {"Credential Access", "Privilege Escalation", "Exfiltration", "Command and Control"}:
            return True

        # Otherwise, base on severity.
        return severity in {"high", "critical"}

    def _engineer_features(self, *, event: Dict[str, Any], entry: Dict[str, Any], step: Dict[str, Any]) -> Dict[str, Any]:
        """
        Feature engineering:
        - tactic_encoded: stable categorical encoding
        - severity_encoded: ordinal severity encoding
        - mcdm_score: pull-through if present in operators.py step
        """
        tactic = str(event.get("tactic") or "")
        severity = str(event.get("severity") or "medium").lower()

        tactic_encoded = self._tactic_encoding.get(tactic, -1)
        severity_encoded = self.SEVERITY_ENCODING.get(severity, 1)

        engineered: Dict[str, Any] = {
            "tactic_encoded": int(tactic_encoded),
            "severity_encoded": int(severity_encoded),
        }

        # Pull through MCDM score if the operator included it in the step dict.
        mcdm = step.get("mcdm")
        if isinstance(mcdm, dict) and "score" in mcdm:
            try:
                engineered["mcdm_score"] = float(mcdm["score"])
            except (TypeError, ValueError):
                engineered["mcdm_score"] = None

        # Optional: include actor label if present.
        if isinstance(entry, dict):
            engineered["threat_actor"] = str(entry.get("threat_actor") or entry.get("artifacts", {}).get("threat_actor") or "")

        return engineered


if __name__ == "__main__":
    # Example usage with a minimal mock mission log entry compatible with operators.py.
    mock_mission_log = [
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "threat_actor": "APT28",
            "status": "success",
            "artifacts": {"domain": "corp.local"},
            "step": {
                "tactic": "Discovery",
                "technique_id": "T1016",
                "technique_name": "System Network Configuration Discovery",
                "description": "Enumerate IP config and routes.",
                "command": "ipconfig /all",
                "expected_result": "Network info collected.",
                "platform": "windows",
                "timing": {"delay_seconds": 1.0, "duration_seconds": 2.0},
                "mcdm": {"score": 7.8},
            },
        }
    ]

    normalizer = EventNormalizer(mock_mission_log, config=NormalizerConfig(seed=1337))
    events = normalizer.normalize_events()
    df = normalizer.export_to_dataframe()
    print("Normalized events:", events)
    print(df.head())
