"""
ATHENA Main Pipeline

End-to-end runnable integration pipeline that connects:
    1) AdversaryOperator (CALDERA simulation)
    2) EventNormalizer (normalize mission logs -> ML-ready events)
    3) ThreatDetectionModel (LSTM + IsolationForest)
    4) AttackChainBuilder (correlate events into attack chains)

This repository currently uses directory names with hyphens (e.g. `ml-models`,
`caldera-simulator`, `correlation-engine`) which are not valid Python package
names. To keep the pipeline runnable without restructuring the repo, this file
loads modules directly from file paths via importlib.
"""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent  # /src
PROJECT_ROOT = BASE_DIR.parent  # repo root

if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from data_collection.threat_collector import extract_threat_ips, fetch_threat_ips
from utils.database import CorrelationRecord, DetectionResult, EventRecord, ensure_schema, reset_pipeline_tables, session_scope
from utils.event_bus import event_bus


def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("athena.pipeline")
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


def _load_attr_from_path(py_path: Path, attr_name: str) -> Any:
    """
    Load a symbol (class/function) from a Python file by path.
    """
    py_path = py_path.resolve()
    if not py_path.exists():
        raise FileNotFoundError(str(py_path))

    module_name = f"athena_dynamic_{py_path.stem}_{abs(hash(str(py_path)))}"
    spec = importlib.util.spec_from_file_location(module_name, str(py_path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load spec for {py_path}")

    mod = importlib.util.module_from_spec(spec)
    # Ensure module is registered for libraries (e.g., dataclasses) that consult sys.modules.
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]

    if not hasattr(mod, attr_name):
        raise AttributeError(f"{py_path} does not define {attr_name}")
    return getattr(mod, attr_name)


@dataclass(frozen=True)
class PipelineConfig:
    threat_actor: str = "APT28"

    # The ML pipeline already saves to src/ml_models/trained_models/ internally.
    # We keep this here for discoverability.
    trained_model_dir: Path = BASE_DIR / "ml_models" / "trained_models"


class AthenaPipeline:
    """
    One working pipeline that ties together ATHENA's modules.
    """

    def __init__(self, *, config: Optional[PipelineConfig] = None) -> None:
        self.logger = _setup_logger()
        self.config = config or PipelineConfig()

        # Resolve module paths (repo uses hyphens in folder names).
        self._operators_path = BASE_DIR / "caldera-simulator" / "operators.py"
        self._normalizer_path = BASE_DIR / "data_collection" / "event_normalizer.py"
        self._training_path = BASE_DIR / "ml-models" / "training_pipeline.py"
        self._correlator_path = BASE_DIR / "correlation-engine" / "attack_chain_builder.py"

        # Loaded classes (late-bound)
        self.AdversaryOperator = _load_attr_from_path(self._operators_path, "AdversaryOperator")
        self.EventNormalizer = _load_attr_from_path(self._normalizer_path, "EventNormalizer")
        self.ThreatDetectionModel = _load_attr_from_path(self._training_path, "ThreatDetectionModel")
        self.AttackChainBuilder = _load_attr_from_path(self._correlator_path, "AttackChainBuilder")

        # Runtime artifacts
        self.operator = self.AdversaryOperator()
        self.mission_log: List[Dict[str, Any]] = []
        self.events: List[Dict[str, Any]] = []
        self.df: Optional[pd.DataFrame] = None
        self.model = self.ThreatDetectionModel()
        self.predictions_df: Optional[pd.DataFrame] = None
        self.correlation_results: Optional[Dict[str, Any]] = None
        self.threat_feed_ips: set[str] = set()
        self.threat_feed_rows: int = 0
        self.db_event_ids: Dict[str, int] = {}

    # -------------------------
    # Orchestration
    # -------------------------

    def run_full_pipeline(self) -> Dict[str, Any]:
        """
        Run end-to-end ATHENA pipeline and return the correlation results.
        """
        try:
            self.logger.info("Starting ATHENA pipeline: actor=%s", self.config.threat_actor)
            ensure_schema()
            with session_scope() as session:
                reset_pipeline_tables(session)

            self.generate_data()
            self.process_data()
            self.train_model()
            self.detect_threats()
            self.correlate_attacks()

            summary = self._print_summary()
            return summary
        except Exception:
            self.logger.exception("Pipeline failed")
            raise

    def generate_data(self) -> None:
        """
        Generate and execute attack simulation; populate `self.mission_log`.
        """
        self.logger.info("Stage 0/7: ingest external threat intelligence")
        self._ingest_threat_intel()

        self.logger.info("Stage 1/7: generate attack chain")
        _ = self.operator.generate_attack_chain(threat_actor=self.config.threat_actor)

        self.logger.info("Stage 2/7: execute attack simulation (async)")
        self.mission_log = asyncio.run(self.operator.execute_attack_chain(threat_actor=self.config.threat_actor))

    def process_data(self) -> None:
        """
        Normalize mission logs into ML-ready events and DataFrame.
        """
        self.logger.info("Stage 3/7: normalize mission logs -> events")
        normalizer = self.EventNormalizer(self.mission_log)
        self.events = normalizer.normalize_events()
        self._enrich_events_with_threat_intel()

        self.logger.info("Stage 4/7: publish normalized events + persist to PostgreSQL")
        event_bus.publish_many(self.events)
        self.df = normalizer.export_to_dataframe()
        self._persist_events()
        self.logger.info("Normalized events persisted: rows=%d", int(len(self.df)))

    def train_model(self) -> None:
        """
        Train LSTM + IsolationForest and save artifacts.
        """
        if self.df is None:
            raise RuntimeError("DataFrame not built. Run process_data() first.")

        self.logger.info("Stage 5/7: consume event bus + train ML models (LSTM + IsolationForest)")
        self.df = self.model.consume_events(event_bus, fallback_df=self.df)
        metrics = self.model.train_model(self.df)
        self.logger.info("Model training metrics saved to: %s", str(self.config.trained_model_dir))
        self.logger.info("LSTM metrics (summary): acc=%.3f f1=%.3f", metrics["lstm"]["accuracy"], metrics["lstm"]["f1"])

    def detect_threats(self) -> None:
        """
        Run predictions (anomaly scoring + classification).
        """
        if self.df is None:
            raise RuntimeError("DataFrame not built. Run process_data() first.")

        self.logger.info("Stage 6/7: predict anomalies")
        self.predictions_df = self.model.predict(self.df)
        self._persist_detections()

    def correlate_attacks(self) -> None:
        """
        Correlate events + predictions into attack chains.
        """
        if self.predictions_df is None:
            raise RuntimeError("Predictions not available. Run detect_threats() first.")

        self.logger.info("Stage 7/7: correlate events -> attack chains")
        builder = self.AttackChainBuilder()

        predictions_records = self.predictions_df.to_dict(orient="records")
        self.correlation_results = builder.correlate_events(self.events, predictions=predictions_records)
        self._persist_correlations()
        self.logger.info("Correlation results persisted to PostgreSQL")

    # -------------------------
    # Reporting
    # -------------------------

    def _print_summary(self) -> Dict[str, Any]:
        total_events = len(self.events)
        anomalies = 0
        if self.predictions_df is not None and "is_malicious_pred" in self.predictions_df.columns:
            anomalies = int(self.predictions_df["is_malicious_pred"].sum())

        chains_found = 0
        if isinstance(self.correlation_results, dict):
            chains_found = int(len(self.correlation_results.get("attack_chains", []) or []))

        summary = {
            "total_events": total_events,
            "anomalies_detected": anomalies,
            "attack_chains_found": chains_found,
            "trained_model_dir": str(self.config.trained_model_dir),
            "threat_feed_rows": self.threat_feed_rows,
        }

        print("\n=== ATHENA PIPELINE SUMMARY ===")
        print(f"Total events: {summary['total_events']}")
        print(f"Anomalies detected: {summary['anomalies_detected']}")
        print(f"Attack chains found: {summary['attack_chains_found']}")
        print(f"Threat feed rows ingested: {summary['threat_feed_rows']}")
        print(f"Trained models: {summary['trained_model_dir']}")
        print("==============================\n")

        return summary

    # -------------------------
    # Storage + enrichment
    # -------------------------

    def _ingest_threat_intel(self) -> None:
        try:
            threat_feed_df = fetch_threat_ips()
            self.threat_feed_ips = extract_threat_ips(threat_feed_df)
            self.threat_feed_rows = int(len(threat_feed_df))
            self.logger.info("Threat feed ingested: rows=%d unique_ips=%d", self.threat_feed_rows, len(self.threat_feed_ips))
        except Exception as exc:
            self.threat_feed_ips = set()
            self.threat_feed_rows = 0
            self.logger.warning("Threat feed ingestion failed; continuing without enrichment: %s", exc)

    def _enrich_events_with_threat_intel(self) -> None:
        for event in self.events:
            src_ip = str(event.get("source_ip") or "")
            dst_ip = str(event.get("destination_ip") or "")
            threat_hit = src_ip in self.threat_feed_ips or dst_ip in self.threat_feed_ips
            event["threat_feed_hit"] = bool(threat_hit)
            event.setdefault("event_name", event.get("event_type") or event.get("technique_id") or event.get("tactic"))

    def _persist_events(self) -> None:
        with session_scope() as session:
            db_events: List[EventRecord] = []
            for event in self.events:
                db_event = EventRecord(
                    event_uid=str(event.get("event_id") or ""),
                    event_name=str(event.get("event_name") or event.get("event_type") or ""),
                    timestamp=self._parse_ts(event.get("timestamp")),
                    source_ip=event.get("source_ip"),
                    destination_ip=event.get("destination_ip"),
                    event_type=event.get("event_type"),
                    tactic=event.get("tactic"),
                    technique_id=event.get("technique_id"),
                    severity=event.get("severity"),
                    is_malicious=bool(event.get("is_malicious", False)),
                    tactic_encoded=self._optional_int(event.get("tactic_encoded")),
                    severity_encoded=self._optional_int(event.get("severity_encoded")),
                    mcdm_score=self._optional_float(event.get("mcdm_score")),
                    threat_actor=event.get("threat_actor"),
                    threat_feed_hit=bool(event.get("threat_feed_hit", False)),
                    raw_data=dict(event),
                )
                db_events.append(db_event)

            session.add_all(db_events)
            session.flush()
            self.db_event_ids = {db_event.event_uid: db_event.id for db_event in db_events}

    def _persist_detections(self) -> None:
        if self.predictions_df is None:
            return

        records = self.predictions_df.to_dict(orient="records")
        with session_scope() as session:
            db_rows: List[DetectionResult] = []
            for event, prediction in zip(self.events, records):
                event_uid = str(event.get("event_id") or "")
                db_event_id = self.db_event_ids.get(event_uid)
                if db_event_id is None:
                    continue
                db_rows.append(
                    DetectionResult(
                        event_id=db_event_id,
                        model_name="athena_detection_stack",
                        confidence_score=self._optional_float(prediction.get("p_malicious_lstm")),
                        anomaly_score=self._optional_float(prediction.get("anomaly_score_iforest")),
                        is_true_positive=self._derive_true_positive(event=event, prediction=prediction),
                        is_malicious_pred=self._optional_bool(prediction.get("is_malicious_pred")),
                        raw_data=dict(prediction),
                    )
                )
            session.add_all(db_rows)

    def _persist_correlations(self) -> None:
        if not isinstance(self.correlation_results, dict):
            return

        chains = self.correlation_results.get("attack_chains", []) or []
        graph = self.correlation_results.get("graph", {}) or {}
        edges = graph.get("edges", []) or []

        event_to_chain: Dict[str, str] = {}
        for chain in chains:
            chain_id = str(chain.get("chain_id") or "")
            for event_uid in chain.get("event_ids", []) or []:
                event_to_chain[str(event_uid)] = chain_id

        with session_scope() as session:
            db_rows: List[CorrelationRecord] = []

            for chain in chains:
                db_rows.append(
                    CorrelationRecord(
                        chain_id=str(chain.get("chain_id") or ""),
                        correlation_type="chain_summary",
                        strength=self._optional_float(chain.get("chain_score")),
                        chain_score=self._optional_float(chain.get("chain_score")),
                        is_multi_stage=bool((chain.get("multi_stage") or {}).get("is_multi_stage", False)),
                        raw_data=dict(chain),
                    )
                )

            for edge in edges:
                source_uid = str(edge.get("source") or "")
                target_uid = str(edge.get("target") or "")
                db_rows.append(
                    CorrelationRecord(
                        chain_id=event_to_chain.get(source_uid) or event_to_chain.get(target_uid),
                        parent_event_id=self.db_event_ids.get(source_uid),
                        child_event_id=self.db_event_ids.get(target_uid),
                        correlation_type="event_edge",
                        strength=self._optional_float(edge.get("strength")),
                        gap_seconds=self._optional_float(edge.get("gap_seconds")),
                        reasons=list(edge.get("reasons", [])),
                        raw_data=dict(edge),
                    )
                )

            session.add_all(db_rows)

    def _derive_true_positive(self, *, event: Dict[str, Any], prediction: Dict[str, Any]) -> Optional[bool]:
        pred_value = self._optional_bool(prediction.get("is_malicious_pred"))
        if pred_value is None:
            return None
        return bool(pred_value == bool(event.get("is_malicious", False)))

    def _parse_ts(self, value: Any) -> datetime:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        if isinstance(value, str) and value.strip():
            try:
                dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                pass
        return datetime.now(timezone.utc)

    def _optional_float(self, value: Any) -> Optional[float]:
        try:
            return None if value is None else float(value)
        except (TypeError, ValueError):
            return None

    def _optional_int(self, value: Any) -> Optional[int]:
        try:
            return None if value is None else int(value)
        except (TypeError, ValueError):
            return None

    def _optional_bool(self, value: Any) -> Optional[bool]:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(int(value))
        if isinstance(value, str):
            if value.lower() in {"true", "1", "yes"}:
                return True
            if value.lower() in {"false", "0", "no"}:
                return False
        return None


if __name__ == "__main__":
    pipeline = AthenaPipeline(config=PipelineConfig(threat_actor="APT28"))
    pipeline.run_full_pipeline()

