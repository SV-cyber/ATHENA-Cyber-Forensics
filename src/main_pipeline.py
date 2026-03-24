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
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent  # /src
PROJECT_ROOT = BASE_DIR.parent  # repo root


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

    # Output locations
    outputs_dir: Path = BASE_DIR / "outputs"
    dataset_csv: Path = BASE_DIR / "outputs" / "normalized_events.csv"
    correlation_json: Path = BASE_DIR / "outputs" / "correlation_results.json"

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

        # Normalize any user-supplied relative paths against PROJECT_ROOT for robustness.
        if not self.config.outputs_dir.is_absolute():
            self.config = PipelineConfig(
                threat_actor=self.config.threat_actor,
                outputs_dir=(PROJECT_ROOT / self.config.outputs_dir).resolve(),
                dataset_csv=(PROJECT_ROOT / self.config.dataset_csv).resolve(),
                correlation_json=(PROJECT_ROOT / self.config.correlation_json).resolve(),
                trained_model_dir=(PROJECT_ROOT / self.config.trained_model_dir).resolve(),
            )

        self.config.outputs_dir.mkdir(parents=True, exist_ok=True)

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

    # -------------------------
    # Orchestration
    # -------------------------

    def run_full_pipeline(self) -> Dict[str, Any]:
        """
        Run end-to-end ATHENA pipeline and return the correlation results.
        """
        try:
            self.logger.info("Starting ATHENA pipeline: actor=%s", self.config.threat_actor)

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
        self.logger.info("Stage 1/7: generate attack chain")
        _ = self.operator.generate_attack_chain(threat_actor=self.config.threat_actor)

        self.logger.info("Stage 2/7: execute attack simulation (async)")
        self.mission_log = asyncio.run(self.operator.execute_attack_chain(threat_actor=self.config.threat_actor))

        # Export mission logs to CSV if the operator supports it.
        try:
            mission_csv = BASE_DIR / "caldera-simulator" / "mission_log.csv"
            self.operator.export_to_csv(mission_csv)
            self.logger.info("Mission log CSV saved: %s", str(mission_csv))
        except Exception:
            # Don't fail the full pipeline if CSV export is unavailable.
            self.logger.warning("Mission log CSV export skipped (operator missing export_to_csv or failed).")

    def process_data(self) -> None:
        """
        Normalize mission logs into ML-ready events and DataFrame.
        """
        self.logger.info("Stage 3/7: normalize mission logs -> events")
        normalizer = self.EventNormalizer(self.mission_log)
        self.events = normalizer.normalize_events()

        self.logger.info("Stage 4/7: export events -> DataFrame + CSV")
        self.df = normalizer.export_to_dataframe()
        self.config.dataset_csv.parent.mkdir(parents=True, exist_ok=True)
        self.df.to_csv(self.config.dataset_csv, index=False)
        self.logger.info("Dataset CSV saved: %s rows=%d", str(self.config.dataset_csv), int(len(self.df)))

    def train_model(self) -> None:
        """
        Train LSTM + IsolationForest and save artifacts.
        """
        if self.df is None:
            raise RuntimeError("DataFrame not built. Run process_data() first.")

        self.logger.info("Stage 5/7: train ML models (LSTM + IsolationForest)")
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

        self.config.correlation_json.parent.mkdir(parents=True, exist_ok=True)
        with self.config.correlation_json.open("w", encoding="utf-8") as f:
            json.dump(self.correlation_results, f, indent=2)
        self.logger.info("Correlation results saved: %s", str(self.config.correlation_json))

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
            "dataset_csv": str(self.config.dataset_csv),
            "trained_model_dir": str(self.config.trained_model_dir),
            "correlation_results_json": str(self.config.correlation_json),
        }

        print("\n=== ATHENA PIPELINE SUMMARY ===")
        print(f"Total events: {summary['total_events']}")
        print(f"Anomalies detected: {summary['anomalies_detected']}")
        print(f"Attack chains found: {summary['attack_chains_found']}")
        print(f"Dataset CSV: {summary['dataset_csv']}")
        print(f"Trained models: {summary['trained_model_dir']}")
        print(f"Correlation JSON: {summary['correlation_results_json']}")
        print("==============================\n")

        return summary


if __name__ == "__main__":
    pipeline = AthenaPipeline(config=PipelineConfig(threat_actor="APT28"))
    pipeline.run_full_pipeline()

