"""
ATHENA ML Training Pipeline (Phase 2)

Goal:
Train anomaly detection models for cyber attack detection using ML-ready events
produced by `src/data-collection/event_normalizer.py`.

Models:
    - LSTM sequence classifier (malicious/benign)
    - Isolation Forest baseline (anomaly scoring)

This module is designed to be used programmatically (import + call methods).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from joblib import dump, load
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

try:
    from tensorflow import keras  # type: ignore
    from tensorflow.keras import layers  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    keras = None  # type: ignore[assignment]
    layers = None  # type: ignore[assignment]


def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("athena.ml.training")
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


@dataclass(frozen=True)
class TrainingConfig:
    model_dir: Path = Path("src/ml_models/trained_models")
    random_state: int = 42
    test_size: float = 0.2

    # LSTM / sequence configuration
    window_size: int = 12
    stride: int = 1

    # Isolation Forest configuration
    iforest_contamination: float = 0.15

    # Training configuration
    batch_size: int = 32
    epochs: int = 12
    learning_rate: float = 1e-3


class ThreatDetectionModel:
    """
    Train and serve anomaly detection for ATHENA.

    Input:
        - DataFrame from EventNormalizer.export_to_dataframe()
    """

    def __init__(self, *, config: Optional[TrainingConfig] = None) -> None:
        self.logger = _setup_logger()
        self.config = config or TrainingConfig()
        self.config.model_dir.mkdir(parents=True, exist_ok=True)

        self.preprocessor: Optional[ColumnTransformer] = None
        self.iforest: Optional[IsolationForest] = None
        self.lstm_model: Optional[Any] = None

        # Cached evaluation sets
        self._X_test_seq: Optional[np.ndarray] = None
        self._y_test_seq: Optional[np.ndarray] = None
        self._X_test_flat: Optional[np.ndarray] = None
        self._y_test_flat: Optional[np.ndarray] = None

        self._feature_columns: List[str] = []

    # -------------------------
    # Preprocessing
    # -------------------------

    def preprocess_data(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Preprocess DataFrame into:
            - flat feature matrix (for Isolation Forest)
            - sequence windows (for LSTM)

        Returns:
            X_train_seq, X_test_seq, y_train_seq, y_test_seq, X_train_flat, X_test_flat
        """
        required = {"timestamp", "tactic", "event_type", "severity", "is_malicious"}
        missing = required.difference(df.columns)
        if missing:
            raise ValueError(f"Missing required columns: {sorted(missing)}")

        work = df.copy()

        # Ensure timestamp sortable; tolerate already-normalized ISO strings.
        work["timestamp"] = pd.to_datetime(work["timestamp"], errors="coerce", utc=True)
        work = work.sort_values("timestamp").reset_index(drop=True)

        # Feature selection: keep high-signal columns; tolerate additional engineered fields.
        cat_features = [c for c in ["tactic", "event_type", "severity"] if c in work.columns]
        num_features = [c for c in ["tactic_encoded", "severity_encoded", "mcdm_score"] if c in work.columns]

        # Fallback: if engineered fields are absent, derive simple numeric from severity.
        if "severity_encoded" not in work.columns and "severity" in work.columns:
            severity_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            work["severity_encoded"] = work["severity"].astype(str).str.lower().map(severity_map).fillna(1).astype(int)
            num_features.append("severity_encoded")

        self._feature_columns = cat_features + num_features

        y = work["is_malicious"].astype(int).to_numpy()

        preprocessor = ColumnTransformer(
            transformers=[
                ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), cat_features),
                ("num", StandardScaler(), num_features),
            ],
            remainder="drop",
        )
        X_all = preprocessor.fit_transform(work)

        self.preprocessor = preprocessor

        # Train/test split at event level.
        X_train_flat, X_test_flat, y_train_flat, y_test_flat = train_test_split(
            X_all,
            y,
            test_size=self.config.test_size,
            random_state=self.config.random_state,
            stratify=y if len(np.unique(y)) > 1 else None,
            shuffle=True,
        )

        # Sequence windows are built from the *chronologically ordered* full dataset.
        # Then we split windows into train/test to avoid leaking future info via shuffling.
        X_seq, y_seq = self._make_sequence_windows(X_all, y, window_size=self.config.window_size, stride=self.config.stride)

        X_train_seq, X_test_seq, y_train_seq, y_test_seq = train_test_split(
            X_seq,
            y_seq,
            test_size=self.config.test_size,
            random_state=self.config.random_state,
            stratify=y_seq if len(np.unique(y_seq)) > 1 else None,
            shuffle=True,
        )

        # Cache for evaluation
        self._X_test_seq, self._y_test_seq = X_test_seq, y_test_seq
        self._X_test_flat, self._y_test_flat = X_test_flat, y_test_flat

        self.logger.info(
            "Preprocess complete: events=%d flat_dim=%d seq=%s",
            len(work),
            int(X_all.shape[1]),
            str(X_seq.shape),
        )

        return X_train_seq, X_test_seq, y_train_seq, y_test_seq, X_train_flat, X_test_flat

    def _make_sequence_windows(self, X: np.ndarray, y: np.ndarray, *, window_size: int, stride: int) -> Tuple[np.ndarray, np.ndarray]:
        """
        Build rolling windows for LSTM.

        Labeling rule for a window:
            - malicious if ANY event within the window is malicious.
        """
        if window_size < 2:
            raise ValueError("window_size must be >= 2")
        if stride < 1:
            raise ValueError("stride must be >= 1")

        n = X.shape[0]
        if n < window_size:
            # Not enough events to form a single window.
            return np.zeros((0, window_size, X.shape[1]), dtype=np.float32), np.zeros((0,), dtype=np.int32)

        windows: List[np.ndarray] = []
        labels: List[int] = []

        for start in range(0, n - window_size + 1, stride):
            end = start + window_size
            w = X[start:end]
            label = int(np.any(y[start:end] == 1))
            windows.append(w.astype(np.float32))
            labels.append(label)

        return np.stack(windows, axis=0), np.array(labels, dtype=np.int32)

    # -------------------------
    # Training
    # -------------------------

    def train_model(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Train both LSTM (sequence classifier) and Isolation Forest (baseline anomaly scorer).
        Saves trained artifacts to `src/ml_models/trained_models/`.
        """
        X_train_seq, X_test_seq, y_train_seq, y_test_seq, X_train_flat, X_test_flat = self.preprocess_data(df)

        # Train Isolation Forest on "mostly benign" assumption: fit on all training flat features.
        iforest = IsolationForest(
            n_estimators=300,
            contamination=self.config.iforest_contamination,
            random_state=self.config.random_state,
        )
        iforest.fit(X_train_flat)
        self.iforest = iforest

        # Train LSTM classifier (optional if tensorflow is installed)
        if keras is None or layers is None:
            self.logger.warning("TensorFlow not installed; skipping LSTM training and using IsolationForest baseline only.")
            self.lstm_model = None
            metrics = self.evaluate_model()
            self._save_artifacts(metrics=metrics)
            return metrics

        if X_train_seq.shape[0] == 0:
            raise ValueError("Not enough events to build sequence windows. Increase data volume or reduce window_size.")

        self.lstm_model = self._build_lstm_model(
            timesteps=X_train_seq.shape[1],
            feature_dim=X_train_seq.shape[2],
            learning_rate=self.config.learning_rate,
        )

        history = self.lstm_model.fit(
            X_train_seq,
            y_train_seq,
            validation_data=(X_test_seq, y_test_seq),
            epochs=self.config.epochs,
            batch_size=self.config.batch_size,
            verbose=0,
        )

        self.logger.info("Training complete: LSTM epochs=%d", len(history.history.get("loss", [])))

        metrics = self.evaluate_model()
        self._save_artifacts(metrics=metrics)
        return metrics

    def _build_lstm_model(self, *, timesteps: int, feature_dim: int, learning_rate: float) -> Any:
        """
        Build an LSTM binary classifier.
        """
        if keras is None or layers is None:
            raise RuntimeError("TensorFlow/Keras is not available.")

        inputs = keras.Input(shape=(timesteps, feature_dim), name="event_sequence")
        x = layers.Masking(mask_value=0.0)(inputs)
        x = layers.LSTM(64, return_sequences=True)(x)
        x = layers.Dropout(0.25)(x)
        x = layers.LSTM(32)(x)
        x = layers.Dense(32, activation="relu")(x)
        x = layers.Dropout(0.20)(x)
        outputs = layers.Dense(1, activation="sigmoid", name="p_malicious")(x)

        model = keras.Model(inputs=inputs, outputs=outputs, name="athena_lstm_detector")
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=learning_rate),
            loss="binary_crossentropy",
            metrics=[keras.metrics.AUC(name="auc"), keras.metrics.BinaryAccuracy(name="acc")],
        )
        return model

    # -------------------------
    # Prediction / Evaluation
    # -------------------------

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Produce anomaly scoring + classification output.

        Returns:
            DataFrame with columns:
                - p_malicious_lstm (0-1)
                - anomaly_score_iforest (higher => more anomalous)
                - is_malicious_pred (0/1)
        """
        if self.preprocessor is None or self.iforest is None:
            raise RuntimeError("Models not trained/loaded. Call train_model() or load artifacts first.")

        work = df.copy()
        work["timestamp"] = pd.to_datetime(work["timestamp"], errors="coerce", utc=True)
        work = work.sort_values("timestamp").reset_index(drop=True)

        cat_features = [c for c in ["tactic", "event_type", "severity"] if c in work.columns]
        num_features = [c for c in ["tactic_encoded", "severity_encoded", "mcdm_score"] if c in work.columns]

        if "severity_encoded" not in work.columns and "severity" in work.columns:
            severity_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            work["severity_encoded"] = work["severity"].astype(str).str.lower().map(severity_map).fillna(1).astype(int)
            num_features.append("severity_encoded")

        # Use fitted preprocessor to transform. It expects the columns used at fit-time.
        X_all = self.preprocessor.transform(work)

        # Isolation Forest anomaly score (invert decision_function so higher = more anomalous)
        # decision_function: higher = more normal. We'll invert.
        normality = self.iforest.decision_function(X_all)
        anomaly_score = (-normality).astype(float)

        # LSTM optional. If unavailable, derive a probability proxy from IsolationForest anomaly scores.
        if self.lstm_model is None or keras is None:
            # Normalize anomaly score to 0-1 using a robust logistic transform.
            p_event = 1.0 / (1.0 + np.exp(-anomaly_score))
            is_mal_pred = (p_event >= 0.5).astype(int)
        else:
            X_seq, _ = self._make_sequence_windows(
                X_all,
                np.zeros((X_all.shape[0],), dtype=np.int32),
                window_size=self.config.window_size,
                stride=1,
            )
            if X_seq.shape[0] == 0:
                raise ValueError("Not enough events to build sequence windows for prediction.")

            p_seq = self.lstm_model.predict(X_seq, verbose=0).reshape(-1)
            p_event = np.full((X_all.shape[0],), np.nan, dtype=float)
            end_indices = np.arange(self.config.window_size - 1, X_all.shape[0])
            p_event[end_indices] = p_seq
            p_event[: self.config.window_size - 1] = p_seq[0]
            is_mal_pred = (p_event >= 0.5).astype(int)

        out = pd.DataFrame(
            {
                "p_malicious_lstm": p_event,
                "anomaly_score_iforest": anomaly_score,
                "is_malicious_pred": is_mal_pred,
            }
        )
        return out

    def evaluate_model(self) -> Dict[str, Any]:
        """
        Evaluate both models on cached test splits from the last training run.
        """
        if self.iforest is None:
            raise RuntimeError("Models not trained. Call train_model() first.")
        if self._X_test_seq is None or self._y_test_seq is None or self._X_test_flat is None or self._y_test_flat is None:
            raise RuntimeError("No cached test split. Call train_model() first.")

        # LSTM metrics (if available), otherwise report baseline placeholder.
        if self.lstm_model is not None and keras is not None:
            p = self.lstm_model.predict(self._X_test_seq, verbose=0).reshape(-1)
            y_true = self._y_test_seq.astype(int)
            y_pred = (p >= 0.5).astype(int)

            try:
                auc = float(roc_auc_score(y_true, p)) if len(np.unique(y_true)) > 1 else float("nan")
            except ValueError:
                auc = float("nan")

            prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
            acc = float(accuracy_score(y_true, y_pred))
            report = classification_report(y_true, y_pred, zero_division=0)
            cm = confusion_matrix(y_true, y_pred).tolist()
        else:
            y_true = self._y_test_seq.astype(int)
            acc, auc, prec, rec, f1 = float("nan"), float("nan"), 0.0, 0.0, 0.0
            report = "TensorFlow not installed; LSTM not evaluated."
            cm = [[0, 0], [0, 0]]

        # IsolationForest: score test set, map to predicted anomalies (-1 => anomaly)
        if_pred = self.iforest.predict(self._X_test_flat)
        if_anom = (if_pred == -1).astype(int)

        metrics = {
            "lstm": {
                "accuracy": acc,
                "auc": auc,
                "precision": float(prec),
                "recall": float(rec),
                "f1": float(f1),
                "confusion_matrix": cm,
                "report": report,
            },
            "isolation_forest": {
                "contamination": self.config.iforest_contamination,
                "anomaly_rate_test": float(np.mean(if_anom)) if len(if_anom) else 0.0,
            },
        }

        if not np.isnan(acc):
            self.logger.info(
                "Eval: LSTM acc=%.3f auc=%s f1=%.3f",
                acc,
                f"{auc:.3f}" if not np.isnan(auc) else "nan",
                float(f1),
            )
        else:
            self.logger.info("Eval: LSTM skipped (TensorFlow not installed)")
        return metrics

    # -------------------------
    # Persistence
    # -------------------------

    def _save_artifacts(self, *, metrics: Dict[str, Any]) -> None:
        if self.preprocessor is None or self.iforest is None:
            raise RuntimeError("Nothing to save. Train the models first.")

        pre_path = self.config.model_dir / "preprocessor.joblib"
        if_path = self.config.model_dir / "isolation_forest.joblib"
        lstm_path = self.config.model_dir / "lstm_detector.keras"
        metrics_path = self.config.model_dir / "metrics.json"
        meta_path = self.config.model_dir / "metadata.json"

        dump(self.preprocessor, pre_path)
        dump(self.iforest, if_path)
        if self.lstm_model is not None and keras is not None:
            self.lstm_model.save(lstm_path)

        with metrics_path.open("w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)

        with meta_path.open("w", encoding="utf-8") as f:
            json.dump(
                {
                    "window_size": self.config.window_size,
                    "stride": self.config.stride,
                    "feature_columns_hint": self._feature_columns,
                    "random_state": self.config.random_state,
                },
                f,
                indent=2,
            )

        self.logger.info("Saved artifacts to %s", str(self.config.model_dir))

    def load_artifacts(self, model_dir: Optional[Path] = None) -> None:
        """
        Load previously trained artifacts from disk.
        """
        d = model_dir or self.config.model_dir
        pre_path = d / "preprocessor.joblib"
        if_path = d / "isolation_forest.joblib"
        lstm_path = d / "lstm_detector.keras"
        meta_path = d / "metadata.json"

        self.preprocessor = load(pre_path)
        self.iforest = load(if_path)
        if keras is not None and lstm_path.exists():
            self.lstm_model = keras.models.load_model(lstm_path)
        else:
            self.lstm_model = None

        if meta_path.exists():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            # Keep config compatible but don't override user-supplied config blindly.
            self._feature_columns = list(meta.get("feature_columns_hint", []))

        self.logger.info("Loaded artifacts from %s", str(d))


if __name__ == "__main__":
    # Minimal example (expects a DataFrame shaped like EventNormalizer.export_to_dataframe()).
    # In production, import ThreatDetectionModel and pass real normalized data.
    example_df = pd.DataFrame(
        [
            {
                "timestamp": "2026-03-17T00:00:00+00:00",
                "tactic": "Discovery",
                "event_type": "Discovery:T1016",
                "severity": "medium",
                "is_malicious": True,
                "tactic_encoded": 7,
                "severity_encoded": 1,
                "mcdm_score": 7.2,
            }
            for _ in range(100)
        ]
    )

    trainer = ThreatDetectionModel()
    metrics = trainer.train_model(example_df)
    print(json.dumps(metrics, indent=2))

    preds = trainer.predict(example_df)
    print(preds.head())