"""
ATHENA Backend - FastAPI Server

Production-ready backend endpoints for running ATHENA pipeline and retrieving results.

Run:
    uvicorn app:app --reload --port 8001
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import pandas as pd

APP_ROOT = Path(__file__).resolve().parent  # src/visualization/backend
REPO_ROOT = APP_ROOT.parents[2]  # src/

OUTPUTS_DIR = REPO_ROOT / "outputs"
DATASET_CSV = OUTPUTS_DIR / "normalized_events.csv"
CORRELATION_JSON = OUTPUTS_DIR / "correlation_results.json"

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]  # goes to /src
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


class FileInfoResponse(BaseModel):
    path: str
    exists: bool
    size_bytes: Optional[int] = None
    modified_at: Optional[str] = None


app = FastAPI(
    title="ATHENA API",
    description="AI-Driven Threat Hunting & Adversary Emulation",
    version="0.2.0",
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stat_file(path: Path) -> FileInfoResponse:
    if not path.exists():
        return FileInfoResponse(path=str(path), exists=False)

    st = path.stat()
    return FileInfoResponse(
        path=str(path),
        exists=True,
        size_bytes=int(st.st_size),
        modified_at=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
    )


def _normalize_pipeline_summary(raw: Dict[str, Any]) -> Dict[str, int]:
    """
    Accepts multiple possible summary key shapes and normalizes them to:
        total_events, anomalies_detected, attack_chains_found
    """
    def pick_int(*keys: str, default: int = 0) -> int:
        for k in keys:
            v = raw.get(k)
            if isinstance(v, bool):
                continue
            if isinstance(v, (int, float)) and str(v).strip() != "":
                return int(v)
        return default

    return {
        "total_events": pick_int("total_events", default=0),
        "anomalies_detected": pick_int("anomalies_detected", "anomalies", default=0),
        "attack_chains_found": pick_int("attack_chains_found", "attack_chains", default=0),
    }


async def _run_pipeline_in_thread() -> Dict[str, Any]:
    """
    Run AthenaPipeline in a worker thread to avoid blocking the event loop.
    """
    AthenaPipeline = _load_attr_from_path(PIPELINE_PATH, "AthenaPipeline")
    PipelineConfig = _load_attr_from_path(PIPELINE_PATH, "PipelineConfig")

    def _runner() -> Dict[str, Any]:
        pipeline = AthenaPipeline(config=PipelineConfig(threat_actor="APT28"))
        return pipeline.run_full_pipeline()

    return await asyncio.to_thread(_runner)


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
    except FileNotFoundError as e:
        logger.exception("Pipeline file missing")
        raise HTTPException(status_code=500, detail=f"Pipeline file not found: {e}") from e
    except Exception as e:
        logger.exception("Pipeline run failed")
        raise HTTPException(status_code=500, detail=f"Pipeline failed: {e}") from e


@app.get("/results")
async def results() -> Dict[str, Any]:
    """Return actual results from normalized_events.csv"""
    if not DATASET_CSV.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Results dataset not found. Expected at {DATASET_CSV}. Run POST /run-pipeline first.",
        )
    try:
        df = pd.read_csv(DATASET_CSV)
        # Convert timestamp to ISO format strings if they aren't already
        return {
            "count": len(df),
            "data": df.to_dict(orient="records"),
            "file_info": _stat_file(DATASET_CSV)
        }
    except Exception as e:
        logger.exception("Failed to read results CSV")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/export-csv")
async def export_csv():
    if not DATASET_CSV.exists():
        raise HTTPException(status_code=404, detail="CSV file not found")
    return FileResponse(
        path=DATASET_CSV,
        media_type="text/csv",
        filename="athena_threat_intelligence.csv"
    )


@app.get("/attack-chains")
async def attack_chains() -> Dict[str, Any]:
    if not CORRELATION_JSON.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Correlation results not found. Expected at {CORRELATION_JSON}. Run POST /run-pipeline first.",
        )

    try:
        data = json.loads(CORRELATION_JSON.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("correlation_results.json is not a JSON object")
        return data
    except json.JSONDecodeError as e:
        logger.exception("Failed to parse correlation JSON")
        raise HTTPException(status_code=500, detail=f"Invalid correlation JSON: {e}") from e


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
