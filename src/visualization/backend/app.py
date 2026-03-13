"""
ATHENA Backend API
"""

from fastapi import FastAPI
from datetime import datetime

app = FastAPI(
    title="ATHENA API",
    description="AI-Driven Threat Hunting & Adversary Emulation",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "message": "Welcome to ATHENA API",
        "docs": "/docs",
        "status": "/health"
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "athena-backend",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/status")
def status():
    return {
        "system": "ATHENA",
        "version": "0.1.0",
        "status": "operational"
    }