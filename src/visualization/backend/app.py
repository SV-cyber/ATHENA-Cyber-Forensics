"""
ATHENA Backend - FastAPI Server
"""

from fastapi import FastAPI
from datetime import datetime
import uvicorn

app = FastAPI(
    title="ATHENA API",
    description="AI-Driven Threat Hunting & Adversary Emulation",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "project": "ATHENA",
        "message": "Backend API running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8001,
        reload=True
    )