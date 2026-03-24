import requests
import pandas as pd
import streamlit as st
from typing import Dict, Any, Optional
import os

# Default API URL (from FastAPI's default port)
API_BASE_URL = os.getenv("ATHENA_API_URL", "http://localhost:8001")

class AthenaAPIClient:
    """Enterprise-grade API client for ATHENA Backend."""
    
    @staticmethod
    @st.cache_data(ttl=60)
    def get_health() -> bool:
        """Check if backend is alive."""
        try:
            response = requests.get(f"{API_BASE_URL}/health", timeout=2)
            return response.status_code == 200
        except Exception:
            return False

    @staticmethod
    def run_pipeline() -> Dict[str, Any]:
        """Trigger threat simulation and return summary."""
        try:
            response = requests.post(f"{API_BASE_URL}/run-pipeline", timeout=120)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    @st.cache_data(ttl=300)
    def get_results() -> Optional[pd.DataFrame]:
        """Fetch normalized events from backend."""
        try:
            response = requests.get(f"{API_BASE_URL}/results", timeout=30)
            response.raise_for_status()
            data = response.json()
            if "data" in data:
                return pd.DataFrame(data["data"])
            return None
        except Exception as e:
            st.error(f"Failed to fetch results: {e}")
            return None

    @staticmethod
    @st.cache_data(ttl=300)
    def get_attack_chains() -> Dict[str, Any]:
        """Fetch attack chain correlations."""
        try:
            response = requests.get(f"{API_BASE_URL}/attack-chains", timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            st.error(f"Failed to fetch attack chains: {e}")
            return {}

    @staticmethod
    def get_export_url() -> str:
        """Return the CSV export URL."""
        return f"{API_BASE_URL}/export-csv"
