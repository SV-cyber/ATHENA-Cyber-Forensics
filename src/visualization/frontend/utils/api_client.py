import requests
import pandas as pd
import streamlit as st
from typing import Dict, Any, Optional
import os
from urllib.parse import urlencode

# Default API URL (from FastAPI's default port)
API_BASE_URL = os.getenv("ATHENA_API_URL", "http://localhost:8001")

class AthenaAPIClient:
    """Enterprise-grade API client for ATHENA Backend."""

    @staticmethod
    def _build_url(path: str, **params: Any) -> str:
        clean_params = {key: value for key, value in params.items() if value not in (None, "", [])}
        if not clean_params:
            return f"{API_BASE_URL}{path}"
        return f"{API_BASE_URL}{path}?{urlencode(clean_params)}"
    
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
    @st.cache_data(ttl=300)
    def get_detections() -> Optional[pd.DataFrame]:
        """Fetch persisted detection results from backend."""
        try:
            response = requests.get(f"{API_BASE_URL}/detections", timeout=30)
            response.raise_for_status()
            data = response.json()
            if "data" in data:
                return pd.DataFrame(data["data"])
            return None
        except Exception as e:
            st.error(f"Failed to fetch detections: {e}")
            return None

    @staticmethod
    def get_export_url() -> str:
        """Return the CSV export URL."""
        return f"{API_BASE_URL}/export-csv"

    @staticmethod
    @st.cache_data(ttl=120)
    def get_simulation_scenarios() -> Dict[str, Any]:
        try:
            response = requests.get(f"{API_BASE_URL}/simulation/scenarios", timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def run_simulation_scenario(scenario_name: str) -> Dict[str, Any]:
        try:
            response = requests.post(f"{API_BASE_URL}/simulation/run/{scenario_name}", timeout=120)
            response.raise_for_status()
            AthenaAPIClient.get_simulation_scenarios.clear()
            AthenaAPIClient.get_results.clear()
            AthenaAPIClient.get_attack_chains.clear()
            AthenaAPIClient.get_simulation_executions.clear()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    @st.cache_data(ttl=60)
    def get_simulation_executions() -> Dict[str, Any]:
        try:
            response = requests.get(f"{API_BASE_URL}/simulation/executions", timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    @st.cache_data(ttl=30)
    def get_simulation_status(execution_id: str) -> Dict[str, Any]:
        try:
            response = requests.get(f"{API_BASE_URL}/simulation/status/{execution_id}", timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    @st.cache_data(ttl=30)
    def get_threat_map_live(time_range: str = "24h", country: Optional[str] = None) -> Dict[str, Any]:
        try:
            response = requests.get(
                AthenaAPIClient._build_url("/threat-map/live-attacks", time_range=time_range, country=country),
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    @st.cache_data(ttl=30)
    def get_threat_map_stats(time_range: str = "24h", country: Optional[str] = None) -> Dict[str, Any]:
        try:
            response = requests.get(
                AthenaAPIClient._build_url("/threat-map/stats", time_range=time_range, country=country),
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    @st.cache_data(ttl=30)
    def get_threat_map_timeline(time_range: str = "24h", country: Optional[str] = None) -> Dict[str, Any]:
        try:
            response = requests.get(
                AthenaAPIClient._build_url("/threat-map/timeline", time_range=time_range, country=country),
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    @st.cache_data(ttl=30)
    def get_threat_map_attack_flows(time_range: str = "24h", country: Optional[str] = None) -> Dict[str, Any]:
        try:
            response = requests.get(
                AthenaAPIClient._build_url("/threat-map/attack-flows", time_range=time_range, country=country),
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    @st.cache_data(ttl=30)
    def get_threat_map_top_threats(time_range: str = "24h", country: Optional[str] = None) -> Dict[str, Any]:
        try:
            response = requests.get(
                AthenaAPIClient._build_url("/threat-map/top-threats", time_range=time_range, country=country),
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    @st.cache_data(ttl=30)
    def get_threat_map_top_industries(time_range: str = "24h", country: Optional[str] = None) -> Dict[str, Any]:
        try:
            response = requests.get(
                AthenaAPIClient._build_url("/threat-map/top-industries", time_range=time_range, country=country),
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    @st.cache_data(ttl=15)
    def get_threat_map_live_feed(time_range: str = "24h", country: Optional[str] = None) -> Dict[str, Any]:
        try:
            response = requests.get(
                AthenaAPIClient._build_url("/threat-map/live-feed", time_range=time_range, country=country),
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}
