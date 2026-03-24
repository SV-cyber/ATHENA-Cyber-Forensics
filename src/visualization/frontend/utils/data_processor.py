import pandas as pd
import numpy as np
import streamlit as st
from typing import Dict, Any, List, Optional
from datetime import datetime

class DataProcessor:
    """Enterprise-grade data processing for SOC visualizations."""
    
    @staticmethod
    def preprocess_events(df: pd.DataFrame) -> pd.DataFrame:
        """Standardize and enrich event data."""
        if df.empty:
            return df
            
        # Ensure timestamp is datetime
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        
        # Sort by timestamp
        df = df.sort_values("timestamp", ascending=False)
        
        # Add risk_score if missing (derived from severity)
        if "risk_score" not in df.columns:
            severity_map = {"low": 10, "medium": 40, "high": 75, "critical": 95}
            df["risk_score"] = df["severity"].str.lower().map(severity_map).fillna(0)
            
        return df

    @staticmethod
    def get_kpis(df: pd.DataFrame) -> Dict[str, Any]:
        """Calculate Key Performance Indicators for the dashboard."""
        if df.empty:
            return {
                "total_events": 0,
                "anomalies": 0,
                "high_risk": 0,
                "active_threats": 0
            }
            
        return {
            "total_events": len(df),
            "anomalies": df["is_malicious"].sum() if "is_malicious" in df.columns else 0,
            "high_risk": len(df[df["severity"].str.lower().isin(["high", "critical"])]),
            "active_threats": df["threat_actor"].nunique() if "threat_actor" in df.columns else 0
        }

    @staticmethod
    def filter_data(df: pd.DataFrame, 
                    ips: List[str] = None, 
                    tactics: List[str] = None, 
                    severity: List[str] = None,
                    anomaly_threshold: float = 0.0) -> pd.DataFrame:
        """Advanced filtering for threat hunting."""
        filtered_df = df.copy()
        
        if ips:
            filtered_df = filtered_df[
                (filtered_df["source_ip"].isin(ips)) | 
                (filtered_df["destination_ip"].isin(ips))
            ]
            
        if tactics:
            filtered_df = filtered_df[filtered_df["tactic"].isin(tactics)]
            
        if severity:
            filtered_df = filtered_df[filtered_df["severity"].isin(severity)]
            
        if "mcdm_score" in filtered_df.columns:
            filtered_df = filtered_df[filtered_df["mcdm_score"] >= anomaly_threshold]
            
        return filtered_df
