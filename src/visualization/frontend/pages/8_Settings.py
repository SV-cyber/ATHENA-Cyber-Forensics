import streamlit as st
import pandas as pd
import sys
from pathlib import Path
import os

# Add project root for local imports
sys.path.append(str(Path(__file__).resolve().parents[1]))

from components.sidebar import setup_sidebar
from utils.api_client import AthenaAPIClient
from utils.data_processor import DataProcessor

def main():
    setup_sidebar()
    st.title("⚙️ System Settings & API Configuration")
    
    # API Settings
    st.subheader("🌐 Backend Connectivity")
    col1, col2 = st.columns(2)
    
    with col1:
        api_url = st.text_input("ATHENA API URL", value=os.getenv("ATHENA_API_URL", "http://localhost:8001"))
        if st.button("Test Connection"):
            is_healthy = AthenaAPIClient.get_health()
            if is_healthy:
                st.success("Successfully connected to ATHENA Backend ✅")
            else:
                st.error("Connection failed ❌")
                
    with col2:
        st.info("**Current Environment:**\n\n- **OS:** " + os.name.upper() + "\n- **Python Version:** " + sys.version.split(' ')[0])

    # Data Settings
    st.markdown("---")
    st.subheader("💾 Data Refresh Settings")
    
    refresh_interval = st.slider("Auto-refresh interval (seconds)", min_value=10, max_value=300, value=60)
    st.write(f"Data will refresh every {refresh_interval}s.")
    
    if st.button("Clear Cache"):
        st.cache_data.clear()
        st.success("Streamlit cache cleared! Refreshing data...")
        st.rerun()

    # UI/UX Settings
    st.markdown("---")
    st.subheader("🎨 Interface Customization")
    
    theme_choice = st.radio("Theme Mode", options=["Dark (Standard SOC)", "Light"], index=0)
    st.session_state.theme = theme_choice.lower()
    
    st.write("Current Theme: " + theme_choice)
    st.info("Theme changes may require a page reload.")

    # System Logs
    st.markdown("---")
    st.subheader("📜 System Status")
    
    is_healthy = AthenaAPIClient.get_health()
    st.json({
        "backend_status": "OK" if is_healthy else "DOWN",
        "api_endpoint": api_url,
        "frontend_version": "1.2.0-PROD",
        "last_sync": st.session_state.get('last_sync', 'Never')
    })

if __name__ == "__main__":
    main()
