import streamlit as st
from datetime import datetime
import sys
from pathlib import Path

# Add project root for local imports
sys.path.append(str(Path(__file__).resolve().parents[1]))

from utils.api_client import AthenaAPIClient

def setup_sidebar():
    """Enterprise-grade sidebar for ATHENA SOC Platform."""
    st.sidebar.title("🛡️ ATHENA SOC")
    st.sidebar.markdown("---")
    
    # Connection Status
    is_healthy = AthenaAPIClient.get_health()
    if is_healthy:
        st.sidebar.success("Backend: CONNECTED ✅")
    else:
        st.sidebar.error("Backend: DISCONNECTED ❌")
        
    # Global Actions
    st.sidebar.markdown("### ⚡ Global Actions")
    if st.sidebar.button("Run Threat Simulation", type="primary", key="global_sim"):
        with st.spinner("Executing pipeline..."):
            result = AthenaAPIClient.run_pipeline()
            if "error" in result:
                st.sidebar.error(f"Simulation failed: {result['error']}")
            else:
                st.sidebar.success(f"Simulation complete! {result.get('total_events', 0)} events analyzed.")
                st.rerun()

    # Data Status
    st.sidebar.markdown("---")
    st.sidebar.info(f"Last Data Sync: {datetime.now().strftime('%H:%M:%S')}")
    
    # Auto-refresh option
    st.sidebar.checkbox("Auto-refresh (60s)", value=True, key="auto_refresh")
    
    # Footer
    st.sidebar.markdown("---")
    st.sidebar.caption("ATHENA | v1.2.0-PROD")
