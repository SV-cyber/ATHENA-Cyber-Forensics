import streamlit as st
import pandas as pd
import sys
from pathlib import Path
from datetime import datetime

# Add current directory to path to ensure modules can be imported
sys.path.append(str(Path(__file__).resolve().parent))

# Import local components and utilities
from components.sidebar import setup_sidebar
from utils.api_client import AthenaAPIClient
from utils.data_processor import DataProcessor

# Page configuration
st.set_page_config(
    page_title="ATHENA | Cyber Threat Intelligence & Forensic Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize Session State
def init_session_state():
    if "df" not in st.session_state:
        st.session_state.df = AthenaAPIClient.get_results()
    if "chains" not in st.session_state:
        st.session_state.chains = AthenaAPIClient.get_attack_chains()
    if "theme" not in st.session_state:
        st.session_state.theme = "dark"

# Main landing logic
def main():
    setup_sidebar()
    init_session_state()
    
    # Redirect to Overview if no page is selected (handled by Streamlit's multi-page automatically)
    st.markdown("""
    # Welcome to ATHENA SOC Platform
    
    ATHENA (AI-Driven Threat Hunting & Adversary Emulation) provides real-time visibility into your infrastructure, 
    detecting anomalies and reconstructing attack chains with high precision.
    
    ### Getting Started
    1. Check the **Overview** dashboard for a high-level summary.
    2. Dive into **Threat Hunting** to investigate suspicious events.
    3. Explore **Attack Chains** to see how threats propagated through your network.
    
    ---
    *Use the sidebar on the left to navigate between modules.*
    """)

if __name__ == "__main__":
    main()
