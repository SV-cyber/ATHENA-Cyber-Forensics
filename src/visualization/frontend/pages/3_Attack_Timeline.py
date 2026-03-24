import streamlit as st
import plotly.express as px
import pandas as pd
import sys
from pathlib import Path

# Add project root for local imports
sys.path.append(str(Path(__file__).resolve().parents[1]))

from components.sidebar import setup_sidebar
from utils.api_client import AthenaAPIClient
from utils.data_processor import DataProcessor

def main():
    setup_sidebar()
    st.title("🕰️ Interactive Attack Timeline")
    
    # Fetch Data
    df = AthenaAPIClient.get_results()
    if df is None or df.empty:
        st.warning("No data found. Please run a threat simulation from the sidebar.")
        return
        
    df = DataProcessor.preprocess_events(df)
    
    # Timeline Options
    st.sidebar.markdown("### 🕒 Timeline Settings")
    color_by = st.sidebar.selectbox("Color By", options=["tactic", "severity", "threat_actor"], index=0)
    size_by = st.sidebar.selectbox("Bubble Size", options=["risk_score", "mcdm_score"], index=0)
    
    # Filter only malicious events for timeline
    timeline_df = df[df["is_malicious"] == True].copy()
    
    if timeline_df.empty:
        st.info("No malicious events detected to display in the timeline.")
        return
        
    st.subheader("🔥 Event Progression Map")
    
    # Plotly Timeline (Scatter Plot with Time on X and Tactic on Y)
    fig = px.scatter(
        timeline_df, 
        x="timestamp", 
        y="tactic", 
        color=color_by,
        size=size_by,
        hover_data=["event_id", "source_ip", "destination_ip", "technique_id", "severity"],
        title="Attack Progression over Time",
        labels={"timestamp": "Time", "tactic": "MITRE Tactic Stage"},
        template="plotly_dark",
        height=600,
        color_discrete_sequence=px.colors.qualitative.Safe
    )
    
    # Customize layout
    fig.update_layout(
        xaxis_title="Timeline",
        yaxis_title="MITRE Tactic stage",
        showlegend=True,
        xaxis=dict(showgrid=True, gridcolor="rgba(255, 255, 255, 0.1)"),
        yaxis=dict(showgrid=True, gridcolor="rgba(255, 255, 255, 0.1)", categoryorder="array",
                   categoryarray=["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"])
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Timeline List
    st.markdown("---")
    st.subheader("📝 Chronological Event Sequence")
    
    st.dataframe(
        timeline_df[["timestamp", "tactic", "technique_id", "source_ip", "destination_ip", "severity"]]
        .sort_values("timestamp"),
        use_container_width=True
    )

if __name__ == "__main__":
    main()
