import streamlit as st
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
    st.title("🚨 Incident Management & Root Cause Analysis")
    
    # Fetch Data
    df = AthenaAPIClient.get_results()
    if df is None or df.empty:
        st.warning("No data found. Please run a threat simulation from the sidebar.")
        return
        
    df = DataProcessor.preprocess_events(df)
    
    # Incident Generation
    st.subheader("⚠️ High-Risk Incidents")
    
    # Group by Threat Actor or High-risk events
    if "threat_actor" in df.columns:
        incidents = df[df["severity"].isin(["high", "critical"])].groupby("threat_actor").size().reset_index(name="count")
        
        if incidents.empty:
            st.info("No high-risk incidents detected.")
            return
            
        # Display incidents as Cards
        for idx, row in incidents.iterrows():
            actor = row['threat_actor']
            count = row['count']
            
            with st.expander(f"🔴 Incident ID: INC-2024-{idx:03d} | Threat Actor: {actor} ({count} events)"):
                # Summary
                col1, col2, col3 = st.columns(3)
                col1.metric("Impacted Assets", df[df['threat_actor'] == actor]['destination_ip'].nunique())
                col2.metric("Tactics Observed", df[df['threat_actor'] == actor]['tactic'].nunique())
                col3.metric("Avg Risk Score", round(df[df['threat_actor'] == actor]['risk_score'].mean(), 1))
                
                # Root Cause
                st.markdown("---")
                st.markdown("### 🔍 Root Cause Analysis")
                first_event = df[df['threat_actor'] == actor].sort_values("timestamp").iloc[0]
                st.write(f"**Patient Zero Event:** {first_event['event_type']} from IP {first_event['source_ip']} at {first_event['timestamp']}")
                st.write(f"**Entry Technique:** {first_event['technique_id']} ({first_event['tactic']})")
                
                # Action Buttons
                st.markdown("---")
                c_act1, c_act2, c_act3 = st.columns(3)
                if c_act1.button(f"Isolate Asset: {first_event['destination_ip']}", key=f"iso_{idx}"):
                    st.success(f"Isolation request sent for {first_event['destination_ip']}")
                if c_act2.button(f"Generate Report for {actor}", key=f"rep_{idx}"):
                    st.info(f"Report generation started for {actor}")
                if c_act3.button(f"Acknowledge Incident", key=f"ack_{idx}"):
                    st.warning("Incident status updated to 'In Progress'")

if __name__ == "__main__":
    main()
