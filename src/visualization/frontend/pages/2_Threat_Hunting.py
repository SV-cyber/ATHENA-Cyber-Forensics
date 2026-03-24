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
    st.title("🎯 Threat Hunting Interface")
    
    # Fetch Data
    df = AthenaAPIClient.get_results()
    if df is None or df.empty:
        st.warning("No data found. Please run a threat simulation from the sidebar.")
        return
        
    df = DataProcessor.preprocess_events(df)
    
    # Advanced Filtering Controls
    st.subheader("🔍 Advanced Filters")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        ips = st.multiselect("Source / Destination IPs", 
                           options=list(set(df['source_ip'].unique()) | set(df['destination_ip'].unique())),
                           placeholder="Filter by IP...")
    with col2:
        tactics = st.multiselect("MITRE Tactics", 
                               options=df['tactic'].unique(),
                               placeholder="Filter by Tactic...")
    with col3:
        severity = st.multiselect("Severity Level", 
                                options=df['severity'].unique(),
                                placeholder="Filter by Severity...")
    
    # Anomaly Slider
    anomaly_threshold = st.slider("Anomaly Score Threshold (MCDM Score)", 
                                min_value=0.0, max_value=10.0, value=0.0, step=0.1,
                                help="Filter events based on the multi-criteria anomaly score.")
    
    # Filter Data
    filtered_df = DataProcessor.filter_data(df, ips, tactics, severity, anomaly_threshold)
    
    # Visualization and Results
    st.markdown("---")
    st.subheader(f"📊 Search Results ({len(filtered_df)} events)")
    
    # Display table with highlights
    def highlight_malicious(row):
        if row.get('is_malicious', False):
            return ['background-color: rgba(255, 0, 0, 0.2)'] * len(row)
        return [''] * len(row)

    st.dataframe(
        filtered_df.style.apply(highlight_malicious, axis=1),
        use_container_width=True,
        column_order=["timestamp", "source_ip", "destination_ip", "tactic", "technique_id", "severity", "mcdm_score", "is_malicious"],
        height=500
    )

    # Drill-down / Detailed View
    if not filtered_df.empty:
        st.markdown("---")
        st.subheader("🕵️ Event Investigation")
        selected_event_id = st.selectbox("Select Event ID for Detailed Analysis", options=filtered_df['event_id'].head(20).tolist())
        
        if selected_event_id:
            event_details = filtered_df[filtered_df['event_id'] == selected_event_id].iloc[0]
            d_col1, d_col2 = st.columns(2)
            
            with d_col1:
                st.json(event_details.to_dict())
            
            with d_col2:
                st.info(f"**Threat Intelligence Context:**\n\n"
                        f"- **Tactic:** {event_details['tactic']}\n"
                        f"- **Technique:** {event_details['technique_id']}\n"
                        f"- **Threat Actor:** {event_details.get('threat_actor', 'Unknown')}\n"
                        f"- **Confidence:** {event_details.get('mcdm_score', 0) * 10}%")

if __name__ == "__main__":
    main()
