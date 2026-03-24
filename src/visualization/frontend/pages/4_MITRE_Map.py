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
    st.title("🧩 MITRE ATT&CK Matrix Visualization")
    
    # Fetch Data
    df = AthenaAPIClient.get_results()
    if df is None or df.empty:
        st.warning("No data found. Please run a threat simulation from the sidebar.")
        return
        
    df = DataProcessor.preprocess_events(df)
    
    # MITRE ATT&CK Tactic-wise Grouping
    st.subheader("🛠️ Tactic & Technique Coverage")
    
    # Frequency by tactic and technique
    mitre_counts = df.groupby(['tactic', 'technique_id']).size().reset_index(name='count')
    
    # Sunburst Chart for MITRE Tactics/Techniques
    fig_sun = px.sunburst(
        mitre_counts, 
        path=['tactic', 'technique_id'], 
        values='count',
        color='count',
        color_continuous_scale='OrRd',
        title="MITRE ATT&CK Coverage (Tactic > Technique)",
        template="plotly_dark",
        height=600
    )
    st.plotly_chart(fig_sun, use_container_width=True)

    # Tactic-wise breakdown
    st.markdown("---")
    st.subheader("🔥 Technique Frequency Analysis")
    
    # Grouped Bar Chart
    fig_bar = px.bar(
        mitre_counts, 
        x='tactic', 
        y='count', 
        color='technique_id',
        title="Frequency of Techniques per Tactic",
        template="plotly_dark",
        barmode='group'
    )
    st.plotly_chart(fig_bar, use_container_width=True)

    # Detailed MITRE Table
    st.markdown("---")
    st.subheader("📋 Technique Detail Mapping")
    st.table(
        df[['tactic', 'technique_id', 'event_type']]
        .drop_duplicates()
        .sort_values(['tactic', 'technique_id'])
        .reset_index(drop=True)
    )

if __name__ == "__main__":
    main()
