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
    st.title("🛡️ SOC Dashboard - Overview")
    
    # Fetch Data
    df = AthenaAPIClient.get_results()
    if df is None or df.empty:
        st.warning("No data found. Please run a threat simulation from the sidebar.")
        return
        
    df = DataProcessor.preprocess_events(df)
    kpis = DataProcessor.get_kpis(df)
    
    # KPI Cards Row
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Events", f"{kpis['total_events']:,}", delta=None)
    with col2:
        st.metric("Anomalies Detected", f"{kpis['anomalies']:,}", delta=f"{kpis['anomalies']} active", delta_color="inverse")
    with col3:
        st.metric("High-Risk Alerts", f"{kpis['high_risk']:,}", delta_color="inverse")
    with col4:
        st.metric("Active Threats", f"{kpis['active_threats']:,}", delta=None)

    st.markdown("---")
    
    # Charts Row 1: Trends & Severity
    col_trend, col_sev = st.columns([2, 1])
    
    with col_trend:
        st.subheader("📊 Attack Trends Over Time")
        trend_df = df.resample('1min', on='timestamp').size().reset_index(name='event_count')
        fig_trend = px.line(trend_df, x='timestamp', y='event_count', title='Events Per Minute',
                            template="plotly_dark", line_shape='spline')
        st.plotly_chart(fig_trend, use_container_width=True)
        
    with col_sev:
        st.subheader("🔴 Severity Distribution")
        sev_counts = df['severity'].value_counts().reset_index()
        fig_sev = px.pie(sev_counts, values='count', names='severity', hole=0.4,
                         template="plotly_dark", color_discrete_map={'high': 'red', 'medium': 'orange', 'low': 'green'})
        st.plotly_chart(fig_sev, use_container_width=True)

    # Charts Row 2: Top IPs & Techniques
    col_ip, col_tech = st.columns(2)
    
    with col_ip:
        st.subheader("🌐 Top Source IPs")
        top_ips = df['source_ip'].value_counts().head(10).reset_index()
        fig_ip = px.bar(top_ips, x='source_ip', y='count', orientation='v',
                        template="plotly_dark", color='count', color_continuous_scale='Reds')
        st.plotly_chart(fig_ip, use_container_width=True)
        
    with col_tech:
        st.subheader("🛠️ Top Techniques (MITRE)")
        top_tech = df['technique_id'].value_counts().head(10).reset_index()
        fig_tech = px.bar(top_tech, x='count', y='technique_id', orientation='h',
                          template="plotly_dark", color='count', color_continuous_scale='Blues')
        st.plotly_chart(fig_tech, use_container_width=True)

if __name__ == "__main__":
    main()
