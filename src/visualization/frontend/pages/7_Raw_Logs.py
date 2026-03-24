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
    st.title("📜 Raw Event Logs & Forensic Data")
    
    # Fetch Data
    df = AthenaAPIClient.get_results()
    if df is None or df.empty:
        st.warning("No data found. Please run a threat simulation from the sidebar.")
        return
        
    df = DataProcessor.preprocess_events(df)
    
    # Search and Filtering Controls
    st.subheader("🔍 Search Logs")
    search_query = st.text_input("Global Search (Regex supported)", placeholder="Search by IP, technique, or event type...")
    
    # Filter by search query
    if search_query:
        df = df[df.apply(lambda row: row.astype(str).str.contains(search_query, case=False).any(), axis=1)]
        
    # Column configuration
    all_columns = df.columns.tolist()
    selected_columns = st.multiselect("Visible Columns", options=all_columns, default=["timestamp", "source_ip", "destination_ip", "tactic", "technique_id", "severity", "is_malicious"])
    
    # Export Data
    st.markdown("---")
    col_stat, col_exp = st.columns([3, 1])
    
    with col_stat:
        st.write(f"📊 Showing {len(df)} entries")
        
    with col_exp:
        # Download as CSV button (frontend-side)
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="💾 Download current view as CSV",
            data=csv,
            file_name='athena_logs_export.csv',
            mime='text/csv',
        )
        
        # Link to backend-side CSV export
        export_url = AthenaAPIClient.get_export_url()
        st.markdown(f"[🔗 Full Backend Export]({export_url})")

    # Data Table
    st.dataframe(
        df[selected_columns],
        use_container_width=True,
        height=700
    )

if __name__ == "__main__":
    main()
