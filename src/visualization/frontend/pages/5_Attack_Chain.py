import streamlit as st
import pandas as pd
import sys
from pathlib import Path
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components

# Add project root for local imports
sys.path.append(str(Path(__file__).resolve().parents[1]))

from components.sidebar import setup_sidebar
from utils.api_client import AthenaAPIClient
from utils.data_processor import DataProcessor

def main():
    setup_sidebar()
    st.title("🔗 Attack Chain Reconstruction")
    
    # Fetch Attack Chains
    chains_data = AthenaAPIClient.get_attack_chains()
    if not chains_data or "chains" not in chains_data:
        st.warning("No attack chains found. Please run a threat simulation from the sidebar.")
        return
        
    chains = chains_data["chains"]
    
    st.subheader("🕸️ Visualizing Lateral Movement & Progression")
    
    # Selection of chain to visualize
    chain_ids = list(chains.keys())
    selected_chain_id = st.selectbox("Select Attack Chain to Inspect", options=chain_ids)
    
    if selected_chain_id:
        chain_events = chains[selected_chain_id]
        
        # Create NetworkX Graph
        G = nx.DiGraph()
        
        # Add nodes and edges
        for i, event in enumerate(chain_events):
            # Node for the event
            label = f"{event['tactic']}\n{event['technique_id']}"
            G.add_node(event['event_id'], 
                       label=label, 
                       title=f"Time: {event['timestamp']}\nSource: {event['source_ip']}\nDest: {event['destination_ip']}",
                       color='red' if i == len(chain_events)-1 else 'orange',
                       size=25)
            
            # Edge to next event in chain
            if i < len(chain_events) - 1:
                G.add_edge(event['event_id'], chain_events[i+1]['event_id'], label="next")

        # Create PyVis Network
        net = Network(height="500px", width="100%", bgcolor="#222222", font_color="white", directed=True)
        net.from_nx(G)
        
        # Save and display
        path = "chain_graph.html"
        net.save_graph(path)
        
        with open(path, 'r', encoding='utf-8') as f:
            html_content = f.read()
            components.html(html_content, height=550)
            
        # Step-by-step table
        st.markdown("---")
        st.subheader("📋 Chain Progression Details")
        chain_df = pd.DataFrame(chain_events)
        st.dataframe(
            chain_df[["timestamp", "source_ip", "destination_ip", "tactic", "technique_id", "severity"]],
            use_container_width=True
        )

if __name__ == "__main__":
    main()
