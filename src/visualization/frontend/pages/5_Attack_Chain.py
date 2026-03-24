import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
import sys
from pathlib import Path

import networkx as nx
from pyvis.network import Network

# Add project root for local imports
sys.path.append(str(Path(__file__).resolve().parents[1]))

from components.sidebar import setup_sidebar
from utils.api_client import AthenaAPIClient


def _normalize_chain_payload(chains_data):
    if not chains_data:
        return {}

    if "chains" in chains_data and isinstance(chains_data["chains"], dict):
        return chains_data["chains"]

    if "attack_chains" in chains_data and isinstance(chains_data["attack_chains"], list):
        chain_map = {}
        for chain in chains_data["attack_chains"]:
            chain_id = chain.get("chain_id")
            events = chain.get("events")
            if chain_id and isinstance(events, list):
                chain_map[chain_id] = events
        return chain_map

    return {}


def main():
    setup_sidebar()
    st.title("Attack Chain Reconstruction")

    chains_data = AthenaAPIClient.get_attack_chains()
    chains = _normalize_chain_payload(chains_data)
    if not chains:
        st.warning("No attack chains found. Please run a threat simulation from the sidebar.")
        return

    st.subheader("Visualizing Lateral Movement and Progression")

    chain_ids = list(chains.keys())
    selected_chain_id = st.selectbox("Select Attack Chain to Inspect", options=chain_ids)

    if selected_chain_id:
        chain_events = chains[selected_chain_id]

        graph = nx.DiGraph()
        for index, event in enumerate(chain_events):
            label = f"{event['tactic']}\n{event['technique_id']}"
            graph.add_node(
                event["event_id"],
                label=label,
                title=(
                    f"Time: {event['timestamp']}\n"
                    f"Source: {event['source_ip']}\n"
                    f"Dest: {event['destination_ip']}"
                ),
                color="red" if index == len(chain_events) - 1 else "orange",
                size=25,
            )
            if index < len(chain_events) - 1:
                graph.add_edge(event["event_id"], chain_events[index + 1]["event_id"], label="next")

        net = Network(height="500px", width="100%", bgcolor="#222222", font_color="white", directed=True)
        net.from_nx(graph)

        path = "chain_graph.html"
        net.save_graph(path)

        with open(path, "r", encoding="utf-8") as handle:
            components.html(handle.read(), height=550)

        st.markdown("---")
        st.subheader("Chain Progression Details")
        chain_df = pd.DataFrame(chain_events)
        st.dataframe(
            chain_df[["timestamp", "source_ip", "destination_ip", "tactic", "technique_id", "severity"]],
            use_container_width=True,
        )


if __name__ == "__main__":
    main()
