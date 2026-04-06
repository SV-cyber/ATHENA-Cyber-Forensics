from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.append(str(Path(__file__).resolve().parents[1]))

from utils.api_client import AthenaAPIClient


st.set_page_config(page_title="Simulation", page_icon=":material/science:")
st.title("Simulation Scenarios")
st.caption("Launch predefined ATT&CK-aligned scenarios and inspect their execution flow.")

scenario_payload = AthenaAPIClient.get_simulation_scenarios()
scenarios = scenario_payload.get("data", []) if isinstance(scenario_payload, dict) else []

if not scenarios:
    st.warning("No simulation scenarios are available.")
else:
    scenario_by_key = {item["key"]: item for item in scenarios}
    selected_key = st.selectbox("Scenario", options=list(scenario_by_key.keys()), format_func=lambda key: scenario_by_key[key]["name"])
    selected = scenario_by_key[selected_key]

    st.subheader(selected["name"])
    st.write(selected["description"])

    chain_df = pd.DataFrame(selected["mitre_chain"])
    if not chain_df.empty:
        st.markdown("**MITRE Chain**")
        st.dataframe(
            chain_df[
                [
                    "mitre_chain_position",
                    "mitre_tactic",
                    "mitre_tactic_id",
                    "mitre_technique",
                    "mitre_technique_id",
                    "event_type",
                    "severity",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )

    if st.button("Run Scenario", type="primary", use_container_width=True):
        result = AthenaAPIClient.run_simulation_scenario(selected_key)
        if "error" in result:
            st.error(result["error"])
        else:
            st.success(f"Execution {result['execution_id']} completed with {result['events_generated']} events.")
            st.json(result)

executions_payload = AthenaAPIClient.get_simulation_executions()
executions = executions_payload.get("data", []) if isinstance(executions_payload, dict) else []

st.markdown("**Recent Executions**")
if executions:
    st.dataframe(pd.DataFrame(executions), use_container_width=True, hide_index=True)
    execution_ids = [item["execution_id"] for item in executions]
    selected_execution = st.selectbox("Execution Status", execution_ids)
    status_payload = AthenaAPIClient.get_simulation_status(selected_execution)
    if status_payload:
        st.json(status_payload)
else:
    st.info("No scenario executions recorded yet.")
