from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from simulation.mitre_mapper import MITREAttackMapper


TACTIC_ENCODING = {
    "Reconnaissance": 0,
    "Initial Access": 1,
    "Execution": 2,
    "Persistence": 3,
    "Privilege Escalation": 4,
    "Defense Evasion": 5,
    "Credential Access": 6,
    "Discovery": 7,
    "Lateral Movement": 8,
    "Collection": 9,
    "Exfiltration": 10,
    "Impact": 11,
}
SEVERITY_ENCODING = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(frozen=True)
class ScenarioDefinition:
    key: str
    name: str
    description: str
    mitre_chain: List[Dict[str, Any]]

    def generate_events(self, mapper: MITREAttackMapper, *, execution_id: Optional[str] = None) -> List[Dict[str, Any]]:
        base_timestamp = datetime.now(timezone.utc)
        source_ip = self._source_ip()
        destination_ip = self._destination_ip()
        hostname = self._hostname()

        mapped_chain = mapper.map_attack_chain(self.mitre_chain)
        events: List[Dict[str, Any]] = []
        for idx, step in enumerate(mapped_chain, start=1):
            timestamp = base_timestamp + timedelta(seconds=idx * 45)
            event = {
                "event_id": str(uuid.uuid4()),
                "event_name": step["technique_name"],
                "timestamp": timestamp,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "event_type": step["event_type"],
                "tactic": step["tactic"],
                "technique_id": step["technique_id"],
                "severity": step["severity"],
                "is_malicious": True,
                "tactic_encoded": TACTIC_ENCODING.get(step["tactic"], -1),
                "severity_encoded": SEVERITY_ENCODING.get(step["severity"], 1),
                "mcdm_score": step.get("mcdm_score", 0.8),
                "threat_actor": self.name,
                "threat_feed_hit": False,
                "raw_data": {
                    **step,
                    "scenario_key": self.key,
                    "scenario_name": self.name,
                    "execution_id": execution_id,
                    "hostname": hostname,
                    "message": f"{self.name} simulated step {idx}: {step['technique_name']}",
                },
            }
            events.append(event)
        return events

    def _source_ip(self) -> str:
        ip_map = {
            "ransomware-attack-chain": "10.10.20.15",
            "apt-lateral-movement": "10.20.30.44",
            "web-application-breach": "172.16.10.21",
            "insider-data-theft": "192.168.50.12",
            "supply-chain-attack": "10.30.40.18",
        }
        return ip_map.get(self.key, "10.0.0.10")

    def _destination_ip(self) -> str:
        ip_map = {
            "ransomware-attack-chain": "10.10.20.99",
            "apt-lateral-movement": "10.20.30.88",
            "web-application-breach": "172.16.10.80",
            "insider-data-theft": "192.168.50.200",
            "supply-chain-attack": "10.30.40.220",
        }
        return ip_map.get(self.key, "10.0.0.99")

    def _hostname(self) -> str:
        host_map = {
            "ransomware-attack-chain": "FIN-WS-01",
            "apt-lateral-movement": "ENG-SRV-02",
            "web-application-breach": "WEB-APP-01",
            "insider-data-theft": "HR-LT-07",
            "supply-chain-attack": "CI-BUILD-03",
        }
        return host_map.get(self.key, "SIM-HOST-01")


class ScenarioLibrary:
    SCENARIOS: Dict[str, ScenarioDefinition] = {
        "ransomware-attack-chain": ScenarioDefinition(
            key="ransomware-attack-chain",
            name="Ransomware Attack Chain",
            description="Phishing-led intrusion that establishes persistence and encrypts data for impact.",
            mitre_chain=[
                {"tactic": "Initial Access", "technique_id": "T1566.001", "technique_name": "Phishing: Spearphishing Attachment", "event_type": "phishing_attachment", "severity": "high"},
                {"tactic": "Execution", "technique_id": "T1059.001", "technique_name": "Command and Scripting Interpreter: PowerShell", "event_type": "powershell_execution", "severity": "high"},
                {"tactic": "Persistence", "technique_id": "T1547.001", "technique_name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "event_type": "registry_run_keys", "severity": "high"},
                {"tactic": "Impact", "technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "event_type": "data_encrypted", "severity": "critical"},
            ],
        ),
        "apt-lateral-movement": ScenarioDefinition(
            key="apt-lateral-movement",
            name="APT Lateral Movement",
            description="An operator scans internally, brute-forces access, moves laterally, collects, and exfiltrates data.",
            mitre_chain=[
                {"tactic": "Discovery", "technique_id": "T1046", "technique_name": "Network Service Scanning", "event_type": "network_scanning", "severity": "medium"},
                {"tactic": "Credential Access", "technique_id": "T1110", "technique_name": "Brute Force", "event_type": "brute_force", "severity": "high"},
                {"tactic": "Lateral Movement", "technique_id": "T1021.001", "technique_name": "Remote Services: Remote Desktop Protocol", "event_type": "rdp_lateral_movement", "severity": "high"},
                {"tactic": "Collection", "technique_id": "T1005", "technique_name": "Data from Local System", "event_type": "local_data_collection", "severity": "medium"},
                {"tactic": "Exfiltration", "technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel", "event_type": "exfiltration_c2", "severity": "critical"},
            ],
        ),
        "web-application-breach": ScenarioDefinition(
            key="web-application-breach",
            name="Web Application Breach",
            description="A public-facing application exploit leads to execution, cleanup, collection, and web-based exfiltration.",
            mitre_chain=[
                {"tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "event_type": "web_exploit", "severity": "high"},
                {"tactic": "Execution", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "event_type": "shell_execution", "severity": "high"},
                {"tactic": "Defense Evasion", "technique_id": "T1070", "technique_name": "Indicator Removal on Host", "event_type": "indicator_removal", "severity": "high"},
                {"tactic": "Collection", "technique_id": "T1119", "technique_name": "Automated Collection", "event_type": "automated_collection", "severity": "medium"},
                {"tactic": "Exfiltration", "technique_id": "T1567", "technique_name": "Exfiltration to Cloud Storage", "event_type": "web_exfiltration", "severity": "critical"},
            ],
        ),
        "insider-data-theft": ScenarioDefinition(
            key="insider-data-theft",
            name="Insider Data Theft",
            description="A trusted user harvests credentials, automates collection, and exfiltrates data over an alternate channel.",
            mitre_chain=[
                {"tactic": "Credential Access", "technique_id": "T1003", "technique_name": "OS Credential Dumping", "event_type": "credential_dumping", "severity": "high"},
                {"tactic": "Collection", "technique_id": "T1119", "technique_name": "Automated Collection", "event_type": "automated_collection", "severity": "medium"},
                {"tactic": "Exfiltration", "technique_id": "T1048", "technique_name": "Exfiltration Over Alternative Protocol", "event_type": "alt_protocol_exfiltration", "severity": "critical"},
            ],
        ),
        "supply-chain-attack": ScenarioDefinition(
            key="supply-chain-attack",
            name="Supply Chain Attack",
            description="A compromised dependency executes, hijacks execution flow, and stages exfiltration from the build pipeline.",
            mitre_chain=[
                {"tactic": "Initial Access", "technique_id": "T1195.001", "technique_name": "Compromise Software Dependencies and Development Tools", "event_type": "compromised_dependency", "severity": "high"},
                {"tactic": "Execution", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "event_type": "malicious_build_execution", "severity": "high"},
                {"tactic": "Persistence", "technique_id": "T1574", "technique_name": "Hijack Execution Flow", "event_type": "execution_flow_hijack", "severity": "high"},
                {"tactic": "Exfiltration", "technique_id": "T1048", "technique_name": "Exfiltration Over Alternative Protocol", "event_type": "build_exfiltration", "severity": "critical"},
            ],
        ),
    }

    def __init__(self):
        self.mapper = MITREAttackMapper()

    def list_scenarios(self) -> List[Dict[str, Any]]:
        scenarios: List[Dict[str, Any]] = []
        for scenario in self.SCENARIOS.values():
            scenarios.append(
                {
                    "key": scenario.key,
                    "name": scenario.name,
                    "description": scenario.description,
                    "mitre_chain": self.mapper.map_attack_chain(scenario.mitre_chain),
                }
            )
        return scenarios

    def get_scenario(self, scenario_name: str) -> Optional[ScenarioDefinition]:
        return self.SCENARIOS.get(scenario_name)

    def generate_events(self, scenario_name: str, *, execution_id: Optional[str] = None) -> List[Dict[str, Any]]:
        scenario = self.get_scenario(scenario_name)
        if scenario is None:
            raise KeyError(f"Unknown scenario: {scenario_name}")
        return scenario.generate_events(self.mapper, execution_id=execution_id)

    def sync_to_db(self, session: Any) -> None:
        from utils.database import AttackScenario

        for scenario in self.SCENARIOS.values():
            first_step = scenario.mitre_chain[0]
            row = session.query(AttackScenario).filter(AttackScenario.scenario_name == scenario.name).one_or_none()
            if row is None:
                row = AttackScenario(
                    scenario_name=scenario.name,
                    mitre_tactic=first_step["tactic"],
                    mitre_technique=first_step["technique_name"],
                    description=scenario.description,
                )
            else:
                row.mitre_tactic = first_step["tactic"]
                row.mitre_technique = first_step["technique_name"]
                row.description = scenario.description
            session.add(row)
