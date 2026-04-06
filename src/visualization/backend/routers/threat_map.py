from __future__ import annotations

import math
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..dependencies import get_db
from ..services.geo_service import geo_service
from utils.database import Alert


router = APIRouter(tags=["threat-map"])
THREAT_TYPES = [
    "CVE-2025-1974 Exchange RCE",
    "Versa.Conductor.Auth.Bypass",
    "Akira Ransomware",
    "Lumma Stealer",
    "PlugX RAT Activity",
    "APT29 Credential Harvesting",
    "Mirai Variant Scanning",
    "CVE-2024-3400 Exploit",
    "XWorm Loader",
    "RedLine Credential Theft",
]
INDUSTRIES = ["Finance", "Healthcare", "Government", "Manufacturing", "Technology", "Energy", "Telecom", "Retail"]
DEMO_PAIRS = [
    ("China", "United States"),
    ("Russia", "Germany"),
    ("Brazil", "United Kingdom"),
    ("India", "United States"),
    ("Singapore", "Australia"),
    ("United States", "Japan"),
    ("South Korea", "United States"),
    ("United Arab Emirates", "Germany"),
    ("Turkey", "France"),
    ("Netherlands", "Canada"),
]
SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _range_to_delta(time_range: str) -> timedelta:
    mapping = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7)}
    return mapping.get(time_range, timedelta(hours=24))


def _severity_color(severity: str) -> str:
    return {"critical": "#ff3b30", "high": "#ff9500", "medium": "#ffd60a"}.get(severity, "#7dd3fc")


def _industry_for_alert(alert: Alert) -> str:
    event_type = str(alert.event_type or "").lower()
    if "rdp" in event_type or "brute" in event_type:
        return "Government"
    if "phishing" in event_type or "credential" in event_type:
        return "Finance"
    if "web" in event_type or "cloud" in event_type:
        return "Technology"
    if "exfil" in event_type:
        return "Healthcare"
    if "build" in event_type:
        return "Manufacturing"
    return INDUSTRIES[abs(hash(event_type or "generic")) % len(INDUSTRIES)]


def _threat_name_for_alert(alert: Alert) -> str:
    event_type = str(alert.event_type or "").lower()
    if "rdp" in event_type:
        return "RDP Password Spray"
    if "credential" in event_type or "brute" in event_type:
        return "CVE-2025-1974 Exchange RCE"
    if "phishing" in event_type:
        return "Lumma Stealer"
    if "exfil" in event_type:
        return "APT29 Credential Harvesting"
    if "powershell" in event_type:
        return "Versa.Conductor.Auth.Bypass"
    return THREAT_TYPES[abs(hash(event_type or "threat")) % len(THREAT_TYPES)]


def _target_country_for_alert(alert: Alert, source_country: str) -> str:
    event_type = str(alert.event_type or "").lower()
    pairs = {
        "rdp": "Germany",
        "brute": "United States",
        "phishing": "United Kingdom",
        "exfil": "Japan",
        "cloud": "Singapore",
        "web": "France",
        "build": "Canada",
    }
    for key, value in pairs.items():
        if key in event_type and value != source_country:
            return value
    for _, target in DEMO_PAIRS:
        if target != source_country:
            return target
    return "United States"


def _load_real_attacks(db: Session, *, time_range: str) -> List[Dict[str, Any]]:
    since = datetime.now(timezone.utc) - _range_to_delta(time_range)
    alerts = (
        db.query(Alert)
        .filter(Alert.timestamp >= since)
        .order_by(Alert.timestamp.desc(), Alert.id.desc())
        .all()
    )
    ips = [str(alert.source_ip) for alert in alerts if alert.source_ip]
    geo_lookup = geo_service.batch_resolve(ips)

    attacks: List[Dict[str, Any]] = []
    for alert in alerts:
        if not alert.source_ip:
            continue
        source_geo = geo_lookup.get(str(alert.source_ip))
        if source_geo is None:
            continue
        target_country = _target_country_for_alert(alert, source_geo["country"])
        pair = geo_service.get_country_pair(source_geo["country"], target_country)
        if pair is None:
            continue
        attacks.append(
            {
                "alert_id": alert.alert_id,
                "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
                "source_ip": str(alert.source_ip),
                "source_country": pair["source"]["country"],
                "source_country_code": pair["source"]["country_code"],
                "source_city": source_geo.get("city") or pair["source"]["city"],
                "source_latitude": pair["source"]["latitude"],
                "source_longitude": pair["source"]["longitude"],
                "target_country": pair["target"]["country"],
                "target_country_code": pair["target"]["country_code"],
                "target_city": pair["target"]["city"],
                "target_latitude": pair["target"]["latitude"],
                "target_longitude": pair["target"]["longitude"],
                "severity": str(alert.severity or "medium"),
                "count": int(alert.duplicate_count or 1),
                "event_type": alert.event_type,
                "threat_name": _threat_name_for_alert(alert),
                "industry": _industry_for_alert(alert),
                "status": alert.status,
            }
        )
    return attacks


def _generate_demo_attacks(*, time_range: str, count: int = 60) -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    delta = _range_to_delta(time_range)
    rng = random.Random(f"threat-map-demo-{time_range}-{now.strftime('%Y%m%d%H')}")
    attacks: List[Dict[str, Any]] = []

    for idx in range(count):
        source_country, target_country = DEMO_PAIRS[idx % len(DEMO_PAIRS)]
        pair = geo_service.get_country_pair(source_country, target_country)
        if pair is None:
            continue
        age_seconds = rng.randint(0, max(60, int(delta.total_seconds())))
        timestamp = now - timedelta(seconds=age_seconds)
        severity = rng.choices(["critical", "high", "medium"], weights=[2, 5, 3], k=1)[0]
        threat_name = rng.choice(THREAT_TYPES)
        industry = rng.choice(INDUSTRIES)
        count_value = rng.randint(5, 240)
        attacks.append(
            {
                "alert_id": f"DEMO-{idx:03d}",
                "timestamp": timestamp.isoformat(),
                "source_ip": f"203.0.113.{(idx % 200) + 1}",
                "source_country": pair["source"]["country"],
                "source_country_code": pair["source"]["country_code"],
                "source_city": pair["source"]["city"],
                "source_latitude": pair["source"]["latitude"],
                "source_longitude": pair["source"]["longitude"],
                "target_country": pair["target"]["country"],
                "target_country_code": pair["target"]["country_code"],
                "target_city": pair["target"]["city"],
                "target_latitude": pair["target"]["latitude"],
                "target_longitude": pair["target"]["longitude"],
                "severity": severity,
                "count": count_value,
                "event_type": threat_name.lower().replace(" ", "_"),
                "threat_name": threat_name,
                "industry": industry,
                "status": "active",
            }
        )
    return attacks


def _get_attack_records(db: Session, *, time_range: str, country: Optional[str]) -> List[Dict[str, Any]]:
    real_attacks = _load_real_attacks(db, time_range=time_range)
    demo_target = 70 if len(real_attacks) < 20 else 35
    attacks = real_attacks + _generate_demo_attacks(time_range=time_range, count=demo_target)

    if country:
        country_lower = country.lower()
        attacks = [
            item
            for item in attacks
            if country_lower in str(item.get("source_country", "")).lower()
            or country_lower in str(item.get("target_country", "")).lower()
        ]

    attacks.sort(key=lambda item: item.get("timestamp") or "", reverse=True)
    return attacks


def _aggregate_flows(attacks: List[Dict[str, Any]], limit: int = 80) -> List[Dict[str, Any]]:
    flows: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for attack in attacks:
        key = (str(attack["source_country"]), str(attack["target_country"]), str(attack["severity"]))
        row = flows.setdefault(
            key,
            {
                "source_country": attack["source_country"],
                "source_country_code": attack["source_country_code"],
                "source_city": attack["source_city"],
                "source_latitude": attack["source_latitude"],
                "source_longitude": attack["source_longitude"],
                "target_country": attack["target_country"],
                "target_country_code": attack["target_country_code"],
                "target_city": attack["target_city"],
                "target_latitude": attack["target_latitude"],
                "target_longitude": attack["target_longitude"],
                "count": 0,
                "severity": attack["severity"],
                "latest_timestamp": attack["timestamp"],
                "threat_names": set(),
                "industries": set(),
            },
        )
        row["count"] += int(attack.get("count", 1))
        if str(attack["timestamp"]) > str(row["latest_timestamp"]):
            row["latest_timestamp"] = attack["timestamp"]
        row["threat_names"].add(str(attack["threat_name"]))
        row["industries"].add(str(attack["industry"]))

    flow_list: List[Dict[str, Any]] = []
    for item in flows.values():
        threats = sorted(item.pop("threat_names"))
        industries = sorted(item.pop("industries"))
        item["severity_color"] = _severity_color(item["severity"])
        item["line_width"] = min(10, 1.5 + math.log(max(item["count"], 1), 2))
        item["threat_name"] = threats[0] if threats else "Unknown Threat"
        item["industry"] = industries[0] if industries else "Unknown"
        flow_list.append(item)

    flow_list.sort(key=lambda entry: (SEVERITY_ORDER.get(entry["severity"], 0), entry["count"]), reverse=True)
    return flow_list[:limit]


def _country_breakdown(attacks: List[Dict[str, Any]], key: str) -> List[Dict[str, Any]]:
    stats: Dict[str, Dict[str, Any]] = {}
    for attack in attacks:
        country = str(attack.get(key) or "Unknown")
        row = stats.setdefault(country, {"country": country, "count": 0})
        row["count"] += int(attack.get("count", 1))
    return sorted(stats.values(), key=lambda item: item["count"], reverse=True)


@router.get("/threat-map/live-attacks")
def live_attacks(
    time_range: str = Query(default="24h"),
    country: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    attacks = _get_attack_records(db, time_range=time_range, country=country)
    recent = [item for item in attacks if item["severity"] in {"high", "critical"}][:50]
    return {"count": len(recent), "data": recent, "geo_status": geo_service.status()}


@router.get("/threat-map/attack-flows")
def attack_flows(
    time_range: str = Query(default="24h"),
    country: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    attacks = _get_attack_records(db, time_range=time_range, country=country)
    flows = _aggregate_flows(attacks, limit=80)
    leaderboard = _country_breakdown(attacks, "target_country")
    return {
        "count": len(flows),
        "data": flows,
        "top_sources": _country_breakdown(attacks, "source_country")[:10],
        "top_targets": _country_breakdown(attacks, "target_country")[:10],
        "leaderboard": leaderboard,
        "geo_status": geo_service.status(),
    }


@router.get("/threat-map/top-threats")
def top_threats(
    time_range: str = Query(default="24h"),
    country: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    attacks = _get_attack_records(db, time_range=time_range, country=country)
    stats: Dict[str, int] = {}
    for attack in attacks:
        name = str(attack["threat_name"])
        stats[name] = stats.get(name, 0) + int(attack["count"])
    data = [{"threat_name": key, "count": value} for key, value in sorted(stats.items(), key=lambda item: item[1], reverse=True)[:10]]
    return {"count": len(data), "data": data}


@router.get("/threat-map/top-industries")
def top_industries(
    time_range: str = Query(default="24h"),
    country: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    attacks = _get_attack_records(db, time_range=time_range, country=country)
    stats: Dict[str, int] = {}
    for attack in attacks:
        industry = str(attack["industry"])
        stats[industry] = stats.get(industry, 0) + int(attack["count"])
    data = [{"industry": key, "count": value} for key, value in sorted(stats.items(), key=lambda item: item[1], reverse=True)[:8]]
    return {"count": len(data), "data": data}


@router.get("/threat-map/live-feed")
def live_feed(
    time_range: str = Query(default="24h"),
    country: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    attacks = _get_attack_records(db, time_range=time_range, country=country)
    return {"count": min(len(attacks), 20), "data": attacks[:20]}


@router.get("/threat-map/stats")
def threat_map_stats(
    time_range: str = Query(default="24h"),
    country: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    attacks = _get_attack_records(db, time_range=time_range, country=country)
    countries = _country_breakdown(attacks, "target_country")
    critical_alerts = sum(1 for attack in attacks if attack["severity"] == "critical")
    return {
        "total_attacks": sum(int(item["count"]) for item in attacks),
        "countries_affected": len(countries),
        "critical_alerts": critical_alerts,
        "countries": countries[:20],
        "top_sources": _country_breakdown(attacks, "source_country")[:8],
        "top_targets": countries[:8],
        "geo_status": geo_service.status(),
    }


@router.get("/threat-map/timeline")
def threat_map_timeline(
    time_range: str = Query(default="24h"),
    country: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    attacks = _get_attack_records(db, time_range=time_range, country=country)
    timeline = [
        {
            "alert_id": item["alert_id"],
            "timestamp": item["timestamp"],
            "source_country": item["source_country"],
            "target_country": item["target_country"],
            "source_ip": item["source_ip"],
            "severity": item["severity"],
            "threat_name": item["threat_name"],
            "industry": item["industry"],
            "count": item["count"],
        }
        for item in attacks[:200]
    ]
    return {"count": len(timeline), "data": timeline}
