from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import geoip2.database
    from geoip2.errors import AddressNotFoundError
except ModuleNotFoundError:  # pragma: no cover
    geoip2 = None  # type: ignore[assignment]
    AddressNotFoundError = Exception  # type: ignore[assignment]


COUNTRY_CENTERS: Dict[str, Dict[str, Any]] = {
    "US": {"country": "United States", "city": "Washington", "latitude": 38.9072, "longitude": -77.0369},
    "CN": {"country": "China", "city": "Beijing", "latitude": 39.9042, "longitude": 116.4074},
    "RU": {"country": "Russia", "city": "Moscow", "latitude": 55.7558, "longitude": 37.6173},
    "DE": {"country": "Germany", "city": "Frankfurt", "latitude": 50.1109, "longitude": 8.6821},
    "IN": {"country": "India", "city": "Mumbai", "latitude": 19.0760, "longitude": 72.8777},
    "SG": {"country": "Singapore", "city": "Singapore", "latitude": 1.3521, "longitude": 103.8198},
    "BR": {"country": "Brazil", "city": "Sao Paulo", "latitude": -23.5505, "longitude": -46.6333},
    "GB": {"country": "United Kingdom", "city": "London", "latitude": 51.5072, "longitude": -0.1276},
    "JP": {"country": "Japan", "city": "Tokyo", "latitude": 35.6762, "longitude": 139.6503},
    "KR": {"country": "South Korea", "city": "Seoul", "latitude": 37.5665, "longitude": 126.9780},
    "AU": {"country": "Australia", "city": "Sydney", "latitude": -33.8688, "longitude": 151.2093},
    "CA": {"country": "Canada", "city": "Toronto", "latitude": 43.6532, "longitude": -79.3832},
    "FR": {"country": "France", "city": "Paris", "latitude": 48.8566, "longitude": 2.3522},
    "NL": {"country": "Netherlands", "city": "Amsterdam", "latitude": 52.3676, "longitude": 4.9041},
    "AE": {"country": "United Arab Emirates", "city": "Dubai", "latitude": 25.2048, "longitude": 55.2708},
    "SA": {"country": "Saudi Arabia", "city": "Riyadh", "latitude": 24.7136, "longitude": 46.6753},
    "TR": {"country": "Turkey", "city": "Istanbul", "latitude": 41.0082, "longitude": 28.9784},
    "ZA": {"country": "South Africa", "city": "Johannesburg", "latitude": -26.2041, "longitude": 28.0473},
    "SE": {"country": "Sweden", "city": "Stockholm", "latitude": 59.3293, "longitude": 18.0686},
    "CH": {"country": "Switzerland", "city": "Zurich", "latitude": 47.3769, "longitude": 8.5417},
}

COUNTRY_NAME_TO_ISO: Dict[str, str] = {value["country"]: code for code, value in COUNTRY_CENTERS.items()}
SIMULATED_LOCATIONS: List[Dict[str, Any]] = list(COUNTRY_CENTERS.values())


class GeoIPResolver:
    def __init__(self, db_path: Optional[str] = None):
        configured_path = db_path or os.getenv("GEOIP_DB_PATH") or "data/GeoLite2-City.mmdb"
        self.db_path = Path(configured_path)
        self.reader: Optional[Any] = None
        if geoip2 is not None and self.db_path.exists():
            self.reader = geoip2.database.Reader(str(self.db_path))

    def resolve_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = ipaddress.ip_address(str(ip))
        except ValueError:
            return None

        if parsed.is_private:
            return self._resolve_private_ip(str(parsed))

        if self.reader is None:
            return None

        try:
            record = self.reader.city(str(parsed))
        except AddressNotFoundError:
            return None

        country_meta = self.resolve_country(country_name=record.country.name, country_code=record.country.iso_code)
        if country_meta is None:
            return None

        return {
            "ip": str(parsed),
            "country": country_meta["country"],
            "country_code": country_meta["country_code"],
            "city": record.city.name or country_meta["city"],
            "latitude": record.location.latitude or country_meta["latitude"],
            "longitude": record.location.longitude or country_meta["longitude"],
        }

    def batch_resolve(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        results: Dict[str, Dict[str, Any]] = {}
        for ip in ips:
            resolved = self.resolve_ip(ip)
            if resolved is not None:
                results[ip] = resolved
        return results

    def resolve_country(self, country_name: Optional[str] = None, country_code: Optional[str] = None) -> Optional[Dict[str, Any]]:
        code = (country_code or "").upper().strip()
        if not code and country_name:
            code = COUNTRY_NAME_TO_ISO.get(str(country_name).strip(), "")
        if not code:
            return None
        meta = COUNTRY_CENTERS.get(code)
        if meta is None:
            return None
        return {
            "country": meta["country"],
            "country_code": code,
            "city": meta["city"],
            "latitude": meta["latitude"],
            "longitude": meta["longitude"],
        }

    def country_pair(self, source_country: str, target_country: str) -> Optional[Dict[str, Any]]:
        source = self.resolve_country(country_name=source_country) or self.resolve_country(country_code=source_country)
        target = self.resolve_country(country_name=target_country) or self.resolve_country(country_code=target_country)
        if source is None or target is None:
            return None
        return {"source": source, "target": target}

    def status(self) -> Dict[str, Any]:
        return {
            "db_path": str(self.db_path),
            "database_loaded": self.reader is not None,
            "geoip2_installed": geoip2 is not None,
            "maxmind_license_key_configured": bool(os.getenv("MAXMIND_LICENSE_KEY")),
            "country_center_count": len(COUNTRY_CENTERS),
        }

    def _resolve_private_ip(self, ip: str) -> Dict[str, Any]:
        location = SIMULATED_LOCATIONS[sum(ord(char) for char in ip) % len(SIMULATED_LOCATIONS)]
        country_code = COUNTRY_NAME_TO_ISO.get(location["country"])
        return {"ip": ip, "country_code": country_code, **location, "simulated": True}
