from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import redis

from intel.geoip import GeoIPResolver
from utils.config import RedisConfig


class GeoService:
    def __init__(self):
        self.resolver = GeoIPResolver()
        self.redis_client: Optional[redis.Redis] = None
        try:
            self.redis_client = redis.Redis(
                host=RedisConfig.HOST,
                port=RedisConfig.PORT,
                db=RedisConfig.DB,
                decode_responses=True,
                socket_connect_timeout=1,
                socket_timeout=3,
            )
            self.redis_client.ping()
        except Exception:
            self.redis_client = None

    def resolve_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        cache_key = f"geoip:{ip}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        resolved = self.resolver.resolve_ip(ip)
        if resolved is not None:
            self._cache_set(cache_key, resolved)
        return resolved

    def batch_resolve(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        results: Dict[str, Dict[str, Any]] = {}
        missing: List[str] = []

        for ip in ips:
            cached = self._cache_get(f"geoip:{ip}")
            if cached is not None:
                results[ip] = cached
            else:
                missing.append(ip)

        if missing:
            resolved = self.resolver.batch_resolve(missing)
            for ip, payload in resolved.items():
                results[ip] = payload
                self._cache_set(f"geoip:{ip}", payload)

        return results

    def resolve_country(self, *, country_name: Optional[str] = None, country_code: Optional[str] = None) -> Optional[Dict[str, Any]]:
        cache_suffix = country_code or country_name
        if not cache_suffix:
            return None
        cache_key = f"geoip:country:{str(cache_suffix).upper()}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        resolved = self.resolver.resolve_country(country_name=country_name, country_code=country_code)
        if resolved is not None:
            self._cache_set(cache_key, resolved)
        return resolved

    def get_country_pair(self, source_country: str, target_country: str) -> Optional[Dict[str, Any]]:
        cache_key = f"geoip:country_pair:{source_country.upper()}:{target_country.upper()}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        pair = self.resolver.country_pair(source_country, target_country)
        if pair is not None:
            self._cache_set(cache_key, pair)
        return pair

    def status(self) -> Dict[str, Any]:
        return {
            "redis_cache_enabled": self.redis_client is not None,
            **self.resolver.status(),
        }

    def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        if self.redis_client is None:
            return None
        raw = self.redis_client.get(key)
        if not raw:
            return None
        return json.loads(raw)

    def _cache_set(self, key: str, value: Dict[str, Any], ttl_seconds: int = 86400) -> None:
        if self.redis_client is None:
            return
        self.redis_client.setex(key, ttl_seconds, json.dumps(value))


geo_service = GeoService()
