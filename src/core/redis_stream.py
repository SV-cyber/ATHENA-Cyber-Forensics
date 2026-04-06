from __future__ import annotations

import json
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Dict, List

import redis


class RedisStream:
    def __init__(self, config: Any):
        self.config = config
        self.client = redis.Redis(
            host=config.HOST,
            port=config.PORT,
            db=config.DB,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=5,
        )

    def ping(self) -> bool:
        return bool(self.client.ping())

    def publish(self, stream: str, event: Dict[str, Any]) -> str:
        payload = dict(event)
        event_name = payload.get("event_name") or payload.get("event_type") or payload.get("event_id") or "unknown-event"
        payload.setdefault("event_name", str(event_name))
        fields = {
            "event_name": str(payload["event_name"]),
            "event_id": str(payload.get("event_id") or ""),
            "timestamp": str(payload.get("timestamp") or ""),
            "payload": json.dumps(payload, default=_json_default),
        }
        return str(self.client.xadd(stream, fields))

    def consume(
        self,
        stream: str,
        consumer_group: str,
        consumer_name: str,
        batch_size: int = 10,
    ) -> List[Dict[str, Any]]:
        self.create_consumer_group(stream, consumer_group)
        entries = self.client.xreadgroup(
            groupname=consumer_group,
            consumername=consumer_name,
            streams={stream: ">"},
            count=batch_size,
            block=1000,
        )
        return _decode_entries(entries)

    def ack(self, stream: str, consumer_group: str, event_id: str) -> int:
        return int(self.client.xack(stream, consumer_group, event_id))

    def create_consumer_group(self, stream: str, consumer_group: str) -> None:
        try:
            self.client.xgroup_create(name=stream, groupname=consumer_group, id="0", mkstream=True)
        except redis.exceptions.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def claim_pending(
        self,
        stream: str,
        consumer_group: str,
        consumer_name: str,
        *,
        min_idle_time_ms: int = 60000,
        batch_size: int = 10,
    ) -> List[Dict[str, Any]]:
        self.create_consumer_group(stream, consumer_group)
        _, entries, _ = self.client.xautoclaim(
            name=stream,
            groupname=consumer_group,
            consumername=consumer_name,
            min_idle_time=min_idle_time_ms,
            start_id="0-0",
            count=batch_size,
        )
        return _decode_claimed_entries(entries)

    def stream_info(self, stream: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "stream": stream,
            "length": int(self.client.xlen(stream)),
            "groups": [],
        }
        try:
            groups = self.client.xinfo_groups(stream)
        except redis.exceptions.ResponseError:
            groups = []
        for group in groups:
            info["groups"].append(
                {
                    "name": group.get("name"),
                    "consumers": int(group.get("consumers", 0) or 0),
                    "pending": int(group.get("pending", 0) or 0),
                    "last_delivered_id": group.get("last-delivered-id"),
                }
            )
        return info


def _decode_entries(entries: List[Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for _, stream_entries in entries:
        for entry_id, fields in stream_entries:
            payload = _decode_payload(fields)
            payload["_redis_event_id"] = str(entry_id)
            events.append(payload)
    return events


def _decode_claimed_entries(entries: List[Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for entry_id, fields in entries:
        payload = _decode_payload(fields)
        payload["_redis_event_id"] = str(entry_id)
        events.append(payload)
    return events


def _decode_payload(fields: Dict[str, Any]) -> Dict[str, Any]:
    raw_payload = fields.get("payload")
    if raw_payload:
        payload = json.loads(raw_payload)
        if isinstance(payload, dict):
            return payload
    return {key: value for key, value in fields.items() if key != "payload"}


def _json_default(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    return str(value)
