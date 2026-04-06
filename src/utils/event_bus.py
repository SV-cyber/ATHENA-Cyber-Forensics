"""
ATHENA SOC Event Bus
Simulates real-time event streaming like SIEM platforms
"""

from __future__ import annotations

import os
import socket
from queue import Queue
from typing import Any, Dict, List, Optional

import redis

from core.redis_stream import RedisStream
from utils.config import RedisConfig


class EventBus:

    def __init__(self):
        self.queue = Queue()
        self.redis_stream: Optional[RedisStream] = None
        self.stream_key = RedisConfig.STREAM_KEY
        self.consumer_group = RedisConfig.CONSUMER_GROUP
        self.consumer_name = f"{socket.gethostname()}-{os.getpid()}"
        self._connect_redis()

    def _connect_redis(self) -> None:
        try:
            stream = RedisStream(RedisConfig)
            stream.ping()
            stream.create_consumer_group(self.stream_key, self.consumer_group)
            self.redis_stream = stream
        except Exception:
            self.redis_stream = None

    @property
    def redis_enabled(self) -> bool:
        return self.redis_stream is not None

    def publish(self, event: Dict[str, Any]) -> None:
        event_name = event.get("event_name") or event.get("event_type") or event.get("event_id") or "unknown-event"
        payload = dict(event)
        payload.setdefault("event_name", str(event_name))
        if self.redis_enabled:
            try:
                assert self.redis_stream is not None
                self.redis_stream.publish(self.stream_key, payload)
                print("Event published:", payload["event_name"])
                return
            except Exception:
                self.redis_stream = None
        self.queue.put(payload)
        print("Event published:", payload["event_name"])

    def publish_many(self, events: List[Dict[str, Any]]) -> None:
        for event in events:
            self.publish(event)

    def consume(self) -> Optional[Dict[str, Any]]:
        if self.redis_enabled:
            try:
                assert self.redis_stream is not None
                events = self.redis_stream.consume(
                    self.stream_key,
                    self.consumer_group,
                    self.consumer_name,
                    batch_size=1,
                )
                if events:
                    event = events[0]
                    print("Event consumed:", event.get("event_name", "unknown-event"))
                    return event
                return None
            except Exception:
                self.redis_stream = None
        if not self.queue.empty():
            event = self.queue.get()
            print("Event consumed:", event["event_name"])
            return event
        return None

    def consume_all(self) -> List[Dict[str, Any]]:
        if self.redis_enabled:
            try:
                assert self.redis_stream is not None
                events: List[Dict[str, Any]] = []
                while True:
                    batch = self.redis_stream.consume(
                        self.stream_key,
                        self.consumer_group,
                        self.consumer_name,
                        batch_size=10,
                    )
                    if not batch:
                        break
                    for event in batch:
                        print("Event consumed:", event.get("event_name", "unknown-event"))
                    events.extend(batch)
                    if len(batch) < 10:
                        break
                return events
            except Exception:
                self.redis_stream = None
        events: List[Dict[str, Any]] = []
        while True:
            event = self.consume()
            if event is None:
                break
            events.append(event)
        return events

    def ack(self, event: Dict[str, Any] | str | None) -> bool:
        if not self.redis_enabled or event is None:
            return True
        event_id = event if isinstance(event, str) else event.get("_redis_event_id")
        if not event_id:
            return True
        try:
            assert self.redis_stream is not None
            return bool(self.redis_stream.ack(self.stream_key, self.consumer_group, str(event_id)))
        except Exception:
            return False

    def claim_pending(self, *, min_idle_time_ms: int = 60000, batch_size: int = 10) -> List[Dict[str, Any]]:
        if not self.redis_enabled:
            return []
        try:
            assert self.redis_stream is not None
            return self.redis_stream.claim_pending(
                self.stream_key,
                self.consumer_group,
                self.consumer_name,
                min_idle_time_ms=min_idle_time_ms,
                batch_size=batch_size,
            )
        except (redis.exceptions.RedisError, OSError):
            return []

    def health_info(self) -> Dict[str, Any]:
        if not self.redis_enabled:
            return {
                "status": "fallback",
                "backend": "in_memory_queue",
                "stream_key": self.stream_key,
                "consumer_group": self.consumer_group,
            }
        try:
            assert self.redis_stream is not None
            info = self.redis_stream.stream_info(self.stream_key)
            info.update(
                {
                    "status": "ok",
                    "backend": "redis_streams",
                    "consumer_group": self.consumer_group,
                    "consumer_name": self.consumer_name,
                }
            )
            return info
        except Exception as exc:
            return {
                "status": "error",
                "backend": "redis_streams",
                "stream_key": self.stream_key,
                "consumer_group": self.consumer_group,
                "error": str(exc),
            }


# global event bus instance
event_bus = EventBus()
