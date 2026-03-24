"""
ATHENA SOC Event Bus
Simulates real-time event streaming like SIEM platforms
"""

from __future__ import annotations

from queue import Queue
from typing import Any, Dict, List, Optional


class EventBus:

    def __init__(self):
        self.queue = Queue()

    def publish(self, event: Dict[str, Any]) -> None:
        event_name = event.get("event_name") or event.get("event_type") or event.get("event_id") or "unknown-event"
        payload = dict(event)
        payload.setdefault("event_name", str(event_name))
        self.queue.put(payload)
        print("Event published:", payload["event_name"])

    def publish_many(self, events: List[Dict[str, Any]]) -> None:
        for event in events:
            self.publish(event)

    def consume(self) -> Optional[Dict[str, Any]]:
        if not self.queue.empty():
            event = self.queue.get()
            print("Event consumed:", event["event_name"])
            return event
        return None

    def consume_all(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        while True:
            event = self.consume()
            if event is None:
                break
            events.append(event)
        return events


# global event bus instance
event_bus = EventBus()
