"""
ATHENA SOC Event Bus
Simulates real-time event streaming like SIEM platforms
"""

from queue import Queue


class EventBus:

    def __init__(self):
        self.queue = Queue()

    def publish(self, event):

        self.queue.put(event)

        print("Event published:", event["event_name"])

    def consume(self):

        if not self.queue.empty():

            event = self.queue.get()

            print("Event consumed:", event["event_name"])

            return event

        return None


# global event bus instance
event_bus = EventBus()