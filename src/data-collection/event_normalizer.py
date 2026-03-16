"""
ATHENA Event Normalizer
Converts simulated attack logs into structured security events
"""

import json
import psycopg2
from datetime import datetime


class EventNormalizer:

    def __init__(self):

        # Database connection
        self.conn = psycopg2.connect(
            host="localhost",
            database="athena_db",
            user="athena",
            password="athena_secure_password_2026",
            port="5432"
        )

        self.cursor = self.conn.cursor()

    def load_attack_chain(self):

        with open("../caldera-simulator/attack_chain.json") as f:
            data = json.load(f)

        return data

    def normalize_event(self, event):

        normalized = {
            "event_name": event["technique"],
            "timestamp": datetime.utcnow(),
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "event_type": event["tactic"],
            "severity": "high",
            "raw_data": json.dumps(event),
            "is_malicious": True
        }

        return normalized

    def insert_event(self, event):

        query = """
        INSERT INTO events
        (event_name, timestamp, source_ip, destination_ip, event_type, severity, raw_data, is_malicious)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """

        values = (
            event["event_name"],
            event["timestamp"],
            event["source_ip"],
            event["destination_ip"],
            event["event_type"],
            event["severity"],
            event["raw_data"],
            event["is_malicious"]
        )

        self.cursor.execute(query, values)
        self.conn.commit()

    def process_events(self):

        chain = self.load_attack_chain()

        for event in chain:

            normalized = self.normalize_event(event)

            self.insert_event(normalized)

            print("Inserted event:", normalized["event_name"])

    def close(self):

        self.cursor.close()
        self.conn.close()


if __name__ == "__main__":

    normalizer = EventNormalizer()

    normalizer.process_events()

    normalizer.close()

    print("\nAll events normalized and inserted into database.")