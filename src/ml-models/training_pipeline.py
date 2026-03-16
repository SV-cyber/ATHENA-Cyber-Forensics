"""
ATHENA ML Training Pipeline
Trains attack detection model using events from database
"""

import psycopg2
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score


class TrainingPipeline:

    def __init__(self):

        self.conn = psycopg2.connect(
            host="localhost",
            database="athena_db",
            user="athena",
            password="athena_secure_password_2026",
            port="5432"
        )

    def load_events(self):

        query = "SELECT event_name, event_type, severity, is_malicious FROM events"

        df = pd.read_sql(query, self.conn)

        return df

    def preprocess(self, df):

        df["severity"] = df["severity"].map({
            "low":0,
            "medium":1,
            "high":2
        })

        df["event_type"] = df["event_type"].astype("category").cat.codes
        df["event_name"] = df["event_name"].astype("category").cat.codes

        return df

    def train_model(self, df):

        X = df[["event_name","event_type","severity"]]
        y = df["is_malicious"]

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2
        )

        model = RandomForestClassifier()

        model.fit(X_train, y_train)

        predictions = model.predict(X_test)

        accuracy = accuracy_score(y_test, predictions)

        print("Model Accuracy:", accuracy)

        return model


if __name__ == "__main__":

    pipeline = TrainingPipeline()

    df = pipeline.load_events()

    df = pipeline.preprocess(df)

    model = pipeline.train_model(df)