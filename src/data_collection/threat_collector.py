import requests
import pandas as pd
from io import StringIO


def fetch_threat_ips():
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

    response = requests.get(url)

    csv_data = StringIO(response.text)

    df = pd.read_csv(csv_data, comment="#")

    return df


if __name__ == "__main__":
    df = fetch_threat_ips()

    print("\nATHENA Threat Feed Loaded\n")
    print(df.head())