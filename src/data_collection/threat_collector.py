import requests
import pandas as pd
from io import StringIO
from typing import Set


def fetch_threat_ips(timeout: int = 10) -> pd.DataFrame:
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

    response = requests.get(url, timeout=timeout)
    response.raise_for_status()

    csv_data = StringIO(response.text)

    df = pd.read_csv(csv_data, comment="#")

    return df


def extract_threat_ips(df: pd.DataFrame) -> Set[str]:
    if df is None or df.empty:
        return set()

    candidate_columns = [
        "ip_address",
        "dst_ip",
        "src_ip",
        "ioc",
        "indicator",
    ]

    for column in candidate_columns:
        if column in df.columns:
            return set(df[column].dropna().astype(str).str.strip())

    # Fallback: use the first column if the feed schema changes.
    first_column = df.columns[0]
    return set(df[first_column].dropna().astype(str).str.strip())


if __name__ == "__main__":
    df = fetch_threat_ips()

    print("\nATHENA Threat Feed Loaded\n")
    print(df.head())
