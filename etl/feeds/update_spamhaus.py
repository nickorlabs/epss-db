import os
import requests
import json
from datetime import datetime
import logging

SPAMHAUS_URL = os.getenv("SPAMHAUS_URL", "https://www.spamhaus.org/drop/drop.txt")
RAW_DIR = os.getenv("RAW_DIR", "/etl-data/raw/")
NORM_DIR = os.getenv("NORM_DIR", "/etl-data/normalize/")
logging.basicConfig(level=logging.INFO)

def fetch_feed(url):
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.text

def parse_entries(text):
    entries = []
    for line in text.splitlines():
        if line and not line.startswith("#"):
            entries.append({"cidr": line.strip()})
    return entries

def save_json(data, outdir, prefix):
    os.makedirs(outdir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    path = os.path.join(outdir, f"{prefix}_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path

def main():
    logging.info(f"Fetching Spamhaus DROP from {SPAMHAUS_URL}")
    raw = fetch_feed(SPAMHAUS_URL)
    raw_path = save_json({"raw": raw}, RAW_DIR, "spamhaus")
    logging.info(f"Raw saved to {raw_path}")
    entries = parse_entries(raw)
    norm_path = save_json(entries, NORM_DIR, "spamhaus")
    logging.info(f"Normalized saved to {norm_path}")

if __name__ == "__main__":
    main()
