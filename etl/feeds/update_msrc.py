import os
import requests
import json
from datetime import datetime
import logging

MSRC_API_URL = os.getenv("MSRC_API_URL", "https://api.msrc.microsoft.com/cvrf/v2.0/updates")
RAW_DIR = os.getenv("RAW_DIR", "/common-data/raw/msrc")
NORM_DIR = os.getenv("NORM_DIR", "/common-data/normalized/msrc")
logging.basicConfig(level=logging.INFO)

def fetch_feed(url):
    headers = {"Accept": "application/json"}
    resp = requests.get(url, headers=headers, timeout=60)
    resp.raise_for_status()
    return resp.json()

def parse_entries(data):
    advisories = []
    for item in data.get("value", []):
        advisories.append({
            "id": item.get("ID", ""),
            "title": item.get("Title", ""),
            "cve": item.get("CVE", []),
            "published": item.get("InitialReleaseDate", ""),
            "severity": item.get("Severity", ""),
            "url": item.get("DocumentTitle", ""),
        })
    return advisories

def save_json(data, outdir, prefix):
    os.makedirs(outdir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    path = os.path.join(outdir, f"{prefix}_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path

def main():
    logging.info(f"Fetching MSRC API from {MSRC_API_URL}")
    raw = fetch_feed(MSRC_API_URL)
    raw_path = save_json(raw, RAW_DIR, "msrc_raw")
    logging.info(f"Raw MSRC data saved to {raw_path}")
    advisories = parse_entries(raw)
    norm_path = save_json(advisories, NORM_DIR, "msrc_norm")
    logging.info(f"Normalized advisories saved to {norm_path}")

if __name__ == "__main__":
    main()
