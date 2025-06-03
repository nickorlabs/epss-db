import os
import requests
import json
from datetime import datetime
import logging

CTA_FEED_URL = os.getenv("CTA_FEED_URL", "https://www.cyberthreatalliance.org/feed.json")  # This feed appears to be deprecated or unavailable as of 2025-05-31
RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw/cyber_threat_alliance")
NORM_DATA_DIR = os.environ.get("NORM_DATA_DIR", "/etl-data/normalized/cyber_threat_alliance")
logging.basicConfig(level=logging.INFO)

def fetch_feed(url):
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    return resp.json()

def parse_entries(data):
    advisories = []
    for item in data.get('advisories', []):
        advisories.append({
            "id": item.get("id", ""),
            "title": item.get("title", ""),
            "published": item.get("published", ""),
            "summary": item.get("summary", ""),
            "link": item.get("link", ""),
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
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    os.makedirs(NORM_DATA_DIR, exist_ok=True)
    logging.info(f"Fetching Cyber Threat Alliance feed from {CTA_FEED_URL}")
    try:
        raw = fetch_feed(CTA_FEED_URL)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logging.warning(f"Cyber Threat Alliance feed URL is not available (404). This ETL is currently deprecated.")
            return
        else:
            raise
    raw_path = os.path.join(RAW_DATA_DIR, f"cta_raw_{ts}.json")
    with open(raw_path, "w", encoding="utf-8") as f:
        json.dump(raw, f, indent=2)
    logging.info(f"Raw CTA feed saved to {raw_path}")
    advisories = parse_entries(raw)
    norm_path = os.path.join(NORM_DATA_DIR, f"cta_norm_{ts}.json")
    with open(norm_path, "w", encoding="utf-8") as f:
        json.dump(advisories, f, indent=2)
    logging.info(f"Normalized advisories saved to {norm_path}")
    # Verification
    from common import verify
    try:
        verify.verify_record_count(raw.get('advisories', []), advisories)
        if advisories and 'id' in advisories[0]:
            verify.verify_ids(raw.get('advisories', []), advisories, raw_id_key='id', norm_id_key='id')
    except Exception as e:
        logging.warning(f"Verification failed: {e}")

if __name__ == "__main__":
    main()
