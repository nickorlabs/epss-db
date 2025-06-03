import os
import requests
import feedparser
import json
from datetime import datetime
import logging

CISCO_RSS_URL = os.getenv("CISCO_RSS_URL", "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml")
RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw/cisco_advisories")
NORM_DATA_DIR = os.environ.get("NORM_DATA_DIR", "/etl-data/normalized/cisco_advisories")
logging.basicConfig(level=logging.INFO)

def fetch_feed(url):
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return feedparser.parse(resp.content)

def parse_entries(feed):
    advisories = []
    for entry in feed.entries:
        advisories.append({
            "title": entry.get("title", ""),
            "link": entry.get("link", ""),
            "published": entry.get("published", ""),
            "summary": entry.get("summary", ""),
            "id": entry.get("id", entry.get("link", "")),
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
    logging.info(f"Fetching Cisco Advisories RSS from {CISCO_RSS_URL}")
    feed = fetch_feed(CISCO_RSS_URL)
    raw_path = os.path.join(RAW_DATA_DIR, f"cisco_advisories_raw_{ts}.json")
    with open(raw_path, "w", encoding="utf-8") as f:
        json.dump(feed, f, indent=2)
    logging.info(f"Raw feed saved to {raw_path}")
    advisories = parse_entries(feed)
    norm_path = os.path.join(NORM_DATA_DIR, f"cisco_advisories_norm_{ts}.json")
    with open(norm_path, "w", encoding="utf-8") as f:
        json.dump(advisories, f, indent=2)
    logging.info(f"Normalized advisories saved to {norm_path}")
    # Verification
    from common import verify
    try:
        verify.verify_record_count(feed.entries, advisories)
        if advisories and 'id' in advisories[0]:
            verify.verify_ids(feed.entries, advisories, raw_id_key='id', norm_id_key='id')
    except Exception as e:
        logging.warning(f"Verification failed: {e}")

if __name__ == "__main__":
    main()
