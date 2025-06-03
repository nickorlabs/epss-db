import os
import requests
import feedparser
import json
from datetime import datetime
import logging

GOVCERTNL_RSS_URL = os.getenv("GOVCERTNL_RSS_URL", "https://www.ncsc.nl/actueel/advisories-adviseringen/feed.xml")
RAW_DIR = os.getenv("RAW_DIR", "/etl-data/raw/")
NORM_DIR = os.getenv("NORM_DIR", "/etl-data/normalize/")
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
    logging.info(f"Fetching GOVCERT.NL RSS from {GOVCERTNL_RSS_URL}")
    feed = fetch_feed(GOVCERTNL_RSS_URL)
    raw_path = save_json(feed, RAW_DIR, "govcertnl_raw")
    logging.info(f"Raw feed saved to {raw_path}")
    advisories = parse_entries(feed)
    norm_path = save_json(advisories, NORM_DIR, "govcertnl_norm")
    logging.info(f"Normalized advisories saved to {norm_path}")

if __name__ == "__main__":
    main()
