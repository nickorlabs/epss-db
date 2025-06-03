import os
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import json
from datetime import datetime
import logging

ACSC_ALERTS_ADVISORIES_URL = "https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories"
RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw/acsc_advisories")
NORM_DATA_DIR = os.environ.get("NORM_DATA_DIR", "/etl-data/normalized/acsc_advisories")
logging.basicConfig(level=logging.INFO)

import time

def fetch_html(url, retries=3, backoff=10):
    for attempt in range(retries):
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(args=["--disable-http2"])
                context = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                                              extra_http_headers={
                                                  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                                                  "Accept-Language": "en-US,en;q=0.9",
                                                  "Connection": "keep-alive"
                                              })
                page = context.new_page()
                page.goto(url, timeout=120000)
                html = page.content()
                browser.close()
                return html
        except Exception as e:
            logging.warning(f"Attempt {attempt+1} failed: {e}")
            if attempt < retries - 1:
                time.sleep(backoff * (2 ** attempt))
            else:
                logging.error(f"All {retries} attempts failed. Giving up.")
                raise

from urllib.parse import urlparse
import hashlib

def extract_id_from_url(url, title, date):
    if not url:
        return hashlib.sha1((title + date).encode('utf-8')).hexdigest()[:16]
    path = urlparse(url).path
    segments = [seg for seg in path.split('/') if seg]
    if segments:
        return segments[-1]
    return hashlib.sha1((title + date).encode('utf-8')).hexdigest()[:16]

def parse_alerts_and_advisories(html):
    soup = BeautifulSoup(html, "html.parser")
    items = []
    for li in soup.find_all("li", class_="listing__item"):
        link_tag = li.find("a", class_="listing__link")
        if not link_tag:
            continue
        title = link_tag.get_text(strip=True)
        url = link_tag.get("href", "")
        date_tag = li.find("span", class_="listing__date")
        date = date_tag.get_text(strip=True) if date_tag else ""
        summary_tag = li.find("div", class_="listing__summary")
        summary = summary_tag.get_text(strip=True) if summary_tag else ""
        item_id = extract_id_from_url(url, title, date)
        items.append({
            "title": title,
            "url": url,
            "date": date,
            "summary": summary,
            "id": item_id
        })
    return items

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
    logging.info(f"Fetching ACSC Alerts and Advisories page from {ACSC_ALERTS_ADVISORIES_URL}")
    html = fetch_html(ACSC_ALERTS_ADVISORIES_URL)
    raw_path = os.path.join(RAW_DATA_DIR, f"acsc_alerts_advisories_raw_{ts}.html")
    with open(raw_path, "w", encoding="utf-8") as f:
        f.write(html)
    logging.info(f"Raw HTML saved to {raw_path}")
    items = parse_alerts_and_advisories(html)
    norm_path = os.path.join(NORM_DATA_DIR, f"acsc_alerts_advisories_norm_{ts}.json")
    with open(norm_path, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2)
    logging.info(f"Normalized alerts/advisories saved to {norm_path}")
    # Verification
    from common import verify
    try:
        verify.verify_record_count(items, items)
        if items and 'id' in items[0]:
            verify.verify_ids(items, items, raw_id_key='id', norm_id_key='id')
    except Exception as e:
        logging.warning(f"Verification failed: {e}")

if __name__ == "__main__":
    main()
