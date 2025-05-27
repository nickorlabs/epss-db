"""
Packet Storm Security ETL
Fetches and parses the Packet Storm Security RSS feed or HTML for exploit records and CVE references.
"""

import os
import sys
import logging
import requests
import datetime
import json
from pathlib import Path
import re
import time
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw")
NORM_DATA_DIR = os.environ.get("NORM_DATA_DIR", "/etl-data/normalized")
MANIFEST_PATH = os.path.join(NORM_DATA_DIR, "packetstorm", "manifest.json")
DEFAULT_DEV_API_URL = "https://api.packetstormsecurity.com/v31337.20240702/dev-api"
DEFAULT_PROD_API_URL = "https://api.packetstormsecurity.com/v31337.20240702/api"
API_URL = os.environ.get("PACKETSTORM_API_URL", DEFAULT_DEV_API_URL)
API_KEY_PATH = os.environ.get("PACKETSTORM_API_KEY_FILE", "/etl/secrets/packetstorm_auth")
API_KEY_ENV = "PACKETSTORM_API_KEY"

SUPPORTED_SECTIONS = ["advisory", "exploit"]  # can add more if needed
DEFAULT_SECTIONS_DEV = ["main"]

# Default queries for full ETL (advisory, exploit, news)
DEFAULT_QUERIES = [
    {"area": "files", "section": "advisory"},
    {"area": "files", "section": "exploit"},
    {"area": "news", "section": "main"},
]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}")

def get_api_key():
    api_secret = None
    # Try secrets file first
    if os.path.exists(API_KEY_PATH):
        with open(API_KEY_PATH, "r") as f:
            line = f.read().strip()
            if '|' in line:
                api_secret = line  # full user_id|apikey string
            else:
                raise RuntimeError("API secret file must be in 'user_id|apikey' format!")
    api_secret = api_secret or os.environ.get(API_KEY_ENV)
    if not api_secret:
        raise RuntimeError("Packet Storm API secret not found in secrets or environment!")
    logging.info(f"Loaded API secret: {api_secret[:8]}...{api_secret[-8:]} (length={len(api_secret)})")
    return api_secret

# --- Manifest for deduplication ---
def load_manifest():
    if os.path.exists(MANIFEST_PATH):
        with open(MANIFEST_PATH, "r") as f:
            return json.load(f)
    return {}

def save_manifest(manifest):
    os.makedirs(os.path.dirname(MANIFEST_PATH), exist_ok=True)
    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)

# --- Packet Storm API ETL ---
def build_osv_object_news(meta, snapshot_date):
    # Normalize Packet Storm news meta to OSV-like format
    return {
        "id": f"packetstorm-news-{meta.get('id', '')}",
        "published": meta.get("date", snapshot_date),
        "summary": meta.get("summary", ""),
        "details": meta.get("title", ""),
        "references": [meta.get("url")] if meta.get("url") else [],
        "type": "news",
        "tags": meta.get("tags", []),
        "author": meta.get("author", "")
    }

def fetch_packet_storm_api(mode="incremental", sections=None, api_url=None):
    api_key = get_api_key()
    if not api_url:
        api_url = API_URL
    snapshot_date = datetime.datetime.utcnow().strftime("%Y%m%d")
    norm_out_dir = os.path.join(NORM_DATA_DIR, "packetstorm", snapshot_date)
    raw_out_dir = os.path.join(RAW_DATA_DIR, "packetstorm", snapshot_date)
    os.makedirs(norm_out_dir, exist_ok=True)
    os.makedirs(raw_out_dir, exist_ok=True)
    manifest = load_manifest()
    summary = []
    # Always use DEFAULT_QUERIES (advisory, exploit, news) unless --sections is specified
    if not sections:
        queries = DEFAULT_QUERIES
    else:
        # If user specifies --sections, default to area=files for each
        queries = [{"area": "files", "section": s} for s in sections]
    max_pages = 2 if mode == "incremental" else 10000
    logging.info(f"Using API endpoint: {api_url}")
    for query in queries:
        area = query["area"]
        section = query["section"]
        params = {
            "area": area,
            "section": section,
            "page": 1,
            "output": "json",
        }
        headers = {
            "Apisecret": api_key,
            "Accept": "application/json"
        }
        total_pages = 1
        page = 1
        section_total = 0
        failed = False
        raw_results = []
        norm_results = []
        while page <= total_pages and page <= max_pages:
            params["page"] = page
            try:
                r = requests.post(api_url, headers=headers, data=params)
                logging.info(f"[API] Area '{area}' Section '{section}' page {page} status: {r.status_code}")
                try:
                    data = r.json()
                except Exception as e:
                    logging.error(f"Failed to decode JSON for area '{area}' section '{section}' page {page}: {e}\nRaw response: {r.text}")
                    failed = True
                    break
                # Collect all raw results for this area/section
                raw_results.append(data)
                if page == 1:
                    total_pages = int(data.get("total_pages", 1))
                    logging.info(f"Area '{area}' Section '{section}': {total_pages} API pages to fetch.")
                if area == "files":
                    files = data.get("files", {})
                    n_files = len(files)
                    logging.info(f"Area '{area}' Section '{section}' page {page}: {n_files} files found.")
                    if n_files == 0:
                        logging.warning(f"Area '{area}' Section '{section}' page {page}: 0 files returned by API. Raw response: {data}")
                    for file_entry in files.values():
                        meta = file_entry.get("meta", {})
                        osv_obj = build_osv_object_api(meta, snapshot_date)
                        norm_results.append(osv_obj)
                        section_total += 1
                else:
                    # For news, normalize each entry
                    files = data.get("files", {})
                    n_files = len(files)
                    for news_entry in files.values():
                        meta = news_entry.get("meta", {})
                        osv_obj = build_osv_object_news(meta, snapshot_date)
                        norm_results.append(osv_obj)
                        section_total += 1
                if page % 100 == 0:
                    logging.info(f"Crawled {page}/{total_pages} API pages for section '{section}'...")
                page += 1
                time.sleep(0.5)
            except Exception as e:
                logging.error(f"Exception during API fetch for section '{section}' page {page}: {e}")
                failed = True
                break
        # Write raw results
        raw_file = os.path.join(raw_out_dir, f"packetstorm_{section}_raw-{snapshot_date}.json")
        with open(raw_file, "w", encoding="utf-8") as f:
            json.dump(raw_results, f, indent=2)
        norm_file = None
        if norm_results:
            norm_file = os.path.join(norm_out_dir, f"packetstorm_{section}_osv-{snapshot_date}.json")
            with open(norm_file, "w", encoding="utf-8") as f:
                json.dump(norm_results, f, indent=2)
        summary.append({
            "area": area,
            "section": section,
            "pages_fetched": page-1,
            "items_written": section_total,
            "failed": failed,
            "raw_file": raw_file,
            "norm_file": norm_file
        })
    save_manifest(manifest)
    print("\n==== Packet Storm API ETL Summary ====")
    for s in summary:
        status = "FAILED" if s["failed"] else "OK"
        print(f"Area: {s['area']} | Section: {s['section']} | Pages: {s['pages_fetched']} | Items: {s['items_written']} | Status: {status}")
        print(f"  Raw: {s['raw_file']}")
        if s.get('norm_file'):
            print(f"  Normalized: {s['norm_file']}")
    print()
    return summary

def build_osv_object_api(meta, snapshot_date):
    osv_id = f"PACKETSTORM-{meta.get('file_sha256', '')[:16]}"
    aliases = []
    cves = meta.get("cves", {})
    for cve in cves.values():
        if isinstance(cve, dict) and "id" in cve:
            aliases.append(cve["id"])
    osv_obj = {
        "id": osv_id,
        "modified": meta.get("posted", snapshot_date),
        "summary": meta.get("title"),
        "details": meta.get("detail") or "",
        "aliases": aliases,
        "references": [{"type": "ADVISORY", "url": meta.get("file_download_link")}],
        "affected": [],
        "database_specific": {
            "author": ", ".join([c["name"] for c in meta.get("credits", {}).values() if "name" in c]),
            "tags": [t["name"] for t in meta.get("tags", {}).values() if "name" in t],
            "file_name": meta.get("file_name"),
            "file_sha256": meta.get("file_sha256"),
            "source": "packetstormsecurity.com"
        }
    }
    return osv_obj

# --- RSS Incremental Mode ---
RSS_URL = "https://packetstormsecurity.com/rss/files/"

def fetch_and_archive_rss(snapshot_date):
    raw_dir = os.path.join(RAW_DATA_DIR, "packetstorm", snapshot_date)
    os.makedirs(raw_dir, exist_ok=True)
    rss_path = os.path.join(raw_dir, "rss.xml")
    if not os.path.exists(rss_path):
        r = requests.get(RSS_URL)
        r.raise_for_status()
        with open(rss_path, "w", encoding="utf-8") as f:
            f.write(r.text)
        logging.info(f"Fetched and archived Packet Storm RSS to {rss_path}")
    else:
        logging.info(f"RSS already archived for {snapshot_date}")
    return rss_path

def parse_rss_for_entries(rss_path):
    tree = ET.parse(rss_path)
    root = tree.getroot()
    ns = {'dc': 'http://purl.org/dc/elements/1.1/'}
    entries = []
    for item in root.findall(".//item"):
        title = item.findtext("title")
        link = item.findtext("link")
        pub_date = item.findtext("pubDate")
        description = item.findtext("description")
        author = item.findtext("dc:creator", namespaces=ns) or item.findtext("author")
        cves = list(set(CVE_REGEX.findall((description or "") + " " + (title or ""))))
        entries.append({
            "title": title,
            "link": link,
            "pub_date": pub_date,
            "description": description,
            "author": author,
            "cves": cves,
        })
    return entries

# --- HTML Historical Crawl Mode ---
LATEST_URL = "https://packetstorm.news/files/latest/1"
MONTH_BASE_URL = "https://packetstorm.news/files/"

def discover_months():
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    }
    r = requests.get(LATEST_URL, headers=headers)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    months = set()
    # Dropdown: <a href="/files/YYYY-MM/1">Month Year</a> or in a <select>/<option>
    for a in soup.select('a[href^="/files/"]'):
        m = re.match(r"/files/(\d{4}-\d{2})/1", a['href'])
        if m:
            months.add(m.group(1))
    # Fallback: parse <option value="/files/YYYY-MM/1"> if present
    for opt in soup.select('option[value^="/files/"]'):
        m = re.match(r"/files/(\d{4}-\d{2})/1", opt['value'])
        if m:
            months.add(m.group(1))
    months = sorted(months)
    if not months:
        logging.warning("No months found in dropdown! Dumping HTML sample for debugging.")
        logging.warning(soup.prettify()[:2000])
        return []
    logging.info(f"Discovered {len(months)} months: {months[0]} to {months[-1]}")
    return months

def crawl_month_pages(month):
    # Try /files/YYYY-MM/1, /2, ... until no entries are found
    entries = []
    page = 1
    while True:
        url = f"{MONTH_BASE_URL}{month}/{page}"
        r = requests.get(url)
        if r.status_code != 200:
            break
        soup = BeautifulSoup(r.text, "html.parser")
        page_entries = parse_month_page(soup)
        if not page_entries:
            break
        entries.extend(page_entries)
        logging.info(f"{month} page {page}: {len(page_entries)} entries")
        page += 1
        time.sleep(1)
    return entries

def parse_month_page(soup):
    entries = []
    for div in soup.select(".list .row"):
        title_tag = div.find("a", class_="title")
        if not title_tag:
            continue
        title = title_tag.get_text(strip=True)
        link = "https://packetstorm.news" + title_tag['href']
        desc = div.find("div", class_="detail-summary")
        description = desc.get_text(strip=True) if desc else ""
        meta = div.find("div", class_="meta")
        pub_date = None
        author = None
        if meta:
            meta_text = meta.get_text("|", strip=True)
            # Example: 'Posted: 2025-05-23 | Source(s): LiquidWorm'
            m = re.search(r"Posted: ([0-9\-]+)", meta_text)
            if m:
                pub_date = m.group(1)
            m = re.search(r"Source\(s\): ([^|]+)", meta_text)
            if m:
                author = m.group(1)
        cves = list(set(CVE_REGEX.findall(description + " " + title)))
        entries.append({
            "title": title,
            "link": link,
            "pub_date": pub_date,
            "description": description,
            "author": author,
            "cves": cves,
        })
    return entries

def parse_archive_day(day_url):
    r = requests.get(day_url)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    entries = []
    for row in soup.select(".list tr")[1:]:  # skip header
        cols = row.find_all("td")
        if len(cols) < 5:
            continue
        title = cols[0].get_text(strip=True)
        link = "https://packetstormsecurity.com" + cols[0].find("a")['href'] if cols[0].find("a") else None
        pub_date = cols[1].get_text(strip=True)
        author = cols[2].get_text(strip=True)
        desc = cols[4].get_text(strip=True)
        cves = list(set(CVE_REGEX.findall((desc or "") + " " + (title or ""))))
        entries.append({
            "title": title,
            "link": link,
            "pub_date": pub_date,
            "description": desc,
            "author": author,
            "cves": cves,
        })
    return entries

# --- OSV Normalization ---
def build_osv_object(entry, snapshot_date):
    osv_id = f"PACKETSTORM-{re.sub(r'[^a-zA-Z0-9]', '-', entry['title'] or entry['link'] or '')[:64]}"
    osv_obj = {
        "id": osv_id,
        "modified": snapshot_date,
        "summary": entry.get("title"),
        "details": entry.get("description") or "",
        "aliases": entry.get("cves", []),
        "references": [{"type": "ADVISORY", "url": entry.get("link")}] if entry.get("link") else [],
        "affected": [],
        "database_specific": {
            "author": entry.get("author"),
            "pub_date": entry.get("pub_date"),
            "source": "packetstormsecurity.com"
        }
    }
    return osv_obj

# --- Main ETL Logic ---
def fetch_packet_storm_security():
    snapshot_date = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    norm_out_dir = os.path.join(NORM_DATA_DIR, "packetstorm", snapshot_date)
    os.makedirs(norm_out_dir, exist_ok=True)
    rss_path = fetch_and_archive_rss(snapshot_date)
    entries = parse_rss_for_entries(rss_path)
    osv_objs = [build_osv_object(e, snapshot_date) for e in entries]
    out_json = os.path.join(norm_out_dir, f"packetstorm_rss_osv-{snapshot_date.replace('-', '')}.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(osv_objs, f, indent=2)
    logging.info(f"Wrote {len(osv_objs)} Packet Storm RSS entries to {out_json} (mode=rss)")
    return out_json
    

if __name__ == "__main__":
    import argparse
    import xml.dom.minidom
    parser = argparse.ArgumentParser(description="Packet Storm ETL: API-first with fallback to scraping or arbitrary API query.")
    parser.add_argument("--mode", choices=["incremental", "full", "rss"], default="incremental", help="ETL mode")
    parser.add_argument("--force-scrape", action="store_true", help="Force fallback to scraping even if API key is present.")
    parser.add_argument("--sections", nargs="*", help="Sections to extract (default: advisory exploit; dev API: main)")
    parser.add_argument("--api-url", help="Override API endpoint URL (dev or prod)")
    parser.add_argument("--api-query", help="Raw POST body for arbitrary Packet Storm API query (e.g. 'area=news&section=main&page=1&output=json')")
    args = parser.parse_args()

    if args.api_query:
        # Arbitrary API query mode
        api_url = args.api_url or API_URL
        api_secret = get_api_key()
        headers = {
            "Apisecret": api_secret,
            "Accept": "*/*"
        }
        logging.info(f"[API-QUERY] POST to {api_url} with body: {args.api_query}")
        import requests
        r = requests.post(api_url, headers=headers, data=args.api_query)
        content_type = r.headers.get('Content-Type', '')
        print(f"[API-QUERY] Status: {r.status_code}, Content-Type: {content_type}")
        out_path = f"/etl-data/raw/packetstorm_apiquery_{int(time.time())}.out"
        if 'json' in content_type:
            try:
                import json
                parsed = r.json()
                pretty = json.dumps(parsed, indent=2)
                print(pretty)
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(pretty)
            except Exception as e:
                print("[API-QUERY] Failed to parse JSON:", e)
                print(r.text)
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(r.text)
        elif 'xml' in content_type or r.text.strip().startswith('<'):
            try:
                dom = xml.dom.minidom.parseString(r.text)
                pretty = dom.toprettyxml()
                print(pretty)
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(pretty)
            except Exception as e:
                print("[API-QUERY] Failed to parse XML:", e)
                print(r.text)
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(r.text)
        else:
            print(r.text)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(r.text)
        print(f"[API-QUERY] Response saved to {out_path}")
    elif args.mode == "rss":
        fetch_packet_storm_security()
    else:
        try:
            if not args.force_scrape:
                fetch_packet_storm_api(mode=args.mode, sections=args.sections, api_url=args.api_url)
            else:
                raise Exception("Force scrape requested")
        except Exception as e:
            logging.warning(f"API ETL failed or unavailable ({e}), falling back to scraping.")
            fetch_packet_storm_security()

def fetch_and_archive_rss(snapshot_date):
    raw_dir = os.path.join(RAW_DATA_DIR, "packetstorm", snapshot_date)
    os.makedirs(raw_dir, exist_ok=True)
    rss_path = os.path.join(raw_dir, "rss.xml")
    if not os.path.exists(rss_path):
        r = requests.get(RSS_URL)
        r.raise_for_status()
        with open(rss_path, "w", encoding="utf-8") as f:
            f.write(r.text)
        logging.info(f"Fetched and archived Packet Storm RSS to {rss_path}")
    else:
        logging.info(f"RSS already archived for {snapshot_date}")
    return rss_path

def parse_rss_for_entries(rss_path):
    tree = ET.parse(rss_path)
    root = tree.getroot()
    ns = {'dc': 'http://purl.org/dc/elements/1.1/'}
    entries = []
    for item in root.findall(".//item"):
        title = item.findtext("title")
        link = item.findtext("link")
        pub_date = item.findtext("pubDate")
        description = item.findtext("description")
        author = item.findtext("dc:creator", namespaces=ns) or item.findtext("author")
        cves = list(set(CVE_REGEX.findall((description or "") + " " + (title or ""))))
        entries.append({
            "title": title,
            "link": link,
            "pub_date": pub_date,
            "description": description,
            "author": author,
            "cves": cves,
        })
    return entries

def build_osv_object(entry, snapshot_date):
    osv_id = f"PACKETSTORM-{re.sub(r'[^a-zA-Z0-9]', '-', entry['title'] or entry['link'] or '')[:64]}"
    osv_obj = {
        "id": osv_id,
        "modified": snapshot_date,
        "summary": entry.get("title"),
        "details": entry.get("description") or "",
        "aliases": entry.get("cves", []),
        "references": [{"type": "ADVISORY", "url": entry.get("link")}] if entry.get("link") else [],
        "affected": [],
        "database_specific": {
            "author": entry.get("author"),
            "pub_date": entry.get("pub_date"),
            "source": "packetstormsecurity.com"
        }
    }
    return osv_obj

def fetch_packet_storm_security():
    snapshot_date = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    norm_out_dir = os.path.join(NORM_DATA_DIR, "packetstorm", snapshot_date)
    os.makedirs(norm_out_dir, exist_ok=True)
    rss_path = fetch_and_archive_rss(snapshot_date)
    entries = parse_rss_for_entries(rss_path)
    osv_objs = [build_osv_object(e, snapshot_date) for e in entries]
    out_json = os.path.join(norm_out_dir, f"packetstorm_rss_osv-{snapshot_date.replace('-', '')}.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(osv_objs, f, indent=2)
    logging.info(f"Wrote {len(osv_objs)} Packet Storm RSS entries to {out_json} (mode=rss)")
    return out_json
    
