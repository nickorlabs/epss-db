import os
import requests
from bs4 import BeautifulSoup
import json
from datetime import datetime
import logging
from common import verify
from common import osv_normalizer

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw/cert_eu_threat_intel")
NORM_DATA_DIR = os.environ.get("NORM_DATA_DIR", "/etl-data/normalized/cert_eu_threat_intel")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

BASE_URL = "https://cert.europa.eu/publications/threat-intelligence/"
START_YEAR = 2019
END_YEAR = datetime.utcnow().year

TS = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
RAW_OUTPUT_JSON = os.path.join(RAW_DATA_DIR, f"cert_eu_threat_intel_raw_{TS}.json")
NORM_OUTPUT_JSON = os.path.join(NORM_DATA_DIR, f"cert_eu_threat_intel_norm_{TS}.json")

def fetch_year(year):
    url = f"{BASE_URL}{year}"
    logging.info(f"Fetching CERT-EU threat intelligence for {year}: {url}")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://cert.europa.eu/"
    }
    with requests.Session() as session:
        session.headers.update(headers)
        resp = session.get(url, timeout=60)
        resp.raise_for_status()
        return resp.text

from urllib.parse import urlparse
import hashlib

def extract_id_from_url(url, title, date):
    if not url:
        return None
    path = urlparse(url).path
    segments = [seg for seg in path.split('/') if seg]
    if segments:
        return segments[-1]
    # fallback: hash title+date
    return hashlib.sha1((title + date).encode('utf-8')).hexdigest()[:16]

def parse_reports(html):
    soup = BeautifulSoup(html, "html.parser")
    reports = []
    for li in soup.find_all("li", class_="publications--list--item"):
        link_tag = li.find("a", class_="publications--list--item--link")
        if not link_tag:
            continue
        title_tag = link_tag.find("h3", class_="publications--list--item--link--title")
        title = title_tag.text.strip() if title_tag else ""
        url = link_tag.get("href", "")
        date_tag = link_tag.find("div", class_="publications--list--item--link--date")
        date = date_tag.text.strip() if date_tag else ""
        desc_tag = link_tag.find("p", class_="publications--list--item--link--description")
        description = desc_tag.get_text(" ", strip=True) if desc_tag else ""
        # Extract PDF URL from sibling share list
        pdf_url = ""
        share_ul = li.find("ul", class_="publications--list--item--share")
        if share_ul:
            pdf_a = share_ul.find("a", attrs={"download": True})
            if pdf_a and pdf_a.has_attr("href"):
                pdf_url = pdf_a["href"]
        # Robust ID extraction
        report_id = extract_id_from_url(url, title, date)
        if not report_id:
            # fallback: hash title+date
            report_id = hashlib.sha1((title + date).encode('utf-8')).hexdigest()[:16]
        reports.append({
            "title": title,
            "url": url,
            "description": description,
            "date": date,
            "id": report_id,
            "pdf_url": pdf_url
        })
    return reports

def safe_write_json(path, data, indent=2):
    import tempfile, os, json
    dir_name = os.path.dirname(path)
    os.makedirs(dir_name, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', dir=dir_name, delete=False, encoding='utf-8') as tf:
        json.dump(data, tf, indent=indent, ensure_ascii=False)
        tempname = tf.name
    os.replace(tempname, path)
def save_json(data, outdir, prefix):
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    path = os.path.join(outdir, f"{prefix}_{ts}.json")
    safe_write_json(path, data, indent=2)
    return path

def main():
    all_reports = []
    raw_htmls = {}
    for year in range(START_YEAR, END_YEAR + 1):
        try:
            html = fetch_year(year)
            # Cache raw HTML to cache dir
            cache_dir = "/etl-data/cache/cert_eu_threat_intel"
            os.makedirs(cache_dir, exist_ok=True)
            cache_ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            cache_path = os.path.join(cache_dir, f"threat_intel_{year}_{cache_ts}.html")
            safe_write_json(cache_path, html, indent=2)
            logging.info(f"Raw HTML for {year} cached to {cache_path}")
            raw_htmls[str(year)] = html
            reports = parse_reports(html)
            all_reports.extend(reports)
        except Exception as e:
            logging.warning(f"Failed to fetch/parse {year}: {e}")
    raw_path = save_json(raw_htmls, RAW_DATA_DIR, "cert_eu_threat_intel_raw")
    logging.info(f"Raw HTML for all years saved to {raw_path}")
    # Normalize to OSV schema
    osv_records = []
    field_map = {
        "summary": "title",
        "details": "summary",
        "modified": "date",
        "references": "references"
    }
    id_fields = ["id"]
    for item in all_reports:
        refs = []
        if item.get("url"):
            refs.append({"type": "ARTICLE", "url": item["url"]})
        item["references"] = refs
        osv_record = osv_normalizer.create_osv_record(
            item,
            feed_name="cert_eu_threat_intel",
            field_map=field_map,
            id_fields=id_fields,
            extra_fields=["date"]
        )
        if item.get("date"):
            osv_record["published"] = item["date"]
        osv_record["database_specific"] = osv_record.get("database_specific", {})
        osv_record["database_specific"]["source_type"] = "cert_eu_threat_intel"
        osv_records.append(osv_record)
    norm_path = save_json(osv_records, NORM_DATA_DIR, "cert_eu_threat_intel_norm")
    logging.info(f"Normalized threat intelligence reports saved to {norm_path}")
    try:
        verify.verify_record_count([r for year in raw_htmls.values() for r in parse_reports(year)], all_reports)
        if all_reports and 'id' in all_reports[0]:
            verify.verify_ids([r for year in raw_htmls.values() for r in parse_reports(year)], all_reports, raw_id_key='id', norm_id_key='id')
    except Exception as e:
        logging.warning(f"Verification failed: {e}")

if __name__ == "__main__":
    main()
