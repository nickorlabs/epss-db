import os
import requests
from bs4 import BeautifulSoup
import json
from datetime import datetime
import logging
from common import verify
from urllib.parse import urljoin
import re
from common import osv_normalizer

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw/cert_eu_advisories")
NORM_DATA_DIR = os.environ.get("NORM_DATA_DIR", "/etl-data/normalized/cert_eu_advisories")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

BASE_URL = "https://cert.europa.eu/publications/security-advisories/"
START_YEAR = 2011
END_YEAR = datetime.utcnow().year

TS = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
RAW_OUTPUT_JSON = os.path.join(RAW_DATA_DIR, f"cert_eu_advisories_raw_{TS}.json")
NORM_OUTPUT_JSON = os.path.join(NORM_DATA_DIR, f"cert_eu_advisories_norm_{TS}.json")


def fetch_year(year):
    url = f"{BASE_URL}{year}"
    logging.info(f"Fetching CERT-EU advisories for {year}: {url}")
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

def parse_advisories(html):
    BASE_URL = "https://cert.europa.eu"
    soup = BeautifulSoup(html, "html.parser")
    advisories = []
    ul = soup.find("ul", class_="publications--list")
    if not ul:
        return advisories
    for li in ul.find_all("li", class_="publications--list--item"):
        a = li.find("a", class_="publications--list--item--link")
        if not a:
            continue
        href = a.get("href")
        advisory_url = urljoin(BASE_URL, href) if href else None
        title_tag = a.find("h3", class_="publications--list--item--link--title")
        title = title_tag.get_text(strip=True) if title_tag else None
        date_tag = a.find("div", class_="publications--list--item--link--date")
        date = date_tag.get_text(strip=True) if date_tag else None
        desc_tag = a.find("p", class_="publications--list--item--link--description")
        description = desc_tag.get_text(strip=True) if desc_tag else None
        # Extract advisory ID from URL or title
        advisory_id = None
        if href:
            # e.g., /publications/security-advisories/2011-0032/
            m = re.search(r"(\d{4}-\d{3,})", href)
            if m:
                advisory_id = m.group(1)
        if not advisory_id and title:
            m = re.search(r"(\d{4}-\d{3,})", title)
            if m:
                advisory_id = m.group(1)
        # Find PDF link (optional)
        pdf_url = None
        for share_li in li.find_all("li"):
            pdf_a = share_li.find("a", class_="share-icon-download-grey")
            if pdf_a and pdf_a.get("href") and pdf_a.get("href").endswith("/pdf"):
                pdf_url = urljoin(BASE_URL, pdf_a.get("href"))
                break
        # Extract CVEs from description
        cves = []
        if description:
            cves = re.findall(r"CVE-\d{4}-\d+", description)
        # Extract CVSS scores from description
        cvss_scores = []
        if description:
            for score in re.findall(r"CVSS(?:v3)?(?: score)?(?: of)? ([0-9]+\.[0-9]+)", description):
                try:
                    cvss_scores.append(float(score))
                except Exception:
                    pass
        # Parse date to ISO8601
        date_iso = None
        if date:
            try:
                from dateutil import parser as dateparser
                date_iso = dateparser.parse(date).isoformat()
            except Exception:
                date_iso = None
        advisories.append({
            "id": advisory_id,
            "title": title,
            "date": date,
            "date_iso": date_iso,
            "description": description,
            "advisory_url": advisory_url,
            "pdf_url": pdf_url,
            "cves": cves,
            "cvss_scores": cvss_scores
        })
    return advisories

def main():
    all_advisories = []
    raw_htmls = {}
    cache_dir = os.path.join("/etl-data/cache/cert_eu")
    os.makedirs(cache_dir, exist_ok=True)
    for year in range(START_YEAR, END_YEAR + 1):
        try:
            html = fetch_year(year)
            raw_htmls[str(year)] = html
            # Save raw HTML for manual review with timestamp and year in filename
            cache_filename = f"security_advisories_{year}_{TS}.html"
            with open(os.path.join(cache_dir, cache_filename), "w", encoding="utf-8") as f:
                f.write(html)
            advisories = parse_advisories(html)
            all_advisories.extend(advisories)
        except Exception as e:
            logging.warning(f"Failed to fetch/parse {year}: {e}")
    # Atomic write for raw HTML output
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
    raw_path = save_json(raw_htmls, RAW_DATA_DIR, "cert_eu_advisories_raw")
    logging.info(f"Raw HTML for all years saved to {raw_path}")
    # Convert to OSV schema using osv_normalizer
    osv_records = []
    field_map = {
        "summary": "title",
        "details": "description",
        "modified": "date_iso",
        "references": "references"
    }
    id_fields = ["id"]
    for adv in all_advisories:
        # Compose references field for OSV
        refs = []
        if adv.get("advisory_url"):
            refs.append({"type": "ADVISORY", "url": adv["advisory_url"]})
        if adv.get("pdf_url"):
            refs.append({"type": "PDF", "url": adv["pdf_url"]})
        adv["references"] = refs
        osv_record = osv_normalizer.create_osv_record(
            adv,
            feed_name="cert_eu_advisories",
            field_map=field_map,
            id_fields=id_fields,
            extra_fields=["cves", "cvss_scores", "date", "date_iso"]
        )
        # Add severity if present
        if adv.get("cvss_scores"):
            osv_record["severity"] = [
                {"type": "CVSS_V3", "score": str(score)} for score in adv["cvss_scores"]
            ]
        # Add published date if available
        if adv.get("date_iso"):
            osv_record["published"] = adv["date_iso"]
        osv_records.append(osv_record)
    norm_path = save_json(osv_records, NORM_DATA_DIR, "cert_eu_advisories_norm")
    logging.info(f"Normalized advisories saved to {norm_path}")
    # Use verify module for record count and ID checks
    try:
        verify.verify_record_count([a for year in raw_htmls.values() for a in parse_advisories(year)], all_advisories)
        if all_advisories and 'id' in all_advisories[0]:
            verify.verify_ids([a for year in raw_htmls.values() for a in parse_advisories(year)], all_advisories, raw_id_key='id', norm_id_key='id')
    except Exception as e:
        logging.warning(f"Verification failed: {e}")

if __name__ == "__main__":
    main()
