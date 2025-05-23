import os
import requests
import zipfile
import io
import logging
import xml.etree.ElementTree as ET
import json

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw")
CPE_FEED_URL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"
OUTPUT_XML = os.path.join(RAW_DATA_DIR, "cpe_dictionary.xml")
OUTPUT_JSON = os.path.join(RAW_DATA_DIR, "cpe_dictionary.json")
OUTPUT_CVE2CPE = os.path.join(RAW_DATA_DIR, "cve_to_cpe.json")
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex=0"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

import time

def fetch_cpe_dictionary():
    logging.info(f"Downloading CPE dictionary from {CPE_FEED_URL}")
    resp = requests.get(CPE_FEED_URL, stream=True, timeout=120)
    resp.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
        for name in z.namelist():
            if name.endswith(".xml"):
                logging.info(f"Extracting {name} from ZIP")
                with z.open(name) as f_in, open(OUTPUT_XML, "wb") as f_out:
                    f_out.write(f_in.read())
                logging.info(f"Saved CPE dictionary XML to {OUTPUT_XML}")
                break
        else:
            raise RuntimeError("No XML file found in CPE dictionary ZIP archive.")

    # Parse XML and convert to JSON
    logging.info("Parsing XML and converting to JSON...")
    tree = ET.parse(OUTPUT_XML)
    root = tree.getroot()
    cpes = []
    ns = {'cpe-dict': 'http://cpe.mitre.org/dictionary/2.0'}
    for cpe_item in root.findall('.//cpe-dict:cpe-item', ns):
        name = cpe_item.get('name')
        title_elem = cpe_item.find('cpe-dict:title', ns)
        title = title_elem.text if title_elem is not None else None
        cpes.append({'name': name, 'title': title})
    with open(OUTPUT_JSON, 'w') as f:
        json.dump(cpes, f)
    logging.info(f"Extracted and wrote {len(cpes)} CPE items to {OUTPUT_JSON}")

    # --- CVE-to-CPE Mapping Extraction ---
    logging.info("Extracting CVE-to-CPE mapping from NVD 2.0 API (all pages)...")
    cve2cpe = {}
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"resultsPerPage": 2000, "startIndex": 0}
    total_results = None
    processed = 0
    # Load NVD API key from Docker secret or env var
    api_key = None
    secret_path = "/run/secrets/nvd_api_key"
    if os.path.exists(secret_path):
        with open(secret_path) as f:
            api_key = f.read().strip()
    else:
        api_key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.7 if api_key else 6.1  # NVD recommends 50 req/30s (API key) or 5 req/30s (no key)
    session = requests.Session()
    backoff_base = 5
    while True:
        try:
            resp = session.get(api_url, params=params, headers=headers, timeout=180)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", backoff_base))
                logging.warning(f"429 Too Many Requests: sleeping for {retry_after} seconds...")
                time.sleep(retry_after)
                backoff_base = min(backoff_base * 2, 120)  # Exponential backoff, max 2 min
                continue
            resp.raise_for_status()
            backoff_base = 5  # Reset backoff after success
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}. Sleeping for {backoff_base} seconds and retrying...")
            time.sleep(backoff_base)
            backoff_base = min(backoff_base * 2, 120)
            continue
        data = resp.json()
        if total_results is None:
            total_results = data.get("totalResults", 0)
            logging.info(f"NVD reports {total_results} CVEs to process.")
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break
        for item in vulns:
            cve_id = item.get('cve', {}).get('id')
            cpes = set()
            configs = item.get('cve', {}).get('configurations', [])
            for config in configs:
                for node in config.get('nodes', []):
                    for match in node.get('cpeMatch', []):
                        if match.get('vulnerable', False):
                            cpes.add(match['criteria'])
            if cve_id:
                cve2cpe[cve_id] = sorted(cpes)
        processed += len(vulns)
        logging.info(f"Processed {processed}/{total_results} CVEs...")
        # Pagination: increment startIndex
        if processed >= total_results:
            break
        params["startIndex"] += params["resultsPerPage"]
        time.sleep(delay)
    with open(OUTPUT_CVE2CPE, 'w') as f:
        json.dump(cve2cpe, f)
    logging.info(f"Extracted and wrote CVE-to-CPE mapping for {len(cve2cpe)} CVEs to {OUTPUT_CVE2CPE}")
    return OUTPUT_JSON

if __name__ == "__main__":
    fetch_cpe_dictionary()
