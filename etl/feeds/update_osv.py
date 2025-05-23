import os
import requests
import logging
import json

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw")
OSV_FEED_URL = "https://osv-vulnerabilities.storage.googleapis.com/all.zip"
OUTPUT_JSON = os.path.join(RAW_DATA_DIR, "osv_all.json")
OUTPUT_CVE_MAP_JSON = os.path.join(RAW_DATA_DIR, "osv_cve_map.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def fetch_osv():
    import zipfile
    import io
    logging.info(f"Downloading OSV all.zip from {OSV_FEED_URL}")
    resp = requests.get(OSV_FEED_URL, timeout=180)
    resp.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
        osv_records = []
        cve_map = {}
        for name in z.namelist():
            if name.endswith(".json"):
                with z.open(name) as f:
                    try:
                        doc = json.load(f)
                        osv_records.append(doc)
                        # OSV advisories can have CVE(s) in 'aliases'
                        for alias in doc.get('aliases', []):
                            if alias.startswith('CVE-'):
                                cve_map.setdefault(alias, []).append(doc.get('id'))
                    except Exception as e:
                        logging.warning(f"Failed to parse {name}: {e}")
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(osv_records, f)
    with open(OUTPUT_CVE_MAP_JSON, 'w', encoding='utf-8') as f:
        json.dump(cve_map, f)
    logging.info(f"Extracted {len(osv_records)} OSV advisories and {len(cve_map)} CVE mappings.")

if __name__ == "__main__":
    fetch_osv()
