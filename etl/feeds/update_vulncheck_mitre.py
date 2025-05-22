from etl.common.secrets import load_api_key
from etl.common.io import write_json
from etl.common.logging import setup_logging
import vulncheck_sdk
import os

print("Files in /run/secrets:", os.listdir("/run/secrets"))

DEFAULT_HOST = "https://api.vulncheck.com"
DEFAULT_API = DEFAULT_HOST + "/v3"

def normalize(entry):
    # Convert to dict if it's a Pydantic model
    if hasattr(entry, "model_dump"):
        src = entry.model_dump()
    elif hasattr(entry, "dict"):
        src = entry.dict()
    else:
        src = entry
    cve_id = src.get("cve", [None])[0]
    unique_id = cve_id or src.get("vulnerability_name") or None
    return {
        "unique_id": unique_id,
        "cve_id": cve_id,
        "description": src.get("description") or src.get("short_description"),
        "published": src.get("published") or src.get("timestamp"),
        "last_modified": src.get("lastModified") or src.get("last_modified"),
        "reference_urls": src.get("references", []) or [r.get("url") for r in src.get("vulncheck_reported_exploitation", []) if r.get("url")],
        "enrichment": {"source": "vulncheck-mitre"},
        "raw": src
    }

def main():
    setup_logging()
    api_key = load_api_key("vulncheck_api_key", "VULNCHECK_API_TOKEN")
    configuration = vulncheck_sdk.Configuration(host=DEFAULT_API)
    configuration.api_key["Bearer"] = api_key
    import logging
    import time
    import json
    import requests
    all_records = []
    cursor = None
    page = 0
    while True:
        full_url = f"{DEFAULT_API}/index/mitre-cvelist-v5"
        params = {"limit": 300}
        if cursor:
            params["cursor"] = cursor
        else:
            params["start_cursor"] = "true"
        headers = {
            "Authorization": f"Bearer {api_key}"
        }
        from urllib.parse import urlencode
        qstring = urlencode(params)
        url_with_params = f"{full_url}?{qstring}"
        print(f"Fetching: {url_with_params}")
        resp = requests.get(url_with_params, headers=headers)
        if resp.status_code != 200 or not resp.content:
            logging.error(f"Request failed. URL: {url_with_params} Status: {resp.status_code}, Reason: {resp.reason}, Body: {resp.content!r}")
            break
        data = resp.json()
        page_records = data.get("data", [])
        all_records.extend(page_records)
        print(f"Fetched page {page+1}: {len(page_records)} records (total: {len(all_records)})")
        cursor = data.get("_meta", {}).get("next_cursor")
        page += 1
        if not cursor:
            break
        time.sleep(0.2)  # be nice to the API
    print(f"Fetched {len(all_records)} MITRE CVE List v5 records from VulnCheck (before normalization)")
    normalized = []
    failed = 0
    for entry in all_records:
        try:
            normalized.append(normalize(entry))
        except Exception as e:
            failed += 1
            logging.error(f"Normalization failed for entry: {entry.get('cve', None) or entry.get('id', None)}: {e}")
    print(f"Successfully normalized {len(normalized)} records. Failed: {failed}")
    output_path = "/etl-data/vulncheck_mitre_dump.json"
    write_json(normalized, output_path)
    print(f"Dumped normalized MITRE CVE List v5 data to {output_path}")

if __name__ == "__main__":
    main()
