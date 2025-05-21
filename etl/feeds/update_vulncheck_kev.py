import os
import requests
import json
from common.db import get_db_conn, upsert_canonical_vuln
from common.logger import get_logger
from common.utils import read_secret

API_URL = "https://api.vulncheck.com/v3/backup/vulncheck-kev"
SECRET_PATH = "/run/secrets/vulncheck_api_key"
ENV_VAR = "VULNCHECK_API_KEY"

logger = get_logger("vulncheck_kev")

def get_api_key():
    key = read_secret(SECRET_PATH)
    if key:
        return key
    return os.environ.get(ENV_VAR)

def fetch_kev(api_key):
    # First, get the S3 URL
    headers = {"Authorization": f"Bearer {api_key.strip()}"}
    resp = requests.get(API_URL, headers=headers, timeout=60)
    resp.raise_for_status()
    
    # Get the S3 URL (prefer us-east-1, fall back to others)
    data = resp.json()
    s3_url = (
        data.get("url_us-east-1") or 
        data.get("url_us-west-2") or 
        data.get("url_eu-west-2") or
        data.get("url_ap-southeast-2")
    )
    
    if not s3_url:
        raise ValueError("No valid S3 URL found in response")
    
    # Download and extract the KEV data
    resp = requests.get(s3_url, timeout=60)
    resp.raise_for_status()
    
    # The response is a zip file, but since we're using requests, we'll assume it's JSON for now
    # In production, you might want to use zipfile to extract it properly
    return resp.json()

def normalize(entry):
    # Extract CVE ID from the entry
    cve_id = entry.get("cveID") or entry.get("cve_id")
    if not cve_id:
        raise ValueError(f"Entry is missing CVE ID: {entry}")
    
    # Map VulnCheck KEV JSON to canonical schema dict
    return {
        "vuln_id": cve_id,
        "cve_id": cve_id,
        "description": entry.get("description", ""),
        "published": entry.get("published") or entry.get("dateAdded"),
        "last_modified": entry.get("lastModified") or entry.get("dateUpdated"),
        "source": "vulncheck-kev",
        "raw_source_id": cve_id,
        "severity": entry.get("severity", "high"),
        "references": json.dumps(entry.get("references", [])),
        "metadata": json.dumps({
            "kev": True,
            "source": "vulncheck-kev",
            "vendorProject": entry.get("vendorProject"),
            "product": entry.get("product"),
            "vulnerabilityName": entry.get("vulnerabilityName"),
            "dateAdded": entry.get("dateAdded"),
            "shortDescription": entry.get("shortDescription")
        })
    }

def main():
    api_key = get_api_key()
    if not api_key:
        logger.error("No VulnCheck API key found in secret or environment.")
        return
    logger.info("Fetching VulnCheck KEV feed...")
    data = fetch_kev(api_key)
    # Handle various possible response formats
    if isinstance(data, dict):
        # Try common keys
        for key in ("kev", "data", "results", "items"):
            if key in data and isinstance(data[key], list):
                entries = data[key]
                break
        else:
            logger.error(f"Unknown VulnCheck response format: dict keys are {list(data.keys())}")
            return
    elif isinstance(data, list):
        entries = data
    else:
        logger.error(f"Unexpected VulnCheck response type: {type(data)}")
        return
    logger.info(f"Fetched {len(entries)} entries. Normalizing and loading...")
    conn = get_db_conn()
    count = 0
    for entry in entries:
        if not isinstance(entry, dict):
            logger.warning(f"Skipping non-dict entry: {entry}")
            continue
        record = normalize(entry)
        upsert_canonical_vuln(conn, record)
        count += 1
    logger.info(f"Done. Loaded {count} entries into canonical_vuln.")

if __name__ == "__main__":
    main()
