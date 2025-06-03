from common.common.secrets import load_api_key
from common.common.api import fetch_paginated
from common.common.io import write_json
from common.common.logging import setup_logging
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
    # Get CVE ID from the first element of the 'cve' list, if present
    cve_list = src.get("cve", [])
    cve_id = cve_list[0] if cve_list else None
    unique_id = cve_id or src.get("vulnerability_name") or None
    return {
        "unique_id": unique_id,
        "cve_id": cve_id,
        "description": src.get("short_description"),
        "published": src.get("timestamp"),
        "last_modified": None,
        "reference_urls": [r.get("url") for r in src.get("vulncheck_reported_exploitation", []) if r.get("url")],
        "enrichment": {"kev": True, "source": "vulncheck-kev"},
        "raw": src
    }

def main():
    setup_logging()
    api_key = load_api_key("vulncheck_api_key", "VULNCHECK_API_TOKEN")
    configuration = vulncheck_sdk.Configuration(host=DEFAULT_API)
    configuration.api_key["Bearer"] = api_key
    with vulncheck_sdk.ApiClient(configuration) as api_client:
        indices_client = vulncheck_sdk.IndicesApi(api_client)
        all_records = fetch_paginated(indices_client.index_vulncheck_kev_get, limit=300)
    print(f"Fetched {len(all_records)} KEV records from VulnCheck")
    # Dump raw API response
    raw_output_path = "/etl-data/raw/vulncheck_kev_api_raw_dump.json"
    def to_dict(entry):
        if hasattr(entry, "model_dump"):
            return entry.model_dump()
        elif hasattr(entry, "dict"):
            return entry.dict()
        elif isinstance(entry, dict):
            return entry
        else:
            return dict(entry)
    write_json([to_dict(e) for e in all_records], raw_output_path)
    print(f"Dumped raw VulnCheck KEV API data to {raw_output_path}")
    # Normalize and dump
    normalized = [normalize(entry) for entry in all_records]
    normalized_output_path = "/etl-data/normalized/vulncheck_kev_normalized_dump.json"
    write_json(normalized, normalized_output_path)
    print(f"Dumped normalized KEV data to {normalized_output_path}")

if __name__ == "__main__":
    main()

def normalize(entry):
    return {
        "cve_id": entry.get("cveID"),
        "description": entry.get("description"),
        "published": entry.get("published"),
        "last_modified": entry.get("lastModified"),
        "reference_urls": json.dumps(entry.get("references", [])),
        "enrichment": json.dumps({"kev": True, "source": "vulncheck-kev"}),
    }


