from etl.common.secrets import load_api_key
from etl.common.api import fetch_paginated
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
        "enrichment": {"source": "vulncheck-nist-nvd2"},
        "raw": src
    }

def main():
    setup_logging()
    api_key = load_api_key("vulncheck_api_key", "VULNCHECK_API_TOKEN")
    configuration = vulncheck_sdk.Configuration(host=DEFAULT_API)
    configuration.api_key["Bearer"] = api_key
    with vulncheck_sdk.ApiClient(configuration) as api_client:
        indices_client = vulncheck_sdk.IndicesApi(api_client)
        all_records = fetch_paginated(indices_client.index_nist_nvd2_get, limit=300)
    print(f"Fetched {len(all_records)} NIST NVD v2 records from VulnCheck")
    normalized = [normalize(entry) for entry in all_records]
    output_path = "/etl-data/vulncheck_nist_nvd2_dump.json"
    write_json(normalized, output_path)
    print(f"Dumped normalized NIST NVD v2 data to {output_path}")

if __name__ == "__main__":
    main()
