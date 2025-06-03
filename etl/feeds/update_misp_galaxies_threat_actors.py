"""
MISP Galaxies - Threat Actors ETL
Downloads and parses the public MISP galaxy JSON for threat actor ↔ CVE mappings.
"""

import os
import requests
import json
import logging

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/common-data/raw")
OUTPUT_JSON = os.path.join(RAW_DATA_DIR, "misp_galaxies_threat_actors.json")
FULL_OUTPUT_JSON = os.path.join(RAW_DATA_DIR, "misp_galaxies_threat_actors_full.json")
MISP_GALAXY_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def fetch_misp_galaxies_threat_actors():
    r = requests.get(MISP_GALAXY_URL)
    r.raise_for_status()
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        f.write(r.text)
    logging.info(f"Fetched and wrote threat actor galaxy to {OUTPUT_JSON}")

    # Parse all threat actor objects (full dump)
    data = r.json()
    all_actors = data.get("values", [])
    os.makedirs(os.path.dirname(FULL_OUTPUT_JSON), exist_ok=True)
    with open(FULL_OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(all_actors, f, indent=2)
    logging.info(f"Extracted {len(all_actors)} threat actors to {FULL_OUTPUT_JSON}")

    # Extract actor ↔ CVE mappings (normalized)
    actor_cve_map = {}
    for obj in all_actors:
        name = obj.get("value") or obj.get("name")
        cves = set()
        meta = obj.get("meta", {})
        for k, v in meta.items():
            if isinstance(v, list):
                for x in v:
                    if isinstance(x, str) and x.upper().startswith("CVE-"):
                        cves.add(x.upper())
            elif isinstance(v, str) and v.upper().startswith("CVE-"):
                cves.add(v.upper())
        import re
        CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
        for field in [obj.get("description", "")] + obj.get("synonyms", []):
            if field:
                cves.update([cve.upper() for cve in CVE_REGEX.findall(field)])
        if cves and name:
            actor_cve_map[name] = sorted(cves)

    norm_path = os.path.join(RAW_DATA_DIR, "../normalized/misp_galaxies_actor_cve_map.json")
    norm_path = os.path.abspath(norm_path)
    os.makedirs(os.path.dirname(norm_path), exist_ok=True)
    with open(norm_path, "w", encoding="utf-8") as f:
        json.dump(actor_cve_map, f, indent=2)
    logging.info(f"Extracted {len(actor_cve_map)} actors with CVE mappings to {norm_path}")
    return FULL_OUTPUT_JSON

if __name__ == "__main__":
    fetch_misp_galaxies_threat_actors()
