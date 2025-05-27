"""
Sigma Rules ETL
Downloads and parses the Sigma rules repo for CVE references in detection rules.
"""

import os
import logging

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw")
OUTPUT_JSON = os.path.join(RAW_DATA_DIR, "sigma_rules.json")
FULL_OUTPUT_JSON = os.path.join(RAW_DATA_DIR, "sigma_rules_full.json")
CVE_MAP_JSON = os.path.join(RAW_DATA_DIR, "sigma_rules_cve_map.json")
REPO_URL = "https://github.com/SigmaHQ/sigma.git"
# TODO: Implement git clone/pull and parse rules for CVEs

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

import subprocess
import tempfile
import shutil
import yaml

SIGMA_REPO_DIR = os.path.join(RAW_DATA_DIR, "sigma_repo")


def fetch_sigma_rules():
    # Clone or pull the Sigma repo
    if not os.path.exists(SIGMA_REPO_DIR):
        logging.info(f"Cloning Sigma rules repo to {SIGMA_REPO_DIR}")
        subprocess.run(["git", "clone", "--depth=1", REPO_URL, SIGMA_REPO_DIR], check=True)
    else:
        logging.info(f"Updating Sigma rules repo in {SIGMA_REPO_DIR}")
        subprocess.run(["git", "-C", SIGMA_REPO_DIR, "pull"], check=True)

    sigma_files = []
    for root, dirs, files in os.walk(SIGMA_REPO_DIR):
        for file in files:
            if file.endswith(".yml") or file.endswith(".yaml"):
                sigma_files.append(os.path.join(root, file))

    all_rules = []
    cve_results = []
    cve_map = {}
    for path in sigma_files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = yaml.safe_load(f)
            if not isinstance(doc, dict):
                continue
            # Add file path for traceability
            doc["_file"] = path
            all_rules.append(doc)

            # CVE extraction (for mapping)
            rule_id = doc.get("id") or os.path.basename(path)
            title = doc.get("title")
            description = doc.get("description")
            references = doc.get("references", [])
            cves = set()
            for ref in references:
                if isinstance(ref, str) and ref.upper().startswith("CVE-"):
                    cves.add(ref.upper())
            tags = doc.get("tags", [])
            for tag in tags:
                if isinstance(tag, str) and tag.upper().startswith("CVE-"):
                    cves.add(tag.upper())
            import re
            CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
            for text in [description, title]:
                if text:
                    cves.update([cve.upper() for cve in CVE_REGEX.findall(text)])
            if cves:
                cve_results.append({
                    "rule_id": rule_id,
                    "title": title,
                    "description": description,
                    "file": path,
                    "cves": sorted(cves),
                })
                for cve in cves:
                    cve_map.setdefault(cve, []).append(rule_id)
        except Exception as e:
            logging.warning(f"Failed to parse {path}: {e}")

    os.makedirs(os.path.dirname(FULL_OUTPUT_JSON), exist_ok=True)
    # Write full rules
    import json
    from datetime import date, datetime

    def convert(obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, dict):
            return {k: convert(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [convert(v) for v in obj]
        return obj

    all_rules_serializable = convert(all_rules)
    with open(FULL_OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(all_rules_serializable, f, indent=2)
    logging.info(f"Extracted {len(all_rules)} Sigma rules to {FULL_OUTPUT_JSON}")
    # Write CVE mapping
    with open(CVE_MAP_JSON, "w", encoding="utf-8") as f:
        json.dump({"cve_to_rules": cve_map, "rules_with_cves": cve_results}, f, indent=2)
    logging.info(f"Extracted {len(cve_results)} Sigma rules with CVE references to {CVE_MAP_JSON}")
    return FULL_OUTPUT_JSON

if __name__ == "__main__":
    fetch_sigma_rules()
