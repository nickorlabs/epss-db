"""
update_open_cvdb.py

Aggregates vulnerability advisories from the Open Cloud Vulnerability DB GitHub repository, normalizes them to OSV format,
and saves both raw and normalized outputs with timestamps. Follows the standardized GitHub ETL template.

- Source: https://github.com/wiz-sec/open-cvdb
- Output: Raw advisories (JSON) and normalized advisories (OSV JSON)
"""
import os
import json
import logging
import argparse
import shutil
from glob import glob
from datetime import datetime
import yaml
from common.io_utils import safe_write_json

NORMALIZED_DATA_DIR = os.environ.get('NORMALIZED_DATA_DIR', '/etl-data/normalized')

from common.git_utils import ensure_git_repo_latest
from common.osv_normalizer import create_osv_record
from common import verify

REPO_URL = os.environ.get("OPEN_CVDB_REPO_URL", "https://github.com/wiz-sec/open-cvdb.git")
REPO_DIR = os.environ.get("OPEN_CVDB_REPO_DIR", "/etl-data/cache/open-cvdb")
RAW_DIR = os.environ.get("RAW_DIR", "/etl-data/raw/open_cvdb")
NORM_DIR = os.environ.get("NORM_DIR", "/etl-data/norm/open_cvdb")

def get_advisory_files(base_dir):
    patterns = [os.path.join(base_dir, "**", "*.yaml"), os.path.join(base_dir, "**", "*.yml"), os.path.join(base_dir, "**", "*.json")]
    files = []
    for pattern in patterns:
        files.extend(glob(pattern, recursive=True))
    return files

def find_all_advisory_files(base_dir):
    patterns = [os.path.join(base_dir, "**", "*.yaml"), os.path.join(base_dir, "**", "*.yml"), os.path.join(base_dir, "**", "*.json")]
    files = []
    for pattern in patterns:
        files.extend(glob(pattern, recursive=True))
    return files

def load_advisories(files):
    advisories = []
    for path in files:
        try:
            if path.endswith((".yaml", ".yml")):
                with open(path, "r") as f:
                    advisories.append(yaml.safe_load(f))
            elif path.endswith(".json"):
                with open(path, "r") as f:
                    advisories.append(json.load(f))
        except Exception as e:
            logging.warning(f"Failed to load {path}: {e}")
    return advisories

def dump_json(data, path, label="data"):
    safe_write_json(path, data, indent=2)
    logging.info(f"Dumped {label} to {path}")

def main():
    parser = argparse.ArgumentParser(description="Aggregate and normalize Open Cloud Vulnerability DB advisories.")
    parser.add_argument('--cleanup-repo', action='store_true', help='Remove the Open Cloud Vulnerability DB repo after aggregation to save space')
    args = parser.parse_args()

    logging.info("Updating Open Cloud Vulnerability DB repository ...")
    ensure_git_repo_latest(REPO_URL, REPO_DIR)

    files = get_advisory_files(REPO_DIR)
    logging.info(f"Found {len(files)} Open Cloud Vulnerability DB advisory files in repo.")

    advisories = load_advisories(files)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    raw_out = os.path.join(RAW_DIR, f"open_cvdb_raw_{timestamp}.json")
    dump_json(advisories, raw_out, label="raw advisories")
    logging.info(f"Saved {len(advisories)} raw advisories.")

    # Normalize advisories
    norm_records = []
    for raw in advisories:
        try:
            # Use 'slug' as the unique OSV id
            osv_id = raw.get("slug")
            if not osv_id:
                osv_id = f"generated:{abs(hash(str(raw)))%10**12}"

            # Use 'summary' as both summary and description
            summary = raw.get("summary", "")
            description = summary

            # Aliases: use cves as a list, or empty list if null
            aliases = raw.get("cves")
            if not aliases:
                aliases = []
            elif isinstance(aliases, str):
                aliases = [aliases]

            # Published date: use publishedAt if present, else disclosedAt; convert to RFC3339 if needed
            published = raw.get("publishedAt") or raw.get("disclosedAt")
            if published and "/" in published:
                # Convert from YYYY/MM/DD to YYYY-MM-DDT00:00:00Z
                try:
                    parts = published.split("/")
                    if len(parts) == 3:
                        published = f"{parts[0]}-{parts[1].zfill(2)}-{parts[2].zfill(2)}T00:00:00Z"
                except Exception:
                    pass

            # Severity
            severity = raw.get("severity")
            if severity:
                severity_list = [{"type": "text", "score": str(severity)}]
            else:
                severity_list = []

            # Affected: combine platforms and services
            affected = []
            platforms = raw.get("affectedPlatforms") or []
            services = raw.get("affectedServices") or []
            if platforms or services:
                affected.append({"platforms": platforms, "services": services})

            # References
            references = []
            refs = raw.get("references") or []
            for ref in refs:
                references.append({"type": "ARTICLE", "url": ref})

            # Credits
            credits = []
            discovered_by = raw.get("discoveredBy")
            contributor = raw.get("contributor")
            if discovered_by:
                credit = {"name": discovered_by.get("name") or "", "contact": []}
                if discovered_by.get("org"):
                    credit["organization"] = discovered_by["org"]
                if contributor:
                    credit["contact"].append(contributor)
                credits.append(credit)
            elif contributor:
                credits.append({"name": contributor, "contact": [contributor]})

            # Prepare database_specific with all other fields
            std_fields = {"slug", "summary", "cves", "publishedAt", "disclosedAt", "severity", "affectedPlatforms", "affectedServices", "references", "discoveredBy", "contributor"}
            database_specific = {k: v for k, v in raw.items() if k not in std_fields}
            database_specific['source_type'] = "Open Cloud Vulnerability DB"

            osv = {
                "id": osv_id,
                "summary": summary,
                "description": description,
                "published": published or "",
                "aliases": aliases,
                "severity": severity_list,
                "affected": affected,
                "references": references,
                "credits": credits,
                "database_specific": database_specific
            }
            norm_records.append(osv)
        except Exception as e:
            logging.warning(f"Failed to normalize advisory: {e}")
    norm_output_path = os.path.join(NORMALIZED_DATA_DIR, f"open_cvdb_norm_{timestamp}.json")
    dump_json(norm_records, norm_output_path, label="normalized advisories")
    logging.info(f"Saved {len(norm_records)} normalized advisories.")

    # --- Verification ---
    try:
        verify.verify_record_count(advisories, norm_records)
        verify.verify_ids(advisories, norm_records, raw_id_key='slug', norm_id_key='id')
        verify.verify_field_presence(norm_records, ['id', 'summary', 'description'])
    except Exception as e:
        logging.warning(f"Verification failed: {e}")

    if args.cleanup_repo:
        shutil.rmtree(REPO_DIR)
        logging.info(f"Removed Open Cloud Vulnerability DB repo at {REPO_DIR} to save space.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    main()
