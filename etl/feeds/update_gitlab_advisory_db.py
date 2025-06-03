import os
import subprocess
import logging
import json
import tempfile

from datetime import datetime
RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw/gitlab_advisory_db")
NORM_DATA_DIR = os.environ.get("NORM_DATA_DIR", "/etl-data/normalized/gitlab_advisory_db")
CACHE_DIR = os.environ.get("CACHE_DIR", "/etl-data/cache/gitlab_advisory_db")
GITLAB_DB_REPO = "https://gitlab.com/gitlab-org/security-products/gemnasium-db.git"
TIMESTAMP = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
RAW_OUTPUT_JSON = os.path.join(RAW_DATA_DIR, f"gitlab_advisories_{TIMESTAMP}.json")
NORM_OUTPUT_JSON = os.path.join(NORM_DATA_DIR, f"gitlab_advisories_norm_{TIMESTAMP}.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def fetch_gitlab_advisories():
    # Clone or update the repo in cache
    if not os.path.exists(CACHE_DIR):
        logging.info(f"Cloning GitLab Advisory Database repo to {CACHE_DIR}")
        os.makedirs(CACHE_DIR, exist_ok=True)
        subprocess.run(["git", "clone", "--depth=1", GITLAB_DB_REPO, CACHE_DIR], check=True)
    else:
        logging.info(f"Pulling latest GitLab Advisory Database repo in {CACHE_DIR}")
        subprocess.run(["git", "-C", CACHE_DIR, "pull"], check=True)

    advisories = []
    for root, dirs, files in os.walk(CACHE_DIR):
        for file in files:
            if file.endswith(".yml") or file.endswith(".yaml"):
                full_path = os.path.join(root, file)
                try:
                    import yaml
                    with open(full_path, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        advisories.append(data)
                except Exception as e:
                    logging.warning(f"Failed to parse {full_path}: {e}")
    os.makedirs(os.path.dirname(RAW_OUTPUT_JSON), exist_ok=True)
    with open(RAW_OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(advisories, f)
    logging.info(f"Extracted and wrote {len(advisories)} GitLab advisories to {RAW_OUTPUT_JSON}")

    # Normalization stub (pass-through for now)
    norm_advisories = advisories
    os.makedirs(os.path.dirname(NORM_OUTPUT_JSON), exist_ok=True)
    with open(NORM_OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(norm_advisories, f)
    logging.info(f"Wrote {len(norm_advisories)} normalized GitLab advisories to {NORM_OUTPUT_JSON}")

    # Verification
    from common import verify
    try:
        verify.verify_record_count(advisories, norm_advisories)
        # If advisories have 'id' fields, do ID verification; else skip
        if advisories and 'id' in advisories[0] and norm_advisories and 'id' in norm_advisories[0]:
            verify.verify_ids(advisories, norm_advisories, raw_id_key='id', norm_id_key='id')
    except Exception as e:
        logging.warning(f"Verification failed: {e}")

if __name__ == "__main__":
    fetch_gitlab_advisories()
