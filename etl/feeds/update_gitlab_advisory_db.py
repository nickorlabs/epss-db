import os
import subprocess
import logging
import json
import tempfile

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw")
GITLAB_DB_REPO = "https://gitlab.com/gitlab-org/security-products/gemnasium-db.git"
OUTPUT_JSON = os.path.join(RAW_DATA_DIR, "gitlab_advisories.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def fetch_gitlab_advisories():
    with tempfile.TemporaryDirectory() as tmpdir:
        logging.info(f"Cloning GitLab Advisory Database repo to {tmpdir}")
        subprocess.run(["git", "clone", "--depth=1", GITLAB_DB_REPO, tmpdir], check=True)
        advisories = []
        for root, dirs, files in os.walk(tmpdir):
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
        with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
            json.dump(advisories, f)
        logging.info(f"Extracted and wrote {len(advisories)} GitLab advisories to {OUTPUT_JSON}")

if __name__ == "__main__":
    fetch_gitlab_advisories()
