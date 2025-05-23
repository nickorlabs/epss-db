import os
import logging
import json
import subprocess

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw")
VULNREPO_URL = "https://github.com/cisagov/vulnrichment.git"
OUTPUT_JSON = os.path.join(RAW_DATA_DIR, "cisa_vulnrichment_full.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def fetch_cisa_vulnrichment():
    repo_dir = os.path.join(RAW_DATA_DIR, "cisa_vulnrichment_repo")
    if not os.path.exists(repo_dir):
        logging.info(f"Cloning CISA Vulnrichment repo to {repo_dir}")
        subprocess.run(["git", "clone", "--depth=1", VULNREPO_URL, repo_dir], check=True)
    else:
        logging.info(f"Updating CISA Vulnrichment repo in {repo_dir}")
        subprocess.run(["git", "-C", repo_dir, "pull"], check=True)

    # Recursively find all .json files (excluding .github, test, or draft folders)
    vuln_files = []
    for root, dirs, files in os.walk(repo_dir):
        # Skip .git and .github and test/example folders
        if any(skip in root for skip in ['.git', '.github', 'test', 'example']):
            continue
        for file in files:
            if file.endswith('.json'):
                vuln_files.append(os.path.join(root, file))
    logging.info(f"Found {len(vuln_files)} JSON files in Vulnrichment repo.")
    records = []
    for fpath in vuln_files:
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                records.append(data)
        except Exception as e:
            logging.warning(f"Failed to parse {fpath}: {e}")
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(records, f)
    logging.info(f"Extracted and wrote {len(records)} CISA Vulnrichment records to {OUTPUT_JSON}")

if __name__ == "__main__":
    fetch_cisa_vulnrichment()
