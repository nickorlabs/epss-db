import os
import json
import logging
import argparse
import subprocess
from glob import glob
import shutil
import yaml

REPO_URL = "https://github.com/wiz-sec/open-cvdb.git"
REPO_PATH = "/etl-data/opencvdb/open-cvdb"
DUMP_PATH = "/etl-data/raw/opencvdb_raw_dump.json"

def ensure_repo():
    if not os.path.isdir(REPO_PATH):
        logging.info(f"Cloning Open-CVDB repo to {REPO_PATH} ...")
        subprocess.run(["git", "clone", "--depth", "1", REPO_URL, REPO_PATH], check=True)
    else:
        logging.info(f"Updating Open-CVDB repo in {REPO_PATH} ...")
        subprocess.run(["git", "-C", REPO_PATH, "pull"], check=True)

def find_all_advisory_files(base_dir):
    patterns = [os.path.join(base_dir, "**", "*.yaml"), os.path.join(base_dir, "**", "*.yml"), os.path.join(base_dir, "**", "*.json")]
    files = []
    for pattern in patterns:
        files.extend(glob(pattern, recursive=True))
    return files

def aggregate_advisories(files):
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

def dump_json(data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    logging.info(f"Dumped Open-CVDB advisories to {path}")

def main():
    parser = argparse.ArgumentParser(description="Aggregate Open-CVDB advisories and dump to file.")
    parser.add_argument('--dump-path', default=DUMP_PATH, help='Where to dump the aggregated Open-CVDB advisories')
    parser.add_argument('--cleanup-repo', action='store_true', help='Remove the Open-CVDB repo after aggregation to save space')
    args = parser.parse_args()
    ensure_repo()
    files = find_all_advisory_files(REPO_PATH)
    logging.info(f"Found {len(files)} Open-CVDB advisory files in repo.")
    advisories = aggregate_advisories(files)
    dump_json(advisories, args.dump_path)
    logging.info(f"Aggregated and dumped {len(advisories)} Open-CVDB advisories.")
    if args.cleanup_repo:
        shutil.rmtree(REPO_PATH)
        logging.info(f"Removed Open-CVDB repo at {REPO_PATH} to save space.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    main()
