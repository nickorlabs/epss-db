import os
import json
import logging
import argparse
from glob import glob
import shutil
import subprocess

# Set up logging
ENV = os.environ.get('ENV', 'development').lower()
LOG_LEVEL = logging.INFO if ENV == 'production' else logging.DEBUG
logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s %(levelname)s %(message)s')

MITRE_REPO_URL = 'https://github.com/CVEProject/cvelistV5.git'
MITRE_REPO_PATH = '/etl-data/mitre/cvelistV5'
MITRE_REPO_CVES = os.path.join(MITRE_REPO_PATH, 'cves')
DUMP_PATH = '/etl-data/raw/mitre_cvelist_raw_dump.json'


def ensure_mitre_repo():
    if not os.path.isdir(MITRE_REPO_PATH):
        logging.info(f"Cloning MITRE cvelistV5 repo to {MITRE_REPO_PATH} ...")
        subprocess.run(['git', 'clone', '--depth', '1', MITRE_REPO_URL, MITRE_REPO_PATH], check=True)
    else:
        logging.info(f"Updating MITRE cvelistV5 repo in {MITRE_REPO_PATH} ...")
        subprocess.run(['git', '-C', MITRE_REPO_PATH, 'pull'], check=True)




def find_all_cve_jsons(base_dir):
    pattern = os.path.join(base_dir, '**', 'CVE-*.json')
    files = glob(pattern, recursive=True)
    return files


def aggregate_cve_jsons(files):
    cves = []
    for path in files:
        try:
            with open(path, 'r') as f:
                cve = json.load(f)
                cves.append(cve)
        except Exception as e:
            logging.warning(f"Failed to load {path}: {e}")
    return cves


def dump_json(data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    logging.info(f"Dumped MITRE CVE List to {path}")


def main():
    parser = argparse.ArgumentParser(description="Aggregate MITRE CVE List v5 JSONs from repo and dump to file.")
    parser.add_argument('--dump-path', default=DUMP_PATH, help='Where to dump the aggregated MITRE CVE JSON (default: /etl-data/raw/mitre_cvelist_raw_dump.json)')
    parser.add_argument('--cleanup-repo', action='store_true', help='Remove the MITRE repo after aggregation to save space')
    args = parser.parse_args()
    ensure_mitre_repo()
    files = find_all_cve_jsons(MITRE_REPO_CVES)
    logging.info(f"Found {len(files)} MITRE CVE JSON files in repo.")
    cves = aggregate_cve_jsons(files)
    dump_json(cves, args.dump_path)
    logging.info(f"Aggregated and dumped {len(cves)} MITRE CVEs.")
    if args.cleanup_repo:
        shutil.rmtree(MITRE_REPO_PATH)
        logging.info(f"Removed MITRE repo at {MITRE_REPO_PATH} to save space.")


if __name__ == "__main__":
    main()
