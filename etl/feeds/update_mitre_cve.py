import os
import json
import logging
import argparse
from glob import glob
import shutil
import subprocess

SOURCE_TYPE = "github"

# Set up logging
ENV = os.environ.get('ENV', 'development').lower()
LOG_LEVEL = logging.INFO if ENV == 'production' else logging.DEBUG
logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s %(levelname)s %(message)s')

MITRE_REPO_URL = 'https://github.com/CVEProject/cvelistV5.git'
MITRE_REPO_PATH = '/etl-data/cache/mitre/cvelistV5'
MITRE_REPO_CVES = os.path.join(MITRE_REPO_PATH, 'cves')
from datetime import datetime
RAW_DATA_DIR = os.environ.get('RAW_DATA_DIR', '/etl-data/raw/mitre_cve')
DUMP_PATH = os.path.join(RAW_DATA_DIR, f"mitre_cvelist_raw_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json")


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
    from common.io_utils import safe_write_json
    safe_write_json(path, data, indent=2)
    logging.info(f"Dumped MITRE CVE List to {path}")

NORMALIZED_DATA_DIR = os.environ.get('NORMALIZED_DATA_DIR', '/etl-data/normalized/mitre_cve')

def dump_normalized_json(data):
    from datetime import datetime
    from common.io_utils import safe_write_json
    timestamp = datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
    norm_out = os.path.join(NORMALIZED_DATA_DIR, f"mitre_norm_{timestamp}.json")
    safe_write_json(norm_out, data, indent=2)
    logging.info(f"Dumped normalized MITRE CVE List to {norm_out}")

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
    # Normalize CVE records inline (no external function)
    norm_records = []
    for rec in cves:
        cve_id = rec.get('cveMetadata', {}).get('cveId') or rec.get('CVE_data_meta', {}).get('ID')
        aliases = []
        for k in ['aliases', 'relatedCVE', 'related_cve', 'related_ids']:
            vals = rec.get(k)
            if vals:
                if isinstance(vals, str):
                    vals = [vals]
                for v in vals:
                    if v and v != cve_id and v not in aliases:
                        aliases.append(v)
        database_specific = {k: v for k, v in rec.items() if k not in ['cveMetadata', 'CVE_data_meta', 'description', 'references', 'affects', 'aliases', 'relatedCVE', 'related_cve', 'related_ids']}
        database_specific['source_type'] = SOURCE_TYPE
        norm_obj = {
            'id': cve_id,
            'aliases': aliases,
            'summary': rec.get('description', {}).get('description_data', [{}])[0].get('value', cve_id) if 'description' in rec else cve_id,
            'details': rec.get('description', {}).get('description_data', [{}])[0].get('value', ''),
            'references': rec.get('references', {}).get('reference_data', []) if 'references' in rec else [],
            'affected': rec.get('affects', []),
            'database_specific': database_specific
        }
        norm_records.append(norm_obj)

    dump_normalized_json(norm_records)
    logging.info(f"Normalized and dumped {len(norm_records)} MITRE CVEs.")

    # Verification step
    from common import verify
    try:
        verify.verify_record_count(cves, norm_records)
        verify.verify_ids(cves, norm_records, raw_id_key='cveMetadata.cveId', norm_id_key='id')
    except Exception as e:
        logging.warning(f"Verification failed: {e}")
    if args.cleanup_repo:
        shutil.rmtree(MITRE_REPO_PATH)
        logging.info(f"Removed MITRE repo at {MITRE_REPO_PATH} to save space.")

if __name__ == "__main__":
    main()
