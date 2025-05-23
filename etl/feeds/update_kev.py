import os
import requests
import logging
import argparse

# Set up logging
ENV = os.environ.get('ENV', 'development').lower()
LOG_LEVEL = logging.INFO if ENV == 'production' else logging.DEBUG
logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s %(levelname)s %(message)s')

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DUMP_PATH = '/etl-data/raw/kev_cisa_raw_dump.json'


def fetch_kev_json():
    logging.info(f"Downloading KEV JSON from {KEV_URL} ...")
    resp = requests.get(KEV_URL)
    resp.raise_for_status()
    return resp.json()


def dump_json(data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        import json
        json.dump(data, f, indent=2)
    logging.info(f"Dumped KEV data to {path}")


def main():
    parser = argparse.ArgumentParser(description="Download raw CISA KEV JSON and dump to file.")
    parser.add_argument('--dump-path', default=DUMP_PATH, help='Where to dump the raw KEV JSON (default: etl-data/kev_dump.json)')
    args = parser.parse_args()
    data = fetch_kev_json()
    dump_json(data, args.dump_path)
    vulns = data.get('vulnerabilities', [])
    logging.info(f"Fetched {len(vulns)} vulnerabilities from KEV.")


if __name__ == "__main__":
    main()
