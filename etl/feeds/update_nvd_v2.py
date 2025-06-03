import os
import requests
import logging
import argparse
import time
from common.common.secrets import load_api_key

# Set up logging
ENV = os.environ.get('ENV', 'development').lower()
LOG_LEVEL = logging.INFO if ENV == 'production' else logging.DEBUG
logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s %(levelname)s %(message)s')

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DUMP_DIR = os.path.join(os.path.dirname(__file__), '../../etl-data')
DUMP_PATH = '/etl-data/raw/nvd_nist_raw_dump.json'
API_KEY_SECRET_PATH = "/run/secrets/nvd_api_key"
API_KEY_ENV_VAR = "NVD_API_KEY"


def fetch_nvd_json(api_key, results_per_page=2000, delay=1.0):
    all_results = []
    start_index = 0
    total_results = None
    headers = {"apiKey": api_key}
    session = requests.Session()
    while True:
        params = {
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }
        logging.info(f"Fetching NVD v2: startIndex={start_index}, resultsPerPage={results_per_page}")
        resp = session.get(NVD_URL, headers=headers, params=params)
        if resp.status_code != 200:
            logging.error(f"Request failed. Status: {resp.status_code}, Reason: {resp.reason}, Body: {resp.content!r}")
            break
        data = resp.json()
        if total_results is None:
            total_results = data.get("totalResults")
            logging.info(f"NVD reports totalResults={total_results}")
        items = data.get("vulnerabilities", [])
        all_results.extend(items)
        logging.info(f"Fetched {len(items)} vulnerabilities (total so far: {len(all_results)})")
        if len(items) < results_per_page or (total_results and len(all_results) >= total_results):
            break
        start_index += results_per_page
        time.sleep(delay)  # NVD API rate limiting
    return all_results


def dump_json(data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    import json
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    logging.info(f"Dumped NVD v2 data to {path}")


def main():
    parser = argparse.ArgumentParser(description="Download raw NVD v2 JSON and dump to file.")
    parser.add_argument('--dump-path', default=DUMP_PATH, help='Where to dump the raw NVD v2 JSON (default: etl-data/nvd_v2_dump.json)')
    parser.add_argument('--results-per-page', type=int, default=2000, help='Number of results per page (max 2000)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between paginated requests (seconds)')
    args = parser.parse_args()
    api_key = load_api_key(secret_name="nvd_api_key", env_var=API_KEY_ENV_VAR)
    if not api_key:
        logging.error("NVD API key not found. Please provide it as a Docker secret or environment variable.")
        return
    data = fetch_nvd_json(api_key, results_per_page=args.results_per_page, delay=args.delay)
    dump_json(data, args.dump_path)
    logging.info(f"Fetched and dumped {len(data)} NVD vulnerabilities.")


if __name__ == "__main__":
    main()
