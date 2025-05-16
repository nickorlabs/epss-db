import os
import requests
import json
import psycopg2
import psycopg2.extras
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import logging

def read_secret(secret_path, fallback=None):
    try:
        with open(secret_path) as f:
            return f.read().strip()
    except Exception:
        return fallback

CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_API_KEY = read_secret('/run/secrets/nvd_api_key', os.environ.get('NVD_API_KEY'))
if not NVD_API_KEY:
    raise RuntimeError("NVD API key is required. Please set it as a Docker secret or environment variable.")

PG_CONFIG = {
    'host': os.environ.get('PGHOST', 'db'),
    'user': read_secret('/run/secrets/pg_user', os.environ.get('PGUSER', 'postgres')),
    'password': read_secret('/run/secrets/pg_password', os.environ.get('PGPASSWORD', 'postgres')),
    'dbname': os.environ.get('PGDATABASE', 'epssdb'),
}

@retry(stop=stop_after_attempt(5), wait=wait_exponential(min=2, max=30), retry=retry_if_exception_type((requests.RequestException,)), reraise=True)
def fetch_cpes_from_api(params):
    headers = {"apiKey": NVD_API_KEY}
    resp = requests.get(CPE_API_URL, params=params, headers=headers, timeout=60)
    if resp.status_code != 200:
        logging.error(f"NVD CPE API error: {resp.status_code} {resp.text}")
        resp.raise_for_status()
    return resp.json()

    cpe23uri TEXT PRIMARY KEY,
    title TEXT,
    deprecated BOOLEAN,
    last_modified TEXT,
    json_data TEXT
);
""")
    finally:
        conn.close()

def upsert_cpes_batch(records):
    if not records:
        return
    conn = psycopg2.connect(**PG_CONFIG)
    try:
        with conn:
            with conn.cursor() as cur:
                psycopg2.extras.execute_batch(
                    cur,
                    """
INSERT INTO nvd_cpe (cpe23uri, title, deprecated, last_modified, json_data)
VALUES (%(cpe23uri)s, %(title)s, %(deprecated)s, %(last_modified)s, %(json_data)s)
ON CONFLICT (cpe23uri) DO UPDATE SET
    title = EXCLUDED.title,
    deprecated = EXCLUDED.deprecated,
    last_modified = EXCLUDED.last_modified,
    json_data = EXCLUDED.json_data;
""",
                    records,
                    page_size=1000
                )
    finally:
        conn.close()

def extract_cpe_record(item):
    cpe = item.get('cpe', {})
    cpe23uri = cpe.get('cpeName')
    title = None
    for t in cpe.get('titles', []):
        if t.get('lang') == 'en':
            title = t.get('title')
            break
    deprecated = cpe.get('deprecated', False)
    last_modified = cpe.get('lastModified')
    return {
        'cpe23uri': cpe23uri,
        'title': title,
        'deprecated': deprecated,
        'last_modified': last_modified,
        'json_data': json.dumps(item)
    }

import time
BATCH_SIZE = 2000
SLEEP_BETWEEN_REQUESTS = 0.5

def process_all_cpes():
    import sys
    results_per_page = BATCH_SIZE
    start_index = 0
    total_results = None
    fetched = 0
    print("Starting NVD CPE import...")
    sys.stdout.flush()
    while True:
        params = {
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        data = fetch_cpes_from_api(params)
        cpes = data.get("products", [])
        records = [extract_cpe_record(cpe_item) for cpe_item in cpes]
        upsert_cpes_batch(records)
        fetched += len(cpes)
        if total_results is None:
            total_results = data.get("totalResults", 0)
        print(f"Fetched {fetched}/{total_results} CPEs...")
        sys.stdout.flush()
        if fetched >= total_results or not cpes:
            break
        start_index += results_per_page
        time.sleep(SLEEP_BETWEEN_REQUESTS)
    print(f"NVD CPE import complete. Total CPEs processed: {fetched}")
    sys.stdout.flush()

def main():
    ensure_cpe_table()
    process_all_cpes()

if __name__ == "__main__":
    main()
