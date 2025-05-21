import os
import sys
import requests
import concurrent.futures
from psycopg2.pool import SimpleConnectionPool
import threading
import time
import gzip
import shutil
import json
import psycopg2
from datetime import datetime
from glob import glob
import logging
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from etl_utils import safe_execute, safe_executemany, dry_run_notice, RunMetrics

# Set up logging; default to WARNING, override with --verbose or ENV
ENV = os.environ.get('ENV', 'development').lower()
LOG_LEVEL = logging.WARNING if ENV == 'production' else logging.INFO
logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s %(levelname)s %(message)s')

# Retry/backoff configuration from environment
NVD_RETRY_ATTEMPTS = int(os.environ.get('NVD_RETRY_ATTEMPTS', 5))
NVD_RETRY_WAIT_MIN = int(os.environ.get('NVD_RETRY_WAIT_MIN', 2))  # seconds
NVD_RETRY_WAIT_MAX = int(os.environ.get('NVD_RETRY_WAIT_MAX', 30))  # seconds

def read_secret(secret_path, default=None):
    try:
        with open(secret_path, 'r') as f:
            return f.read().strip()
    except Exception:
        return default

PG_CONFIG = {
    'host': os.environ.get('PGHOST', 'db'),
    'user': read_secret('/run/secrets/pg_user', os.environ.get('PGUSER', 'postgres')),
    'password': read_secret('/run/secrets/pg_password', os.environ.get('PGPASSWORD', 'postgres')),
    'dbname': os.environ.get('PGDATABASE', 'epssdb'),
}

# Connection pool (initialized in main)
db_pool = None


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Read NVD API key from Docker secret or environment variable
NVD_API_KEY = read_secret('/run/secrets/nvd_api_key', os.environ.get('NVD_API_KEY'))

if not NVD_API_KEY:
    raise RuntimeError("NVD API key is required. Please set it as a Docker secret or environment variable.")

# Helper: Parse CVSS vector string
import re
def parse_cvss_vector(vector):
    if not vector:
        return {}
    vector = re.sub(r'^CVSS:[\d.]+/', '', vector)
    parts = vector.split('/')
    result = {}
    for part in parts:
        if ':' in part:
            k, v = part.split(':', 1)
        elif '=' in part:
            k, v = part.split('=', 1)
        else:
            continue
        result[k.lower()] = v
    return result

@retry(
    stop=stop_after_attempt(NVD_RETRY_ATTEMPTS),
    wait=wait_exponential(min=NVD_RETRY_WAIT_MIN, max=NVD_RETRY_WAIT_MAX),
    retry=retry_if_exception_type((requests.RequestException,)),
    reraise=True
)
# Global rate limiter for NVD API (default: 5 requests per 30 seconds)
class NvdRateLimiter:
    def __init__(self, max_requests=5, period=30):
        self.max_requests = max_requests
        self.period = period
        self.lock = threading.Lock()
        self.timestamps = []
        self.pause_until = 0

    def acquire(self):
        while True:
            now = time.time()
            with self.lock:
                # If we are paused due to 403, wait
                if now < self.pause_until:
                    sleep_time = self.pause_until - now
                    logging.warning(f"Rate limiter paused due to 403. Sleeping for {sleep_time:.1f} seconds.")
                    pass  # will sleep below
                else:
                    # Remove timestamps older than period
                    self.timestamps = [t for t in self.timestamps if now - t < self.period]
                    if len(self.timestamps) < self.max_requests:
                        self.timestamps.append(now)
                        return
                    else:
                        sleep_time = self.period - (now - self.timestamps[0])
            time.sleep(max(sleep_time, 0.1))

    def pause(self, seconds):
        with self.lock:
            self.pause_until = max(self.pause_until, time.time() + seconds)

# This will be initialized in main
nvd_rate_limiter = None

def fetch_cves_from_api(params):
    global nvd_rate_limiter
    nvd_rate_limiter.acquire()
    headers = {"apiKey": NVD_API_KEY}
    resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=60)
    if resp.status_code == 403:
        logging.error(f"NVD API error: 403 {resp.text}")
        # Pause all threads for 5 minutes (configurable)
        nvd_rate_limiter.pause(int(os.environ.get('NVD_403_PAUSE', 300)))
        raise requests.HTTPError("403 Forbidden: Paused all threads for rate limiting.")
    if resp.status_code != 200:
        logging.error(f"NVD API error: {resp.status_code} {resp.text}")
        resp.raise_for_status()
    return resp.json()

def get_existing_last_modified(conn):
    # Get last modified date for all CVEs in DB
    with conn.cursor() as cur:
        cur.execute("SELECT cve_id, last_modified FROM nvd_cve;")
        return {row[0]: row[1] for row in cur.fetchall()}

def get_connection():
    global db_pool
    if db_pool is None:
        raise RuntimeError("DB connection pool not initialized!")
    return db_pool.getconn()

def put_connection(conn):
    global db_pool
    if db_pool:
        db_pool.putconn(conn)


import psycopg2.extras

def upsert_cves_batch(conn, records, dry_run=False, metrics=None):
    if not records:
        return
    if metrics is None:
        metrics = RunMetrics(dry_run=dry_run)
    if dry_run:
        dry_run_notice()
        logging.info(f"[DRY RUN] Would upsert {len(records)} CVE records into nvd_cve.")
        metrics.inserts += len(records)
        return
    # Convert 'references' to JSON string if it's a list or dict
    for rec in records:
        if isinstance(rec.get('references'), (list, dict)):
            rec['references'] = json.dumps(rec['references'])
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(
            cur,
            """
INSERT INTO nvd_cve (
    cve_id, published, last_modified, description, cwe,
    cvss2_base_score, cvss2_vector, cvss2_av, cvss2_ac, cvss2_au, cvss2_c, cvss2_i, cvss2_a,
    cvss3_base_score, cvss3_vector, cvss3_av, cvss3_ac, cvss3_pr, cvss3_ui, cvss3_s, cvss3_c, cvss3_i, cvss3_a,
    cvss4_base_score, cvss4_vector, cvss4_av, cvss4_ac, cvss4_at, cvss4_pr, cvss4_ui, cvss4_v, cvss4_c, cvss4_i, cvss4_a, cvss4_s, cvss4_si, cvss4_sc, cvss4_sa,
    "references", json_data
) VALUES (
    %(cve_id)s, %(published)s, %(last_modified)s, %(description)s, %(cwe)s,
    %(cvss2_base_score)s, %(cvss2_vector)s, %(cvss2_av)s, %(cvss2_ac)s, %(cvss2_au)s, %(cvss2_c)s, %(cvss2_i)s, %(cvss2_a)s,
    %(cvss3_base_score)s, %(cvss3_vector)s, %(cvss3_av)s, %(cvss3_ac)s, %(cvss3_pr)s, %(cvss3_ui)s, %(cvss3_s)s, %(cvss3_c)s, %(cvss3_i)s, %(cvss3_a)s,
    %(cvss4_base_score)s, %(cvss4_vector)s, %(cvss4_av)s, %(cvss4_ac)s, %(cvss4_at)s, %(cvss4_pr)s, %(cvss4_ui)s, %(cvss4_v)s, %(cvss4_c)s, %(cvss4_i)s, %(cvss4_a)s, %(cvss4_s)s, %(cvss4_si)s, %(cvss4_sc)s, %(cvss4_sa)s,
    %(references)s, %(json_data)s
)
ON CONFLICT (cve_id) DO UPDATE SET
    published = EXCLUDED.published,
    last_modified = EXCLUDED.last_modified,
    description = EXCLUDED.description,
    cwe = EXCLUDED.cwe,
    cvss2_base_score = EXCLUDED.cvss2_base_score,
    cvss2_vector = EXCLUDED.cvss2_vector,
    cvss2_av = EXCLUDED.cvss2_av,
    cvss2_ac = EXCLUDED.cvss2_ac,
    cvss2_au = EXCLUDED.cvss2_au,
    cvss2_c = EXCLUDED.cvss2_c,
    cvss2_i = EXCLUDED.cvss2_i,
    cvss2_a = EXCLUDED.cvss2_a,
    cvss3_base_score = EXCLUDED.cvss3_base_score,
    cvss3_vector = EXCLUDED.cvss3_vector,
    cvss3_av = EXCLUDED.cvss3_av,
    cvss3_ac = EXCLUDED.cvss3_ac,
    cvss3_pr = EXCLUDED.cvss3_pr,
    cvss3_ui = EXCLUDED.cvss3_ui,
    cvss3_s = EXCLUDED.cvss3_s,
    cvss3_c = EXCLUDED.cvss3_c,
    cvss3_i = EXCLUDED.cvss3_i,
    cvss3_a = EXCLUDED.cvss3_a,
    cvss4_base_score = EXCLUDED.cvss4_base_score,
    cvss4_vector = EXCLUDED.cvss4_vector,
    cvss4_av = EXCLUDED.cvss4_av,
    cvss4_ac = EXCLUDED.cvss4_ac,
    cvss4_at = EXCLUDED.cvss4_at,
    cvss4_pr = EXCLUDED.cvss4_pr,
    cvss4_ui = EXCLUDED.cvss4_ui,
    cvss4_v = EXCLUDED.cvss4_v,
    cvss4_c = EXCLUDED.cvss4_c,
    cvss4_i = EXCLUDED.cvss4_i,
    cvss4_a = EXCLUDED.cvss4_a,
    cvss4_s = EXCLUDED.cvss4_s,
    cvss4_si = EXCLUDED.cvss4_si,
    cvss4_sc = EXCLUDED.cvss4_sc,
    cvss4_sa = EXCLUDED.cvss4_sa,
    "references" = EXCLUDED."references",
    json_data = EXCLUDED.json_data;
""",
            records,
            page_size=1000
        )
    metrics.inserts += len(records)

def extract_cve_record(item):
    # NVD REST API v2.0 CVE record structure
    cve_id = item.get('id')
    published = item.get('published')
    last_modified = item.get('lastModified')
    # Description
    description = None
    for desc in item.get('descriptions', []):
        if desc.get('lang') == 'en':
            description = desc.get('value')
            break
    # CWE/Weakness
    cwe = None
    for weakness in item.get('weaknesses', []):
        for desc in weakness.get('description', []):
            if desc.get('lang') == 'en':
                cwe = desc.get('value')
                break
    # References
    references = None
    refs = item.get('references', [])
    if refs:
        references = ",".join([r.get('url') for r in refs if r.get('url')])
    # CVSS v2
    cvss2 = {}
    cvss2_vector = None
    cvss2_components = {}
    for metric in item.get('metrics', {}).get('cvssMetricV2', []):
        cvss2 = metric.get('cvssData', {})
        cvss2_vector = cvss2.get('vectorString')
        cvss2_components = parse_cvss_vector(cvss2_vector)
        break
    # CVSS v3
    cvss3 = {}
    cvss3_vector = None
    cvss3_components = {}
    for metric in item.get('metrics', {}).get('cvssMetricV3', []):
        cvss3 = metric.get('cvssData', {})
        cvss3_vector = cvss3.get('vectorString')
        cvss3_components = parse_cvss_vector(cvss3_vector)
        break
    # CVSS v4 (future-proof)
    cvss4 = {}
    cvss4_vector = None
    cvss4_components = {}
    for metric in item.get('metrics', {}).get('cvssMetricV4', []):
        cvss4 = metric.get('cvssData', {})
        cvss4_vector = cvss4.get('vectorString')
        cvss4_components = parse_cvss_vector(cvss4_vector)
        break
    return {
        'cve_id': cve_id,
        'published': published,
        'last_modified': last_modified,
        'description': description,
        'cwe': cwe,
        # CVSS v2
        'cvss2_base_score': cvss2.get('baseScore'),
        'cvss2_vector': cvss2_vector,
        'cvss2_av': cvss2_components.get('av'),
        'cvss2_ac': cvss2_components.get('ac'),
        'cvss2_au': cvss2_components.get('au'),
        'cvss2_c': cvss2_components.get('c'),
        'cvss2_i': cvss2_components.get('i'),
        'cvss2_a': cvss2_components.get('a'),
        # CVSS v3
        'cvss3_base_score': cvss3.get('baseScore'),
        'cvss3_vector': cvss3_vector,
        'cvss3_av': cvss3_components.get('av'),
        'cvss3_ac': cvss3_components.get('ac'),
        'cvss3_pr': cvss3_components.get('pr'),
        'cvss3_ui': cvss3_components.get('ui'),
        'cvss3_s': cvss3_components.get('s'),
        'cvss3_c': cvss3_components.get('c'),
        'cvss3_i': cvss3_components.get('i'),
        'cvss3_a': cvss3_components.get('a'),
        # CVSS v4
        'cvss4_base_score': cvss4.get('baseScore'),
        'cvss4_vector': cvss4_vector,
        'cvss4_av': cvss4_components.get('av'),
        'cvss4_ac': cvss4_components.get('ac'),
        'cvss4_at': cvss4_components.get('at'),
        'cvss4_pr': cvss4_components.get('pr'),
        'cvss4_ui': cvss4_components.get('ui'),
        'cvss4_v': cvss4_components.get('v'),
        'cvss4_c': cvss4_components.get('c'),
        'cvss4_i': cvss4_components.get('i'),
        'cvss4_a': cvss4_components.get('a'),
        'cvss4_s': cvss4_components.get('s'),
        'cvss4_si': cvss4_components.get('si'),
        'cvss4_sc': cvss4_components.get('sc'),
        'cvss4_sa': cvss4_components.get('sa'),
        'references': references,
        'json_data': json.dumps(item)
    }

import time
BATCH_SIZE = int(os.environ.get('NVD_BATCH_SIZE', 2000))
SLEEP_BETWEEN_REQUESTS = float(os.environ.get('NVD_SLEEP_BETWEEN_REQUESTS', 0.5))

def upsert_cve_references_batch(conn, records, dry_run=False, metrics=None):
    # records: list of dicts with keys 'cve_id', 'url'
    if not records:
        return
    if metrics is None:
        metrics = RunMetrics(dry_run=dry_run)
    if dry_run:
        dry_run_notice()
        logging.info(f"[DRY RUN] Would upsert {len(records)} nvd_cve_reference records.")
        metrics.inserts += len(records)
        return
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(
            cur,
            """
INSERT INTO nvd_cve_reference (cve_id, url)
VALUES (%(cve_id)s, %(url)s)
ON CONFLICT DO NOTHING;
""",
            records
        )
    metrics.inserts += len(records)

from cve_utils import ensure_cve_exists


def fetch_and_process_page(page_idx, results_per_page, last_mod_start_date, last_mod_end_date, existing_last_modified):
    params = {
        "resultsPerPage": results_per_page,
        "startIndex": page_idx * results_per_page,
    }
    if last_mod_start_date:
        params["lastModStartDate"] = last_mod_start_date
    if last_mod_end_date:
        params["lastModEndDate"] = last_mod_end_date
    data = fetch_cves_from_api(params)
    cves = data.get("vulnerabilities", [])
    records = []
    references_batch = []
    conn = get_connection()
    try:
        for cve_item in cves:
            item = cve_item.get("cve")
            if not item:
                continue
            record = extract_cve_record(item)
            cve_id = record['cve_id']
            ensure_cve_exists(conn, cve_id, source='nvd')
            last_mod = record['last_modified']
            if (cve_id not in existing_last_modified) or (last_mod and last_mod > str(existing_last_modified[cve_id])):
                records.append(record)
                refs = item.get('references', [])
                for r in refs:
                    url = r.get('url')
                    if url:
                        references_batch.append({'cve_id': cve_id, 'url': url})
    finally:
        put_connection(conn)
    return records, references_batch, len(cves)

def process_all_cves_parallel(existing_last_modified, last_mod_start_date=None, last_mod_end_date=None, workers=4, batch_size=2000, sleep_between_requests=0.5, dry_run=False, metrics=None):
    print("Starting NVD CVE import (parallel)...")
    sys.stdout.flush()
    # First, get total number of results
    params = {"resultsPerPage": 1}
    if last_mod_start_date:
        params["lastModStartDate"] = last_mod_start_date
    if last_mod_end_date:
        params["lastModEndDate"] = last_mod_end_date
    data = fetch_cves_from_api(params)
    total_results = data.get("totalResults", 0)
    n_pages = (total_results + batch_size - 1) // batch_size
    print(f"Total results: {total_results}, pages: {n_pages}")
    sys.stdout.flush()
    fetched = 0
    all_records = []
    all_references = []
    failed_pages = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_page = {
            executor.submit(
                fetch_and_process_page,
                page_idx,
                batch_size,
                last_mod_start_date,
                last_mod_end_date,
                existing_last_modified
            ): page_idx for page_idx in range(n_pages)
        }
        for future in concurrent.futures.as_completed(future_to_page):
            page_idx = future_to_page[future]
            try:
                records, references, n_fetched = future.result()
                all_records.extend(records)
                all_references.extend(references)
                fetched += n_fetched
                print(f"Fetched page {page_idx+1}/{n_pages} ({n_fetched} CVEs)")
                sys.stdout.flush()
            except Exception as exc:
                logging.error(f"Page {page_idx+1} generated an exception: {exc}")
                failed_pages.append((page_idx, str(exc)))
            time.sleep(sleep_between_requests)
    # Retry failed pages with exponential backoff (up to 3 times)
    max_retries = 3
    retry_delays = [10, 30, 60]
    for attempt in range(max_retries):
        if not failed_pages:
            break
        logging.warning(f"Retrying {len(failed_pages)} failed pages (attempt {attempt+1}/{max_retries})...")
        new_failed = []
        for page_idx, last_err in failed_pages:
            try:
                time.sleep(retry_delays[min(attempt, len(retry_delays)-1)])
                records, references, n_fetched = fetch_and_process_page(
                    page_idx,
                    batch_size,
                    last_mod_start_date,
                    last_mod_end_date,
                    existing_last_modified
                )
                all_records.extend(records)
                all_references.extend(references)
                fetched += n_fetched
                print(f"Retried page {page_idx+1}/{n_pages} ({n_fetched} CVEs)")
                sys.stdout.flush()
            except Exception as exc:
                logging.error(f"Retry for page {page_idx+1} failed: {exc}")
                new_failed.append((page_idx, str(exc)))
        failed_pages = new_failed
    # Upsert in batches (to avoid memory issues)
    conn = get_connection()
    try:
        for i in range(0, len(all_records), batch_size):
            upsert_cves_batch(conn, all_records[i:i+batch_size], dry_run=dry_run, metrics=metrics)
        for i in range(0, len(all_references), batch_size):
            upsert_cve_references_batch(conn, all_references[i:i+batch_size], dry_run=dry_run, metrics=metrics)
    finally:
        put_connection(conn)
    print(f"NVD CVE import complete. Total CVEs processed: {fetched}")
    if failed_pages:
        print(f"WARNING: The following pages failed after retries: {[p[0]+1 for p in failed_pages]}")
        for page_idx, err in failed_pages:
            print(f"  Page {page_idx+1}: {err}")
    sys.stdout.flush()



import argparse

def download_nvd_json(api_version='2.0', years=None, out_dir="./nvd-data"): 
    """
    Download all CVEs for each year using the NVD API and save as nvdcve-{version}-YYYY.json.
    """
    import os
    import time
    import requests
    from datetime import datetime
    import zipfile
    from io import BytesIO
    os.makedirs(out_dir, exist_ok=True)
    if years is None or not years:
        current_year = datetime.utcnow().year
        years = list(range(2002, current_year+1))
    else:
        years = [int(y) for y in years]
    if api_version == '2.0':
        headers = {"apiKey": NVD_API_KEY}
        base_url = NVD_API_URL
        import calendar
        for year in years:
            all_cves = []
            print(f"[NVD 2.0] Downloading year {year} by month...")
            for month in range(1, 13):
                month_start = f"{year}-{month:02d}-01T00:00:00.000Z"
                last_day = calendar.monthrange(year, month)[1]
                month_end = f"{year}-{month:02d}-{last_day}T23:59:59.999Z"
                params = {
                    "pubStartDate": month_start,
                    "pubEndDate": month_end,
                    "resultsPerPage": 2000,
                    "startIndex": 0
                }
                total = None
                while True:
                    resp = requests.get(base_url, params=params, headers=headers, timeout=60)
                    if resp.status_code == 404:
                        print(f"Error fetching {year}-{month:02d} (startIndex={params['startIndex']}): 404 Not Found. Check if the API endpoint or date range is correct.")
                        break
                    elif resp.status_code != 200:
                        print(f"Error fetching {year}-{month:02d} (startIndex={params['startIndex']}): {resp.status_code} {resp.text}")
                        break
                    data = resp.json()
                    if total is None:
                        total = data.get("totalResults", 0)
                        print(f"  {year}-{month:02d}: Total CVEs: {total}")
                    cves = data.get("vulnerabilities", [])
                    if not cves and data.get("totalResults", 0) == 0:
                        print(f"  No CVEs found for {year}-{month:02d}. (Empty result from NVD API)")
                        break
                    all_cves.extend(cves)
                    params["startIndex"] += params["resultsPerPage"]
                    if len(cves) < params["resultsPerPage"]:
                        break
                    time.sleep(0.6)
            out_path = os.path.join(out_dir, f"nvdcve-2.0-{year}.json")
            with open(out_path, "w") as f:
                json.dump({"vulnerabilities": all_cves, "totalResults": len(all_cves)}, f)
            print(f"  Saved {len(all_cves)} CVEs to {out_path}")
    elif api_version == '1.1':
        for year in years:
            url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip"
            print(f"[NVD 1.1] Downloading {url} ...")
            resp = requests.get(url, timeout=120)
            if resp.status_code != 200:
                print(f"  Error downloading {url}: {resp.status_code} {resp.text}")
                continue
            with zipfile.ZipFile(BytesIO(resp.content)) as zf:
                for fname in zf.namelist():
                    if fname.endswith('.json'):
                        out_path = os.path.join(out_dir, fname)
                        with open(out_path, 'wb') as f:
                            f.write(zf.read(fname))
                        print(f"  Saved {fname} to {out_path}")

def main():
    import argparse
    global db_pool, nvd_rate_limiter
    parser = argparse.ArgumentParser(description="NVD ETL: full or incremental mode")
    parser.add_argument('--mode', choices=['full', 'incremental'], default='incremental', help='Update mode: full (all data) or incremental (default)')
    parser.add_argument('--workers', type=int, default=int(os.environ.get('NVD_WORKERS', 4)), help='Number of parallel workers for fetching')
    parser.add_argument('--batch-size', type=int, default=int(os.environ.get('NVD_BATCH_SIZE', 2000)), help='Batch size for API and DB operations')
    parser.add_argument('--sleep', type=float, default=float(os.environ.get('NVD_SLEEP_BETWEEN_REQUESTS', 0.5)), help='Sleep between requests (seconds, recommended ≥0.5s for NVD best practice)')
    parser.add_argument('--rate-limit', type=int, default=int(os.environ.get('NVD_RATE_LIMIT', 50)), help='Max NVD API requests per window (default 50 for API key users, 5 for public)')
    parser.add_argument('--rate-period', type=int, default=int(os.environ.get('NVD_RATE_PERIOD', 30)), help='NVD API rate limit window in seconds (default 30)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--dry-run', action='store_true', help='Dry run mode: log DB actions, do not write')
    parser.add_argument('--download-versions', type=str, default='', help='Comma-separated NVD versions to download (e.g. 1.1,2.0). Default: none')
    parser.add_argument('--ingest-versions', type=str, default='', help='Comma-separated NVD versions to ingest (e.g. 1.1,2.0). Default: none')
    parser.add_argument('--years', type=str, default='', help='Comma-separated years to download/ingest (default: all available)')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.WARNING)

    # Parse versions for download/ingest
    download_versions = [v.strip() for v in args.download_versions.split(',') if v.strip()]
    ingest_versions = [v.strip() for v in args.ingest_versions.split(',') if v.strip()]
    years = [int(y) for y in args.years.split(",") if y.strip()] if args.years else None

    # Download step
    for v in download_versions:
        print(f"[DOWNLOAD] Downloading NVD version {v} ...")
        download_nvd_json(api_version=v, years=years, out_dir="./nvd-data")
    if download_versions:
        print("Download complete.")

    # Ingest step
    for v in ingest_versions:
        print(f"[INGEST] Ingesting NVD version {v} ...")
        ingest_nvd_version(version=v, years=years)
    if ingest_versions:
        print("Ingestion complete.")
    if not (download_versions or ingest_versions):
        print("No download or ingest versions specified. Exiting.")
        return

    dry_run = args.dry_run
    metrics = RunMetrics(dry_run=dry_run)
    if dry_run:
        dry_run_notice()

    # Warn if user tries to exceed official API key rate limit
    if args.rate_limit > 50:
        logging.warning("NVD API key users are limited to 50 requests per 30 seconds. Setting a higher rate may result in 403 errors or bans.")
    if args.sleep < 0.5:
        logging.warning("NVD recommends sleeping at least 0.5 seconds between requests, even with an API key.")

def ingest_nvd_version(version, years=None):
    # Initialize global NVD API rate limiter
    nvd_rate_limiter = NvdRateLimiter(max_requests=int(os.environ.get('NVD_RATE_LIMIT', 5)), period=int(os.environ.get('NVD_RATE_PERIOD', 30)))
    # Initialize DB connection pool
    db_pool = SimpleConnectionPool(
        minconn=1,
        maxconn=8,
        **PG_CONFIG
    )
    # Ensure nvd_cve and nvd_cve_reference tables exist
    conn = db_pool.getconn()
    try:
        with conn:
            with conn.cursor() as cur:
                # Main CVE table
                safe_execute(cur, """
CREATE TABLE IF NOT EXISTS nvd_cve (
    cve_id TEXT PRIMARY KEY,
    published TEXT,
    last_modified TEXT,
    description TEXT,
    cwe TEXT,
    cvss2_base_score FLOAT,
    cvss2_vector TEXT,
    cvss2_av TEXT,
    cvss2_ac TEXT,
    cvss2_au TEXT,
    cvss2_c TEXT,
    cvss2_i TEXT,
    cvss2_a TEXT,
    cvss3_base_score FLOAT,
    cvss3_vector TEXT,
    cvss3_av TEXT,
    cvss3_ac TEXT,
    cvss3_pr TEXT,
    cvss3_ui TEXT,
    cvss3_s TEXT,
    cvss3_c TEXT,
    cvss3_i TEXT,
    cvss3_a TEXT,
    cvss4_base_score FLOAT,
    cvss4_vector TEXT,
    cvss4_av TEXT,
    cvss4_ac TEXT,
    cvss4_at TEXT,
    cvss4_pr TEXT,
    cvss4_ui TEXT,
    cvss4_v TEXT,
    cvss4_c TEXT,
    cvss4_i TEXT,
    cvss4_a TEXT,
    cvss4_s TEXT,
    cvss4_si TEXT,
    cvss4_sc TEXT,
    cvss4_sa TEXT,
    "references" TEXT,
    json_data TEXT
);
""", dry_run=False)
                # Normalized references table
                safe_execute(cur, """
CREATE TABLE IF NOT EXISTS nvd_cve_reference (
    id SERIAL PRIMARY KEY,
    cve_id TEXT REFERENCES nvd_cve(cve_id),
    url TEXT NOT NULL
);
""", dry_run=False)
        # Get all existing last_modified dates
        existing_last_modified = get_existing_last_modified(conn)
        if version == '2.0':
            # --- 2.0 ingestion logic ---
            import glob
            nvd_dir = './nvd-data'
            json_files = sorted(glob.glob(f"{nvd_dir}/nvdcve-2.0-*.json"))
            if years:
                json_files = [f for f in json_files if any(str(y) in f for y in years)]
            print(f"Found {len(json_files)} NVD 2.0 JSON files for ingestion.")
            for json_file in json_files:
                print(f"Processing {json_file} ...")
                with open(json_file, 'r') as f:
                    nvd_data = json.load(f)
                # Each file has a 'vulnerabilities' list
                for item in nvd_data.get('vulnerabilities', []):
                    record = extract_cve_record_2_0(item)
                    if record:
                        upsert_cves_batch(conn, [record], dry_run=False, metrics=None)
        elif version == '1.1':
            # --- 1.1 ingestion logic ---
            import glob
            nvd_dir = './nvd-data'
            json_files = sorted(glob.glob(f"{nvd_dir}/nvdcve-1.1-*.json"))
            if years:
                json_files = [f for f in json_files if any(str(y) in f for y in years)]
            print(f"Found {len(json_files)} NVD 1.1 JSON files for ingestion.")
            for json_file in json_files:
                print(f"Processing {json_file} ...")
                with open(json_file, 'r') as f:
                    nvd_data = json.load(f)
                # Each file has a 'CVE_Items' list
                for item in nvd_data.get('CVE_Items', []):
                    record = extract_cve_record_1_1(item)
                    if record:
                        upsert_cves_batch(conn, [record], dry_run=False, metrics=None)
    finally:
        db_pool.putconn(conn)
        db_pool.closeall()

def extract_cve_record_1_1(item):
    import logging
    # Extract fields from a NVD 1.1 CVE record (legacy format)
    cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
    published = item.get('publishedDate')
    last_modified = item.get('lastModifiedDate')
    # Description
    description = None
    for desc in item.get('cve', {}).get('description', {}).get('description_data', []):
        if desc.get('lang') == 'en':
            description = desc.get('value')
            break
    # CWE
    cwe = None
    for probtype in item.get('cve', {}).get('problemtype', {}).get('problemtype_data', []):
        for desc in probtype.get('description', []):
            if desc.get('lang') == 'en':
                cwe = desc.get('value')
                break
    # References
    references = []
    for ref in item.get('cve', {}).get('references', {}).get('reference_data', []):
        url = ref.get('url')
        if url:
            references.append({'url': url})
    # CVSS2
    cvss2 = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {})
    cvss2_base_score = cvss2.get('baseScore', None)
    cvss2_vector = cvss2.get('vectorString', None)
    cvss2_components = parse_cvss_vector(cvss2_vector) if cvss2_vector else {}
    # CVSS3
    cvss3 = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})
    cvss3_base_score = cvss3.get('baseScore', None)
    cvss3_vector = cvss3.get('vectorString', None)
    cvss3_components = parse_cvss_vector(cvss3_vector) if cvss3_vector else {}
    # Log missing CVSS fields
    if cvss2_base_score is None or cvss2_vector is None:
        logging.debug(f"CVE {cve_id}: Missing CVSS2 fields. base_score={cvss2_base_score}, vector={cvss2_vector}")
    if cvss3_base_score is None or cvss3_vector is None:
        logging.debug(f"CVE {cve_id}: Missing CVSS3 fields. base_score={cvss3_base_score}, vector={cvss3_vector}")
    # Compose record (fill missing fields as needed)
    return {
        'cve_id': cve_id,
        'published': published,
        'last_modified': last_modified,
        'description': description,
        'cwe': cwe,
        'cvss2_base_score': cvss2_base_score,
        'cvss2_vector': cvss2_vector,
        'cvss2_av': cvss2_components.get('av'),
        'cvss2_ac': cvss2_components.get('ac'),
        'cvss2_au': cvss2_components.get('au'),
        'cvss2_c': cvss2_components.get('c'),
        'cvss2_i': cvss2_components.get('i'),
        'cvss2_a': cvss2_components.get('a'),
        'cvss3_base_score': cvss3_base_score,
        'cvss3_vector': cvss3_vector,
        'cvss3_av': cvss3_components.get('av'),
        'cvss3_ac': cvss3_components.get('ac'),
        'cvss3_pr': cvss3_components.get('pr'),
        'cvss3_ui': cvss3_components.get('ui'),
        'cvss3_s': cvss3_components.get('s'),
        'cvss3_c': cvss3_components.get('c'),
        'cvss3_i': cvss3_components.get('i'),
        'cvss3_a': cvss3_components.get('a'),
        # CVSS4 fields, always present (None if not available)
        'cvss4_base_score': None,
        'cvss4_vector': None,
        'cvss4_av': None,
        'cvss4_ac': None,
        'cvss4_at': None,
        'cvss4_pr': None,
        'cvss4_ui': None,
        'cvss4_v': None,
        'cvss4_c': None,
        'cvss4_i': None,
        'cvss4_a': None,
        'cvss4_s': None,
        'cvss4_si': None,
        'cvss4_sc': None,
        'cvss4_sa': None,
        'references': references,
        'json_data': json.dumps(item)
    }

def extract_cve_record_2_0(item):
    # Extract fields from a NVD 2.0 CVE record
    cve_id = item.get('cve', {}).get('id')
    published = item.get('published')
    last_modified = item.get('lastModified')
    description = None
    for desc in item.get('descriptions', []):
        if desc.get('lang', '').startswith('en'):
            description = desc.get('value')
            break
    # CWE
    cwe = None
    for probtype in item.get('problemTypes', []):
        for desc in probtype.get('descriptions', []):
            if desc.get('lang', '').startswith('en'):
                cwe = desc.get('cweId') or desc.get('description')
                break
    # References
    references = []
    for ref in item.get('references', []):
        url = ref.get('url')
        if url:
            references.append({'url': url})
    # CVSS2/3/4 (if present)
    metrics = item.get('metrics', {})
    cvss2 = metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {}) if 'cvssMetricV2' in metrics else {}
    cvss2_base_score = cvss2.get('baseScore')
    cvss2_vector = cvss2.get('vectorString')
    cvss3 = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}) if 'cvssMetricV30' in metrics else {}
    cvss3_base_score = cvss3.get('baseScore')
    cvss3_vector = cvss3.get('vectorString')
    # Compose record (fill missing fields as needed)
    return {
        'cve_id': cve_id,
        'published': published,
        'last_modified': last_modified,
        'description': description,
        'cwe': cwe,
        'cvss2_base_score': cvss2_base_score,
        'cvss2_vector': cvss2_vector,
        'cvss3_base_score': cvss3_base_score,
        'cvss3_vector': cvss3_vector,
        'references': references,
        'json_data': json.dumps(item)
    }

def extract_cve_record_1_1(item):
    import logging
    # Extract fields from a NVD 1.1 CVE record (legacy format)
    cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
    published = item.get('publishedDate')
    last_modified = item.get('lastModifiedDate')
    # Description
    description = None
    for desc in item.get('cve', {}).get('description', {}).get('description_data', []):
        if desc.get('lang') == 'en':
            description = desc.get('value')
            break
    # CWE
    cwe = None
    for probtype in item.get('cve', {}).get('problemtype', {}).get('problemtype_data', []):
        for desc in probtype.get('description', []):
            if desc.get('lang') == 'en':
                cwe = desc.get('value')
                break
    # References
    references = []
    for ref in item.get('cve', {}).get('references', {}).get('reference_data', []):
        url = ref.get('url')
        if url:
            references.append({'url': url})
    # CVSS2
    cvss2 = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {})
    cvss2_base_score = cvss2.get('baseScore', None)
    cvss2_vector = cvss2.get('vectorString', None)
    cvss2_components = parse_cvss_vector(cvss2_vector) if cvss2_vector else {}
    # CVSS3
    cvss3 = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})
    cvss3_base_score = cvss3.get('baseScore', None)
    cvss3_vector = cvss3.get('vectorString', None)
    cvss3_components = parse_cvss_vector(cvss3_vector) if cvss3_vector else {}
    # Log missing CVSS fields
    if cvss2_base_score is None or cvss2_vector is None:
        logging.debug(f"CVE {cve_id}: Missing CVSS2 fields. base_score={cvss2_base_score}, vector={cvss2_vector}")
    if cvss3_base_score is None or cvss3_vector is None:
        logging.debug(f"CVE {cve_id}: Missing CVSS3 fields. base_score={cvss3_base_score}, vector={cvss3_vector}")
    # Compose record (fill missing fields as needed)
    return {
        'cve_id': cve_id,
        'published': published,
        'last_modified': last_modified,
        'description': description,
        'cwe': cwe,
        'cvss2_base_score': cvss2_base_score,
        'cvss2_vector': cvss2_vector,
        'cvss2_av': cvss2_components.get('av'),
        'cvss2_ac': cvss2_components.get('ac'),
        'cvss2_au': cvss2_components.get('au'),
        'cvss2_c': cvss2_components.get('c'),
        'cvss2_i': cvss2_components.get('i'),
        'cvss2_a': cvss2_components.get('a'),
        'cvss3_base_score': cvss3_base_score,
        'cvss3_vector': cvss3_vector,
        'cvss3_av': cvss3_components.get('av'),
        'cvss3_ac': cvss3_components.get('ac'),
        'cvss3_pr': cvss3_components.get('pr'),
        'cvss3_ui': cvss3_components.get('ui'),
        'cvss3_s': cvss3_components.get('s'),
        'cvss3_c': cvss3_components.get('c'),
        'cvss3_i': cvss3_components.get('i'),
        'cvss3_a': cvss3_components.get('a'),
        # CVSS4 fields, always present (None if not available)
        'cvss4_base_score': None,
        'cvss4_vector': None,
        'cvss4_av': None,
        'cvss4_ac': None,
        'cvss4_at': None,
        'cvss4_pr': None,
        'cvss4_ui': None,
        'cvss4_v': None,
        'cvss4_c': None,
        'cvss4_i': None,
        'cvss4_a': None,
        'cvss4_s': None,
        'cvss4_si': None,
        'cvss4_sc': None,
        'cvss4_sa': None,
        'references': references,
        'json_data': json.dumps(item)
    }

if __name__ == "__main__":
    main()
