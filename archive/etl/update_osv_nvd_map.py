import os
import json
import argparse
import logging
import psycopg2
from psycopg2.extras import execute_batch
from urllib.request import urlopen
from etl_utils import RunMetrics, dry_run_notice

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

CREATE_TABLE_SQL = '''
CREATE TABLE IF NOT EXISTS osv_nvd_map (
    cve_id TEXT NOT NULL,
    osv_id TEXT NOT NULL,
    PRIMARY KEY (cve_id, osv_id)
);
'''

MAPPING_URL = "https://osv-vulnerabilities.storage.googleapis.com/mappings/nvd_cve_to_osv_vulns.json.gz"


import gzip
from io import BytesIO

def fetch_mapping(url):
    with urlopen(url) as resp:
        with gzip.GzipFile(fileobj=BytesIO(resp.read())) as gz:
            return json.load(gz)

def parse_local_osv_jsons(directory):
    rows = []
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith('.json'):
                try:
                    with open(os.path.join(root, f)) as fp:
                        osv = json.load(fp)
                        cve_ids = osv.get('aliases', [])
                        osv_id = osv.get('id')
                        for cve in cve_ids:
                            if cve.startswith('CVE-'):
                                rows.append((cve, osv_id))
                except Exception as e:
                    logging.warning(f"Failed to parse {f}: {e}")
    return rows

def upsert_mapping(conn, rows, dry_run, metrics):
    if dry_run:
        logging.info(f"[DRY RUN] Would upsert {len(rows)} (cve_id, osv_id) pairs into osv_nvd_map.")
        metrics.inserts += len(rows)
        return
    with conn.cursor() as cur:
        execute_batch(cur, """
            INSERT INTO osv_nvd_map (cve_id, osv_id)
            VALUES (%s, %s)
            ON CONFLICT (cve_id, osv_id) DO NOTHING
        """, rows)
        metrics.inserts += len(rows)


def ensure_table(conn):
    with conn.cursor() as cur:
        cur.execute(CREATE_TABLE_SQL)
    conn.commit()


def main():
    parser = argparse.ArgumentParser(description="Update OSV↔NVD mapping table from OSV feed or local OSV JSONs")
    parser.add_argument('--dry-run', '-n', action='store_true', help='Log DB actions, do not write')
    parser.add_argument('--local-dir', type=str, help='Directory containing OSV JSONs for local mapping generation')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    if args.dry_run:
        dry_run_notice()

    metrics = RunMetrics(dry_run=args.dry_run)
    conn = psycopg2.connect(**PG_CONFIG)
    ensure_table(conn)

    if args.local_dir:
        rows = parse_local_osv_jsons(args.local_dir)
        logging.info(f"Parsed {len(rows)} (cve_id, osv_id) pairs from local OSV JSONs.")
        upsert_mapping(conn, rows, args.dry_run, metrics)
    else:
        mapping = fetch_mapping(MAPPING_URL)
        # Convert mapping to rows format for upsert_mapping
        rows = []
        for entry in mapping:
            cve = entry.get("cve_id")
            for osv in entry.get("osv_ids", []):
                rows.append((cve, osv))
        logging.info(f"Fetched mapping with {len(rows)} (cve_id, osv_id) pairs from remote feed.")
        upsert_mapping(conn, rows, args.dry_run, metrics)

    if not args.dry_run:
        conn.commit()
    conn.close()

    logging.info(f"[SUMMARY] Inserted {metrics.inserts} (cve_id, osv_id) pairs.")

if __name__ == "__main__":
    main()
