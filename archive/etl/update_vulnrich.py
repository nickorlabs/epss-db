import os
import subprocess
import json
import psycopg2
from psycopg2.extras import execute_batch
from glob import glob
from datetime import datetime
import logging
from cve_utils import ensure_cve_exists
import concurrent.futures
import time
import argparse
from etl_utils import RunMetrics, dry_run_notice

# Set up logging based on environment
ENV = os.environ.get('ENV', 'development').lower()
LOG_LEVEL = logging.INFO if ENV == 'production' else logging.DEBUG
logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s %(levelname)s %(message)s')

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


# Path to the Vulnrichment repo (relative to project root)
VULNREPO_DIR = os.path.join(os.path.dirname(__file__), 'vulnrichment')  # Now under etl/vulnrichment

CREATE_TABLE_SQL = '''
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'vulnrichment') THEN
        CREATE TABLE vulnrichment (
            cve TEXT PRIMARY KEY,
            cvssScore FLOAT,
            cvssVector TEXT,
            published TEXT,
            lastModified TEXT,
            summary TEXT,
            cwe TEXT,
            "references" TEXT
        );
    END IF;
END$$;
'''

INSERT_SQL = '''
INSERT INTO vulnrichment (
    cve, cvssScore, cvssVector, published, lastModified, summary, cwe, "references"
) VALUES (
    %(cve)s, %(cvssScore)s, %(cvssVector)s, %(published)s, %(lastModified)s, %(summary)s, %(cwe)s, %(references)s
)
ON CONFLICT (cve) DO UPDATE SET
    cvssScore = EXCLUDED.cvssScore,
    cvssVector = EXCLUDED.cvssVector,
    published = EXCLUDED.published,
    lastModified = EXCLUDED.lastModified,
    summary = EXCLUDED.summary,
    cwe = EXCLUDED.cwe,
    "references" = EXCLUDED."references";
'''

def update_repo():
    logging.info(f"Ensuring Vulnrichment repo at {VULNREPO_DIR} ...")
    if not os.path.isdir(VULNREPO_DIR):
        logging.info("Repo not found, cloning...")
        try:
            subprocess.run(["git", "clone", "https://github.com/cisagov/vulnrichment", VULNREPO_DIR], check=True)
        except Exception as e:
            if ENV == 'production':
                logging.error("Could not clone Vulnrichment repo.")
            else:
                logging.error(f"Error: Could not clone Vulnrichment repo: {e}", exc_info=True)
            return
    # Set git safe.directory to avoid ownership errors
    try:
        subprocess.run(["git", "config", "--global", "--add", "safe.directory", VULNREPO_DIR], check=True)
    except Exception as e:
        if ENV == 'production':
            logging.warning("Could not set git safe.directory.")
        else:
            logging.warning(f"Warning: Could not set git safe.directory: {e}", exc_info=True)
    try:
        subprocess.run(["git", "pull"], cwd=VULNREPO_DIR, check=True)
    except Exception as e:
        if ENV == 'production':
            logging.warning("Could not update Vulnrichment repo.")
        else:
            logging.warning(f"Warning: Could not update Vulnrichment repo: {e}", exc_info=True)

def get_latest_commit():
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=VULNREPO_DIR).decode().strip()

def get_changed_files(last_commit, current_commit):
    output = subprocess.check_output(['git', 'diff', '--name-only', f'{last_commit}', f'{current_commit}'], cwd=VULNREPO_DIR)
    return [os.path.join(VULNREPO_DIR, f) for f in output.decode().splitlines() if f.endswith('.json') and 'CVE-' in f]

def get_all_cve_jsons():
    files = []
    for root, dirs, filelist in os.walk(VULNREPO_DIR):
        for file in filelist:
            if file.startswith('CVE-') and file.endswith('.json'):
                files.append(os.path.join(root, file))
    return files

def parse_jsons(json_files):
    logging.info(f"Parsing {len(json_files)} Vulnrichment JSONs ...")
    records = []
    for json_file in json_files:
        with open(json_file, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                cve_id = data.get('cveMetadata', {}).get('cveId')
                if not cve_id:
                    continue
                adp = None
                containers = data.get('containers', {})
                if 'adp' in containers and isinstance(containers['adp'], list) and containers['adp']:
                    adp = containers['adp'][0]
                record = {
                    'cve': cve_id,
                    'cvssScore': adp.get('cvssV3', {}).get('baseScore') if adp and 'cvssV3' in adp else None,
                    'cvssVector': adp.get('cvssV3', {}).get('vectorString') if adp and 'cvssV3' in adp else None,
                    'published': data.get('cveMetadata', {}).get('datePublished'),
                    'lastModified': data.get('cveMetadata', {}).get('dateUpdated'),
                    'summary': adp.get('description') if adp else None,
                    'cwe': adp.get('cwe') if adp and 'cwe' in adp else None,
                    'references': ",".join([ref.get('url') for ref in adp.get('references', []) if 'url' in ref]) if adp and 'references' in adp else None
                }
                records.append(record)
            except Exception as e:
                if ENV == 'production':
                    logging.warning(f"Failed to parse {json_file}")
    logging.info(f"Parsed {len(records)} records.")
    return records


def import_to_postgres(records, batch_size=1000, max_retries=3, dry_run=False, metrics=None):
    if metrics is not None:
        metrics.inserts += len(records)
    if dry_run:
        logging.info(f"[DRY RUN] Would upsert {len(records)} records into vulnrichment.")
        return
    conn = psycopg2.connect(**PG_CONFIG)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(CREATE_TABLE_SQL)
                for i in range(0, len(records), batch_size):
                    batch = records[i:i+batch_size]
                    psycopg2.extras.execute_batch(cur, INSERT_SQL, batch, page_size=100)
                    logging.info(f"Upserted {len(batch)} records into vulnrichment.")
        logging.info("Vulnrichment import complete.")
    finally:
        conn.close()

import argparse

def process_json_file(json_file):
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        cve_id = data.get('cveMetadata', {}).get('cveId')
        if not cve_id:
            return None
        adp = None
        containers = data.get('containers', {})
        if 'adp' in containers and isinstance(containers['adp'], list) and containers['adp']:
            adp = containers['adp'][0]
        record = {
            'cve': cve_id,
            'cvssScore': adp.get('cvssV3', {}).get('baseScore') if adp and 'cvssV3' in adp else None,
            'cvssVector': adp.get('cvssV3', {}).get('vectorString') if adp and 'cvssV3' in adp else None,
            'published': data.get('cveMetadata', {}).get('datePublished'),
            'lastModified': data.get('cveMetadata', {}).get('dateUpdated'),
            'summary': adp.get('description') if adp else None,
            'cwe': adp.get('cwe') if adp and 'cwe' in adp else None,
            'references': ",".join([ref.get('url') for ref in adp.get('references', []) if 'url' in ref]) if adp and 'references' in adp else None
        }
        return record
    except Exception as e:
        logging.warning(f"Failed to parse {json_file}: {e}", exc_info=True)
        return None

def main():
    update_repo()
    parser = argparse.ArgumentParser(description="Vulnrichment ETL: Choose mode (incremental/full)")
    parser.add_argument('--mode', choices=['incremental', 'full'], default='incremental', help="Import mode: incremental (default) or full")
    parser.add_argument('--workers', type=int, default=int(os.environ.get('VULN_WORKERS', 4)), help="Number of parallel worker threads (default: 4)")
    parser.add_argument('--batch-size', type=int, default=int(os.environ.get('VULN_BATCH_SIZE', 1000)), help="Batch size for DB upserts (default: 1000)")
    parser.add_argument('--verbosity', type=int, default=2, help="Verbosity: 1=WARNING, 2=INFO, 3=DEBUG")
    parser.add_argument('--dry-run', '-n', action='store_true', help='Run ETL without writing to the database')
    args = parser.parse_args()

    # Set logging level per CLI
    if args.verbosity == 1:
        logging.getLogger().setLevel(logging.WARNING)
    elif args.verbosity == 2:
        logging.getLogger().setLevel(logging.INFO)
    elif args.verbosity >= 3:
        logging.getLogger().setLevel(logging.DEBUG)

    metrics = RunMetrics(dry_run=args.dry_run)
    if args.dry_run:
        dry_run_notice()

    LAST_COMMIT_FILE = os.path.join(VULNREPO_DIR, '.last_import_commit')
    current_commit = get_latest_commit()
    last_commit = None
    if os.path.exists(LAST_COMMIT_FILE):
        with open(LAST_COMMIT_FILE, 'r') as f:
            last_commit = f.read().strip()

    if args.mode == 'full' or not last_commit:
        logging.info("Performing full import of Vulnrichment JSONs...")
        json_files = get_all_cve_jsons()
    else:
        logging.info(f"Performing incremental import: {last_commit} -> {current_commit}")
        changed_files = get_changed_files(last_commit, current_commit)
        if not changed_files:
            logging.info("No changed JSON files to import.")
            # Still update the commit file
            with open(LAST_COMMIT_FILE, 'w') as f:
                f.write(current_commit)
            return
        json_files = changed_files

    # Parallel parse
    records = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_json = {executor.submit(process_json_file, jf): jf for jf in json_files}
        for future in concurrent.futures.as_completed(future_to_json):
            record = future.result()
            if record:
                records.append(record)
    logging.info(f"Parsed {len(records)} records.")

    if not records:
        logging.warning("No records to import!")
        # Still update the commit file
        with open(LAST_COMMIT_FILE, 'w') as f:
            f.write(current_commit)
        return
    import_to_postgres(records, batch_size=args.batch_size, dry_run=args.dry_run, metrics=metrics)
    logging.info(f"[SUMMARY] Records processed: {metrics.inserts}")
    # Update commit file after successful import
    if not args.dry_run:
        with open(LAST_COMMIT_FILE, 'w') as f:
            f.write(current_commit)


if __name__ == "__main__":
    main()
