import os
import sys
import requests
import gzip
import shutil
import csv
import psycopg2
import logging
from cve_utils import ensure_cve_exists
from datetime import datetime, timedelta
from etl_utils import safe_execute, dry_run_notice, RunMetrics

# Set up logging to both file and console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler('update_epss.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

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


EPSS_DATA_DIR = os.path.join(os.path.dirname(__file__), 'epss-data', '3rd')
EPSS_OUT_DIR = os.path.join(os.path.dirname(__file__), 'epss-data')

MIN_DATE = datetime.strptime('2022-02-04', '%Y-%m-%d')

EPSS_URL_TEMPLATE = 'https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz'


def get_last_imported_date():
    # Connect to PostgreSQL and get the last imported date
    try:
        conn = psycopg2.connect(**PG_CONFIG)
        cur = conn.cursor()
        cur.execute("SELECT MAX(publish_date) FROM epssdb;")
        row = cur.fetchone()
        if row and row[0]:
            return datetime.strptime(str(row[0]), '%Y-%m-%d')
        else:
            return MIN_DATE
    except Exception as e:
        logging.warning(f"Warning: Could not get last imported date from DB: {e}")
        return MIN_DATE
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

def download_and_extract(date):
    os.makedirs(EPSS_DATA_DIR, exist_ok=True)
    os.makedirs(EPSS_OUT_DIR, exist_ok=True)
    gz_file = os.path.join(EPSS_DATA_DIR, f'epss_scores-{date}.csv.gz')
    csv_file = os.path.join(EPSS_OUT_DIR, f'epss_scores-{date}.csv')
    url = EPSS_URL_TEMPLATE.format(date=date)
    if os.path.exists(gz_file):
        logging.info(f"File already exists: {gz_file}")
    else:
        logging.info(f"Downloading {url} ...")
        r = requests.get(url, stream=True)
        if r.status_code != 200:
            logging.error(f"ERROR: Could not download {url}")
            return None
        with open(gz_file, 'wb') as f:
            f.write(r.content)
    # Extract
    with gzip.open(gz_file, 'rb') as f_in, open(csv_file, 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)
    return csv_file

def preprocess_csv(csv_file, default_date):
    """
    Parse an EPSS CSV file, extracting model_version and publish_date from the header comment.
    Attach both to every row for storage.
    """
    model_version = None
    publish_date = None
    processed_rows = []
    with open(csv_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('#'):
                # Look for model_version and publish_date in the comment
                if 'model_version' in line and 'publish_date' in line:
                    # Example: # model_version: v2023.03.01, publish_date: 2023-03-07
                    parts = line.strip('#').strip().split(',')
                    for part in parts:
                        if 'model_version' in part:
                            model_version = part.split(':')[1].strip()
                        if 'publish_date' in part:
                            publish_date = part.split(':')[1].strip()
                continue
            if line.startswith('cve,epss,percentile'):
                continue
            row = line.strip().split(',')
            if len(row) == 3:
                cve, epss, percentile = row
                # Use publish_date from header if present, otherwise fallback to default_date
                processed_rows.append([cve, epss, percentile, model_version, publish_date or default_date])
    return processed_rows


def import_to_postgres(rows, dry_run=False, metrics=None):
    # Ensure all CVEs in rows are present in canonical table
    if metrics is None:
        metrics = RunMetrics(dry_run=dry_run)
    if dry_run:
        dry_run_notice()
        logging.info(f"[DRY RUN] Would process {len(rows)} rows.")
    try:
        if not dry_run:
            conn = psycopg2.connect(**PG_CONFIG)
            with conn:
                for row in rows:
                    ensure_cve_exists(conn, row[0], source='epss')
            conn.close()
        else:
            for row in rows:
                logging.info(f"[DRY RUN] Would ensure CVE exists: {row[0]}")
    except Exception as e:
        logging.error(f"ERROR ensuring CVEs: {e}")
        metrics.errors += 1
    metrics.fetched += len(rows)
    metrics.inserts += len(rows)
    if dry_run:
        logging.info(f"[DRY RUN] Would import {len(rows)} rows into PostgreSQL...")
        return
    conn = None
    try:
        conn = psycopg2.connect(**PG_CONFIG)
        cur = conn.cursor()
        safe_execute(cur, """
        CREATE TABLE IF NOT EXISTS epssdb (
            cve TEXT,
            epss FLOAT,
            percentile FLOAT,
            model TEXT,
            publish_date DATE
        );
        """, dry_run=dry_run)
        # Use COPY for efficient bulk import
        import io
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerows(rows)
        buf.seek(0)
        if not dry_run:
            cur.copy_expert(
                "COPY epssdb (cve, epss, percentile, model, publish_date) FROM STDIN WITH CSV",
                buf
            )
            conn.commit()
            logging.info("Import complete.")
        else:
            logging.info(f"[DRY RUN] Would COPY {len(rows)} rows into epssdb.")
    except Exception as e:
        logging.error(f"ERROR importing to PostgreSQL: {e}")
        metrics.errors += 1
        if conn:
            conn.rollback()
    finally:
        if conn:
            cur.close()
            conn.close()

def daterange(start_date, end_date):
    for n in range(int((end_date - start_date).days)):
        yield start_date + timedelta(n)

import argparse

def main():
    parser = argparse.ArgumentParser(description="EPSS ETL: full or incremental mode")
    parser.add_argument('--mode', choices=['full', 'incremental'], default='incremental', help='Update mode: full (all data) or incremental (default)')
    parser.add_argument('--dry-run', action='store_true', help='Dry run mode: log DB actions, do not write')
    args = parser.parse_args()

    dry_run = args.dry_run
    metrics = RunMetrics(dry_run=dry_run)
    print("Starting update_epss.py", flush=True)
    logging.info("Starting update_epss.py")
    if dry_run:
        dry_run_notice()

    if args.mode == 'full':
        # Full mode: truncate table and re-import all data
        logging.info("FULL mode: truncating epssdb table and re-importing all EPSS data.")
        if not dry_run:
            conn = psycopg2.connect(**PG_CONFIG)
            try:
                with conn:
                    cur = conn.cursor()
                    safe_execute(cur, "DROP TABLE IF EXISTS epssdb;", dry_run=dry_run)
                    conn.commit()
            finally:
                conn.close()
        else:
            logging.info("[DRY RUN] Would drop table epssdb.")
        # Earliest possible EPSS date (v1) is 2021-04-14
        start_date = datetime.strptime('2021-04-14', '%Y-%m-%d')
    else:
        last_date = get_last_imported_date()
        start_date = last_date + timedelta(days=1)

    end_date = datetime.today() + timedelta(days=1)
    logging.info(f"Auto data import: {start_date.date()} to {end_date.date()}")
    for d in daterange(start_date, end_date):
        date_str = d.strftime('%Y-%m-%d')
        logging.info(f"Processing {date_str}")
        csv_file = download_and_extract(date_str)
        if not csv_file:
            logging.warning(f"Skipping {date_str} (no file)")
            metrics.skipped += 1
            continue
        rows = preprocess_csv(csv_file, date_str)
        if rows:
            import_to_postgres(rows, dry_run=dry_run, metrics=metrics)
        else:
            logging.info(f"No data for {date_str}")
            metrics.skipped += 1
        # Clean up
        try:
            os.remove(csv_file)
        except Exception:
            pass
    metrics.log_summary()
    logging.info("Auto data import finished.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print("Fatal error in update_epss.py:", e, file=sys.stderr, flush=True)
        traceback.print_exc()
        logging.error("Fatal error in update_epss.py", exc_info=True)
        sys.exit(1)
