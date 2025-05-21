import os
import requests
import psycopg2
import json
import logging

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


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CREATE_TABLE_SQL = """
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'kevcatalog') THEN
        CREATE TABLE kevcatalog (
            id SERIAL PRIMARY KEY,
            cveID TEXT UNIQUE,
            vendorProject TEXT,
            product TEXT,
            vulnerabilityName TEXT,
            dateAdded DATE,
            shortDescription TEXT,
            requiredAction TEXT,
            dueDate DATE,
            knownRansomwareCampaignUse TEXT,
            notes TEXT,
            last_seen DATE,
            status TEXT DEFAULT 'active',
            removed_at DATE
        );
    END IF;
    -- Add new columns if missing (idempotent)
    BEGIN
        ALTER TABLE kevcatalog ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';
    EXCEPTION WHEN duplicate_column THEN END;
    BEGIN
        ALTER TABLE kevcatalog ADD COLUMN IF NOT EXISTS removed_at DATE;
    EXCEPTION WHEN duplicate_column THEN END;
END$$;
"""

UPSERT_SQL = """
INSERT INTO kevcatalog (
    cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes, last_seen, status, removed_at
) VALUES (
    %(cveID)s, %(vendorProject)s, %(product)s, %(vulnerabilityName)s, %(dateAdded)s, %(shortDescription)s, %(requiredAction)s, %(dueDate)s, %(knownRansomwareCampaignUse)s, %(notes)s, %(last_seen)s, 'active', NULL
)
ON CONFLICT (cveID) DO UPDATE SET
    vendorProject = EXCLUDED.vendorProject,
    product = EXCLUDED.product,
    vulnerabilityName = EXCLUDED.vulnerabilityName,
    dateAdded = EXCLUDED.dateAdded,
    shortDescription = EXCLUDED.shortDescription,
    requiredAction = EXCLUDED.requiredAction,
    dueDate = EXCLUDED.dueDate,
    knownRansomwareCampaignUse = EXCLUDED.knownRansomwareCampaignUse,
    notes = EXCLUDED.notes,
    last_seen = EXCLUDED.last_seen,
    status = 'active',
    removed_at = NULL;
"""

def fetch_kev_json():
    logging.info(f"Downloading KEV JSON from {KEV_URL} ...")
    resp = requests.get(KEV_URL)
    resp.raise_for_status()
    return resp.json()

from cve_utils import ensure_cve_exists

def import_to_postgres(vulns, dry_run=False, metrics=None):
    from datetime import date
    from etl_utils import safe_execute, safe_executemany
    if metrics is None:
        from etl_utils import RunMetrics
        metrics = RunMetrics(dry_run=dry_run)
    logging.info(f"Importing {len(vulns)} vulnerabilities into PostgreSQL with upsert... (dry_run={dry_run})")
    conn = None
    try:
        conn = psycopg2.connect(**PG_CONFIG)
        with conn:
            with conn.cursor() as cur:
                safe_execute(cur, CREATE_TABLE_SQL, dry_run=dry_run)
                today = date.today()
                kev_cveids = set()
                for v in vulns:
                    cve_id = v.get('cveID')
                    kev_cveids.add(cve_id)
                    if not dry_run:
                        ensure_cve_exists(conn, cve_id, source='kev')
                        metrics.inserts += 1  # Treat as insert for metrics (or refine if you can detect update)
                    else:
                        logging.info(f"[DRY RUN] Would ensure CVE exists: {cve_id} (kev)")
                        metrics.inserts += 1
                    row = {
                        'cveID': cve_id,
                        'vendorProject': v.get('vendorProject'),
                        'product': v.get('product'),
                        'vulnerabilityName': v.get('vulnerabilityName'),
                        'dateAdded': v.get('dateAdded'),
                        'shortDescription': v.get('shortDescription'),
                        'requiredAction': v.get('requiredAction'),
                        'dueDate': v.get('dueDate'),
                        'knownRansomwareCampaignUse': v.get('knownRansomwareCampaignUse'),
                        'notes': v.get('notes'),
                        'last_seen': today,
                    }
                    cur.execute(UPSERT_SQL, row)
                # Mark removed CVEs
                cur.execute("SELECT cveID FROM kevcatalog WHERE status = 'active'")
                db_active = set(row[0] for row in cur.fetchall())
                removed = db_active - kev_cveids
                if removed:
                    cur.execute(
                        "UPDATE kevcatalog SET status = 'removed', removed_at = %s WHERE cveID = ANY(%s)",
                        (today, list(removed))
                    )
                    logging.info(f"Marked {len(removed)} CVEs as removed from KEV.")
        logging.info("KEV upsert complete.")
    except Exception as e:
        if ENV == 'production':
            logging.error("Error importing vulnerabilities into PostgreSQL.")
        else:
            logging.error(f"Error importing vulnerabilities into PostgreSQL: {e}", exc_info=True)
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

def main():
    import argparse
    from etl_utils import RunMetrics, dry_run_notice
    parser = argparse.ArgumentParser(description="KEV ETL")
    parser.add_argument('--dry-run', '-n', action='store_true', help='Run ETL without writing to the database')
    args = parser.parse_args()
    metrics = RunMetrics(dry_run=args.dry_run)
    if args.dry_run:
        dry_run_notice()
    data = fetch_kev_json()
    vulns = data.get('vulnerabilities', [])
    metrics.fetched = len(vulns)
    if not vulns:
        logging.warning("No vulnerabilities found in KEV JSON!")
        metrics.log_summary()
        return
    import_to_postgres(vulns, dry_run=args.dry_run, metrics=metrics)
    metrics.log_summary()

if __name__ == "__main__":
    main()
