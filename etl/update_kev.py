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

def import_to_postgres(vulns):
    from datetime import date
    logging.info(f"Importing {len(vulns)} vulnerabilities into PostgreSQL with upsert...")
    conn = None
    try:
        conn = psycopg2.connect(**PG_CONFIG)
        with conn:
            with conn.cursor() as cur:
                cur.execute(CREATE_TABLE_SQL)
                today = date.today()
                kev_cveids = set()
                for v in vulns:
                    cve_id = v.get('cveID')
                    kev_cveids.add(cve_id)
                    ensure_cve_exists(conn, cve_id, source='kev')
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
    data = fetch_kev_json()
    vulns = data.get('vulnerabilities', [])
    if not vulns:
        logging.warning("No vulnerabilities found in KEV JSON!")
        return
    import_to_postgres(vulns)

if __name__ == "__main__":
    main()
