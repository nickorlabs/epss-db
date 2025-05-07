import os
import subprocess
import json
import psycopg2
from glob import glob
from datetime import datetime
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

def parse_jsons():
    logging.info(f"Parsing Vulnrichment JSONs in {VULNREPO_DIR} ...")
    records = []
    for json_file in glob(os.path.join(VULNREPO_DIR, "**", "*.json"), recursive=True):
        with open(json_file, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                cve_id = data.get('cveMetadata', {}).get('cveId')
                if not cve_id:
                    continue
                # Try to extract fields from the most common locations
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
                else:
                    logging.warning(f"Failed to parse {json_file}: {e}", exc_info=True)
    logging.info(f"Parsed {len(records)} records.")
    return records

def import_to_postgres(records):
    logging.info(f"Importing {len(records)} records into PostgreSQL in batches...")
    conn = psycopg2.connect(**PG_CONFIG)
    batch_size = 1000
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(CREATE_TABLE_SQL)
                for i in range(0, len(records), batch_size):
                    batch = records[i:i+batch_size]
                    cur.executemany(INSERT_SQL, batch)
                    logging.info(f"Inserted batch {i//batch_size+1} ({len(batch)} records)")
        logging.info("Vulnrichment import complete.")
    finally:
        conn.close()

def main():
    update_repo()
    records = parse_jsons()
    if not records:
        logging.warning("No records to import!")
        return
    import_to_postgres(records)

if __name__ == "__main__":
    main()
