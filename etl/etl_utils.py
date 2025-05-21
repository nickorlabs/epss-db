import os
import psycopg2
import logging
from contextlib import contextmanager

# Load DB connection from environment variables (or .env)
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME', 'canonical_vulndb')
def load_secret(secret_name, default=None):
    secret_path = f"/run/secrets/{secret_name}"
    if os.path.exists(secret_path):
        with open(secret_path, "r") as f:
            return f.read().strip()
    return default

DB_USER = load_secret('pg_user', os.getenv('DB_USER', 'postgres'))
DB_PASS = load_secret('pg_password', os.getenv('DB_PASS', 'postgres'))

# Logging setup
def setup_logging(name="etl_v2", level=logging.INFO):
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    return logging.getLogger(name)

@contextmanager
def get_db_conn():
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )
    try:
        yield conn
    finally:
        conn.close()

def upsert_canonical_vuln(conn, vuln):
    """
    Upsert a vulnerability record into canonical_vuln table.
    Expects 'vuln' as a dict matching canonical schema.
    """
    with conn.cursor() as cur:
        cur.execute("""
        INSERT INTO canonical_vuln (
            vuln_id, cve_id, osv_id, ghsa_id, cnnvd_id, cnvd_id,
            published, modified, description, references,
            cvss2, cvss3, cvss4, enrichment, sources, provenance, primary_source, raw_data
        ) VALUES (
            %(vuln_id)s, %(cve_id)s, %(osv_id)s, %(ghsa_id)s, %(cnnvd_id)s, %(cnvd_id)s,
            %(published)s, %(modified)s, %(description)s, %(references)s,
            %(cvss2)s, %(cvss3)s, %(cvss4)s, %(enrichment)s, %(sources)s, %(provenance)s, %(primary_source)s, %(raw_data)s
        ) ON CONFLICT (vuln_id) DO UPDATE SET
            cve_id = EXCLUDED.cve_id,
            osv_id = EXCLUDED.osv_id,
            ghsa_id = EXCLUDED.ghsa_id,
            cnnvd_id = EXCLUDED.cnnvd_id,
            cnvd_id = EXCLUDED.cnvd_id,
            published = EXCLUDED.published,
            modified = EXCLUDED.modified,
            description = EXCLUDED.description,
            references = EXCLUDED.references,
            cvss2 = EXCLUDED.cvss2,
            cvss3 = EXCLUDED.cvss3,
            cvss4 = EXCLUDED.cvss4,
            enrichment = EXCLUDED.enrichment,
            sources = EXCLUDED.sources,
            provenance = EXCLUDED.provenance,
            primary_source = EXCLUDED.primary_source,
            raw_data = EXCLUDED.raw_data;
        """, vuln)
        conn.commit()
