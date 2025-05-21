import os
import psycopg2

def get_db_conn():
    host = os.environ.get("DB_HOST", "localhost")
    port = os.environ.get("DB_PORT", "5432")
    dbname = os.environ.get("DB_NAME", "canonical_vulndb")
    user = os.environ.get("DB_USER", "postgres")
    password = os.environ.get("DB_PASSWORD", "")
    return psycopg2.connect(
        host=host, port=port, dbname=dbname, user=user, password=password
    )

def upsert_canonical_vuln(conn, record):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO canonical_vuln (vuln_id, cve_id, description, published, last_modified, source, raw_source_id, severity, "references", metadata)
            VALUES (%(vuln_id)s, %(cve_id)s, %(description)s, %(published)s, %(last_modified)s, %(source)s, %(raw_source_id)s, %(severity)s, %(references)s, %(metadata)s)
            ON CONFLICT (vuln_id) DO UPDATE SET
                cve_id = EXCLUDED.cve_id,
                description = EXCLUDED.description,
                published = EXCLUDED.published,
                last_modified = EXCLUDED.last_modified,
                source = EXCLUDED.source,
                raw_source_id = EXCLUDED.raw_source_id,
                severity = EXCLUDED.severity,
                "references" = EXCLUDED."references",
                metadata = EXCLUDED.metadata;
            """,
            record,
        )
        conn.commit()
