import psycopg2
import psycopg2.extras
import json
import os

PG_CONFIG = {
    'host': os.environ.get('PGHOST', 'db'),
    'user': os.environ.get('PGUSER', 'postgres'),
    'password': os.environ.get('PGPASSWORD', 'postgres'),
    'dbname': os.environ.get('PGDATABASE', 'epssdb'),
}

def extract_references_from_json(cve_id, json_data):
    try:
        item = json.loads(json_data)
    except Exception:
        return []
    refs = item.get('references', [])
    result = []
    for r in refs:
        url = r.get('url')
        if url:
            result.append({'cve_id': cve_id, 'url': url})
    return result

def main():
    conn = psycopg2.connect(**PG_CONFIG)
    try:
        with conn:
            with conn.cursor(name='cve_cur') as cur:
                cur.itersize = 1000
                cur.execute("SELECT cve_id, json_data FROM nvd_cve")
                batch = []
                for row in cur:
                    cve_id, json_data = row
                    batch.extend(extract_references_from_json(cve_id, json_data))
                    if len(batch) >= 1000:
                        upsert_cve_references_batch(conn, batch)
                        batch = []
                if batch:
                    upsert_cve_references_batch(conn, batch)
    finally:
        conn.close()

def upsert_cve_references_batch(conn, records):
    if not records:
        return
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(
            cur,
            """
INSERT INTO nvd_cve_reference (cve_id, url)
VALUES (%(cve_id)s, %(url)s)
ON CONFLICT DO NOTHING;
""",
            records,
            page_size=1000
        )

if __name__ == "__main__":
    main()
