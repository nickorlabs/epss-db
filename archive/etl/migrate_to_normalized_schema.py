"""
Hybrid CVE Data Migration Script
- Reads from raw source tables (mitre_cve, nvd_cve) which are preserved for audit and fidelity.
- Populates canonical normalized tables (cve, cve_reference, cvss) for unified analytics.
- Views/materialized views can be created on top for analytics and reporting.
- Does NOT drop or modify raw source tables.
"""
import os
import psycopg2
import json
import logging

def get_pg_config():
    return {
        'host': os.environ.get('PGHOST', 'db'),
        'user': read_secret('/run/secrets/pg_user', os.environ.get('PGUSER', 'postgres')),
        'password': read_secret('/run/secrets/pg_password', os.environ.get('PGPASSWORD', 'postgres')),
        'dbname': os.environ.get('PGDATABASE', 'epssdb'),
    }

def read_secret(secret_path, default):
    try:
        with open(secret_path, 'r') as f:
            return f.read().strip()
    except Exception:
        return default

def migrate_table(source_table, source):
    pg_config = get_pg_config()
    conn = psycopg2.connect(**pg_config)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {source_table};")
    rows = cur.fetchall()
    colnames = [desc[0] for desc in cur.description]
    count = 0
    for row in rows:
        data = dict(zip(colnames, row))
        cve_id = data.get('cve_id')
        # Prepare json_data with the current source
        raw_json = data.get('json_data')
        if isinstance(raw_json, str):
            try:
                raw_json = json.loads(raw_json)
            except Exception:
                pass
        json_data_obj = {source: raw_json} if raw_json else {}

        # Try to insert; if conflict, update json_data to merge
        cur.execute(
            """
            INSERT INTO cve (cve_id, source, published, last_modified, description, cwe, assigner, state, year, json_data)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (cve_id) DO UPDATE SET
                json_data = cve.json_data || EXCLUDED.json_data
            """,
            (
                cve_id,
                source,
                data.get('published'),
                data.get('last_modified'),
                data.get('description'),
                data.get('cwe'),
                data.get('assigner'),
                data.get('state'),
                data.get('year'),
                json.dumps(json_data_obj)
            )
        )
        # Insert references
        references = data.get('references')
        if references:
            if isinstance(references, str):
                try:
                    ref_list = json.loads(references)
                except Exception:
                    ref_list = [references]
            else:
                ref_list = references
            for ref in ref_list:
                cur.execute(
                    "INSERT INTO cve_reference (cve_id, reference) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (cve_id, ref)
                )
        # Insert CVSS (v2, v3, v4)
        for version in ['2', '3', '4']:
            base_score = data.get(f'cvss{version}_score') or data.get(f'cvss{version}_base_score')
            vector = data.get(f'cvss{version}_vector')
            if base_score or vector:
                cur.execute(
                    """
                    INSERT INTO cvss (
                        cve_id, version, base_score, vector, av, ac, au, pr, ui, v, c, i, a, s, si, sc, sa, source
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    ) ON CONFLICT DO NOTHING
                    """,
                    (
                        cve_id,
                        f'{version}.0',
                        base_score,
                        vector,
                        data.get(f'cvss{version}_av'),
                        data.get(f'cvss{version}_ac'),
                        data.get(f'cvss{version}_au'),
                        data.get(f'cvss{version}_pr'),
                        data.get(f'cvss{version}_ui'),
                        data.get(f'cvss{version}_v'),
                        data.get(f'cvss{version}_c'),
                        data.get(f'cvss{version}_i'),
                        data.get(f'cvss{version}_a'),
                        data.get(f'cvss{version}_s'),
                        data.get(f'cvss{version}_si'),
                        data.get(f'cvss{version}_sc'),
                        data.get(f'cvss{version}_sa'),
                        source
                    )
                )
        count += 1
        if count % 1000 == 0:
            print(f"Migrated {count} records from {source_table}")
    print(f"Migration from {source_table} complete. Total: {count}")
    cur.close()
    conn.close()

def upsert_from_nvd_cve():
    pg_config = get_pg_config()
    conn = psycopg2.connect(**pg_config)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("SELECT * FROM nvd_cve;")
    rows = cur.fetchall()
    colnames = [desc[0] for desc in cur.description]
    count = 0
    for row in rows:
        data = dict(zip(colnames, row))
        cve_id = data.get('cve_id')
        # Prepare json_data for NVD
        raw_json = data.get('json_data')
        if isinstance(raw_json, str):
            try:
                raw_json = json.loads(raw_json)
            except Exception:
                raw_json = {}
        json_data_obj = {"nvd": raw_json} if raw_json else {}

        cur.execute(
            """
            INSERT INTO cve (cve_id, source, published, last_modified, description, cwe, json_data)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (cve_id) DO UPDATE SET
                source = EXCLUDED.source,
                published = EXCLUDED.published,
                last_modified = EXCLUDED.last_modified,
                description = EXCLUDED.description,
                cwe = EXCLUDED.cwe,
                json_data = cve.json_data || EXCLUDED.json_data
            """,
            (
                cve_id,
                "nvd",
                data.get('published'),
                data.get('last_modified'),
                data.get('description'),
                data.get('cwe'),
                json.dumps(json_data_obj)
            )
        )
        count += 1
        if count % 1000 == 0:
            print(f"Upserted {count} records from nvd_cve to cve")
    print(f"Upsert from nvd_cve complete. Total: {count}")
    cur.close()
    conn.close()

def main():
    logging.basicConfig(level=logging.INFO)
    migrate_table('mitre_cve', 'mitre')
    migrate_table('nvd_cve', 'nvd')
    upsert_from_nvd_cve()

if __name__ == "__main__":
    main()
