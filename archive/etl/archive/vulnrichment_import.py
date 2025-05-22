import os
import psycopg2

PG_CONFIG = {
    'host': os.environ.get('PGHOST', 'db'),
    'user': os.environ.get('PGUSER', 'postgres'),
    'password': os.environ.get('PGPASSWORD', 'postgres'),
    'dbname': os.environ.get('PGDATABASE', 'epssdb'),
}

VULN_CSV = 'vulnrichment.csv'  # Now reads from project directory

def import_vulnrichment():
    print("Importing vulnrichment data into PostgreSQL with COPY ...")
    conn = None
    try:
        conn = psycopg2.connect(**PG_CONFIG)
        conn.autocommit = True
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnrichment (
            cve_id TEXT,
            cpe TEXT,
            description TEXT,
            severity TEXT,
            published_date DATE,
            last_modified_date DATE
        );
        """)
        with open(VULN_CSV, 'r', encoding='utf-8') as f:
            cursor.copy_expert(
                "COPY vulnrichment (cve_id, cpe, description, severity, published_date, last_modified_date) FROM STDIN WITH CSV HEADER",
                f
            )
        print("Imported vulnrichment data into PostgreSQL via COPY.")
    except Exception as e:
        print(f"PostgreSQL Error: {e}")
        exit(1)
    finally:
        if conn:
            cursor.close()
            conn.close()

if __name__ == "__main__":
    import_vulnrichment()
