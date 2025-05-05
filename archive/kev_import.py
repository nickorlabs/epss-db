import os
import psycopg2

PG_CONFIG = {
    'host': os.environ.get('PGHOST', 'db'),
    'user': os.environ.get('PGUSER', 'postgres'),
    'password': os.environ.get('PGPASSWORD', 'postgres'),
    'dbname': os.environ.get('PGDATABASE', 'epssdb'),
}

KEV_CSV = 'kev.csv'  # Now reads from project directory

def import_kev():
    print("Importing KEV data into PostgreSQL with COPY ...")
    conn = None
    try:
        conn = psycopg2.connect(**PG_CONFIG)
        conn.autocommit = True
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS kev (
            cve_id TEXT PRIMARY KEY,
            vendor_project TEXT,
            product TEXT,
            vulnerability_name TEXT,
            date_added DATE,
            short_description TEXT,
            required_action TEXT,
            due_date DATE,
            notes TEXT
        );
        """)
        with open(KEV_CSV, 'r', encoding='utf-8') as f:
            cursor.copy_expert(
                "COPY kev (cve_id, vendor_project, product, vulnerability_name, date_added, short_description, required_action, due_date, notes) FROM STDIN WITH CSV HEADER",
                f
            )
        print("Imported KEV data into PostgreSQL via COPY.")
    except Exception as e:
        print(f"PostgreSQL Error: {e}")
        exit(1)
    finally:
        if conn:
            cursor.close()
            conn.close()

if __name__ == "__main__":
    import_kev()
