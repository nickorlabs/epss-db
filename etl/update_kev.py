import os
import requests
import psycopg2
import json

PG_CONFIG = {
    'host': os.environ.get('PGHOST', 'db'),
    'user': os.environ.get('PGUSER', 'postgres'),
    'password': os.environ.get('PGPASSWORD', 'postgres'),
    'dbname': os.environ.get('PGDATABASE', 'epssdb'),
}

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CREATE_TABLE_SQL = """
DROP TABLE IF EXISTS kevcatalog;
CREATE TABLE kevcatalog (
    id SERIAL PRIMARY KEY,
    cveID TEXT,
    vendorProject TEXT,
    product TEXT,
    vulnerabilityName TEXT,
    dateAdded DATE,
    shortDescription TEXT,
    requiredAction TEXT,
    dueDate DATE,
    knownRansomwareCampaignUse TEXT,
    notes TEXT
);
"""

INSERT_SQL = """
INSERT INTO kevcatalog (
    cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes
) VALUES (
    %(cveID)s, %(vendorProject)s, %(product)s, %(vulnerabilityName)s, %(dateAdded)s, %(shortDescription)s, %(requiredAction)s, %(dueDate)s, %(knownRansomwareCampaignUse)s, %(notes)s
);
"""

def fetch_kev_json():
    print(f"Downloading KEV JSON from {KEV_URL} ...")
    resp = requests.get(KEV_URL)
    resp.raise_for_status()
    return resp.json()

def import_to_postgres(vulns):
    print(f"Importing {len(vulns)} vulnerabilities into PostgreSQL...")
    conn = psycopg2.connect(**PG_CONFIG)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(CREATE_TABLE_SQL)
                for v in vulns:
                    # Clean up and map fields
                    row = {
                        'cveID': v.get('cveID'),
                        'vendorProject': v.get('vendorProject'),
                        'product': v.get('product'),
                        'vulnerabilityName': v.get('vulnerabilityName'),
                        'dateAdded': v.get('dateAdded'),
                        'shortDescription': v.get('shortDescription'),
                        'requiredAction': v.get('requiredAction'),
                        'dueDate': v.get('dueDate'),
                        'knownRansomwareCampaignUse': v.get('knownRansomwareCampaignUse'),
                        'notes': v.get('notes'),
                    }
                    cur.execute(INSERT_SQL, row)
        print("KEV import complete.")
    finally:
        conn.close()

def main():
    data = fetch_kev_json()
    vulns = data.get('vulnerabilities', [])
    if not vulns:
        print("No vulnerabilities found in KEV JSON!")
        return
    import_to_postgres(vulns)

if __name__ == "__main__":
    main()
