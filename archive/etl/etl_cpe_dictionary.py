"""
ETL script to download, parse, and load the NVD CPE dictionary into the cpe_dictionary table.
- Downloads the official CPE dictionary from NVD (https://nvd.nist.gov/products/cpe)
- Parses the XML or JSON feed
- Loads/updates the cpe_dictionary table
"""
import os
import requests
import xml.etree.ElementTree as ET
import psycopg2

import os
import requests
import gzip
import json
import psycopg2

CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

PG_CONFIG = {
    'host': os.environ.get('PGHOST', 'db'),
    'user': os.environ.get('PGUSER', 'postgres'),
    'password': os.environ.get('PGPASSWORD', 'postgres'),
    'dbname': os.environ.get('PGDATABASE', 'epssdb'),
}

def fetch_and_load_cpe_api():
    conn = psycopg2.connect(**PG_CONFIG)
    cur = conn.cursor()
    url = CPE_API_URL
    params = {"resultsPerPage": 2000, "startIndex": 0}
    total = None
    fetched = 0
    while True:
        resp = requests.get(url, params=params)
        resp.raise_for_status()
        data = resp.json()
        products = data.get("products", [])
        for product in products:
            cpe = product.get("cpe")
            if not cpe:
                continue
            cpe23uri = cpe.get("cpeName")
            deprecated = cpe.get("deprecated", False)
            title = None
            titles = cpe.get("titles", [])
            if titles:
                for t in titles:
                    if t.get("lang") == "en":
                        title = t.get("title")
                        break
                if not title:
                    title = titles[0].get("title")
            # Parse CPE parts
            parts = cpe23uri.split(":") if cpe23uri else []
            part = parts[2] if len(parts) > 2 else None
            vendor = parts[3] if len(parts) > 3 else None
            product_name = parts[4] if len(parts) > 4 else None
            version = parts[5] if len(parts) > 5 else None
            update = parts[6] if len(parts) > 6 else None
            edition = parts[7] if len(parts) > 7 else None
            language = parts[8] if len(parts) > 8 else None
            cur.execute("""
                INSERT INTO cpe_dictionary (cpe_id, part, vendor, product, version, update, edition, language, title, deprecated)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (cpe_id) DO UPDATE SET
                    title = EXCLUDED.title,
                    deprecated = EXCLUDED.deprecated
            """, (cpe23uri, part, vendor, product_name, version, update, edition, language, title, deprecated))
        fetched += len(products)
        if total is None:
            total = data.get("totalResults", 0)
        if fetched >= total:
            break
        params["startIndex"] += params["resultsPerPage"]
    conn.commit()
    cur.close()
    conn.close()
    print(f"CPE dictionary loaded: {fetched} entries.")

def main():
    fetch_and_load_cpe_api()

if __name__ == "__main__":
    main()
