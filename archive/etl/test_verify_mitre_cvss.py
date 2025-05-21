import os
import json
import random
import psycopg2
from glob import glob

PG_CONFIG = {
    'host': os.environ.get('PGHOST', 'db'),
    'user': os.environ.get('PGUSER', 'postgres'),
    'password': os.environ.get('PGPASSWORD', 'postgres'),
    'dbname': os.environ.get('PGDATABASE', 'epssdb'),
}

MITRE_DIR = os.path.join(os.path.dirname(__file__), 'mitre-cvelistV5', 'cves')

# Helper to find CVE json path from CVE ID
def find_cve_json_path(cve_id):
    parts = cve_id.split('-')
    year = parts[1]
    num = parts[2]
    subdir = num[:2] + 'xxx' if len(num) > 2 else num.zfill(4) + 'xxx'
    return os.path.join(MITRE_DIR, year, subdir, f'CVE-{year}-{num}.json')

def get_db_connection():
    return psycopg2.connect(**PG_CONFIG)

def sample_cves_with_cvss(version_col, sample_size=100):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT cve_id FROM mitre_cve WHERE {version_col} IS NOT NULL LIMIT %s", (sample_size,))
            return [row[0] for row in cur.fetchall()]

def sample_cves_without_cvss(version_col, sample_size=100):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT cve_id FROM mitre_cve WHERE {version_col} IS NULL LIMIT %s", (sample_size,))
            return [row[0] for row in cur.fetchall()]

def extract_cvss_from_json(cve_json, version):
    metrics = cve_json.get('containers', {}).get('cna', {}).get('metrics', [])
    version_map = {2: 'cvssV2_0', 3: 'cvssV3_1', 4: 'cvssV4_0'}
    key = version_map.get(version)
    for m in metrics:
        if m.get('format', '').lower() == 'cvss':
            if key and key in m:
                cvss = m[key]
                ver = cvss.get('version') or m.get('version') or str(version)
                vector = cvss.get('vectorString') or cvss.get('vector')
                score = cvss.get('baseScore') or cvss.get('score')
                return ver, vector, score
            if m.get('version', '').startswith(str(version)):
                return m.get('version'), m.get('vector'), m.get('score')
    return None, None, None

def verify_cve_cvss(cve_id, db_row, version):
    path = find_cve_json_path(cve_id)
    if not os.path.exists(path):
        print(f"JSON missing for {cve_id} at {path}")
        return False
    with open(path, 'r', encoding='utf-8') as f:
        cve_json = json.load(f)
    json_ver, json_vec, json_score = extract_cvss_from_json(cve_json, version)
    db_ver, db_vec, db_score = db_row
    if (db_ver, db_vec, db_score) != (json_ver, json_vec, json_score):
        print(f"Mismatch for {cve_id}: DB=({db_ver}, {db_vec}, {db_score}), JSON=({json_ver}, {json_vec}, {json_score})")
        return False
    return True

def main():
    versions = [(2, 'cvss2_vector', 'cvss2_version', 'cvss2_score'),
                (3, 'cvss3_vector', 'cvss3_version', 'cvss3_score'),
                (4, 'cvss4_vector', 'cvss4_version', 'cvss4_score')]
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            for v, vec_col, ver_col, score_col in versions:
                print(f"\n--- Verifying CVEs WITH CVSS v{v} ---")
                ids = sample_cves_with_cvss(vec_col, 1000)
                for cve_id in ids:
                    cur.execute(f"SELECT {ver_col}, {vec_col}, {score_col} FROM mitre_cve WHERE cve_id = %s", (cve_id,))
                    db_row = cur.fetchone()
                    verify_cve_cvss(cve_id, db_row, v)
                print(f"\n--- Verifying CVEs WITHOUT CVSS v{v} ---")
                ids = sample_cves_without_cvss(vec_col, 1000)
                for cve_id in ids:
                    cur.execute(f"SELECT {ver_col}, {vec_col}, {score_col} FROM mitre_cve WHERE cve_id = %s", (cve_id,))
                    db_row = cur.fetchone()
                    verify_cve_cvss(cve_id, db_row, v)

if __name__ == "__main__":
    main()
