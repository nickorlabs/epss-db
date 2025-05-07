import os
import json
import psycopg2
from datetime import datetime
from glob import glob

PG_CONFIG = {
    'host': os.environ.get('PGHOST', 'db'),
    'user': os.environ.get('PGUSER', 'postgres'),
    'password': os.environ.get('PGPASSWORD', 'postgres'),
    'dbname': os.environ.get('PGDATABASE', 'epssdb'),
}

import subprocess
MITRE_ROOT = os.path.join(os.path.dirname(__file__), 'mitre-cvelistV5')
MITRE_DIR = os.path.join(MITRE_ROOT, 'cves')

# Helper to extract CVSS metrics from CNA metrics array
def extract_cvss(metrics, version):
    """
    Extract CVSS version, vector, and score from MITRE CNA metrics array.
    Handles both nested (cvssV2_0, cvssV3_1, cvssV4_0) and legacy flat structures.
    """
    if not metrics:
        return None, None, None
    version_map = {
        2: 'cvssV2_0',
        3: 'cvssV3_1',
        4: 'cvssV4_0',
    }
    key = version_map.get(version)
    for m in metrics:
        if m.get('format', '').lower() == 'cvss':
            # Nested structure (preferred)
            if key and key in m:
                cvss = m[key]
                ver = cvss.get('version') or m.get('version') or str(version)
                vector = cvss.get('vectorString') or cvss.get('vector')
                score = cvss.get('baseScore') or cvss.get('score')
                return ver, vector, score
            # Legacy flat structure fallback
            if m.get('version', '').startswith(str(version)):
                return m.get('version'), m.get('vector'), m.get('score')
    return None, None, None

# Helper: Parse CVSS vector string (same as in update_nvd.py)
import re
def parse_cvss_vector(vector):
    if not vector:
        return {}
    vector = re.sub(r'^CVSS:[\d.]+/', '', vector)
    parts = vector.split('/')
    result = {}
    for part in parts:
        if ':' in part:
            k, v = part.split(':', 1)
        elif '=' in part:
            k, v = part.split('=', 1)
        else:
            continue
        result[k.lower()] = v
    return result

def upsert_cve(record):
    conn = psycopg2.connect(**PG_CONFIG)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                INSERT INTO mitre_cve (
                    cve_id, year, state, assigner, published, last_modified, description, "references",
                    cvss2_version, cvss2_vector, cvss2_score,
                    cvss3_version, cvss3_vector, cvss3_score,
                    cvss4_version, cvss4_vector, cvss4_score,
                    json_data
                ) VALUES (
                    %(cve_id)s, %(year)s, %(state)s, %(assigner)s, %(published)s, %(last_modified)s, %(description)s, %(references)s,
                    %(cvss2_version)s, %(cvss2_vector)s, %(cvss2_score)s,
                    %(cvss3_version)s, %(cvss3_vector)s, %(cvss3_score)s,
                    %(cvss4_version)s, %(cvss4_vector)s, %(cvss4_score)s,
                    %(json_data)s
                )
                ON CONFLICT (cve_id) DO UPDATE SET
                    year = EXCLUDED.year,
                    state = EXCLUDED.state,
                    assigner = EXCLUDED.assigner,
                    published = EXCLUDED.published,
                    last_modified = EXCLUDED.last_modified,
                    description = EXCLUDED.description,
                    "references" = EXCLUDED."references",
                    cvss2_version = EXCLUDED.cvss2_version,
                    cvss2_vector = EXCLUDED.cvss2_vector,
                    cvss2_score = EXCLUDED.cvss2_score,
                    cvss3_version = EXCLUDED.cvss3_version,
                    cvss3_vector = EXCLUDED.cvss3_vector,
                    cvss3_score = EXCLUDED.cvss3_score,
                    cvss4_version = EXCLUDED.cvss4_version,
                    cvss4_vector = EXCLUDED.cvss4_vector,
                    cvss4_score = EXCLUDED.cvss4_score,
                    json_data = EXCLUDED.json_data;
                """, record)
    finally:
        conn.close()

def parse_cve_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    meta = data.get('cveMetadata', {})
    cna = data.get('containers', {}).get('cna', {})
    cve_id = meta.get('cveId')
    year = int(cve_id.split('-')[1]) if cve_id and '-' in cve_id else None
    state = meta.get('state')
    assigner = meta.get('assignerShortName') or meta.get('assignerOrgId')
    published = meta.get('datePublished')
    last_modified = meta.get('dateUpdated')
    # Description
    descs = cna.get('descriptions', [])
    description = next((d['value'] for d in descs if d.get('lang') == 'en'), None)
    # References
    refs = cna.get('references', [])
    references = [r.get('url') for r in refs if r.get('url')]
    # CVSS metrics
    metrics = cna.get('metrics', [])
    cvss2_version, cvss2_vector, cvss2_score = extract_cvss(metrics, 2)
    cvss3_version, cvss3_vector, cvss3_score = extract_cvss(metrics, 3)
    cvss4_version, cvss4_vector, cvss4_score = extract_cvss(metrics, 4)
    # Parse vector components
    cvss2_components = parse_cvss_vector(cvss2_vector)
    cvss3_components = parse_cvss_vector(cvss3_vector)
    cvss4_components = parse_cvss_vector(cvss4_vector)
    return {
        'cve_id': cve_id,
        'year': year,
        'state': state,
        'assigner': assigner,
        'published': published,
        'last_modified': last_modified,
        'description': description,
        'references': references,
        # CVSS v2
        'cvss2_version': cvss2_version,
        'cvss2_vector': cvss2_vector,
        'cvss2_score': cvss2_score,
        'cvss2_av': cvss2_components.get('av'),
        'cvss2_ac': cvss2_components.get('ac'),
        'cvss2_au': cvss2_components.get('au'),
        'cvss2_c': cvss2_components.get('c'),
        'cvss2_i': cvss2_components.get('i'),
        'cvss2_a': cvss2_components.get('a'),
        # CVSS v3
        'cvss3_version': cvss3_version,
        'cvss3_vector': cvss3_vector,
        'cvss3_score': cvss3_score,
        'cvss3_av': cvss3_components.get('av'),
        'cvss3_ac': cvss3_components.get('ac'),
        'cvss3_pr': cvss3_components.get('pr'),
        'cvss3_ui': cvss3_components.get('ui'),
        'cvss3_s': cvss3_components.get('s'),
        'cvss3_c': cvss3_components.get('c'),
        'cvss3_i': cvss3_components.get('i'),
        'cvss3_a': cvss3_components.get('a'),
        # CVSS v4
        'cvss4_version': cvss4_version,
        'cvss4_vector': cvss4_vector,
        'cvss4_score': cvss4_score,
        'cvss4_av': cvss4_components.get('av'),
        'cvss4_ac': cvss4_components.get('ac'),
        'cvss4_at': cvss4_components.get('at'),
        'cvss4_pr': cvss4_components.get('pr'),
        'cvss4_ui': cvss4_components.get('ui'),
        'cvss4_v': cvss4_components.get('v'),
        'cvss4_c': cvss4_components.get('c'),
        'cvss4_i': cvss4_components.get('i'),
        'cvss4_a': cvss4_components.get('a'),
        'cvss4_s': cvss4_components.get('s'),
        'cvss4_si': cvss4_components.get('si'),
        'cvss4_sc': cvss4_components.get('sc'),
        'cvss4_sa': cvss4_components.get('sa'),
        'json_data': json.dumps(data)
    }

def main():
    import psycopg2
    import subprocess
    # Ensure MITRE cvelistV5 repo is present and up to date
    import shutil
    if not os.path.exists(MITRE_ROOT):
        print("MITRE cvelistV5 repo not found, cloning...")
        subprocess.run([
            'git', 'clone', 'https://github.com/CVEProject/cvelistV5.git', MITRE_ROOT
        ], check=True)
    elif not os.path.exists(os.path.join(MITRE_ROOT, '.git')):
        print("MITRE cvelistV5 directory exists but is not a git repo. Removing and cloning fresh...")
        shutil.rmtree(MITRE_ROOT)
        subprocess.run([
            'git', 'clone', 'https://github.com/CVEProject/cvelistV5.git', MITRE_ROOT
        ], check=True)
    else:
        print("MITRE cvelistV5 repo found and is a git repo, pulling latest updates...")
        subprocess.run([
            'git', '-C', MITRE_ROOT, 'pull'
        ], check=True)
    # Ensure mitre_cve table exists
    conn = psycopg2.connect(**PG_CONFIG)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
CREATE TABLE IF NOT EXISTS mitre_cve (
    cve_id TEXT PRIMARY KEY,
    year INT,
    state TEXT,
    assigner TEXT,
    published TEXT,
    last_modified TEXT,
    description TEXT,
    "references" TEXT,
    cvss2_version TEXT,
    cvss2_vector TEXT,
    cvss2_score FLOAT,
    cvss3_version TEXT,
    cvss3_vector TEXT,
    cvss3_score FLOAT,
    cvss4_version TEXT,
    cvss4_vector TEXT,
    cvss4_score FLOAT,
    json_data TEXT
);
""")
    finally:
        conn.close()
    pattern = os.path.join(MITRE_DIR, '**', 'CVE-*.json')
    files = glob(pattern, recursive=True)
    print(f"Found {len(files)} MITRE CVE JSON files.")
    mismatches = []
    for i, path in enumerate(files):
        record = parse_cve_json(path)
        upsert_cve(record)
        # Inline validation: re-query and compare
        try:
            conn = psycopg2.connect(**PG_CONFIG)
            with conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT cvss2_version, cvss2_vector, cvss2_score,
                               cvss3_version, cvss3_vector, cvss3_score,
                               cvss4_version, cvss4_vector, cvss4_score
                        FROM mitre_cve WHERE cve_id = %s
                    """, (record['cve_id'],))
                    db_row = cur.fetchone()
                    db_map = {
                        'cvss2_version': db_row[0], 'cvss2_vector': db_row[1], 'cvss2_score': db_row[2],
                        'cvss3_version': db_row[3], 'cvss3_vector': db_row[4], 'cvss3_score': db_row[5],
                        'cvss4_version': db_row[6], 'cvss4_vector': db_row[7], 'cvss4_score': db_row[8],
                    }
                    for k in db_map:
                        val_db = db_map[k]
                        val_rec = record.get(k)
                        if k.endswith('_score'):
                            try:
                                if val_db is None and val_rec is None:
                                    continue
                                if val_db is None or val_rec is None:
                                    mismatches.append((record['cve_id'], k, val_rec, val_db))
                                    print(f"Mismatch for {record['cve_id']} field {k}: record={val_rec}, db={val_db}")
                                    continue
                                if float(val_db) != float(val_rec):
                                    mismatches.append((record['cve_id'], k, val_rec, val_db))
                                    print(f"Mismatch for {record['cve_id']} field {k}: record={val_rec}, db={val_db}")
                            except Exception:
                                if str(val_db) != str(val_rec):
                                    mismatches.append((record['cve_id'], k, val_rec, val_db))
                                    print(f"Mismatch for {record['cve_id']} field {k}: record={val_rec}, db={val_db}")
                        else:
                            if str(val_db) != str(val_rec):
                                mismatches.append((record['cve_id'], k, val_rec, val_db))
                                print(f"Mismatch for {record['cve_id']} field {k}: record={val_rec}, db={val_db}")
        except Exception as e:
            print(f"Validation error for {record['cve_id']}: {e}")
        if (i+1) % 1000 == 0:
            print(f"Upserted {i+1} records...")
    if mismatches:
        print(f"\nValidation complete. {len(mismatches)} mismatches found.")
    else:
        print("\nValidation complete. No mismatches found.")
    print("MITRE CVE import complete.")

if __name__ == "__main__":
    main()
