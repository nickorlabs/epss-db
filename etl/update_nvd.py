import os
import requests
import gzip
import shutil
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

NVD_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/"
NVD_DATA_DIR = os.path.join(os.path.dirname(__file__), 'nvd-data')
os.makedirs(NVD_DATA_DIR, exist_ok=True)

# Helper: Parse CVSS vector string
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

def download_feed(feed_name):
    url = f"{NVD_FEED_URL}{feed_name}.json.gz"
    gz_path = os.path.join(NVD_DATA_DIR, f"{feed_name}.json.gz")
    json_path = os.path.join(NVD_DATA_DIR, f"{feed_name}.json")
    if not os.path.exists(gz_path):
        print(f"Downloading {url} ...")
        resp = requests.get(url, stream=True)
        if resp.status_code == 200:
            with open(gz_path, 'wb') as f:
                f.write(resp.content)
        else:
            print(f"Failed to download {url}")
            return None
    if not os.path.exists(json_path):
        with gzip.open(gz_path, 'rb') as f_in, open(json_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    return json_path

def load_json(json_path):
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def get_existing_last_modified():
    # Get last modified date for all CVEs in DB
    conn = psycopg2.connect(**PG_CONFIG)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT cve_id, last_modified FROM nvd_cve;")
            return {row[0]: row[1] for row in cur.fetchall()}
    finally:
        conn.close()

def upsert_cve(record):
    conn = psycopg2.connect(**PG_CONFIG)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                INSERT INTO nvd_cve (
                    cve_id, published, last_modified, description, cwe,
                    cvss2_base_score, cvss2_vector, cvss2_av, cvss2_ac, cvss2_au, cvss2_c, cvss2_i, cvss2_a,
                    cvss3_base_score, cvss3_vector, cvss3_av, cvss3_ac, cvss3_pr, cvss3_ui, cvss3_s, cvss3_c, cvss3_i, cvss3_a,
                    cvss4_base_score, cvss4_vector, cvss4_av, cvss4_ac, cvss4_at, cvss4_pr, cvss4_ui, cvss4_v, cvss4_c, cvss4_i, cvss4_a, cvss4_s, cvss4_si, cvss4_sc, cvss4_sa,
                    "references", json_data
                ) VALUES (
                    %(cve_id)s, %(published)s, %(last_modified)s, %(description)s, %(cwe)s,
                    %(cvss2_base_score)s, %(cvss2_vector)s, %(cvss2_av)s, %(cvss2_ac)s, %(cvss2_au)s, %(cvss2_c)s, %(cvss2_i)s, %(cvss2_a)s,
                    %(cvss3_base_score)s, %(cvss3_vector)s, %(cvss3_av)s, %(cvss3_ac)s, %(cvss3_pr)s, %(cvss3_ui)s, %(cvss3_s)s, %(cvss3_c)s, %(cvss3_i)s, %(cvss3_a)s,
                    %(cvss4_base_score)s, %(cvss4_vector)s, %(cvss4_av)s, %(cvss4_ac)s, %(cvss4_at)s, %(cvss4_pr)s, %(cvss4_ui)s, %(cvss4_v)s, %(cvss4_c)s, %(cvss4_i)s, %(cvss4_a)s, %(cvss4_s)s, %(cvss4_si)s, %(cvss4_sc)s, %(cvss4_sa)s,
                    %(references)s, %(json_data)s
                )
                ON CONFLICT (cve_id) DO UPDATE SET
                    published = EXCLUDED.published,
                    last_modified = EXCLUDED.last_modified,
                    description = EXCLUDED.description,
                    cwe = EXCLUDED.cwe,
                    cvss2_base_score = EXCLUDED.cvss2_base_score,
                    cvss2_vector = EXCLUDED.cvss2_vector,
                    cvss2_av = EXCLUDED.cvss2_av,
                    cvss2_ac = EXCLUDED.cvss2_ac,
                    cvss2_au = EXCLUDED.cvss2_au,
                    cvss2_c = EXCLUDED.cvss2_c,
                    cvss2_i = EXCLUDED.cvss2_i,
                    cvss2_a = EXCLUDED.cvss2_a,
                    cvss3_base_score = EXCLUDED.cvss3_base_score,
                    cvss3_vector = EXCLUDED.cvss3_vector,
                    cvss3_av = EXCLUDED.cvss3_av,
                    cvss3_ac = EXCLUDED.cvss3_ac,
                    cvss3_pr = EXCLUDED.cvss3_pr,
                    cvss3_ui = EXCLUDED.cvss3_ui,
                    cvss3_s = EXCLUDED.cvss3_s,
                    cvss3_c = EXCLUDED.cvss3_c,
                    cvss3_i = EXCLUDED.cvss3_i,
                    cvss3_a = EXCLUDED.cvss3_a,
                    cvss4_base_score = EXCLUDED.cvss4_base_score,
                    cvss4_vector = EXCLUDED.cvss4_vector,
                    cvss4_av = EXCLUDED.cvss4_av,
                    cvss4_ac = EXCLUDED.cvss4_ac,
                    cvss4_at = EXCLUDED.cvss4_at,
                    cvss4_pr = EXCLUDED.cvss4_pr,
                    cvss4_ui = EXCLUDED.cvss4_ui,
                    cvss4_v = EXCLUDED.cvss4_v,
                    cvss4_c = EXCLUDED.cvss4_c,
                    cvss4_i = EXCLUDED.cvss4_i,
                    cvss4_a = EXCLUDED.cvss4_a,
                    cvss4_s = EXCLUDED.cvss4_s,
                    cvss4_si = EXCLUDED.cvss4_si,
                    cvss4_sc = EXCLUDED.cvss4_sc,
                    cvss4_sa = EXCLUDED.cvss4_sa,
                    "references" = EXCLUDED."references",
                    json_data = EXCLUDED.json_data;
                """, record)
    finally:
        conn.close()

def extract_cve_record(item):
    cve_id = item['cve']['CVE_data_meta']['ID']
    published = item.get('publishedDate')
    last_modified = item.get('lastModifiedDate')
    descs = item['cve']['description']['description_data']
    description = next((d['value'] for d in descs if d['lang'] == 'en'), None)
    cwe = None
    for problem in item['cve'].get('problemtype', {}).get('problemtype_data', []):
        for desc in problem.get('description', []):
            if desc.get('lang') == 'en':
                cwe = desc.get('value')
    refs = item['cve'].get('references', {}).get('reference_data', [])
    references = ",".join([r.get('url') for r in refs]) if refs else None
    # CVSS v2
    cvss2 = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {})
    cvss2_vector = cvss2.get('vectorString')
    cvss2_components = parse_cvss_vector(cvss2_vector)
    # CVSS v3
    cvss3 = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})
    cvss3_vector = cvss3.get('vectorString')
    cvss3_components = parse_cvss_vector(cvss3_vector)
    # CVSS v4 (future-proof, NVD may not have this yet)
    cvss4 = item.get('impact', {}).get('baseMetricV4', {}).get('cvssV4', {})
    cvss4_vector = cvss4.get('vectorString')
    cvss4_components = parse_cvss_vector(cvss4_vector)
    return {
        'cve_id': cve_id,
        'published': published,
        'last_modified': last_modified,
        'description': description,
        'cwe': cwe,
        # CVSS v2
        'cvss2_base_score': cvss2.get('baseScore'),
        'cvss2_vector': cvss2_vector,
        'cvss2_av': cvss2_components.get('av'),
        'cvss2_ac': cvss2_components.get('ac'),
        'cvss2_au': cvss2_components.get('au'),
        'cvss2_c': cvss2_components.get('c'),
        'cvss2_i': cvss2_components.get('i'),
        'cvss2_a': cvss2_components.get('a'),
        # CVSS v3
        'cvss3_base_score': cvss3.get('baseScore'),
        'cvss3_vector': cvss3_vector,
        'cvss3_av': cvss3_components.get('av'),
        'cvss3_ac': cvss3_components.get('ac'),
        'cvss3_pr': cvss3_components.get('pr'),
        'cvss3_ui': cvss3_components.get('ui'),
        'cvss3_s': cvss3_components.get('s'),
        'cvss3_c': cvss3_components.get('c'),
        'cvss3_i': cvss3_components.get('i'),
        'cvss3_a': cvss3_components.get('a'),
        # CVSS v4
        'cvss4_base_score': cvss4.get('baseScore'),
        'cvss4_vector': cvss4_vector,
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
        'references': references,
        'json_data': json.dumps(item)
    }

def process_feed(feed_name, existing_last_modified):
    json_path = download_feed(feed_name)
    if not json_path:
        return
    data = load_json(json_path)
    items = data.get('CVE_Items', [])
    for item in items:
        record = extract_cve_record(item)
        # Only upsert if new or modified
        cve_id = record['cve_id']
        last_mod = record['last_modified']
        if (cve_id not in existing_last_modified) or (last_mod and last_mod > str(existing_last_modified[cve_id])):
            upsert_cve(record)
            print(f"Upserted {cve_id}")

def main():
    # Get all existing last_modified dates
    existing_last_modified = get_existing_last_modified()
    # Initial load: all years
    for year in range(2002, datetime.now().year + 1):
        process_feed(f"nvdcve-1.1-{year}", existing_last_modified)
    # Incremental: recent and modified
    for feed in ["nvdcve-1.1-recent", "nvdcve-1.1-modified"]:
        process_feed(feed, existing_last_modified)
    print("NVD import complete.")

if __name__ == "__main__":
    main()
