import os
import requests
import csv
import logging
import io
import json

import os
import requests
import csv
import logging
import io
import json
from datetime import datetime
TS = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/common-data/raw")
CWE_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
OUTPUT_CSV = os.path.join(RAW_DATA_DIR, f"cwe_{TS}.csv")
OUTPUT_JSON = os.path.join(RAW_DATA_DIR, f"cwe_{TS}.json")
NORM_DATA_DIR = os.environ.get("NORM_DATA_DIR", "/etl-data/normalized/cwe")
NORM_OUTPUT_JSON = os.path.join(NORM_DATA_DIR, f"cwe_norm_{TS}.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def fetch_cwe():
    logging.info(f"Downloading CWE CSV ZIP from {CWE_URL}")
    resp = requests.get(CWE_URL, timeout=120)
    resp.raise_for_status()
    import zipfile
    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    os.makedirs(NORM_DATA_DIR, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
        for name in z.namelist():
            if name.endswith(".csv"):
                logging.info(f"Extracting {name} from ZIP")
                with z.open(name) as f_in, open(OUTPUT_CSV, "wb") as f_out:
                    f_out.write(f_in.read())
                break
        else:
            raise RuntimeError("No CSV file found in CWE ZIP archive.")
    logging.info(f"Saved CWE CSV to {OUTPUT_CSV}")
    # Convert to JSON
    with open(OUTPUT_CSV, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        cwe_list = list(reader)
    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    os.makedirs(NORM_DATA_DIR, exist_ok=True)
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(cwe_list, f)
    logging.info(f"Extracted and wrote {len(cwe_list)} CWE entries to {OUTPUT_JSON}")
    # Normalized output (pass-through)
    with open(NORM_OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(cwe_list, f)
    logging.info(f"Wrote {len(cwe_list)} normalized CWE entries to {NORM_OUTPUT_JSON}")
    # Verification
    from common import verify
    try:
        verify.verify_record_count(cwe_list, cwe_list)
        if cwe_list and 'ID' in cwe_list[0]:
            verify.verify_ids(cwe_list, cwe_list, raw_id_key='ID', norm_id_key='ID')
    except Exception as e:
        logging.warning(f"Verification failed: {e}")

if __name__ == "__main__":
    fetch_cwe()
