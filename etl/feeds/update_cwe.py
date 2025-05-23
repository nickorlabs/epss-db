import os
import requests
import csv
import logging
import io
import json

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw")
CWE_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
OUTPUT_CSV = os.path.join(RAW_DATA_DIR, "cwe.csv")
OUTPUT_JSON = os.path.join(RAW_DATA_DIR, "cwe.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def fetch_cwe():
    logging.info(f"Downloading CWE CSV ZIP from {CWE_URL}")
    resp = requests.get(CWE_URL, timeout=120)
    resp.raise_for_status()
    import zipfile
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
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(cwe_list, f)
    logging.info(f"Extracted and wrote {len(cwe_list)} CWE entries to {OUTPUT_JSON}")

if __name__ == "__main__":
    fetch_cwe()
