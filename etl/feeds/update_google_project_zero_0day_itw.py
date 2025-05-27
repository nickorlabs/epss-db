import os
import csv
import requests
import logging
from datetime import datetime

"""
Google Project Zero 0-day ITW ETL
Automates merge of all yearly tabs from the local Excel (.xlsx) file.
Requires: pandas, openpyxl

To use:
1. Download the full sheet as .xlsx from Google Sheets (File > Download > Excel).
2. Place at /etl-data/raw/google_project_zero_0day_itw.xlsx
3. Install dependencies: pip install pandas openpyxl
"""

import os
import logging
import json
from datetime import datetime
import pandas as pd

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw")
INPUT_XLSX = os.path.join(RAW_DATA_DIR, "google_project_zero_0day_itw.xlsx")
OUTPUT_CSV = os.path.join(RAW_DATA_DIR, "google_project_zero_0day_itw.csv")
OUTPUT_JSON = os.path.join(RAW_DATA_DIR, "google_project_zero_0day_itw.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def merge_google_project_zero_0day_itw_xlsx():
    if not os.path.exists(INPUT_XLSX):
        logging.error(f"XLSX file not found: {INPUT_XLSX}")
        return None
    all_sheets = pd.read_excel(INPUT_XLSX, sheet_name=None, engine="openpyxl")

    # Canonical column order (from your screenshots)
    canonical_columns = [
        "CVE", "Vendor", "Product", "Type", "Description",
        "Date Discovered", "Date Patched", "Advisory", "Analysis URL",
        "Root Cause Analysis", "Reported By"
    ]

    # Stack all rows from all sheets except Introduction
    frames = []
    for name, df in all_sheets.items():
        if name == "Introduction":
            continue
        # Keep only canonical columns and drop fully empty columns
        df = df[[col for col in canonical_columns if col in df.columns]].dropna(axis=1, how="all")
        # Filter to rows with non-empty CVE
        df = df[df["CVE"].notnull() & (df["CVE"].astype(str).str.strip() != "")]
        frames.append(df)
    if not frames:
        logging.error("No valid data found in any sheet!")
        return None
    all_data = pd.concat(frames, ignore_index=True)
    # Deduplicate by CVE
    before = len(all_data)
    deduped = all_data.drop_duplicates(subset=["CVE"])
    after = len(deduped)
    deduped = deduped[canonical_columns]  # Ensure consistent order
    # Output
    deduped.to_csv(OUTPUT_CSV, index=False)
    records = deduped.astype(str).to_dict(orient="records")
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
    logging.info(f"Merged all sheets (excluding Introduction), filtered to non-empty CVE, deduped: {before} -> {after} unique CVEs. Output: {OUTPUT_CSV}, {OUTPUT_JSON}")
    # Log any duplicate CVEs
    dupes = all_data[all_data.duplicated(subset=["CVE"], keep=False)]
    if not dupes.empty:
        dupes_path = os.path.join(RAW_DATA_DIR, "google_project_zero_0day_itw_duplicate_cves.csv")
        dupes.to_csv(dupes_path, index=False)
        logging.warning(f"Duplicate CVEs found and written to {dupes_path}")
    else:
        logging.info("No duplicate CVEs found.")
    return OUTPUT_JSON

if __name__ == "__main__":
    merge_google_project_zero_0day_itw_xlsx()
