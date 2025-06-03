#!/usr/bin/env python3
"""
Fetches and archives daily EPSS CSV snapshots from FIRST.org, supporting both incremental (single day) and full historical backfill modes.

- Stores as /common-data/raw/epss/v{version}/epss_scores-YYYY-MM-DD.csv
- Version is determined by date based on official release history
"""
import os
import sys
import argparse
import requests
from datetime import datetime, timedelta, date
from pathlib import Path
import logging
import hashlib

# EPSS version release dates (inclusive, UTC)
EPSS_VERSION_DATES = [
    ("v4", date(2025, 3, 17)),
    ("v3", date(2023, 3, 7)),
    ("v2", date(2022, 2, 4)),
    ("v1", date(2021, 1, 7)),
]

EPSS_FIRST_DATE = date(2021, 4, 14)
EPSS_BASE_URL = "https://epss.empiricalsecurity.com/"
RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/common-data/raw")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def get_epss_version(target_date):
    for version, start_date in EPSS_VERSION_DATES:
        if target_date >= start_date:
            return version
    return "unknown"

def get_epss_url(target_date):
    return f"{EPSS_BASE_URL}epss_scores-{target_date.isoformat()}.csv.gz"

def get_storage_path(version, target_date, ext):
    return Path(RAW_DATA_DIR) / "epss" / version / f"epss_scores-{target_date.isoformat()}.{ext}"

def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

import gzip

def download_and_store(target_date, skip_existing=True):
    version = get_epss_version(target_date)
    url = get_epss_url(target_date)
    gz_path = get_storage_path(version, target_date, "csv.gz")
    csv_path = get_storage_path(version, target_date, "csv")
    gz_path.parent.mkdir(parents=True, exist_ok=True)
    if skip_existing and gz_path.exists() and csv_path.exists():
        logging.info(f"Exists: {gz_path} & {csv_path} (skipping)")
        return False
    try:
        logging.info(f"Downloading {url}")
        resp = requests.get(url, timeout=120)
        if resp.status_code == 404:
            logging.warning(f"Not available: {url}")
            return False
        resp.raise_for_status()
        with open(gz_path, "wb") as f:
            f.write(resp.content)
        sha_gz = file_sha256(gz_path)
        logging.info(f"Saved {gz_path} (sha256={sha_gz})")
        # Decompress to .csv
        with gzip.open(gz_path, "rb") as f_in, open(csv_path, "wb") as f_out:
            f_out.write(f_in.read())
        sha_csv = file_sha256(csv_path)
        logging.info(f"Decompressed and saved {csv_path} (sha256={sha_csv})")
        return True
    except Exception as e:
        logging.error(f"Failed for {target_date}: {e}")
        return False

def daterange(start_date, end_date):
    for n in range((end_date - start_date).days + 1):
        yield start_date + timedelta(n)

def main():
    parser = argparse.ArgumentParser(description="EPSS ETL: Archive daily CSV snapshots from FIRST.org")
    parser.add_argument("--full", action="store_true", help="Backfill all available dates (2021-01-07 to today)")
    parser.add_argument("--date", type=str, help="Fetch a specific date (YYYY-MM-DD, default: today UTC)")
    args = parser.parse_args()

    if args.full:
        today = datetime.utcnow().date()
        for d in daterange(EPSS_FIRST_DATE, today):
            download_and_store(d)
    else:
        if args.date:
            target_date = datetime.strptime(args.date, "%Y-%m-%d").date()
        else:
            target_date = datetime.utcnow().date()
        download_and_store(target_date, skip_existing=False)

if __name__ == "__main__":
    main()
