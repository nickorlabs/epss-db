import os
import sys
import logging
import json
import feedparser
import requests
import re
from glob import glob
from datetime import datetime
from etl.common.git_utils import ensure_git_repo_latest
from etl.common.osv_normalizer import create_osv_record

SOURCE_TYPE_ARCHIVE = "github"
SOURCE_TYPE_ATOM = "atom"
SOURCE_TYPE_API = "api"

ARCHIVE_REPO = "https://github.com/CERTCC/Vulnerability-Data-Archive.git"
ARCHIVE_DIR = os.environ.get("CERTCC_ARCHIVE_DIR", "/etl-data/cache/Vulnerability-Data-Archive")
ATOM_FEED_URL = os.environ.get("CERTCC_ATOM_FEED_URL", "https://www.kb.cert.org/vulfeed/atom.xml")
RAW_DIR = os.environ.get("RAW_DIR", "/etl-data/raw/certcc")
NORM_DIR = os.environ.get("NORM_DIR", "/etl-data/normalized/certcc")
VULN_API_BASE = "https://kb.cert.org/vuls/api/"
logging.basicConfig(level=logging.INFO)
ensure_git_repo_latest(ARCHIVE_REPO, ARCHIVE_DIR)

"""
CERT/CC ETL Script

- Primary source: Vulnerability Note API (public, no authentication)
- Enumerates all years and months, fetches all VU#s, and downloads each note's details
- CVE IDs are ALWAYS mapped to the OSV 'aliases' field for compliance and deduplication.
- All normalization logic ensures aliases are populated from CVE IDs (comma/space separated).
"""

def safe_write_json(path, data, indent=2):
    import tempfile, os, json
    dir_name = os.path.dirname(path)
    os.makedirs(dir_name, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', dir=dir_name, delete=False, encoding='utf-8') as tf:
        json.dump(data, tf, indent=indent, ensure_ascii=False)
        tempname = tf.name
    os.replace(tempname, path)

def save_json(data, outdir, prefix):
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    path = os.path.join(outdir, f"{prefix}_{ts}.json")
    safe_write_json(path, data, indent=2)
    return path

def extract_aliases(entry):
    # Always extract CVE IDs as aliases for OSV compliance
    aliases = []
    cve_ids = entry.get("CVE IDs") or entry.get("cve_ids") or entry.get("cve_id") or ""
    if cve_ids:
        for cve in re.split(r"[\s,;]+", cve_ids):
            cve = cve.strip()
            if cve and cve.upper().startswith("CVE-"):
                aliases.append(cve)
    return aliases

def create_osv_from_entry(entry, source):
    # Define field_map and id_fields based on the source
    if source == "certcc_archive":
        field_map = {
            "summary": "Title",
            "details": "Description",
            "modified": "Date Public",
            "references": "References",
        }
        id_fields = ["Vulnerability Note ID"]
        extra_fields = ["Vendor", "Product", "Date Public"]
        source_type = SOURCE_TYPE_ARCHIVE
    elif source == "certcc_atom":
        field_map = {
            "summary": "title",
            "details": "summary",
            "modified": "updated",
            "references": "links",
        }
        id_fields = ["id"]
        extra_fields = []
        source_type = SOURCE_TYPE_ATOM
    elif source == "vulnnotes_api":
        field_map = {
            "summary": "name",  # Map 'name' to 'summary' (OSV title)
            "details": "clean_desc",  # Use 'clean_desc' for details/description
            "modified": "date_modified",
            "references": "references",
        }
        id_fields = ["id", "vuid", "cveids", "certadvisory", "uscerttechnicalalert"]
        extra_fields = []
        source_type = SOURCE_TYPE_API
    else:
        field_map = {}
        id_fields = []
        extra_fields = []
        source_type = "unknown"

    # Always use the CERT/CC advisory's own unique id as the OSV id
    osv_obj = create_osv_record(entry, source, field_map, id_fields, extra_fields)
    aliases = extract_aliases(entry)
    if aliases:
        osv_obj["aliases"] = aliases
    if "database_specific" not in osv_obj or not isinstance(osv_obj["database_specific"], dict):
        osv_obj["database_specific"] = {}
    osv_obj["database_specific"]["source_type"] = source_type
    return osv_obj

def load_archive_advisories():
    """Load and normalize advisories from the GitHub Vulnerability-Data-Archive (historical)."""
    advisories = []
    archive_files = glob(os.path.join(ARCHIVE_DIR, "**", "*.json"), recursive=True)
    field_map = {
        "id": "Vulnerability Note ID",
        "modified": "Date Public",
        "summary": "Title",
        "details": "Description"
    }
    id_fields = ["Vulnerability Note ID"]
    extra_fields = ["Title", "Date Public", "Description", "CVE IDs", "Vendor", "Product", "References"]
    for file in archive_files:
        try:
            with open(file) as f:
                entry = json.load(f)
            osv_obj = create_osv_from_entry(entry, "certcc_archive")
            osv_obj["references"] = []
            osv_obj["affected"] = []
            advisories.append(osv_obj)
        except Exception as e:
            logging.warning(f"Failed to process archive file {file}: {e}")
    return advisories

def load_atomfeed_advisories():
    """Load and normalize advisories from the Atom feed (recent)."""
    advisories = []
    feed = feedparser.parse(ATOM_FEED_URL)
    field_map = {
        "id": "id",
        "modified": "updated",
        "summary": "title",
        "details": "summary"
    }
    id_fields = ["id", "link"]
    extra_fields = ["title", "link", "updated", "summary"]
    for entry in feed.entries:
        references = []
        link = entry.get("link", "")
        if link:
            references.append({"type": "ADVISORY", "url": link})
        osv_obj = create_osv_from_entry(entry, "certcc_atom")
        osv_obj["references"] = references
        osv_obj["affected"] = []
        advisories.append(osv_obj)
    return advisories

def fetch_vince_advisories():
    """
    Fetch advisories from the Vulnerability Notes API using the API key at the standard path.
    Returns: (raw_list, normalized_list)
    """
    with open(VINCE_API_KEY_PATH) as f:
        api_key = f.read().strip()
    headers = {"Authorization": f"Token {api_key}"}
    advisories = []
    page = 1
    while True:
        url = f"{VINCE_API_URL}?page={page}"
        resp = requests.get(url, headers=headers, timeout=60)
        if resp.status_code == 404 or resp.status_code == 401:
            logging.warning(f"Vulnerability Notes API returned {resp.status_code} for page {page}")
            break
        resp.raise_for_status()
        data = resp.json()
        if not data or not data.get("results"):
            break
        advisories.extend(data["results"])
        if not data.get("next"):
            break
        page += 1
    raw = advisories
    normalized = [create_osv_from_entry(a, "vulnnotes_api") for a in advisories]
    return raw, normalized

def fetch_all_vulnnotes():
    """
    Enumerate all years and months, fetch all VU#s, and retrieve each note's details.
    For any VU# that fails to fetch from the API, attempt to backfill from the CERTCC archive.
    Returns: (raw_list, normalized_list)
    """
    import time
    raw = []
    normalized = []
    failed_vuids = []
    current_year = datetime.utcnow().year
    start_year = 1998  # earliest likely year
    for year in range(start_year, current_year + 1):
        url = f"{VULN_API_BASE}{year}/summary/"
        try:
            resp = requests.get(url, timeout=60)
            if resp.status_code != 200:
                logging.warning(f"Year {year}: {resp.status_code} {resp.text}")
                continue
            summary = resp.json()
            vuids = summary.get("notes", [])
            logging.info(f"Year {year}: {len(vuids)} notes found.")
            for vuid in vuids:
                note_url = f"{VULN_API_BASE}{vuid.replace('VU#','')}/"
                import socket
                max_retries = 3
                last_exception = None
                for attempt in range(max_retries):
                    try:
                        note_resp = requests.get(note_url, timeout=60)
                        if note_resp.status_code != 200:
                            logging.warning(f"{vuid}: HTTP {note_resp.status_code} {note_resp.text}")
                            failed_vuids.append(vuid)
                            break
                        entry = note_resp.json()
                        # Always set id and vuid fields
                        entry['id'] = vuid
                        entry['vuid'] = vuid
                        raw.append(entry)
                        normalized.append(create_osv_from_entry(entry, "vulnnotes_api"))
                        break
                    except requests.exceptions.Timeout as e:
                        logging.warning(f"Timeout fetching note {vuid} (attempt {attempt+1}/{max_retries}): {e}")
                        last_exception = e
                    except requests.exceptions.ConnectionError as e:
                        if isinstance(e.args[0], socket.gaierror):
                            logging.warning(f"Name resolution error for note {vuid} (attempt {attempt+1}/{max_retries}): {e}")
                        else:
                            logging.warning(f"Connection error for note {vuid} (attempt {attempt+1}/{max_retries}): {e}")
                        last_exception = e
                    except Exception as e:
                        logging.warning(f"Unexpected error fetching note {vuid} (attempt {attempt+1}/{max_retries}): {e}")
                        last_exception = e
                    time.sleep(0.2)
                else:
                    logging.error(f"Failed to fetch note {vuid} after {max_retries} attempts. Last error: {last_exception}")
                    failed_vuids.append(vuid)
                time.sleep(0.2)
        except Exception as e:
            logging.warning(f"Failed to fetch year summary {year}: {e}")
        time.sleep(0.2)
    # Attempt backfill for failures from the CERTCC archive (recursive search)
    import glob
    for vuid in failed_vuids:
        vuid_num = vuid.replace('VU#','').lstrip('0')
        # Search for any file containing the VU number, case-insensitive, with underscores or dashes
        pattern = os.path.join(ARCHIVE_DIR, '**', f'*{vuid_num}*.json')
        matches = glob.glob(pattern, recursive=True)
        found = False
        for match in matches:
            try:
                with open(match) as f:
                    entry = json.load(f)
                entry['id'] = vuid
                entry['vuid'] = vuid
                raw.append(entry)
                normalized.append(create_osv_from_entry(entry, "certcc_archive"))
                logging.info(f"Backfilled {vuid} from archive file: {match}")
                found = True
                break
            except Exception as e:
                logging.warning(f"Failed to process archive file {match} for {vuid}: {e}")
        if not found:
            logging.warning(f"VU# {vuid} missing from both API and archive after recursive search.")

    # Always fetch and merge Atom feed advisories
    atom_advisories = load_atomfeed_advisories()
    # Build set of all IDs already present (case-insensitive)
    existing_ids = set(str(entry.get('id','')).lower() for entry in raw)
    added_count = 0
    for atom_entry in atom_advisories:
        atom_id = str(atom_entry.get('id','')).lower()
        if atom_id and atom_id not in existing_ids:
            raw.append(atom_entry)
            normalized.append(atom_entry)  # already normalized by load_atomfeed_advisories
            existing_ids.add(atom_id)
            added_count += 1
    logging.info(f"Added {added_count} unique advisories from Atom feed.")
    return raw, normalized

def main():
    try:
        logging.info("Loading CERT/CC advisories from Vulnerability Note API (primary)...")
        raw, normalized = fetch_all_vulnnotes()
        if raw:
            raw_path = save_json(raw, RAW_DIR, "certcc_vuln_api_raw")
            logging.info(f"Vulnerability Note API raw advisories saved to {raw_path}")
        if normalized:
            norm_path = save_json(normalized, NORM_DIR, "certcc_norm")
            logging.info(f"Wrote {len(normalized)} normalized CERT/CC advisories to {norm_path}")
            from etl.common import verify
            try:
                verify.verify_record_count(raw, normalized)
                verify.verify_ids(raw, normalized, raw_id_key='vuid', norm_id_key='id')
            except Exception as e:
                logging.warning(f"Verification failed: {e}")
        if not raw:
            logging.warning("No advisories loaded from Vulnerability Note API.")
    except Exception as e:
        logging.error(f"Error in CERT/CC ETL: {e}", exc_info=True)

if __name__ == "__main__":
    main()
