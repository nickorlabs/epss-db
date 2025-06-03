"""
Nuclei Templates ETL
Downloads and parses the public Nuclei templates repo for CVE references.
"""
SOURCE_TYPE = "github"
import os
import logging
import shutil
import subprocess
import json
import datetime
from pathlib import Path
import yaml
from common.io_utils import safe_write_json

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw/nuclei_templates")
NORM_DATA_DIR = os.environ.get("NORM_DATA_DIR", "/etl-data/normalized/nuclei_templates")
REPO_URL = "https://github.com/projectdiscovery/nuclei-templates.git"
REPO_CACHE = "/etl-data/cache/nuclei-templates"
TEMPLATES_DIR = os.path.join(REPO_CACHE)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def clone_or_pull_repo():
    if os.path.exists(REPO_CACHE):
        logging.info(f"Pulling latest Nuclei templates repo in {REPO_CACHE}...")
        subprocess.run(["git", "-C", REPO_CACHE, "pull"], check=True)
    else:
        logging.info(f"Cloning Nuclei templates repo to {REPO_CACHE}...")
        subprocess.run(["git", "clone", "--depth", "1", REPO_URL, REPO_CACHE], check=True)

def get_repo_commit():
    try:
        result = subprocess.run(["git", "-C", REPO_CACHE, "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except Exception as e:
        logging.warning(f"Could not get repo commit: {e}")
        return None

def archive_raw_templates(snapshot_date):
    raw_tpl_dir = os.path.join(RAW_DATA_DIR, "nuclei", snapshot_date, "templates")
    if os.path.exists(raw_tpl_dir):
        logging.info(f"Raw templates already archived for {snapshot_date}")
        return raw_tpl_dir
    logging.info(f"Archiving raw templates to {raw_tpl_dir}...")
    shutil.copytree(TEMPLATES_DIR, raw_tpl_dir, ignore=shutil.ignore_patterns(".git", "README.md", ".github"))
    return raw_tpl_dir

def parse_template_file(file_path):
    meta = {
        "template_id": None,
        "name": None,
        "description": None,
        "tags": [],
        "severity": None,
        "cves": [],
        "references": [],
        "authors": [],
        "path": str(file_path),
    }
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            y = yaml.safe_load(f)
        if isinstance(y, dict):
            meta["template_id"] = y.get("id") or y.get("template-id") or file_path.stem
            meta["name"] = y.get("name")
            meta["description"] = y.get("description")
            meta["tags"] = y.get("tags", [])
            meta["severity"] = y.get("severity")
            refs = y.get("reference") or y.get("references")
            if refs:
                if isinstance(refs, list):
                    meta["references"] = refs
                elif isinstance(refs, str):
                    meta["references"] = [refs]
            cves = y.get("cve")
            if cves:
                if isinstance(cves, list):
                    meta["cves"] = cves
                elif isinstance(cves, str):
                    meta["cves"] = [cves]
            authors = y.get("author") or y.get("authors")
            if authors:
                if isinstance(authors, list):
                    meta["authors"] = authors
                elif isinstance(authors, str):
                    meta["authors"] = [authors]
    except Exception as e:
        logging.warning(f"Failed to parse {file_path}: {e}")
    return meta

def build_osv_object(meta, commit, snapshot_date):
    # Always use the Nuclei template's own unique id as the OSV id (with NUCLEI- prefix)
    template_id = meta['template_id'] or Path(meta['path']).stem
    osv_id = f"NUCLEI-{template_id}"
    aliases = []
    cves = meta.get("cves", [])
    if cves:
        aliases.extend(cves)
    # Prepare database_specific with all fields not mapped to OSV
    std_fields = {"template_id", "name", "description", "tags", "severity", "cves", "references", "authors", "path"}
    database_specific = {k: v for k, v in meta.items() if k not in std_fields}
    database_specific["tags"] = meta.get("tags", [])
    database_specific["severity"] = meta.get("severity")
    database_specific["authors"] = meta.get("authors", [])
    database_specific["path"] = meta.get("path")
    database_specific["commit"] = commit
    database_specific["date_extracted"] = snapshot_date
    database_specific["source_type"] = SOURCE_TYPE
    osv_obj = {
        "id": osv_id,
        "modified": snapshot_date,
        "summary": meta.get("name") or template_id,
        "details": meta.get("description") or "",
        "aliases": aliases,
        "references": [{"type": "ARTICLE", "url": ref} for ref in meta.get("references", [])],
        "affected": [],
        "database_specific": database_specific
    }
    return osv_obj

def fetch_nuclei_templates():
    snapshot_date = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    norm_out_dir = os.path.join(NORM_DATA_DIR, "nuclei", snapshot_date)
    os.makedirs(norm_out_dir, exist_ok=True)
    clone_or_pull_repo()
    commit = get_repo_commit()
    archive_raw_templates(snapshot_date)

    parsed_templates = []
    osv_objs = []
    for root, dirs, files in os.walk(TEMPLATES_DIR):
        for fname in files:
            if fname.endswith(".yaml") or fname.endswith(".yml"):
                fpath = Path(root) / fname
                meta = parse_template_file(fpath)
                parsed_templates.append(meta)
                osv_obj = build_osv_object(meta, commit, snapshot_date)
                osv_objs.append(osv_obj)

    # Save raw parsed templates as JSON
    raw_output_path = os.path.join(RAW_DATA_DIR, f"nuclei_raw_{snapshot_date}.json")
    safe_write_json(raw_output_path, parsed_templates, indent=2)
    logging.info(f"Wrote {len(parsed_templates)} raw Nuclei templates to {raw_output_path}")

    norm_output_path = os.path.join(NORM_DATA_DIR, f"nuclei_norm_{snapshot_date}.json")
    safe_write_json(norm_output_path, osv_objs, indent=2)
    logging.info(f"Wrote {len(osv_objs)} normalized Nuclei templates to {norm_output_path}")

    # Verification step
    from common import verify
    try:
        verify.verify_record_count(parsed_templates, osv_objs)
        verify.verify_ids(parsed_templates, osv_objs, raw_id_key='template_id', norm_id_key='id')
    except Exception as e:
        logging.warning(f"Verification failed: {e}")
    return norm_output_path

if __name__ == "__main__":
    fetch_nuclei_templates()
