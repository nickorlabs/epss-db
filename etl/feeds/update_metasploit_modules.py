"""
Metasploit Modules ETL
Clones or pulls the public Metasploit modules repo and extracts CVE references from module metadata.
"""

import os
import logging
import shutil
import subprocess
import json
import datetime
from common.io_utils import safe_write_json
from pathlib import Path

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw/metasploit")
NORM_DATA_DIR = os.environ.get("NORM_DATA_DIR", "/etl-data/normalized/metasploit")
REPO_URL = "https://github.com/rapid7/metasploit-framework.git"
REPO_CACHE = "/etl-data/cache/metasploit-framework"
MODULES_DIR = os.path.join(REPO_CACHE, "modules")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

SOURCE_TYPE = "github"

def clone_or_pull_repo():
    if os.path.exists(REPO_CACHE):
        logging.info(f"Pulling latest Metasploit repo in {REPO_CACHE}...")
        subprocess.run(["git", "-C", REPO_CACHE, "pull"], check=True)
    else:
        logging.info(f"Cloning Metasploit repo to {REPO_CACHE}...")
        subprocess.run(["git", "clone", "--depth", "1", REPO_URL, REPO_CACHE], check=True)

def get_repo_commit():
    try:
        result = subprocess.run(["git", "-C", REPO_CACHE, "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except Exception as e:
        logging.warning(f"Could not get repo commit: {e}")
        return None

def archive_raw_modules(snapshot_date):
    raw_mod_dir = os.path.join(RAW_DATA_DIR, "metasploit", snapshot_date, "modules")
    if os.path.exists(raw_mod_dir):
        logging.info(f"Raw modules already archived for {snapshot_date}")
        return raw_mod_dir
    logging.info(f"Archiving raw modules to {raw_mod_dir}...")
    shutil.copytree(MODULES_DIR, raw_mod_dir)
    return raw_mod_dir

def parse_module_file(file_path):
    # Minimalistic parser for Metasploit module metadata
    meta = {
        "module_name": None,
        "module_type": None,
        "path": str(file_path),
        "description": None,
        "cves": [],
        "references": [],
        "authors": [],
        "targets": [],
    }
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        for line in lines:
            line_str = line.strip()
            if meta["module_name"] is None and line_str.startswith("require 'msf/core'"):
                meta["module_name"] = str(file_path.relative_to(MODULES_DIR)).replace(".rb", "").replace(os.sep, "/")
            if meta["module_type"] is None and "Module.new" in line_str:
                # Guess type from path
                meta["module_type"] = str(file_path).split(os.sep)[-4] if len(str(file_path).split(os.sep)) > 3 else None
            if line_str.lower().startswith("# description:") or line_str.lower().startswith("#description:"):
                meta["description"] = line_str.split(":", 1)[-1].strip()
            if "CVE-" in line_str:
                meta["cves"] += [part for part in line_str.split() if part.startswith("CVE-")]
            if line_str.lower().startswith("# author:") or line_str.lower().startswith("#author:"):
                meta["authors"].append(line_str.split(":", 1)[-1].strip())
            if line_str.lower().startswith("# targets:") or line_str.lower().startswith("#targets:"):
                meta["targets"].append(line_str.split(":", 1)[-1].strip())
            if line_str.lower().startswith("# reference:") or line_str.lower().startswith("#reference:"):
                meta["references"].append(line_str.split(":", 1)[-1].strip())
    except Exception as e:
        logging.warning(f"Failed to parse {file_path}: {e}")
    # Fallback for module_name and type
    if not meta["module_name"]:
        rel_path = str(file_path.relative_to(MODULES_DIR)).replace(".rb", "").replace(os.sep, "/")
        meta["module_name"] = rel_path
    if not meta["module_type"]:
        meta["module_type"] = str(file_path).split(os.sep)[-4] if len(str(file_path).split(os.sep)) > 3 else None
    return meta

def build_osv_object(meta, commit, snapshot_date):
    # Always use the Metasploit module's own unique id as the OSV id (with MSF- prefix)
    osv_id = f"MSF-{meta['module_name']}"
    aliases = []
    cves = meta.get("cves", [])
    if cves:
        aliases.extend(cves)
    # Prepare database_specific with all fields not mapped to OSV
    std_fields = {"module_name", "module_type", "path", "description", "cves", "references", "authors", "targets"}
    database_specific = {k: v for k, v in meta.items() if k not in std_fields}
    database_specific["module_type"] = meta.get("module_type")
    database_specific["authors"] = meta.get("authors", [])
    database_specific["targets"] = meta.get("targets", [])
    database_specific["path"] = meta.get("path")
    database_specific["commit"] = commit
    database_specific["date_extracted"] = snapshot_date
    database_specific["source_type"] = SOURCE_TYPE
    osv_obj = {
        "id": osv_id,
        "modified": snapshot_date,
        "summary": meta.get("description") or meta.get("module_name"),
        "details": meta.get("description") or "",
        "aliases": aliases,
        "references": [{"type": "ARTICLE", "url": ref} for ref in meta.get("references", [])],
        "affected": [],
        "database_specific": database_specific
    }
    return osv_obj

def fetch_metasploit_modules():
    snapshot_date = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    norm_out_dir = os.path.join(NORM_DATA_DIR, "metasploit", snapshot_date)
    os.makedirs(norm_out_dir, exist_ok=True)
    clone_or_pull_repo()
    commit = get_repo_commit()
    archive_raw_modules(snapshot_date)

    parsed_modules = []
    osv_objs = []
    for root, dirs, files in os.walk(MODULES_DIR):
        for fname in files:
            if fname.endswith(".rb"):
                fpath = Path(root) / fname
                meta = parse_module_file(fpath)
                parsed_modules.append(meta)
                osv_obj = build_osv_object(meta, commit, snapshot_date)
                osv_objs.append(osv_obj)

    # Save raw parsed modules as JSON
    raw_output_path = os.path.join(RAW_DATA_DIR, f"metasploit_raw_{snapshot_date}.json")
    safe_write_json(raw_output_path, parsed_modules, indent=2)
    logging.info(f"Wrote {len(parsed_modules)} raw Metasploit modules to {raw_output_path}")

    norm_output_path = os.path.join(NORM_DATA_DIR, f"metasploit_norm_{snapshot_date}.json")
    safe_write_json(norm_output_path, osv_objs, indent=2)
    logging.info(f"Wrote {len(osv_objs)} normalized Metasploit modules to {norm_output_path}")

    # Verification step
    from common import verify
    try:
        verify.verify_record_count(parsed_modules, osv_objs)
        # Adjust for normalized ID prefixing: strip 'MSF-' from normalized IDs for comparison
        raw_ids = set(str(m.get('module_name')) for m in parsed_modules if m.get('module_name'))
        norm_ids = set(str(n.get('id')).replace('MSF-', '') for n in osv_objs if n.get('id'))
        match = raw_ids == norm_ids
        logging.info(f"Raw IDs count: {len(raw_ids)}, Normalized IDs count: {len(norm_ids)}. IDs match (prefix-insensitive): {match}")
        if not match:
            missing_in_norm = raw_ids - norm_ids
            missing_in_raw = norm_ids - raw_ids
            if missing_in_norm:
                logging.warning(f"IDs present in raw but missing in normalized: {list(missing_in_norm)[:10]}")
            if missing_in_raw:
                logging.warning(f"IDs present in normalized but missing in raw: {list(missing_in_raw)[:10]}")
    except Exception as e:
        logging.warning(f"Verification failed: {e}")
    return norm_output_path

if __name__ == "__main__":
    fetch_metasploit_modules()
