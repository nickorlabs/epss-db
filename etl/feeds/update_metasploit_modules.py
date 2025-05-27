"""
Metasploit Modules ETL
Clones or pulls the public Metasploit modules repo and extracts CVE references from module metadata.
"""

import os
import sys
import logging
import shutil
import subprocess
import json
import datetime
from pathlib import Path

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw")
NORM_DATA_DIR = os.environ.get("NORM_DATA_DIR", "/etl-data/normalized")
REPO_URL = "https://github.com/rapid7/metasploit-framework.git"
REPO_CACHE = "/etl-data/cache/metasploit-framework"
MODULES_DIR = os.path.join(REPO_CACHE, "modules")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

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
            l = line.strip()
            if meta["module_name"] is None and l.startswith("require 'msf/core'"):
                meta["module_name"] = str(file_path.relative_to(MODULES_DIR)).replace(".rb", "").replace(os.sep, "/")
            if meta["module_type"] is None and "Module.new" in l:
                # Guess type from path
                meta["module_type"] = str(file_path).split(os.sep)[-4] if len(str(file_path).split(os.sep)) > 3 else None
            if l.lower().startswith("# description:") or l.lower().startswith("#description:"):
                meta["description"] = l.split(":", 1)[-1].strip()
            if "CVE-" in l:
                meta["cves"] += [part for part in l.split() if part.startswith("CVE-")]
            if l.lower().startswith("# author:") or l.lower().startswith("#author:"):
                meta["authors"].append(l.split(":", 1)[-1].strip())
            if l.lower().startswith("# targets:") or l.lower().startswith("#targets:"):
                meta["targets"].append(l.split(":", 1)[-1].strip())
            if l.lower().startswith("# reference:") or l.lower().startswith("#reference:"):
                meta["references"].append(l.split(":", 1)[-1].strip())
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
    osv_id = f"MSF-{meta['module_name']}"
    osv_obj = {
        "id": osv_id,
        "modified": snapshot_date,
        "summary": meta.get("description") or meta.get("module_name"),
        "details": meta.get("description") or "",
        "aliases": meta.get("cves", []),
        "references": [{"type": "REFERENCE", "url": ref} for ref in meta.get("references", [])],
        "affected": [],
        "database_specific": {
            "module_type": meta.get("module_type"),
            "authors": meta.get("authors", []),
            "targets": meta.get("targets", []),
            "path": meta.get("path"),
            "commit": commit,
            "date_extracted": snapshot_date
        }
    }
    return osv_obj

def fetch_metasploit_modules():
    snapshot_date = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    norm_out_dir = os.path.join(NORM_DATA_DIR, "metasploit", snapshot_date)
    os.makedirs(norm_out_dir, exist_ok=True)
    clone_or_pull_repo()
    commit = get_repo_commit()
    archive_raw_modules(snapshot_date)

    osv_objs = []
    for root, dirs, files in os.walk(MODULES_DIR):
        for fname in files:
            if fname.endswith(".rb"):
                fpath = Path(root) / fname
                meta = parse_module_file(fpath)
                osv_obj = build_osv_object(meta, commit, snapshot_date)
                osv_objs.append(osv_obj)

    out_json = os.path.join(norm_out_dir, "modules.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(osv_objs, f, indent=2)
    logging.info(f"Wrote {len(osv_objs)} modules to {out_json}")
    return out_json

if __name__ == "__main__":
    fetch_metasploit_modules()
