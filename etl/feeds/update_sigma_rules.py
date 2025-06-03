"""
update_sigma_rules.py

Aggregates and normalizes detection rules from the SigmaHQ/sigma GitHub repository.
Saves both raw and normalized outputs with timestamps, following the standardized GitHub ETL template.

- Source: https://github.com/SigmaHQ/sigma
- Output: Raw rules (JSON) and normalized rules (OSV JSON)
"""
import os
import json
import logging
from glob import glob
from datetime import datetime
import yaml
from common.io_utils import safe_write_json

from common.git_utils import ensure_git_repo_latest
from common.osv_normalizer import create_osv_record

REPO_URL = os.environ.get("SIGMA_REPO_URL", "https://github.com/SigmaHQ/sigma.git")
REPO_DIR = os.environ.get("SIGMA_REPO_DIR", "/etl-data/cache/sigma")
RAW_DIR = os.environ.get("RAW_DIR", "/etl-data/raw/sigma")
NORM_DIR = os.environ.get("NORM_DIR", "/etl-data/normalized/sigma")


def get_sigma_rule_files(base_dir):
    patterns = [os.path.join(base_dir, "**", "*.yaml"), os.path.join(base_dir, "**", "*.yml")]
    files = []
    for pattern in patterns:
        files.extend(glob(pattern, recursive=True))
    return files

def load_sigma_rules(files):
    rules = []
    def flatten_and_append(obj, path, depth=0):
        if isinstance(obj, dict):
            obj["_file"] = path
            rules.append(obj)
        elif isinstance(obj, list):
            for item in obj:
                flatten_and_append(item, path, depth=depth+1)
        else:
            logging.warning(f"[Sigma ETL] Skipping non-dict/list object at depth {depth} in {path}: {type(obj)} - value: {repr(obj)[:120]}")
    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))
            for doc in docs:
                flatten_and_append(doc, path)
        except Exception as e:
            logging.warning(f"Failed to parse {path}: {e}")
    return rules

def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.info("Updating Sigma rules repository ...")
    ensure_git_repo_latest(REPO_URL, REPO_DIR)

    files = get_sigma_rule_files(REPO_DIR)
    logging.info(f"Found {len(files)} Sigma rule files in repo.")

    rules = load_sigma_rules(files)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    raw_output_path = os.path.join(RAW_DIR, f"sigma_raw_{timestamp}.json")
    safe_write_json(raw_output_path, rules, indent=2)
    logging.info(f"Wrote {len(rules)} Sigma rules to {raw_output_path}")

    # Diagnostic output: write types and previews of first 50 non-dict rules to a file
    debug_path = "/etl-data/sigma_loader_debug.txt"
    try:
        with open(debug_path, "w", encoding="utf-8") as dbg:
            non_dicts = [r for r in rules if not isinstance(r, dict)]
            for i, nd in enumerate(non_dicts[:50]):
                if isinstance(nd, list):
                    dbg.write(f"Non-dict rule #{i}: type=list, len={len(nd)}, first_elem_type={type(nd[0]) if nd else 'EMPTY'}, value={repr(nd)[:120]}\n")
                else:
                    dbg.write(f"Non-dict rule #{i}: type={type(nd)}, value={repr(nd)[:120]}\n")
            dbg.write(f"Total non-dict rules after flattening: {len(non_dicts)}\n")
        logging.info(f"[Sigma ETL][DEBUG] Wrote non-dict rule diagnostics to {debug_path}")
    except Exception as e:
        logging.warning(f"[Sigma ETL][DEBUG] Could not write debug file: {e}")

    # Filter rules to only dicts, log any non-dict
    filtered_rules = []
    non_dict_count = 0
    for rule in rules:
        if isinstance(rule, dict):
            filtered_rules.append(rule)
        else:
            if non_dict_count < 5:
                logging.warning(f"[Sigma ETL] Non-dict in rules after flattening: {type(rule)} - value: {repr(rule)[:120]}")
            non_dict_count += 1
    if non_dict_count > 0:
        logging.warning(f"[Sigma ETL] Total non-dict rules skipped after flattening: {non_dict_count}")

    # Normalize rules using OSV mapping
    norm_records = []
    for rule in filtered_rules:
        try:
            # Defensive: check type before get()
            from common.osv_normalizer import recursive_get
            # Enhanced logging for all fields (debug for expected types, warning for unexpected)
            field_type_expect = {
                "id": str,
                "title": str,
                "description": str,
                "references": list,
                "tags": list,
                "detection": dict,
            }
            for key in ["id", "title", "description", "references", "tags", "detection"]:
                val = recursive_get(rule, key, None)
                expected_type = field_type_expect.get(key)
                if expected_type and val is not None:
                    if not isinstance(val, expected_type):
                        logging.warning(f"[FieldExtract] Field '{key}' has UNEXPECTED type: {type(val)}, value preview: {str(val)[:200]}")
                    else:
                        logging.debug(f"[FieldExtract] Field '{key}' type: {type(val)}, value preview: {str(val)[:200]}")
                else:
                    logging.debug(f"[FieldExtract] Field '{key}' type: {type(val)}, value preview: {str(val)[:200]}")
            sigma_id = recursive_get(rule, "id")
            if not sigma_id:
                sigma_id = os.path.basename(rule["_file"]) if isinstance(rule, dict) and "_file" in rule else None

            summary = recursive_get(rule, "title", "")
            description = recursive_get(rule, "description", "")
            references = recursive_get(rule, "references", [])
            tags = recursive_get(rule, "tags", [])
            detection = recursive_get(rule, "detection")
            # Log the type and preview of detection
            if detection is not None:
                logging.debug(f"Rule {sigma_id} detection type: {type(detection)}, value preview: {str(detection)[:200]}")
                if isinstance(detection, list):
                    logging.warning(f"Rule {sigma_id} has detection as list. Including as-is in normalized output.")
            import re
            CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

            # Build aliases from references, tags, title, description
            aliases = set()
            for ref in references:
                if isinstance(ref, str) and ref.upper().startswith("CVE-"):
                    aliases.add(ref.upper())
            for tag in tags:
                if isinstance(tag, str) and tag.upper().startswith("CVE-"):
                    aliases.add(tag.upper())
            for text in [summary, description]:
                if text:
                    aliases.update([cve.upper() for cve in CVE_REGEX.findall(text)])

            # Define a field_map for OSV normalization
            field_map = {
                "summary": "title",
                "details": "description",
                "references": "references",
                "modified": "modified",
                "affected": "affected",
            }
            osv = create_osv_record(
                rule,
                feed_name="sigma",
                field_map=field_map,
                id_fields=["id"],
                extra_fields=None
            )
            norm_records.append(osv)
        except Exception as e:
            # Log the full problematic rule to a file for inspection
            import json
            error_path = "/etl-data/sigma_norm_error.json"
            import traceback
            try:
                with open(error_path, "a", encoding="utf-8") as ef:
                    error_record = {
                        "rule": rule,
                        "error": str(e),
                        "traceback": traceback.format_exc()
                    }
                    ef.write(json.dumps(error_record, default=str) + "\n")
                logging.error(f"[Sigma ETL][ERROR] Wrote problematic rule and error details to {error_path}")
            except Exception as file_e:
                logging.error(f"[Sigma ETL][ERROR] Could not write error rule: {file_e}")
            # Log types of all fields accessed with .get()
            if isinstance(rule, dict):
                for key in ["id", "title", "description", "references", "tags", "detection"]:
                    val = rule.get(key, None)
                    logging.warning(f"Field '{key}' type: {type(val)}, value preview: {str(val)[:200]}")
            logging.warning(f"Failed to normalize Sigma rule: {e}. Rule type: {type(rule)}. Rule preview: {str(rule)[:200]}")
    norm_output_path = os.path.join(NORM_DIR, f"sigma_norm_{timestamp}.json")
    safe_write_json(norm_output_path, norm_records, indent=2)
    logging.info(f"Wrote {len(norm_records)} normalized Sigma rules to {norm_output_path}")

    # Verification step
    from common import verify
    try:
        # Use 'id' if present, else fallback to filename for raw_id_key
        verify.verify_record_count(rules, norm_records)
        verify.verify_ids(rules, norm_records, raw_id_key='id', norm_id_key='id')
    except Exception as e:
        logging.warning(f"Verification failed: {e}")

if __name__ == "__main__":
    main()
