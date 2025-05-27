"""
Emerging Threats ET Open ETL
Downloads and parses the public Snort/Suricata ruleset for CVE references.
"""

import os
import logging

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw")
OUTPUT_TXT = os.path.join(RAW_DATA_DIR, "emerging_threats_et_open.rules")
FULL_OUTPUT_JSON = os.path.join(RAW_DATA_DIR, "emerging_threats_et_open_full.json")
RULES_URL = "https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules"
# TODO: Download and parse rules for CVEs

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

import requests
import re
import json

def fetch_emerging_threats_et_open():
    # Download rules file
    if not os.path.exists(OUTPUT_TXT):
        logging.info(f"Downloading Emerging Threats rules from {RULES_URL}")
        r = requests.get(RULES_URL)
        r.raise_for_status()
        os.makedirs(os.path.dirname(OUTPUT_TXT), exist_ok=True)
        with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
            f.write(r.text)
    else:
        logging.info(f"Rules file already exists at {OUTPUT_TXT}")

    cve_map = {}
    sid_map = {}
    all_rules = []
    CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    SID_REGEX = re.compile(r"sid:(\d+)")
    RULE_HEADER_REGEX = re.compile(r'^(alert|log|pass|activate|dynamic|drop|reject|sdrop)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+->\s+([^\s]+)\s+([^\s]+)\s*\((.*)\)')
    with open(OUTPUT_TXT, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cves = set(CVE_REGEX.findall(line))
            sid_match = SID_REGEX.search(line)
            sid = sid_match.group(1) if sid_match else None
            # Parse rule fields
            rule_obj = {"raw": line}
            m = RULE_HEADER_REGEX.match(line)
            if m:
                rule_obj["action"] = m.group(1)
                rule_obj["proto"] = m.group(2)
                rule_obj["src_addr"] = m.group(3)
                rule_obj["src_port"] = m.group(4)
                rule_obj["direction"] = m.group(6)
                rule_obj["dst_addr"] = m.group(7)
                rule_obj["dst_port"] = m.group(8)
                rule_obj["options"] = m.group(9)
            if sid:
                rule_obj["sid"] = sid
            if cves:
                rule_obj["cves"] = list(sorted({cve.upper() for cve in cves}))
            all_rules.append(rule_obj)
            if cves and sid:
                for cve in cves:
                    cve = cve.upper()
                    cve_map.setdefault(cve, []).append(sid)
                sid_map[sid] = list(cves)
    # Write full rules
    os.makedirs(os.path.dirname(FULL_OUTPUT_JSON), exist_ok=True)
    with open(FULL_OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(all_rules, f, indent=2)
    logging.info(f"Extracted {len(all_rules)} rules to {FULL_OUTPUT_JSON}")
    # Write mapping
    norm_path = os.path.join(RAW_DATA_DIR, "../normalized/emerging_threats_cve_map.json")
    norm_path = os.path.abspath(norm_path)
    os.makedirs(os.path.dirname(norm_path), exist_ok=True)
    with open(norm_path, "w", encoding="utf-8") as f:
        json.dump({"cve_to_sids": cve_map, "sid_to_cves": sid_map}, f, indent=2)
    logging.info(f"Extracted {len(cve_map)} CVEs from Emerging Threats rules to {norm_path}")
    return FULL_OUTPUT_JSON

if __name__ == "__main__":
    fetch_emerging_threats_et_open()
