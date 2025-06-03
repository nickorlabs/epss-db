import os
import logging
import json
import subprocess
from datetime import datetime

SOURCE_TYPE = "github"

RAW_DATA_DIR = os.environ.get("RAW_DATA_DIR", "/etl-data/raw/cisa_vulnrichment")
NORMALIZED_DATA_DIR = os.environ.get("NORMALIZED_DATA_DIR", "/etl-data/normalized/cisa_vulnrichment")
CACHE_DIR = os.environ.get("CACHE_DIR", "/etl-data/cache")
VULNREPO_URL = "https://github.com/cisagov/vulnrichment.git"
OUTPUT_JSON = os.path.join(RAW_DATA_DIR, f"cisa_vulnrichment_full_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json")
NORMALIZED_OUTPUT_JSON = os.path.join(NORMALIZED_DATA_DIR, f"cisa_vulnrichment_normalized_{datetime.now().strftime('%Y%m%d%H%M%S')}.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def fetch_cisa_vulnrichment():
    repo_dir = os.path.join(CACHE_DIR, "cisa_vulnrichment_repo")
    if not os.path.exists(repo_dir):
        logging.info(f"Cloning CISA Vulnrichment repo to {repo_dir}")
        subprocess.run(["git", "clone", "--depth=1", VULNREPO_URL, repo_dir], check=True)
    else:
        logging.info(f"Updating CISA Vulnrichment repo in {repo_dir}")
        subprocess.run(["git", "-C", repo_dir, "pull"], check=True)

    # Recursively find all .json files (excluding .github, test, or draft folders)
    vuln_files = []
    for root, dirs, files in os.walk(repo_dir):
        # Skip .git and .github and test/example folders
        if any(skip in root for skip in ['.git', '.github', 'test', 'example']):
            continue
        for file in files:
            if file.endswith('.json'):
                vuln_files.append(os.path.join(root, file))
    logging.info(f"Found {len(vuln_files)} JSON files in Vulnrichment repo.")
    records = []
    for fpath in vuln_files:
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                records.append(data)
        except Exception as e:
            logging.warning(f"Failed to parse {fpath}: {e}")
    os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(records, f)
    logging.info(f"Extracted and wrote {len(records)} CISA Vulnrichment records to {OUTPUT_JSON}")

    # Normalize Vulnrichment records to OSV format
    normalized_records = []
    for record in records:
        # --- OSV Normalization Mapping ---
        # 1. Primary ID
        osv_id = record.get('cveMetadata', {}).get('cveId')
        # 2. Aliases
        aliases = set()
        legacy_id = (record.get('containers', {})
            .get('cna', {})
            .get('x_legacyV4Record', {})
            .get('CVE_data_meta', {})
            .get('ID'))
        if legacy_id and legacy_id != osv_id:
            aliases.add(legacy_id)
        for ref in record.get('containers', {}).get('cna', {}).get('references', []):
            if 'name' in ref and ref['name'] != osv_id:
                aliases.add(ref['name'])
        # 3. Summary/Description
        summary = description = None
        descs = record.get('containers', {}).get('cna', {}).get('descriptions', [])
        if descs:
            summary = descs[0].get('value')
            description = descs[0].get('value')
        if not summary:
            legacy_descs = (record.get('containers', {})
                .get('cna', {})
                .get('x_legacyV4Record', {})
                .get('description', {})
                .get('description_data', []))
            if legacy_descs:
                summary = legacy_descs[0].get('value')
                description = legacy_descs[0].get('value')
        # 4. Severity
        severities = []
        for adp in record.get('containers', {}).get('adp', []):
            for metric in adp.get('metrics', []):
                cvss = metric.get('cvssV3_1')
                if cvss and 'baseSeverity' in cvss:
                    severities.append(cvss['baseSeverity'])
        severity = max(severities, default=None)
        # 5. Affected
        affected = record.get('containers', {}).get('cna', {}).get('affected', [])
        # 6. References
        references = record.get('containers', {}).get('cna', {}).get('references', []).copy()
        for adp in record.get('containers', {}).get('adp', []):
            for ref in adp.get('references', []):
                references.append(ref)
        # 7. Problem Types
        problem_types = []
        for pt in record.get('containers', {}).get('cna', {}).get('problemTypes', []):
            for desc in pt.get('descriptions', []):
                if 'description' in desc:
                    problem_types.append(desc['description'])
        legacy_pts = (record.get('containers', {})
            .get('cna', {})
            .get('x_legacyV4Record', {})
            .get('problemtype', {})
            .get('problemtype_data', []))
        for pt in legacy_pts:
            for desc in pt.get('description', []):
                if 'value' in desc:
                    problem_types.append(desc['value'])
        # 8. Dates
        published = record.get('cveMetadata', {}).get('datePublished')
        modified = record.get('cveMetadata', {}).get('dateUpdated')
        # --- Build OSV Record ---
        database_specific = {'source_type': SOURCE_TYPE}
        normalized_record = {
            'id': osv_id,
            'aliases': list(aliases),
            'summary': summary,
            'description': description,
            'severity': severity,
            'affected': affected,
            'references': references,
            'problem_types': problem_types,
            'published': published,
            'modified': modified,
            'database_specific': database_specific
        }
        normalized_records.append(normalized_record)

    from common.io_utils import safe_write_json
    # Save normalized output to a timestamped file
    safe_write_json(NORMALIZED_OUTPUT_JSON, normalized_records, indent=2)
    logging.info(f"Normalized and wrote {len(normalized_records)} OSV records to {NORMALIZED_OUTPUT_JSON}")

    # Verification
    from common import verify
    verify.verify_record_count(records, normalized_records)
    verify.verify_ids(records, normalized_records, raw_id_key='cveMetadata.cveId', norm_id_key='id')
    verify.verify_field_presence(normalized_records, ['id', 'summary', 'description'])
    try:
        pass
    except Exception as e:
        logging.warning(f"Verification failed: {e}")

if __name__ == "__main__":
    fetch_cisa_vulnrichment()
