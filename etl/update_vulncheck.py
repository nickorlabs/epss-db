"""
update_vulncheck.py - Ingest VulnCheck CNNVD/CNVD indices into canonical_vuln

Usage:
    python update_vulncheck.py --index cnnvd --api-key <key> [--dry-run]
    python update_vulncheck.py --index cnvd --api-key <key> [--dry-run]

Requirements:
    pip install vulncheck psycopg2-binary
"""
import argparse
import os
import json
import logging
from etl_utils import setup_logging, get_db_conn, upsert_canonical_vuln
from vulncheck_sdk import VulnCheck

def normalize_vulncheck_record(record, index):
    # Extract IDs
    cve_id = record.get('cve_id') or record.get('cveId')
    cnnvd_id = record.get('cnnvd_id') or record.get('cnnvdId')
    cnvd_id = record.get('cnvd_id') or record.get('cnvdId')
    vuln_id = cve_id or cnnvd_id or cnvd_id or record.get('id')
    
    return {
        'vuln_id': vuln_id,
        'cve_id': cve_id,
        'osv_id': record.get('osv_id'),
        'ghsa_id': record.get('ghsa_id'),
        'cnnvd_id': cnnvd_id,
        'cnvd_id': cnvd_id,
        'published': record.get('published') or record.get('publish_date'),
        'modified': record.get('modified') or record.get('last_modified'),
        'description': record.get('description'),
        'references': json.dumps(record.get('references', [])),
        'cvss2': json.dumps(record.get('cvss2', {})),
        'cvss3': json.dumps(record.get('cvss3', {})),
        'cvss4': json.dumps(record.get('cvss4', {})),
        'enrichment': json.dumps({}),
        'sources': json.dumps({f'vulncheck_{index}': record}),
        'provenance': json.dumps({'source_list': [f'vulncheck_{index}']}),
        'primary_source': f'vulncheck_{index}',
        'raw_data': json.dumps(record),
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--index', required=True, choices=['cnnvd', 'cnvd'], help='VulnCheck index to ingest')
    parser.add_argument('--api-key', required=False, help='VulnCheck API key (or set VULNCHECK_API_KEY env)')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()

    logger = setup_logging('update_vulncheck', logging.INFO)
    # Helper to load Docker secret
    def load_secret(secret_name):
        secret_path = f"/run/secrets/{secret_name}"
        if os.path.exists(secret_path):
            with open(secret_path, "r") as f:
                return f.read().strip()
        return None

    api_key = (
        args.api_key
        or os.getenv('VULNCHECK_API_KEY')
        or load_secret('vulncheck_api_key')
    )
    if not api_key:
        logger.error('VulnCheck API key required. Set via --api-key, VULNCHECK_API_KEY env, or /run/secrets/vulncheck_api_key')
        exit(1)
    vc = VulnCheck(api_key=api_key)
    logger.info(f'Fetching {args.index} records from VulnCheck...')
    records = list(vc.index(args.index))
    logger.info(f'Fetched {len(records)} records from {args.index}.')

    if args.dry_run:
        logger.info(f'Dry run: would ingest {len(records)} records.')
        return

    with get_db_conn() as conn:
        for record in records:
            vuln = normalize_vulncheck_record(record, args.index)
            upsert_canonical_vuln(conn, vuln)
    logger.info(f'Ingested {len(records)} records into canonical_vuln.')

if __name__ == '__main__':
    main()
