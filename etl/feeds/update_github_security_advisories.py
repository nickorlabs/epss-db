import os
import json
import logging
import argparse
import requests
from etl.common.io_utils import safe_write_json

graphql_url = "https://api.github.com/graphql"
RAW_DUMP_PATH = "/etl-data/raw/github_security_advisories_dump.json"
NORM_DATA_DIR = os.environ.get("NORM_DATA_DIR", "/etl-data/normalized")

# Load token from Docker secret or env
def load_github_token():
    secret_path = "/run/secrets/github_api_token"
    if os.path.exists(secret_path):
        with open(secret_path) as f:
            return f.read().strip()
    return os.environ.get("GITHUB_API_TOKEN")

def run_query(query, variables, token):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "exploitpulse-etl-script"
    }
    response = requests.post(graphql_url, headers=headers, json={"query": query, "variables": variables}, timeout=60)
    response.raise_for_status()
    return response.json()

def fetch_all_advisories(token):
    query = """
    query($cursor: String) {
      securityAdvisories(first: 100, after: $cursor) {
        totalCount
        pageInfo {
          endCursor
          hasNextPage
        }
        nodes {
          ghsaId
          summary
          description
          severity
          publishedAt
          updatedAt
          withdrawnAt
          references { url }
          identifiers { type value }
        }
      }
    }
    """
    advisories = []
    cursor = None
    total_count = None
    page = 1
    while True:
        variables = {"cursor": cursor}
        result = run_query(query, variables, token)
        sa = result["data"]["securityAdvisories"]
        if total_count is None:
            total_count = sa["totalCount"]
            logging.info(f"Total advisories reported by API: {total_count}")
        advisories.extend(sa["nodes"])
        logging.info(f"Page {page}: fetched {len(sa['nodes'])} advisories (total so far: {len(advisories)})")
        if not sa["pageInfo"]["hasNextPage"]:
            break
        cursor = sa["pageInfo"]["endCursor"]
        page += 1
    return advisories

def dump_json(advisories, path):
    safe_write_json(path, advisories, indent=2)
    logging.info(f"Wrote {len(advisories)} GitHub Security Advisories advisories to {path}")

    # Verification step
    from etl.common import verify
    try:
        verify.verify_record_count(advisories, advisories)
        verify.verify_ids(advisories, advisories, raw_id_key='ghsaId', norm_id_key='ghsaId')
    except Exception as e:
        logging.warning(f"Verification failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Download all GitHub Security Advisories (GitHub Security Advisories) via GraphQL and dump to file.")
    parser.add_argument('--dump-path', default=RAW_DUMP_PATH, help='Where to dump the raw GitHub Security Advisories JSON')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    token = load_github_token()
    if not token:
        raise RuntimeError("GitHub API token not found. Provide via /run/secrets/github_api_token or GITHUB_API_TOKEN env var.")
    advisories = fetch_all_advisories(token)
    dump_json(advisories, args.dump_path)
    logging.info(f"Fetched and dumped {len(advisories)} GitHub Security Advisories advisories.")

if __name__ == "__main__":
    main()
