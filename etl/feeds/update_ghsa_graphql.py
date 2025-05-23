import os
import json
import logging
import argparse
import requests

graphql_url = "https://api.github.com/graphql"
RAW_DUMP_PATH = "/etl-data/raw/ghsa_graphql_dump.json"

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

def dump_json(data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    logging.info(f"Dumped GHSA advisories to {path}")

def main():
    parser = argparse.ArgumentParser(description="Download all GitHub Security Advisories (GHSA) via GraphQL and dump to file.")
    parser.add_argument('--dump-path', default=RAW_DUMP_PATH, help='Where to dump the raw GHSA JSON')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    token = load_github_token()
    if not token:
        raise RuntimeError("GitHub API token not found. Provide via /run/secrets/github_api_token or GITHUB_API_TOKEN env var.")
    advisories = fetch_all_advisories(token)
    dump_json(advisories, args.dump_path)
    logging.info(f"Fetched and dumped {len(advisories)} GHSA advisories.")

if __name__ == "__main__":
    main()
