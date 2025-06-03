# GitHub-Based ETL Script Template & Best Practices

This document outlines the recommended structure and best practices for all ETL scripts in this repository that ingest data from GitHub (or GitLab) repositories. Use this as a checklist and reference when refactoring or creating new ETL scripts.

---

## 1. File/Module Structure
- **Imports:**
  - Use standard imports for logging, configuration, and shared utilities.
  - Always import `ensure_git_repo_latest` from `etl.common.git_utils` for repo management.
  - Always import `create_osv_record` from `etl.common.osv_normalizer` for OSV normalization.
- **Config:**
  - Use environment variables for all paths, URLs, and tokens.

## 2. Repository Handling
- Use `ensure_git_repo_latest` for all GitHub/GitLab repo operations (clone, pull, update).
- Store cloned repos in `/etl-data/cache/<repo>` or another consistent directory.

## 3. Raw Data Collection
- Fetch or read raw data from the repo (e.g., walk JSON/YAML files, parse as needed).
- Save raw data to a timestamped file in the `RAW_DIR`.

## 4. Normalization
- Use `create_osv_record` to convert each raw entry to the OSV format.
- The **primary ID** (`id` field in OSV) must always be the source's own unique/canonical identifier:
  - For CVE-based sources (NVD, Vulnrichment, MITRE, etc.), this is the CVE ID (since the CVE is the source's own ID).
  - For all other sources (Sigma, Nuclei, ExploitDB, CERT/CC, etc.), use the source’s own unique ID (e.g., Sigma rule `id`, Nuclei template `id`, ExploitDB ID, CERT/CC advisory ID).
- **Never use a cross-referenced global ID (like a CVE) as the primary OSV `id` unless it is the source's own ID.**
- Populate the `aliases` field with all other global/cross-referenced identifiers (e.g., CVEs, GHSA IDs, vendor IDs, Sigma/Nuclei/ExploitDB IDs, etc.).
- Save each normalized record to a timestamped file in the `NORM_DIR` for traceability and reproducibility.

**Rationale:**
- Using the source's own ID as the OSV `id` guarantees traceability and prevents ambiguity about record origin.
- Aliases provide linkage to all other global identifiers for deduplication and enrichment.


**Rationale:**
- Using the canonical/global ID as the primary ID ensures that downstream systems can reliably deduplicate, correlate, and enrich records from multiple sources.
- Aliases provide additional linkage across databases and ecosystems.

## 5. Normalization Guide for All Feeds

The following table outlines the expected primary ID and typical aliases for each major feed. **The OSV `id` is always the source's own unique/canonical ID. All other global/cross-referenced IDs go in `aliases`.**

| Feed Name                  | Primary ID (OSV `id` field)      | Typical Aliases (OSV `aliases`)                      |
|----------------------------|-----------------------------------|------------------------------------------------------|
| NVD, Vulnrichment, MITRE   | CVE ID (e.g., CVE-2023-1234)      | Other CVEs, vendor IDs, GHSA IDs                     |
| Sigma Rules                | Sigma rule `id`                   | All CVEs, tags, cross-referenced IDs                 |
| Nuclei Templates           | Nuclei template `id`              | CVEs, vendor IDs, other template IDs                 |
| ExploitDB                  | ExploitDB ID                      | CVEs, vendor IDs, other exploit IDs                  |
| CERT/CC                    | CERT/CC advisory ID               | CVEs, vendor IDs, other cross-referenced IDs         |
| MISP Galaxies              | MISP Galaxy ID                    | Threat actor IDs, CVEs                               |
| Anchore NVD Data Overrides | Anchore override ID               | CVEs, GHSA IDs, vendor IDs                           |
| Disposable Email Domains   | Domain name                       | Email addresses                                      |
| DigitalSide Threat-Intel   | DigitalSide threat intel ID       | CVEs, GHSA IDs, vendor IDs                           |
| ...                        | ...                               | ...                                                  |

Add additional feeds as needed. For each, clearly specify what should be used as the OSV `id` and what must be included in `aliases` for full traceability and deduplication.

## 6. Error Handling and Logging
- Use structured logging for every major step (repo update, fetch, parse, normalize, save).
- Handle and log exceptions gracefully, especially for file and network operations.

## 7. Main Entrypoint
- Provide a `main()` function that orchestrates the ETL process.
- Use `if __name__ == "__main__": main()` for script execution.

## 8. Documentation
- Add a docstring at the top describing the script’s purpose, data sources, and output format.
- Comment key steps and decisions in the code.

---

## 9. Future GitHub ETL Candidates

After completing the current prioritized data feeds, consider implementing ETL scripts for these additional GitHub-based sources using this template:

| Feed Name                  | GitHub Repo URL                                      | Status           | Notes                                 |
|----------------------------|------------------------------------------------------|------------------|---------------------------------------|
| MISP Galaxies              | https://github.com/MISP/misp-galaxy                  | Not implemented  | Threat actor enrichment               |
| Anchore NVD Data Overrides | https://github.com/anchore/nvd-data-overrides        | Not implemented  | NVD CPE/CVSS corrections              |
| Disposable Email Domains   | https://github.com/martenson/disposable-email-domains| Not implemented  | Email fraud enrichment                |
| DigitalSide Threat-Intel   | https://github.com/digital-side/osint-feed           | Not implemented  | Multi-format threat feeds             |

---

## Example Skeleton

```python
"""
<Script Name> ETL Script

- Source: <GitHub Repo/API URL>
- Description: <What this script does>
- Output: Raw and normalized OSV JSON files
"""

import os
import logging
import json
from etl.common.git_utils import ensure_git_repo_latest
from etl.common.osv_normalizer import create_osv_record

# Config
REPO_URL = "<github_repo_url>"
REPO_DIR = os.environ.get("REPO_DIR", "/etl-data/cache/<repo>")
RAW_DIR = os.environ.get("RAW_DIR", "/etl-data/raw/")
NORM_DIR = os.environ.get("NORM_DIR", "/etl-data/normalize/")
logging.basicConfig(level=logging.INFO)

def fetch_and_update_repo():
    ensure_git_repo_latest(REPO_URL, REPO_DIR)

def collect_raw_data():
    # Walk repo, parse files, collect raw entries
    pass

def normalize_entry(entry):
    # Use create_osv_record and handle aliases
    pass

def main():
    fetch_and_update_repo()
    raw_entries = collect_raw_data()
    # Save raw
    # Normalize and save normalized
    pass

if __name__ == "__main__":
    main()
```

---

## Checklist for Refactoring
- [ ] Uses `ensure_git_repo_latest` for repo management
- [ ] Uses `create_osv_record` for normalization
- [ ] Saves both raw and normalized data with timestamps
- [ ] Uses environment variables for config/paths
- [ ] Provides structured logging
- [ ] Has a clear main entrypoint
- [ ] Is documented and commented

---

**Apply this template and checklist to all GitHub/GitLab-based ETL scripts for consistency and maintainability.**
