# ETL V2: Canonical Vulnerability Ingestion Pipeline

## Overview
This directory contains the next-generation (v2) ETL pipeline for ingesting, normalizing, and enriching vulnerability data from multiple sources into a unified, canonical PostgreSQL database. The goal is to enable robust analytics, deduplication, provenance tracking, and extensibility for future sources and enrichment layers.

## Key Features
- **Canonical schema** for all vulnerabilities (CVE, CNNVD, CNVD, OSV, GHSA, etc.)
- **Provenance and deduplication**: Track all contributing sources and unique IDs
- **Enrichment**: Store cross-linked risk scores (EPSS), KEV, exploits, and more
- **Historical data**: Retain time series for EPSS and other enrichments
- **Modular ETL scripts**: Each source has a dedicated, maintainable script
- **Shared utilities**: Common logic for DB, logging, secrets, and upserts

## Directory Structure
```
etl_v2/
  ├── README.md
  ├── canonical_schema.sql
  ├── etl_utils.py
  ├── update_vulncheck.py
  ├── .env.example
  └── (future scripts)
```

## Getting Started
1. Create a new PostgreSQL database (e.g., `canonical_vulndb`).
2. Apply `canonical_schema.sql` to set up the canonical table.
3. Configure secrets and environment variables using `.env` or Docker secrets.
4. Run the ETL scripts (start with `update_vulncheck.py`).
5. Validate results and iterate.

## Contributing
- Follow the v2 modular design and schema.
- Document new sources, enrichments, or utility functions.
- See the checklist in the project root for implementation steps.

---

# Implementation Checklist
- [ ] Database and schema setup
- [ ] Shared utilities (`etl_utils.py`)
- [ ] VulnCheck ingestion (`update_vulncheck.py`)
- [ ] Enrichment/EPSS logic
- [ ] Validation and testing
- [ ] Documentation
- [ ] Future sources (MITRE, NVD, OSV, etc.)
