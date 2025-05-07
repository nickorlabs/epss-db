# ExploitDB Importer (PostgreSQL Edition)

This script downloads and imports ExploitDB data into a PostgreSQL database using Python, Docker Compose, and the `COPY` command for efficient bulk import.

## Setup & Usage

### 1. Prerequisites
- Docker & Docker Compose installed

### 2. Start the Database
From the ETL directory, start the database and supporting containers:
```bash
docker compose up -d db
```

### 3. Run Each ETL Import Individually
For best results (especially with large datasets), run each ETL update script one at a time. This makes troubleshooting easier and avoids resource contention.

Example commands:

**Exploits:**
```bash
docker compose run --rm importer python update_exploitdb.py
```
**NVD:**
```bash
docker compose run --rm importer python update_nvd.py
```
**MITRE:**
```bash
docker compose run --rm importer python update_mitre.py
```
**EPSS:**
```bash
docker compose run --rm importer python update_epss.py
```
**KEV:**
```bash
docker compose run --rm importer python update_kev.py
```
**Vulnrichment:**
```bash
docker compose run --rm importer python update_vulnrich.py
```

Repeat for any other ETL scripts as needed.

> **Note:** Running `update_all.py` is not recommended for large imports or troubleshooting. Run each update individually for best results.

### 3. Database Access
- Default database: `epssdb`
- Default user/password: `postgres`/`postgres`
- To access the DB:
  ```bash
  docker-compose exec db psql -U postgres -d epssdb
  ```

### 4. Customization
- Edit `exploitdb_import.py` for schema or logic changes.
- Edit `docker-compose.yml` for service config.

### 5. ML/Vector Support
- The script enables the `pgvector` extension for future ML/vector search support.

## Requirements
- See `requirements.txt` (uses `psycopg2-binary` for PostgreSQL)

## Notes
- The importer script uses the `COPY` command for fast bulk loading.
- All data is loaded into the `exploits` table.

## Environment Variables
- `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_HOST`, `MYSQL_DATABASE` (optional, defaults provided in script)

## Notes
- The `.venv` directory is the standard convention for Python projects and should be gitignored for cleanliness.
