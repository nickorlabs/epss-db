# ExploitDB Importer (PostgreSQL Edition)

This script downloads and imports ExploitDB data into a PostgreSQL database using Python, Docker Compose, and the `COPY` command for efficient bulk import.

## Setup & Usage

### 1. Prerequisites
- Docker & Docker Compose installed

### 2. Start the Database and Importer
From the `subprogram/exploits` directory, run:
```bash
docker-compose up --build
```
- This will start a PostgreSQL database and a Python importer container.
- The importer will download, process, and import the ExploitDB CSV into PostgreSQL.

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
