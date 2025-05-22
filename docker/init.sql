-- Enable useful PostgreSQL extensions for ETL and analytics
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS hstore;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS vector;

-- Table for VulnCheck KEV ETL
CREATE TABLE IF NOT EXISTS kev_cve (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    published TIMESTAMP,
    last_modified TIMESTAMP,
    reference_urls JSONB,
    enrichment JSONB
);
