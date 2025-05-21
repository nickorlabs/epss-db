CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS hstore;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE canonical_vuln (
    vuln_id TEXT PRIMARY KEY,
    cve_id TEXT,
    osv_id TEXT,
    ghsa_id TEXT,
    cnnvd_id TEXT,
    cnvd_id TEXT,
    published TIMESTAMP,
    modified TIMESTAMP,
    description TEXT,
    reference_urls JSONB,
    cvss2 JSONB,
    cvss3 JSONB,
    cvss4 JSONB,
    enrichment JSONB,
    sources JSONB,
    provenance JSONB,
    primary_source TEXT,
    raw_data JSONB
);

CREATE INDEX idx_canonical_vuln_cve_id ON canonical_vuln (cve_id);
CREATE INDEX idx_canonical_vuln_cnnvd_id ON canonical_vuln (cnnvd_id);
CREATE INDEX idx_canonical_vuln_cnvd_id ON canonical_vuln (cnvd_id);
CREATE INDEX idx_canonical_vuln_primary_source ON canonical_vuln (primary_source);
CREATE INDEX idx_canonical_vuln_sources_gin ON canonical_vuln USING GIN (sources);
CREATE INDEX idx_canonical_vuln_enrichment_gin ON canonical_vuln USING GIN (enrichment);
