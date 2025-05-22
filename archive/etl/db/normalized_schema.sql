-- Hybrid CVE data architecture:
--   - Raw source tables (mitre_cve, nvd_cve) are preserved for full-fidelity ingest and audit.
--   - Canonical normalized table (cve) is populated by ETL for unified analytics and querying.
--   - Views/materialized views can be created for common analytics use cases.
--
-- This file defines the canonical normalized schema only.


CREATE TABLE IF NOT EXISTS cve (
    cve_id TEXT PRIMARY KEY,
    source TEXT NOT NULL, -- e.g., 'nvd', 'mitre'
    published DATE,
    last_modified DATE,
    description TEXT,
    cwe TEXT,
    assigner TEXT,
    state TEXT,
    year INT,
    json_data JSONB -- structure: {"mitre": {...}, "nvd": {...}}
);

CREATE TABLE IF NOT EXISTS cve_reference (
    id SERIAL PRIMARY KEY,
    cve_id TEXT REFERENCES cve(cve_id) ON DELETE CASCADE,
    reference TEXT
);

CREATE TABLE IF NOT EXISTS cvss (
    id SERIAL PRIMARY KEY,
    cve_id TEXT REFERENCES cve(cve_id) ON DELETE CASCADE,
    version TEXT NOT NULL, -- e.g., '2.0', '3.1', '4.0'
    base_score FLOAT,
    vector TEXT,
    av TEXT,
    ac TEXT,
    au TEXT,
    pr TEXT,
    ui TEXT,
    v TEXT,
    c TEXT,
    i TEXT,
    a TEXT,
    s TEXT,
    si TEXT,
    sc TEXT,
    sa TEXT
);

CREATE INDEX IF NOT EXISTS idx_cve_year ON cve(year);
CREATE INDEX IF NOT EXISTS idx_cve_last_modified ON cve(last_modified);
CREATE INDEX IF NOT EXISTS idx_cvss_cve_id ON cvss(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_reference_cve_id ON cve_reference(cve_id);
