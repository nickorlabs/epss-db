-- Schema for expanded NVD CVE table with CVSS v2, v3, v4 vector components
CREATE TABLE IF NOT EXISTS nvd_cve (
    cve_id TEXT PRIMARY KEY,
    published DATE,
    last_modified DATE,
    description TEXT,
    cwe TEXT,

    -- CVSS v2
    cvss2_base_score FLOAT,
    cvss2_vector TEXT,
    cvss2_av TEXT,  -- Access Vector
    cvss2_ac TEXT,  -- Access Complexity
    cvss2_au TEXT,  -- Authentication
    cvss2_c TEXT,   -- Confidentiality Impact
    cvss2_i TEXT,   -- Integrity Impact
    cvss2_a TEXT,   -- Availability Impact

    -- CVSS v3.x
    cvss3_base_score FLOAT,
    cvss3_vector TEXT,
    cvss3_av TEXT,  -- Attack Vector
    cvss3_ac TEXT,  -- Attack Complexity
    cvss3_pr TEXT,  -- Privileges Required
    cvss3_ui TEXT,  -- User Interaction
    cvss3_s TEXT,   -- Scope
    cvss3_c TEXT,   -- Confidentiality Impact
    cvss3_i TEXT,   -- Integrity Impact
    cvss3_a TEXT,   -- Availability Impact

    -- CVSS v4.0
    cvss4_base_score FLOAT,
    cvss4_vector TEXT,
    cvss4_av TEXT,
    cvss4_ac TEXT,
    cvss4_at TEXT,  -- Attack Requirements
    cvss4_pr TEXT,
    cvss4_ui TEXT,
    cvss4_v TEXT,   -- Vulnerable System
    cvss4_c TEXT,
    cvss4_i TEXT,
    cvss4_a TEXT,
    cvss4_s TEXT,
    cvss4_si TEXT,  -- Safety Impact
    cvss4_sc TEXT,  -- Safety Confidentiality
    cvss4_sa TEXT,  -- Safety Availability

    "references" TEXT,
    json_data JSONB
);

CREATE INDEX IF NOT EXISTS idx_nvd_cve_last_modified ON nvd_cve(last_modified);
