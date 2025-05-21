-- CPE Dictionary Table
CREATE TABLE IF NOT EXISTS cpe_dictionary (
    cpe_id TEXT PRIMARY KEY, -- the CPE URI
    part TEXT,
    vendor TEXT,
    product TEXT,
    version TEXT,
    update TEXT,
    edition TEXT,
    language TEXT,
    title TEXT,
    deprecated BOOLEAN
);

-- CVE-CPE Join Table
CREATE TABLE IF NOT EXISTS cve_cpe (
    cve_id TEXT REFERENCES cve(cve_id),
    cpe_id TEXT REFERENCES cpe_dictionary(cpe_id),
    PRIMARY KEY (cve_id, cpe_id)
);
