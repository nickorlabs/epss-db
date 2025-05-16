-- Ensure indexes for orphan CVE ID detection
CREATE INDEX IF NOT EXISTS idx_cve_cve_id ON cve(cve_id);
CREATE INDEX IF NOT EXISTS idx_exploits_cve_id ON exploits(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulnrichment_cve ON vulnrichment(cve);
