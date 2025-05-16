-- Example unified analytics views for hybrid CVE architecture

-- 1. Unified CVE View: Merges canonical CVE fields with MITRE and NVD source data
CREATE OR REPLACE VIEW unified_cve AS
SELECT
    cve.cve_id,
    cve.published,
    cve.last_modified,
    cve.description,
    cve.cwe,
    cve.assigner,
    cve.state,
    cve.year,
    cve.json_data->'mitre' AS mitre_json,
    cve.json_data->'nvd' AS nvd_json
FROM cve;

-- 2. CVEs with both sources present
CREATE OR REPLACE VIEW cve_with_both_sources AS
SELECT * FROM unified_cve
WHERE mitre_json IS NOT NULL AND nvd_json IS NOT NULL;

-- 3. CVEs with only one source (MITRE or NVD)
CREATE OR REPLACE VIEW cve_with_single_source AS
SELECT *,
    CASE 
        WHEN mitre_json IS NOT NULL AND nvd_json IS NULL THEN 'mitre_only'
        WHEN mitre_json IS NULL AND nvd_json IS NOT NULL THEN 'nvd_only'
        ELSE 'both'
    END AS source_status
FROM unified_cve
WHERE (mitre_json IS NULL OR nvd_json IS NULL);

-- 4. Example: Count of CVEs by source status
CREATE OR REPLACE VIEW cve_source_counts AS
SELECT source_status, COUNT(*) AS cve_count
FROM cve_with_single_source
GROUP BY source_status;

-- You can add more views for deduplication, discrepancy analysis, or any analytics needs.
