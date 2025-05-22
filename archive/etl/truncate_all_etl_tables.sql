-- WARNING: This will delete ALL data from the ETL and canonical tables!
-- Run this only if you are sure you want to start over.

TRUNCATE TABLE 
    nvd_cve_reference,
    nvd_cve,
    kev_cve,
    mitre_cve,
    exploit_tags,
    exploit_metadata,
    vulnrichment,
    epssdb,
    cve
RESTART IDENTITY CASCADE;
