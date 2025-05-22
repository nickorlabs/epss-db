-- Normalize and enforce referential integrity for additional tables

-- 1. Add FK from epssdb.cve to canonical cve(cve_id)
ALTER TABLE IF EXISTS epssdb
ADD CONSTRAINT fk_epssdb_cve FOREIGN KEY (cve) REFERENCES cve(cve_id) ON DELETE CASCADE;

-- 2. Add FK from exploits.cve_id to canonical cve(cve_id)
ALTER TABLE IF EXISTS exploits
ADD CONSTRAINT fk_exploits_cve FOREIGN KEY (cve_id) REFERENCES cve(cve_id) ON DELETE SET NULL;

-- 3. Add FK from exploit_tags.exploit_id to exploits.source_id
ALTER TABLE IF EXISTS exploit_tags
ADD CONSTRAINT fk_exploit_tags_exploit FOREIGN KEY (exploit_id) REFERENCES exploits(source_id) ON DELETE CASCADE;

-- 4. Add FK from exploit_metadata.exploit_id to exploits.source_id
ALTER TABLE IF EXISTS exploit_metadata
ADD CONSTRAINT fk_exploit_metadata_exploit FOREIGN KEY (exploit_id) REFERENCES exploits(source_id) ON DELETE CASCADE;

-- 5. Add FK from kevcatalog.cveID to canonical cve(cve_id)
ALTER TABLE IF EXISTS kevcatalog
ADD CONSTRAINT fk_kevcatalog_cve FOREIGN KEY (cveID) REFERENCES cve(cve_id) ON DELETE SET NULL;

-- 6. Add FK from vulnrichment.cve to canonical cve(cve_id)
ALTER TABLE IF EXISTS vulnrichment
ADD CONSTRAINT fk_vulnrichment_cve FOREIGN KEY (cve) REFERENCES cve(cve_id) ON DELETE SET NULL;

-- 7. Normalize vulnrichment references into cve_reference (optional, not destructive)
-- This step is for future ETL: parse comma-separated references in vulnrichment.references and insert into cve_reference table.
-- No destructive change made here.

-- All FKs use ON DELETE SET NULL or CASCADE as appropriate for data safety.
