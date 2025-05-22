import psycopg2
import logging

def ensure_cve_exists(conn, cve_id, source='unknown'):
    """
    Ensure the CVE exists in the canonical cve table. If not, insert a minimal placeholder row with required NOT NULL fields.
    Track all sources in the sources TEXT[] column. If MITRE is seen, set as primary source.
    """
    if not cve_id:
        return
    with conn.cursor() as cur:
        cur.execute("SELECT source, sources FROM cve WHERE cve_id = %s;", (cve_id,))
        row = cur.fetchone()
        if row:
            current_source, sources = row
            updated = False
            # If MITRE is seen, set as primary
            if source == 'mitre' and current_source != 'mitre':
                cur.execute("UPDATE cve SET source = 'mitre' WHERE cve_id = %s;", (cve_id,))
                logging.info(f"Updated primary source to 'mitre' for {cve_id}")
                updated = True
            # Update sources array if needed
            sources = sources or []
            if source not in sources:
                cur.execute("UPDATE cve SET sources = array_append(COALESCE(sources, ARRAY[]::text[]), %s) WHERE cve_id = %s;", (source, cve_id))
                logging.info(f"Appended '{source}' to sources for {cve_id}")
                updated = True
            if not updated:
                logging.debug(f"No update needed for {cve_id} (already has source '{current_source}' and sources {sources})")
        else:
            cur.execute(
                "INSERT INTO cve (cve_id, source, sources) VALUES (%s, %s, ARRAY[%s]) ON CONFLICT (cve_id) DO NOTHING;",
                (cve_id, source, source)
            )
            if cur.rowcount > 0:
                logging.info(f"Created placeholder in canonical cve table for {cve_id} (source='{source}', sources=['{source}'])")
