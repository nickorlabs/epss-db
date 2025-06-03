import re

def get_primary_id(raw, id_fields):
    """
    Returns the most authoritative/global ID (e.g., CVE) if present, else the first available ID from id_fields.
    """
    from common.osv_normalizer import recursive_get
    for field in id_fields:
        val = recursive_get(raw, field, "")
        if val and isinstance(val, str) and re.match(r"^CVE-\\d{4}-\\d+$", val):
            return val
    # Fallback: first available ID
    for field in id_fields:
        val = recursive_get(raw, field, "")
        if val:
            return val
    # If truly nothing, hash the record for uniqueness
    return f"generated:{abs(hash(str(raw)))%10**12}"

def build_aliases(raw, id_fields, primary_id):
    """
    Returns a list of alternate IDs (not including the primary).
    """
    aliases = []
    from common.osv_normalizer import recursive_get
    for field in id_fields:
        val = recursive_get(raw, field, "")
        if val and val != primary_id and val not in aliases:
            aliases.append(val)
    return aliases

def recursive_get(obj, path, default=None):
    """Safely traverse nested dicts/lists using a dot-separated path or list of keys/indexes."""
    if isinstance(path, str):
        path = path.split(".")
    for key in path:
        if isinstance(obj, dict):
            obj = obj.get(key, default)
        elif isinstance(obj, list):
            try:
                idx = int(key)
                obj = obj[idx]
            except (ValueError, IndexError, TypeError):
                return default
        else:
            return default
        if obj is None:
            return default
    return obj

def create_osv_record(raw, feed_name, field_map, id_fields, extra_fields=None):
    """
    Builds an OSV-compliant vulnerability record from a raw entry.
    - field_map: maps OSV fields to raw fields (e.g., {"summary": "desc", ...})
    - id_fields: list of candidate ID fields in order of authority
    - extra_fields: additional fields to include in database_specific
    """
    primary_id = get_primary_id(raw, id_fields)
    aliases = build_aliases(raw, id_fields, primary_id)
    osv = {
        "id": primary_id,
        "modified": recursive_get(raw, field_map.get("modified", "modified"), ""),
        "summary": recursive_get(raw, field_map.get("summary", "summary"), ""),
        "details": recursive_get(raw, field_map.get("details", "details"), ""),
        "aliases": aliases,
        "references": recursive_get(raw, field_map.get("references", "references"), []),
        "affected": recursive_get(raw, field_map.get("affected", "affected"), []),
        "database_specific": {
            "source": feed_name
        }
    }
    # Add extra fields to database_specific
    if extra_fields:
        for k in extra_fields:
            osv["database_specific"][k] = recursive_get(raw, k, "")
    return osv
