-- Raw table for VulnCheck KEV feed
drop table if exists vulncheck_kev_raw cascade;
create table vulncheck_kev_raw (
    id serial primary key,
    fetched_at timestamptz default now(),
    raw_json jsonb not null
);

-- Canonical vulnerability table (minimal example, expand as needed)
drop table if exists canonical_vuln cascade;
create table canonical_vuln (
    vuln_id text primary key,
    cve_id text,
    description text,
    published timestamptz,
    last_modified timestamptz,
    source text,
    raw_source_id text,
    severity text,
    "references" jsonb,
    metadata jsonb
);
