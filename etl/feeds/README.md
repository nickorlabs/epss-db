# ETL Feed Scripts

## ETL Script Coverage

The following table lists all ETL scripts present in this folder, the feed they correspond to, and their status:

| Script Name                       | Feed Source / Description                          | Status        |
|-----------------------------------|---------------------------------------------------|---------------|
| update_ghsa_graphql.py            | GitHub Security Advisories (GHSA, GraphQL)        | Implemented   |
| update_kev.py                     | CISA Known Exploited Vulnerabilities (KEV)        | Implemented   |
| update_mitre.py                   | MITRE CVE List V5                                 | Implemented   |
| update_nvd_v2.py                  | NIST NVD 2.0                                      | Implemented   |
| update_opencvdb.py                | CloudVulnDB / open-cvdb                           | Implemented   |
| update_vulncheck_kev.py           | VulnCheck KEV                                     | Implemented   |
| update_vulncheck_mitre.py         | VulnCheck MITRE CVE V5                            | Implemented   |
| update_vulncheck_nist_nvd2.py     | VulnCheck NVD 2.0                                 | Implemented   |
| list_vulncheck_indices.py         | VulnCheck indices utility                         | Implemented   |
| update_gitlab_advisory_db.py      | GitLab Advisory Database                          | Implemented   |
| update_osv.py                     | OSV                                               | Implemented   |
| update_cpe_dictionary.py          | NVD CPE Dictionary                                | Implemented   |
| update_cwe.py                     | CWE                                               | Implemented   |
| update_exploitdb.py                | Exploit-DB (exploitdb.com, CSV+repo)             | Implemented   |
| update_cisa_vulnrichment.py        | CISA Vulnrichment (GitHub enrichment repo)       | Implemented   |
| update_cnnvd.py                   | CNNVD                                             | Removed       |
| update_vulncheck_nist_nvd1.py     | VulnCheck NVD 1.0                                 | Removed       |

_All feeds listed below are zero‑cost; cite attribution where licences request it._
---

# Vulnerability‑Intelligence Source List  
_All sources below are zero‑cost for commercial use unless otherwise noted.  
URLs appear without the `https://` scheme for quick copy/paste._

## 1  Vulnerability Databases & Prioritization Feeds
This section consolidates all foundational vulnerability databases and risk/prioritization feeds. These sources provide the core CVE, CWE, CPE, and enrichment data, as well as prioritization signals used for downstream analytics, enrichment, and alerting.

### CVE-to-CPE Mapping
A critical step in vulnerability intelligence is mapping CVEs (vulnerabilities) to CPEs (affected products/platforms). This enables:
- Asset impact analysis (which CVEs affect your environment)
- Automated patching and risk workflows
- Accurate enrichment and correlation with exploits, telemetry, and inventory

**Primary sources:**
- NIST NVD feeds: Each CVE entry includes affected CPEs and version ranges
- VulnCheck NVD++: Adds corrections and enrichment to NVD's mapping
- Anchore NVD Data Overrides: Fixes missing or incorrect CPEs
- CISA Vulnrichment: May clarify affected platforms for critical vulns

Our ETL extracts and maintains a dedicated CVE-to-CPE mapping for downstream use.

| Feed | What it covers / adds | Access / Pattern | Update cadence | Licence / Notes |
|---|---|---|---|---|
| **NIST NVD** | Authoritative U.S. government CVE database | nvd.nist.gov/feeds/json/cve/1.1/ | Hourly | Public domain |
| **MITRE CVE List** | Canonical CVE assignments | github.com/CVEProject/cvelistV5 | ~7 min pushes | Public domain |
| **GitHub Security Advisories (GHSA)** | Package-level advisories | GitHub GraphQL/REST | Continuous | CC-BY 4.0 |
| **GitLab Advisory Database** | Dependency & container advisories | gitlab.com/gitlab-org/security-products/advisory-database | Hourly | MIT |
| **Open Source Vulnerabilities (OSV)** | Multi-ecosystem advisories | api.osv.dev/v1/vulns or all.zip | Hourly | CC0/CC-BY |
| **CloudVulnDB / open-cvdb** | Cloud-service vulnerabilities | github.com/wiz-sec/open-cvdb | Hourly | CC-BY 4.0 |
| **NVD CPE Dictionary** | Standardized product identifiers & deprecated-by chains | nvd.nist.gov/feeds/json/cpe/1.0/ | With NVD push | Public domain |
| **MITRE CWE** | Weakness taxonomy for root-cause tagging | cwe.mitre.org/data/downloads.html | 2–3× yr | Public domain |
| **VulnCheck KEV** | Superset of CISA‑KEV (known‑exploited CVEs) | api.vulncheck.com/v3/backup/**vulncheck‑kev** or `/index/vulncheck‑kev?pubstartdate=` | Hourly | Free w/ Community token & attribution |
| **CISA KEV** | CVEs exploited in the wild | cisa.gov/known-exploited-vulnerabilities‑catalog (JSON/CSV) | Weekdays | Public domain |
| **CISA Vulnrichment (SSVC)** | SSVC decision points + CWE / CVSS enrichments for new CVEs | github.com/cisagov/vulnrichment (Git) | Continuous commits | CC0 (public domain) |
| **EPSS** | 30‑day exploit‑probability scores | api.first.org/epss (REST) or first.org/epss/data.csv | Daily | CC‑BY‑4.0 |
| **Anchore NVD Data Overrides** | Fixes missing CPE / CVSS in NVD | github.com/anchore/nvd-data-overrides (Git) | Daily | CC0 |


## 2  Exploit-Code Repositories
These sources provide proof-of-concept and weaponized exploit code for known vulnerabilities. They are prioritized here for enrichment and risk validation.

| Feed | Scope | Access | Cadence | Licence / Notes |
|---|---|---|---|---|
| **Exploit‑DB** | ≈ 100 new PoCs / month | gitlab.com/exploit-database/exploitdb | Hourly Git pull | GPL‑2 |
| **Packet Storm Security** | 25‑year exploit archive | packetstormsecurity.com (RSS / scrape) | Daily | Attribution required |
| **Metasploit Modules** | Ready‑to‑run exploits | github.com/rapid7/metasploit-framework | Continuous Git | BSD |
| **Vapid Labs** | WordPress & misc. PoCs | vapidlabs.com/list.php | Weekly | Free text |
| **0day.today** | Community PoC exchange | 0day.today (free account) | Ad‑hoc | Credit system; downloads free |

## 3  Live‑Exploitation / Exposure Telemetry
| Feed | What it shows | Access pattern | Cadence | Licence / Limits |
|---|---|---|---|---|
| **Shadowserver “Exploited‑CVE”** | Honeypot hits per CVE | dashboard.shadowserver.org/statistics/honeypot/vulnerability/monitoring/ (CSV/JSON) | Daily | Free; poll ≤ 1 h |
| **ONYPHE vulnscan (community)** | Internet hosts with CVE banners | search.onyphe.io (free API key) | Near‑real‑time | 10 k calls/day |
| **Censys Search API** | Host banners & certs mapped to CVEs | search.censys.io/api (API key) | Near‑real‑time | 5 k calls/day |
| **Google Project Zero “0‑day ITW”** | Confirmed 0‑days exploited before patch | googleprojectzero.blogspot.com/p/0day.html (CSV) | Ad‑hoc | Apache‑2.0 |
| **Shodan Search & Streaming** | Exposure + early‑warning telemetry (`vuln:` filter, firehose) | api.shodan.io (REST) / stream.shodan.io (WS) | Real‑time or scheduled queries | Requires your paid Shodan plan (free usage up to quota) |

## 4  Detection Rules & Signatures
| Feed | Format | Access | Cadence | Licence |
|---|---|---|---|---|
| **Emerging Threats ET Open** | Snort / Suricata | rules.emergingthreats.net/open/.../emerging-all.rules.tar.gz | Daily | GPL‑2 |
| **Sigma Rules** | Generic SIEM YAML | github.com/SigmaHQ/sigma | Continuous Git | Apache‑2.0 / LGPL‑2.1 |
+| **Nuclei Templates** | HTTP/Net scanner templates (YAML) | github.com/projectdiscovery/nuclei-templates | Dozens of commits / day | MIT |

## 5  Vendor & Research Advisories
| Feed | Coverage | Access | Cadence |
|---|---|---|---|
| **Tenable Research** | Third‑party vuln write‑ups | tenable.com/expert-resources/rss-feeds#research-advisories | As published |
| **Positive Tech Security Lab** | Enterprise / ICS vulns | global.ptsecurity.com/analytics/ | Ad‑hoc |
| **Shielder Advisories** | Web & cloud 0‑days | shielder.com/advisories/ | Ad‑hoc |
| **Huawei IPS Vuln List** | IPS signatures ↔ CVE map | isecurity.huawei.com/sec/web/ipsVulnerability.do | Daily |
| **JVN (Japan CERT)** | JP‑CERT advisories | jvn.jp/en/rss/ | Daily |
| **Qubes Security Bulletins** | Qubes OS / Xen | qubes-os.org/security/qsb/ | Ad‑hoc |

## 6  Context & Threat‑Actor Enrichment
| Feed | Adds… | Access | Licence |
|---|---|---|---|
| **MISP Galaxies – Threat Actors** | Actor ↔ CVE tags | github.com/MISP/misp-galaxy | CC0 / MIT |