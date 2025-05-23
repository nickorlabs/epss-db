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
| update_exploitdb.py                | Exploit-DB (exploitdb.com, CSV+repo)              | Implemented   |
| update_cisa_vulnrichment.py        | CISA Vulnrichment (GitHub enrichment repo)        | Implemented   |
| update_cnnvd.py                   | CNNVD                                             | Removed       |
| update_vulncheck_nist_nvd1.py     | VulnCheck NVD 1.0                                 | Removed       |

_All feeds listed below are zero‑cost; cite attribution where licences request it._

| # | Feed | Scope / What it covers | Access pattern | Update cadence | Licence / Notes | Status |
|---|---|---|---|---|---|---|
| **A 1** | **VulnCheck NVD++ – NIST NVD 2.0** | NVD 2.0 JSON mirrored by VulnCheck; added CPE rows | api.vulncheck.com/v3/backup/**nist‑nvd2** | Hourly | Free w/ token | Implemented |
| **A 2** | **VulnCheck NVD++ – NIST NVD 1.0 (legacy)** | Long‑term copy of retired 1.0 format | api.vulncheck.com/v3/backup/**nist‑nvd** | Hourly | Free w/ token | Removed |
| **A 3** | **VulnCheck NVD++ – MITRE CVE List V5** | MITRE JSON 5 files served via VulnCheck | api.vulncheck.com/v3/backup/**mitre‑cvelist‑v5** | Hourly | Free w/ token | Implemented |
| **B 1** | **NIST NVD 2.0 (canonical)** | Authoritative U.S. NVD JSON 1.1 feeds | nvd.nist.gov/feeds/json/cve/1.1/ (+ free API) | Hourly sync | Public domain | Implemented |
| **B 2** | **MITRE CVE List V5 (canonical)** | Live CVE Program repo (JSON‑5) | github.com/CVEProject/cvelistV5 (Git) | ~7 min pushes | Public domain | Implemented |
| **B 3** | **CloudVulnDB / open‑cvdb** | Cloud‑service vulnerabilities (AWS, Azure, GCP, …) | github.com/wiz-sec/open-cvdb (Git) | Hourly | CC‑BY 4.0 | Implemented |
| **B 4** | **GitHub Security Advisories (GHSA)** | Package‑level advisories across 15+ ecosystems | GitHub GraphQL `advisoryDatabase` / REST `/advisories` | Continuous | CC‑BY 4.0; token rate‑limit | Implemented |
| **B 5** | **GitLab Advisory Database (OSS edition)** | Dependency & container vulns | gitlab.com/gitlab-org/security-products/advisory-database (Git) | Hourly | MIT; 30‑day lag vs. SaaS feed | Planned |
| **B 6** | **Open Source Vulnerabilities (OSV)** | OSV‑format advisories for Debian, PyPI, npm, Rust, etc. | api.osv.dev/v1/vulns  or all.zip snapshot | Hourly API / Daily dump | CC0 (data); some repos CC‑BY | Planned |
| **B 7** | **NVD CPE Dictionary (official)** | Standardised product identifiers & deprecations | nvd.nist.gov/feeds/json/cpe/1.0/ | With each NVD push | Public domain | Implemented |

---

# Vulnerability‑Intelligence Source List  
_All sources below are zero‑cost for commercial use unless otherwise noted.  
URLs appear without the `https://` scheme for quick copy/paste._

## 1  Risk & Prioritisation Feeds
| Feed | What it adds | Access pattern | Update cadence | Licence / Notes |
|---|---|---|---|---|
| **VulnCheck KEV** | Superset of CISA‑KEV (known‑exploited CVEs) | api.vulncheck.com/v3/backup/**vulncheck‑kev**  or `/index/vulncheck‑kev?pubstartdate=` | Hourly | Free w/ Community token & attribution |
| **CISA KEV** | CVEs exploited in the wild | cisa.gov/known-exploited-vulnerabilities‑catalog (JSON / CSV) | Weekdays | Public domain |
| **CISA Vulnrichment (SSVC)** | SSVC decision points + CWE / CVSS enrichments for new CVEs | github.com/cisagov/vulnrichment (Git) | Continuous commits | CC0 (public domain) |
| **EPSS** | 30‑day exploit‑probability scores | api.first.org/epss (REST) or first.org/epss/data.csv | Daily | CC‑BY‑4.0 |
| **Anchore NVD Data Overrides** | Fixes missing CPE / CVSS in NVD | github.com/anchore/nvd-data-overrides (Git) | Daily | CC0 |
| **NIST Official CPE Dictionary** | Authoritative CPE names & deprecated‑by chains | nvd.nist.gov/feeds/json/cpe/1.0/ (JSON ZIP) | With each NVD push | U.S.‑Gov public data |
| **MITRE CWE** | Weakness taxonomy for root‑cause tagging | cwe.mitre.org/data/downloads.html (CSV / XML) | 2–3× yr | Public domain |

## 2  Exploit‑Code Repositories
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