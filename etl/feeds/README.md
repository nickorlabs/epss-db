# ETL Feed Scripts

## Overview
This folder contains ETL scripts and documentation for integrating, normalizing, and enriching threat intelligence, vulnerability, and security data feeds. Feeds include vulnerability advisories, blocklists, malware, detection rules, threat actors, and more. The project aims to maximize coverage and operational context for security analytics and research.

---

## Implemented Feeds
| Feed Name                | Type/Focus                    | Access/URL                                             | Cadence           | Licence/Notes                |
|-------------------------|-------------------------------|--------------------------------------------------------|-------------------|------------------------------|
| CERT-FR Actualité             | CERT-FR Security News                    | https://www.cert.ssi.gouv.fr/actualite/  | As published | Government Data |
| CERT-FR Alerte                | CERT-FR Security Alerts                  | https://www.cert.ssi.gouv.fr/alerte/     | As published | Government Data |
| CERT-FR Avis                  | CERT-FR Security Advisories              | https://www.cert.ssi.gouv.fr/avis/       | As published | Government Data |
| CERT-FR CTI                   | CERT-FR Cyber Threat Intelligence        | https://www.cert.ssi.gouv.fr/cti/        | As published | Government Data |
| CERT-FR IOC                   | CERT-FR Indicators of Compromise         | https://www.cert.ssi.gouv.fr/ioc/        | As published | Government Data |
| CISA Vulnrichment (SSVC) | SSVC decision points + CWE / CVSS enrichments for new CVEs | https://github.com/cisagov/vulnrichment                | Continuous commits | CC0 (public domain)           |
| EPSS                     | Exploit Prediction Scoring    | https://www.first.org/epss                             | Daily             | CC BY-SA 4.0                  |
| Emerging Threats ET Open | IDS/IPS Rules (Snort/Suricata)| https://rules.emergingthreats.net/open/                | Daily             | GPL-2                        |
| ExploitDB                | Exploit Archive               | https://www.exploit-db.com                             | Daily             | GPL-2                        |
| Google Project Zero 0-day ITW | 0-day Exploits in the Wild | https://googleprojectzero.blogspot.com/                | As published      | CC BY 4.0                    |
| MISP Galaxies Threat Actors | Threat Actor ↔ CVE Map    | https://github.com/MISP/misp-galaxy                    | Continuous Git    | CC0 / MIT                    |
| MITRE CVE List           | Canonical CVE assignments     | https://github.com/CVEProject/cvelistV5                | ~7 min pushes     | Public domain                 |
| NIST NVD                 | Authoritative U.S. government CVE database | https://nvd.nist.gov/feeds/json/cve/1.1/              | Hourly            | Public domain                 |
| Nuclei Templates         | Scanner Templates (YAML)      | https://github.com/projectdiscovery/nuclei-templates   | Daily             | MIT                          |
| Packet Storm Security    | Exploit Archive               | https://packetstormsecurity.com                        | Daily             | Varies (see site)            |
| Shadowserver Exploited-CVE | Exploited CVEs in Honeypots | https://www.shadowserver.org/                          | Daily             | CC BY-NC-SA 4.0               |
| Sigma Rules              | SIEM Detection Rules (YAML)   | https://github.com/SigmaHQ/sigma                       | Continuous Git    | Apache-2.0 / LGPL-2.1        |
| VulnCheck (KEV, NVD++, MITRE) | Known exploited, enriched, and corrected CVE data | https://api.vulncheck.com/                             | Hourly            | Free w/ Community token & attribution |

---

## Candidate Feeds (In Progress / Planned)
| Feed/Source               | Type/Focus                    | Access/URL                                             | Status/Notes                     |
|--------------------------|-------------------------------|--------------------------------------------------------|----------------------------------|
| CERT/CC                   | Advisories                    | https://www.cisa.gov/uscert/                            | In Progress (RSS available)      |
| Rapid7                    | Advisories/Vulns              | https://www.rapid7.com/db/                              | In Progress (Web only; scraping possible) |
| Cisco Security Advisories | Advisories                    | https://tools.cisco.com/security/center/publicationListing.x | In Progress (RSS available)      |
| Microsoft MSRC            | Advisories                    | https://msrc.microsoft.com/update-guide/rss             | In Progress (RSS available)      |
| Oracle Security Alerts    | Advisories                    | https://www.oracle.com/security-alerts/                 | In Progress (RSS available)      |
| IBM PSIRT                 | Advisories                    | https://www.ibm.com/support/pages/ibm-product-security-incident-response-team-psirt | In Progress (RSS available)      |
| Adobe Security Bulletins  | Advisories                    | https://helpx.adobe.com/security.html                   | In Progress (RSS available)      |
| AlienVault OTX            | Threat Intel/IoCs             | https://otx.alienvault.com                              | In Progress (API, CSV, OpenIoC, STIX) |
| Spamhaus                  | Blocklists                    | https://www.spamhaus.org                                | In Progress (Downloadable lists) |
| OpenPhish                 | Phishing                      | https://openphish.com                                   | In Progress (Free/premium, CSV, API) |
| VirusTotal                | Malware/URL/IP Reputation     | https://virustotal.com                                  | In Progress (API, key required)  |
| CrowdSec                  | Malicious IPs                 | https://www.crowdsec.net                                | In Progress (API, global coverage) |
| Cyber Cure                | IoCs/Malware/URLs             | https://www.cybercure.ai                                | In Progress (API, actionable IoCs) |
| HoneyDB                   | Honeypot/Attack Telemetry     | https://honeydb.io                                      | In Progress (API, bad hosts, payloads) |
| CISA AIS                  | Vulns/IoCs/TTPs               | https://www.cisa.gov/ais                                | In Progress (STIX/TAXII, machine-readable) |
| Blocklist.de              | Server Attacks                | https://blocklist.de                                    | In Progress (Downloadable lists) |

_Note: The above table reflects current priorities and in-progress work for new ETL integrations._
| FBI InfraGard             | Critical Infrastructure       | https://www.infragard.org                               | Sector-specific, registration    |
| abuse.ch URLhaus          | Malicious URLs/Domains        | https://urlhaus.abuse.ch                                | Feeds, APIs, ASN/country/TLD     |
| ELLIO                      | IP Blocklists                 | https://ellio.tech                                      | Frequent updates                 |
| Hunt.io                   | C2/SSL Anomalies              | https://hunt.io                                         | API, real-time data              |
| tools.security            | Aggregator                    | https://tools.security                                  | Vuln/threat research             |
| AbuseIPDB                 | IP Reputation/Blocklist       | https://www.abuseipdb.com/                              | API                              |
| APT Groups and Operations | APT Tracking                  | https://docs.google.com/spreadsheets/...                | Spreadsheet                      |
| Binary Defense IP Banlist | IP Blocklist                  | https://www.binarydefense.com/banlist.txt               | Text file                        |
| BGP Ranking               | Malicious ASNs/IPs            | https://www.circl.lu/projects/bgpranking/               | Blocklist                        |
| Botnet Tracker (MalwareTech) | Botnet C2 Tracking         | https://intel.malwaretech.com/                          | Feed                             |
| BruteForceBlocker         | SSH Blocklist                 | https://danger.rulez.sk/...                              | Blocklist                        |
| C&C Tracker (Bambenek)    | C2 Blocklist                  | http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt | Blocklist                  |
| CertStream                | Certificate Transparency      | https://certstream.calidog.io/                           | Real-time stream                 |
| CCSS Forum Malware Certificates | Malware Certs           | http://www.ccssforum.org/malware-certificates.php        | Feed                             |
| CI Army List              | IP Blocklist                  | http://cinsscore.com/list/ci-badguys.txt                 | Blocklist                        |
| CINS Score                | IP Reputation/Blocklist       | http://cinsscore.com/                                    | Blocklist                        |
| Cisco Umbrella            | Threat Intel/Blocklist        | http://s3-us-west-1.amazonaws.com/umbrella-static/index.html | Blocklist                   |
| Cloudmersive Virus Scan   | Malware Scan                  | https://cloudmersive.com/virus-api                       | API                              |
| CrowdSec Console          | Threat Intel Dashboard        | https://app.crowdsec.net/                                | Dashboard                        |
| Cyware Threat Intel Feeds | Community Threat Feeds        | https://cyware.com/community/ctix-feeds                  | Feeds                            |
| DataPlane.org             | IP/Domain Threat Feeds        | https://dataplane.org/                                   | Feeds                            |
| DigitalSide Threat-Intel  | Threat Feeds (STIX2/CSV/MISP) | https://osint.digitalside.it/                            | Feeds, GitHub repo               |
| Disposable Email Domains  | Disposable Email List         | https://github.com/martenson/disposable-email-domains    | List                             |
| DNS Trails (SecurityTrails)| DNS History                  | https://securitytrails.com/dns-trails                    | API                              |
| Emerging Threats Firewall Rules | Firewall Rules           | http://rules.emergingthreats.net/fwrules/                | Rules                            |
| Emerging Threats IDS Rules | IDS Rules                    | http://rules.emergingthreats.net/blockrules/             | Rules                            |
| ExoneraTor                | Tor Relay History             | https://exonerator.torproject.org/                       | Feed                             |
| Exploitalert              | Exploit Database              | http://www.exploitalert.com/                             | Feed                             |
| FastIntercept             | Threat Lists                  | https://intercept.sh/threatlists/                        | Lists                            |
| ZeuS Tracker (abuse.ch)   | Malware C2 Tracking           | https://feodotracker.abuse.ch/                           | Feed                             |
| FireHOL IP Lists          | Aggregated IP Blocklists      | http://iplists.firehol.org/                              | Lists                            |
| FraudGuard                | IP Reputation                 | https://fraudguard.io/                                   | API                              |
| HoneyPy                   | Honeypot Tool                 | https://github.com/foospidy/HoneyPy                      | Tool, not a feed                 |
| Icewater                  | Threat Intel Tool              | https://github.com/SupportIntelligence/Icewater          | Tool, not a feed                 |
| Infosec CERT-PA           | Malware/Blocklists/Vuln DB    | https://infosec.cert-pa.it                               | Feeds, DB                        |
| InQuest Labs              | Malware/Threat Analysis        | https://labs.inquest.net                                 | Feeds                            |
| I-Blocklist               | IP Blocklists                 | https://www.iblocklist.com/lists                                  | Lists                            |
| IPsum                     | IP Blocklist                  | https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt | List                      |
| James Brine Threat Feeds  | Threat Feeds                  | https://jamesbrine.com.au                                         | Feeds                            |
| Kaspersky Threat Data Feeds| Threat Data (Commercial)      | https://support.kaspersky.com/datafeeds                   | Registration required            |
| Majestic Million          | Top Domains                   | https://majestic.com/reports/majestic-million            | List                             |
| Maldatabase               | Malware Samples               | https://maldatabase.com/                                   | Feed                             |
| Malpedia                  | Malware Encyclopedia          | https://malpedia.caad.fkie.fraunhofer.de/                  | DB, API                          |
| MalShare.com              | Malware Samples               | http://www.malshare.com/                                   | API                              |
| Maltiverse                | Threat Intel                  | https://www.maltiverse.com/                                | API                              |
| MalwareBazaar (abuse.ch)  | Malware Samples               | https://bazaar.abuse.ch/                                   | API                              |
| Malware Domain List       | Malicious Domains             | https://www.malwaredomainlist.com/                         | List                             |
| Malware Patrol            | Malware Feeds                 | https://www.malwarepatrol.net/                             | API                              |
| Malware-Traffic-Analysis.net | Malware Traffic Samples     | https://malware-traffic-analysis.net/                     | Samples                          |
| MalwareDomains.com        | Malicious Domains             | http://www.malwaredomains.com/                             | List                             |
| MetaDefender Cloud        | Threat Intelligence Feed      | https://www.opswat.com/developers/threat-intelligence-feed | API                              |
| Netlab OpenData Project   | Threat Data/C2                | https://blog.netlab.360.com/tag/english/                   | Feeds                            |
| NoThink!                  | Malicious IPs                 | http://www.nothink.org                                     | Blocklists                       |
| NormShield Services       | Threat Intelligence           | https://services.normshield.com                            | API                              |
| NovaSense Threats         | Threat Feeds                  | https://novasense-threats.com                              | Feeds                            |
| Obstracts                 | Threat Intelligence           | https://www.obstracts.com/                                 | API                              |
| Vulners                   | Vuln Aggregator               | https://vulners.com                                        | API                              |
| Pulsedive                 | Threat Intelligence           | https://pulsedive.com                                      | API                              |
| AlienVault OTX            | Threat Intelligence           | https://www.alienvault.com                                 | API                              |
| PolySwarm                 | Malware/Threat Intelligence   | https://polyswarm.io                                       | API                              |
| FullHunt                  | Exposures/Attack Surface      | https://fullhunt.io                                        | API                              |
| SecurityTrails            | DNS/Threat Data               | https://securitytrails.com                                 | API                              |
| ONYPHE                    | Threat Data                   | https://www.onyphe.io                                      | API                              |
| Netlas                    | Internet Assets               | https://netlas.io                                          | API                              |
| Censys                    | Internet Scan/Exposure        | https://censys.io                                          | API                              |
| BinaryEdge                | Exposures                     | https://www.binaryedge.io                                  | API                              |
| GreyNoise                 | Scan/Noise Intel              | https://www.greynoise.io                                   | API                              |
| LeakIX                    | Leaks/Exposed Data            | https://leakix.net                                         | API                              |
| HIBP                      | Breach Lookup                 | https://haveibeenpwned.com                                 | Not Implemented                  |
| DeHashed                  | Breach Lookup                 | https://www.dehashed.com                                   | Not Implemented                  |
| Snusbase                  | Breach Lookup                 | https://snusbase.com                                       | Not Implemented                  |
| Bug Bounty Hunting        | Public Bug Bounty Findings    | https://www.bugbountyhunting.com                           | Public findings                  |
| Breach Detective          | Breach/Leak Intel             | https://breachdetective.com                                | Feed                             |
| IntelligenceX             | Dark Web/Leak Search          | https://intelx.io                                          | Not Implemented                  |
| CRT.sh                    | Cert Transparency Logs        | https://crt.sh                                             | Feed                             |
| DNSDumpster               | DNS Recon/Exposure            | https://dnsdumpster.com                                    | Feed                             |
| ZoomEye                   | Internet Scan/Exposure        | https://ZoomEye.ai                                         | API                              |
| Shodan                    | Exposure/Telemetry            | https://www.shodan.io                                      | API                              |

---

## How to Contribute or Prioritize
To request a new feed integration, suggest a candidate, or contribute an ETL script, please open an issue or pull request. If you wish to prioritize a feed, comment with your use case or operational requirement.

## GitHub ETL Refactoring Plan & Checklist

The following ETL scripts ingest data from GitHub or GitLab repositories and should be refactored to follow the standardized [GitHub ETL Template](./GITHUB_ETL_TEMPLATE.md). This ensures consistency, maintainability, and robust data processing.

### **Refactoring Order and Checklist**

#### **Prioritized Refactoring Order:**
1. `update_opencvdb.py` — [wiz-sec/open-cvdb](https://github.com/wiz-sec/open-cvdb)
2. `update_sigma_rules.py` — [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
3. `update_nuclei_templates.py` — [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
4. `update_metasploit_modules.py` — [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework)
5. `update_exploitdb.py` — [exploit-database/exploitdb](https://gitlab.com/exploit-database/exploitdb)
6. `update_gitlab_advisory_db.py` — [gitlab-org/security-products/gemnasium-db](https://gitlab.com/gitlab-org/security-products/gemnasium-db)
7. `update_mitre.py` — [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)
8. `update_cisa_vulnrichment.py` — [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment)
9. `update_ghsa_graphql.py` — (GitHub Security Advisories via API)

#### **Refactoring Steps for Each Script:**
- [ ] Use `ensure_git_repo_latest` from `etl.common.git_utils` for all repo operations (clone, pull, update)
- [ ] Use `create_osv_record` from `etl.common.osv_normalizer` for normalization
- [ ] Save both raw and normalized data with timestamps in appropriate directories
- [ ] Use environment variables for all configuration (paths, URLs, tokens)
- [ ] Provide structured logging for each major operation
- [ ] Ensure a clear `main()` entrypoint
- [ ] Add or update module docstrings and inline comments
- [ ] Remove legacy/custom git logic and redundant code

Refer to [GITHUB_ETL_TEMPLATE.md](./GITHUB_ETL_TEMPLATE.md) for the full template and code skeleton.

---

## References
- [Awesome Threat Intelligence (GitHub)](https://github.com/hslatman/awesome-threat-intelligence)
- [CyberSources (GitHub)](https://github.com/bst04/cybersources)
- [OSINT Framework](https://osintframework.com/)
- [tools.security](https://tools.security)
- **Emerging Threats ET Open** – Snort/Suricata IDS rules

#### **Immediate Next Priorities:**
- ~~Google Project Zero "0-day ITW"~~ (Implemented)
- ~~Shadowserver Exploited-CVE~~ (Implemented)
- Metasploit Modules (Pending)
- ~~MISP Galaxies~~ (Implemented)
- Shodan (Pending)

---

| Script Name                       | Feed Source / Description                          | Status        |
|-----------------------------------|---------------------------------------------------|---------------|
| list_vulncheck_indices.py         | VulnCheck indices utility                         | Implemented   |
| update_certfr_actualite.py        | CERT-FR Actualité (News)                          | Implemented   |
| update_certfr_alerte.py           | CERT-FR Alerte (Alerts)                           | Implemented   |
| update_certfr_avis.py             | CERT-FR Avis (Advisories)                         | Implemented   |
| update_certfr_cti.py              | CERT-FR CTI (Cyber Threat Intelligence)           | Implemented   |
| update_certfr_ioc.py              | CERT-FR IOC (Indicators of Compromise)            | Implemented   |
| update_cisa_known_exploited.py    | CISA Known Exploited Vulnerabilities (KEV)        | Implemented   |
| update_cisa_vulnrichment.py       | CISA Vulnrichment (GitHub enrichment repo)        | Implemented   |
| update_cnnvd.py                   | CNNVD                                             | Removed       |
| update_cpe_dictionary.py          | NVD CPE Dictionary and CVE to CPE mapping         | Implemented   |
| update_cwe.py                     | CWE                                               | Implemented   |
| update_exploitdb.py               | Exploit-DB (exploitdb.com, CSV+repo)              | Implemented   |
| update_ghsa_graphql.py            | GitHub Security Advisories (GHSA, GraphQL)        | Implemented   |
| update_gitlab_advisory_db.py      | GitLab Advisory Database                          | Implemented   |
| update_google_project_zero_0day_itw.py | Google Project Zero "0-day ITW"               | Implemented   |
| update_metasploit_modules.py      | Metasploit Modules                                | Implemented   |
| update_misp_galaxies_threat_actors.py | MISP Galaxies - Threat Actors                   | Implemented   |
| update_mitre.py                   | MITRE CVE List V5                                 | Implemented   |
| update_nvd_v2.py                  | NIST NVD 2.0                                      | Implemented   |
| update_opencvdb.py                | CloudVulnDB / open-cvdb                           | Implemented   |
| update_osv.py                     | OSV                                               | Implemented   |
| update_shadowserver_exploited_cve.py | Shadowserver Exploited-CVE (Playwright-scraped, all table data from dashboard, not limited to CVEs) | Implemented   |
| update_vulncheck_kev.py           | VulnCheck KEV                                     | Implemented   |
| update_vulncheck_mitre.py         | VulnCheck MITRE CVE V5                            | Implemented   |
| update_vulncheck_nist_nvd1.py     | VulnCheck NVD 1.0                                 | Removed       |
| update_vulncheck_nist_nvd2.py     | VulnCheck NVD 2.0                                 | Implemented   |
| update_packet_storm_security.py | Packet Storm Security (RSS Only were poor y0 5k a month :( )) | Implemented       |
| update_nuclei_templates.py | Nuclei Templates | Implemented       |
| update_sigma_rules.py | Sigma Rules | Implemented       |
| update_emerging_threats_et_open.py | Emerging Threats ET Open | Implemented       |
| update_epss.py | EPSS | Implemented   |


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

### Additional Vendor & Research Advisory Sources (Planned / Candidate)
| Feed/Source               | Status             | Access/Notes                                  |
|--------------------------|--------------------|-----------------------------------------------|
| Vapid Labs               | Not implemented    | No structured feed; scraping needed           |
| 0day.today               | Not implemented    | No structured feed; scraping needed           |
| CERT/CC                  | Not implemented    | RSS available                                 |
| Rapid7                   | Not implemented    | Web only; scraping possible                   |
| Cisco Security Advisories| Not implemented    | RSS available                                 |
| Microsoft MSRC           | Not implemented    | RSS available                                 |
| Oracle Security Alerts   | Not implemented    | RSS available                                 |
| IBM PSIRT                | Not implemented    | RSS available                                 |
| Adobe Security Bulletins | Not implemented    | RSS available                                 |


> These sources are candidates for future ETL expansion. If you would like to prioritize or contribute to any of these, please open an issue or pull request.

## 6  Context & Threat‑Actor Enrichment
| Feed | Adds… | Access | Licence |
|---|---|---|---|

---

## Threat Intelligence, Exposure, and Aggregator Feeds (Candidate)
These sources are notable for vulnerability, threat, exposure, or breach intelligence and are strong candidates for future ETL integration. Many offer APIs or feeds (some require registration or have usage limits).

| Feed/Source         | Status           | Access/API/Notes                                   |
|---------------------|------------------|----------------------------------------------------|
| AbuseIPDB                          | Not implemented  | https://www.abuseipdb.com/ (API, IP reputation/blocklist)             |
| APT Groups and Operations          | Not implemented  | https://docs.google.com/spreadsheets/... (APT tracking spreadsheet)    |
| Binary Defense IP Banlist          | Not implemented  | https://www.binarydefense.com/banlist.txt (IP blocklist)              |
| BGP Ranking                        | Not implemented  | https://www.circl.lu/projects/bgpranking/ (malicious ASNs/IPs)        |
| Botnet Tracker (MalwareTech)       | Not implemented  | https://intel.malwaretech.com/ (botnet C2 tracking)                   |
| BruteForceBlocker                  | Not implemented  | https://danger.rulez.sk/... (SSH brute force blocklist)               |
| C&C Tracker (Bambenek)             | Not implemented  | http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt         |
| CertStream                         | Not implemented  | https://certstream.calidog.io/ (real-time cert transparency)           |
| CCSS Forum Malware Certificates    | Not implemented  | http://www.ccssforum.org/malware-certificates.php                     |
| CI Army List                       | Not implemented  | http://cinsscore.com/list/ci-badguys.txt (IP blocklist)               |
| CINS Score                         | Not implemented  | http://cinsscore.com/ (IP reputation/blocklist)                       |
| Cisco Umbrella                     | Not implemented  | http://s3-us-west-1.amazonaws.com/umbrella-static/index.html          |
| Cloudmersive Virus Scan            | Not implemented  | https://cloudmersive.com/virus-api (API, malware scan)                |
| CrowdSec Console                   | Not implemented  | https://app.crowdsec.net/ (dashboard for CrowdSec)                    |
| Cyware Threat Intelligence Feeds   | Not implemented  | https://cyware.com/community/ctix-feeds (community threat feeds)      |
| DataPlane.org                      | Not implemented  | https://dataplane.org/ (IP/domain threat feeds)                       |
| DigitalSide Threat-Intel           | Not implemented  | https://osint.digitalside.it/ (feeds: STIX2, CSV, MISP, GitHub)       |
| Disposable Email Domains           | Not implemented  | https://github.com/martenson/disposable-email-domains (list)          |
| DNS Trails (SecurityTrails)        | Not implemented  | https://securitytrails.com/dns-trails (DNS history, API)              |
| Emerging Threats Firewall Rules    | Not implemented  | http://rules.emergingthreats.net/fwrules/ (firewall rules)            |
| Emerging Threats IDS Rules         | Not implemented  | http://rules.emergingthreats.net/blockrules/ (IDS rules)              |
| ExoneraTor                         | Not implemented  | https://exonerator.torproject.org/ (Tor relay history)                |
| Exploitalert                       | Not implemented  | http://www.exploitalert.com/ (exploit database)                       |
| FastIntercept                      | Not implemented  | https://intercept.sh/threatlists/ (threat lists)                      |
| ZeuS Tracker (abuse.ch)            | Not implemented  | https://feodotracker.abuse.ch/ (malware C2 tracking)                  |
| FireHOL IP Lists                   | Not implemented  | http://iplists.firehol.org/ (aggregated IP blocklists)                |
| FraudGuard                         | Not implemented  | https://fraudguard.io/ (IP reputation, API)                           |
| HoneyPy                            | Not implemented  | https://github.com/foospidy/HoneyPy (honeypot tool, not a feed)       |
| Icewater                           | Not implemented  | https://github.com/SupportIntelligence/Icewater (tool, not a feed)    |
| Infosec CERT-PA                    | Not implemented  | https://infosec.cert-pa.it (malware, blocklists, vuln DB)             |
| InQuest Labs                       | Not implemented  | https://labs.inquest.net (malware, threat analysis)                   |
| I-Blocklist                        | Not implemented  | https://www.iblocklist.com/lists (IP blocklists)                      |
| IPsum                              | Not implemented  | https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt     |
| James Brine Threat Feeds           | Not implemented  | https://jamesbrine.com.au (threat feeds)                              |
| Kaspersky Threat Data Feeds        | Not implemented  | https://support.kaspersky.com/datafeeds (commercial, registration)     |
| Majestic Million                   | Not implemented  | https://majestic.com/reports/majestic-million (top domains)           |
| Maldatabase                        | Not implemented  | https://maldatabase.com/ (malware samples)                            |
| Malpedia                           | Not implemented  | https://malpedia.caad.fkie.fraunhofer.de/ (malware encyclopedia)      |
| MalShare.com                       | Not implemented  | http://www.malshare.com/ (malware samples, API)                       |
| Maltiverse                         | Not implemented  | https://www.maltiverse.com/ (threat intel, API)                       |
| MalwareBazaar (abuse.ch)           | Not implemented  | https://bazaar.abuse.ch/ (malware samples, API)                       |
| Malware Domain List                | Not implemented  | https://www.malwaredomainlist.com/ (malicious domains)                |
| Malware Patrol                     | Not implemented  | https://www.malwarepatrol.net/ (malware feeds, API)                   |
| Malware-Traffic-Analysis.net       | Not implemented  | https://malware-traffic-analysis.net/ (malware traffic samples)       |
| MalwareDomains.com                 | Not implemented  | http://www.malwaredomains.com/ (malicious domains)                    |
| MetaDefender Cloud                 | Not implemented  | https://www.opswat.com/developers/threat-intelligence-feed (API)      |
| Netlab OpenData Project            | Not implemented  | https://blog.netlab.360.com/tag/english/ (threat data, C2)            |
| NoThink!                           | Not implemented  | http://www.nothink.org (malicious IPs, blocklists)                    |
| NormShield Services                | Not implemented  | https://services.normshield.com (threat intelligence, API)            |
| NovaSense Threats                  | Not implemented  | https://novasense-threats.com (threat feeds)                          |
| Obstracts                          | Not implemented  | https://www.obstracts.com/ (threat intelligence, API)                 |
| VirusTotal          | Not implemented  | https://virustotal.com (API, multi-engine, community) |
| Cisco Talos         | Not implemented  | https://talosintelligence.com (feeds, advisories, API) |
| OTX (LevelBlue Labs)| Not implemented  | https://otx.alienvault.com (API, CSV, OpenIoC, STIX) |
| Spamhaus            | Not implemented  | https://www.spamhaus.org (blocklists, downloadable) |
| OpenPhish           | Not implemented  | https://openphish.com (free/premium, CSV, API)     |
| CrowdSec            | Not implemented  | https://www.crowdsec.net (API, malicious IPs)      |
| Cyber Cure          | Not implemented  | https://www.cybercure.ai (API, IoCs, malware/URLs) |
| HoneyDB             | Not implemented  | https://honeydb.io (API, honeypot, bad hosts)      |
| CISA AIS            | Not implemented  | https://www.cisa.gov/ais (STIX/TAXII, gov/private) |
| Blocklist.de        | Not implemented  | https://blocklist.de (server attack lists, downloadable) |
| FBI InfraGard       | Not implemented  | https://www.infragard.org (sector-specific, registration required) |
| abuse.ch URLhaus    | Not implemented  | https://urlhaus.abuse.ch (feeds, APIs, malicious URLs) |
| ELLIO               | Not implemented  | https://ellio.tech (IP blocklists, frequent updates) |
| Hunt.io             | Not implemented  | https://hunt.io (API, C2, SSL anomalies)           |
| tools.security      | Not implemented  | https://tools.security (aggregator, vuln/threat research) |
| Vulners             | Not implemented  | https://vulners.com (API, vuln aggregator)         |
| Pulsedive           | Not implemented  | https://pulsedive.com (API, threat intelligence)   |
| AlienVault OTX      | Not implemented  | https://www.alienvault.com (API, threat intel)     |
| PolySwarm           | Not implemented  | https://polyswarm.io (API, malware/threat intel)   |
| FullHunt            | Not implemented  | https://fullhunt.io (API, exposures, attack surf.) |
| SecurityTrails      | Not implemented  | https://securitytrails.com (API, DNS/threat data)  |
| ONYPHE              | Not implemented  | https://www.onyphe.io (API, threat data)           |
| Netlas              | Not implemented  | https://netlas.io (API, internet assets)           |
| Censys              | Not implemented  | https://censys.io (API, internet scan/exposure)    |
| BinaryEdge          | Not implemented  | https://www.binaryedge.io (API, exposures)         |
| GreyNoise           | Not implemented  | https://www.greynoise.io (API, scan/noise intel)   |
| LeakIX              | Not implemented  | https://leakix.net (API, leaks/exposed data)       |
| HIBP                | Available (account) | https://haveibeenpwned.com (API, breach lookup; user has account) |
| DeHashed            | Available (account) | https://www.dehashed.com (API, breach lookup; user has account) |
| Snusbase            | Available (account) | https://snusbase.com (API, breach lookup; user has account) |
| Bug Bounty Hunting  | Not implemented  | https://www.bugbountyhunting.com (public findings) |
| Breach Detective    | Not implemented  | https://breachdetective.com (breach/leak intel)    |
| IntelligenceX       | Available (paid) | https://intelx.io (API, dark web/leak search; user has paid account) |
| CRT.sh              | Not implemented  | https://crt.sh (cert transparency logs)            |
| DNSDumpster         | Not implemented  | https://dnsdumpster.com (DNS recon/exposure)       |
| ZoomEye             | Not implemented  | https://ZoomEye.ai (API, internet scan/exposure)   |
| Packet Storm        | Implemented      | https://packetstormsecurity.com                    |
| ExploitDB           | Implemented      | https://www.exploit-db.com                         |
| Shodan              | Not Implemented      | https://www.shodan.io (API, exposure/telemetry)    |

> These feeds are candidates for future enrichment, exposure monitoring, or threat intelligence ETL. If you wish to prioritize or contribute ETL for any of these, please open an issue or pull request.

| **MISP Galaxies – Threat Actors** | Actor ↔ CVE tags | github.com/MISP/misp-galaxy | CC0 / MIT |