# External-Recon / OSINT Data Sources — Integration Menu

A menu of data sources, feeds, and repositories that assist **external, information-gathering
reconnaissance** against domains/hosts/live targets you own — with an emphasis on sources whose
value is the **data/access itself** (and which often lack good off-the-shelf OSS tooling, so they
need custom integration). Scope is pure discovery/attribution/exposure OSINT plus the credential-
breach, third-party-posture, and domain/IP/URL reputation layers. **No** CVE/vuln-scoring sources
and **no** collaborative threat-sharing (ISAC/AIS) — those are intentionally out of scope.

**Legend — access model:**
`FREE` · `REG` (free with registration) · `FREEMIUM` (free tier + paid) · `PAID` · `ENT` (enterprise
only) · `VETTED` (verified-researcher / community-gated) · `OWN` (must prove asset/domain ownership)
· `AFFIL` (membership/affiliation-gated).
**OSS column:** `wrapped` (good OSS clients exist) · `partial` · **`GAP`** (little/no OSS — the data/access is the barrier).

> ⚠️ **Access terms, pricing, rate limits, and availability change constantly and must be verified with
> each provider.** Status flags below reflect the research snapshot and are called out as *verify*.

### Already wired into `run-recon.sh`

The toolkit integrates a subset of these directly; the rest of this menu is the backlog for custom fetchers.

- **`subfinder` provider config** (`~/.config/subfinder/provider-config.yaml`, scaffolded by the installer) — pasting API keys unlocks passive subdomain discovery from **Censys, Shodan, VirusTotal, SecurityTrails, FullHunt, Netlas, Chaos, BinaryEdge, CertSpotter, LeakIX, BeVigil, GitHub** and more. For these, tooling already exists; the key is the barrier.
- **`--osint`** (free, no key) — **RDAP** domain registration, **Shodan InternetDB** (`internetdb.shodan.io`, passive ports/hostnames/tags per IP), and **Team Cymru** IP-to-ASN (org name reveals cloud tenancy).
- **`--virustotal`** (`VT_API_KEY`) — VirusTotal domain report: reputation, passive DNS records, subdomains.
- **`--urlscan`** (optional `URLSCAN_API_KEY`) — urlscan.io historical page URLs + resolved IPs for a domain.
- **`--social`** (tookie-osint) — social-media account discovery for the org brand username across many platforms.
- **`--github`** — GitHub code search for leaked subdomains/endpoints (`github-subdomains`/`-endpoints`).
- **`--buckets`** — cloud storage enumeration (`cloud_enum`: S3/Azure/GCP).
- **CT logs** are already consumed for subdomains via `subfinder`; **`crt.sh`** direct bulk/Postgres access (below) remains a `GAP` worth building for identity/org-name pivots.

Everything else below — passive-DNS bulk (DNSDB), DNS **zone-file programs** (CZDS/Verisign), **RIR bulk** data, **breach** providers (HIBP/DeHashed/SpyCloud), **third-party ratings** (SecurityScorecard/BitSight), and the paid internet-scan tiers — needs custom integration and is flagged with its access model and OSS gap.

---

## 1. Internet-wide scan & service-exposure data
Who/what is listening on your IPs/ports/services, indexed and queryable by IP, domain, cert, or banner.

| Source | Recon use | Access | Mechanism / format | OSS |
|---|---|---|---|---|
| **Censys** | Hosts/services/certs by IP/domain/ASN; rich field search | FREEMIUM→ENT | REST (Platform API); bulk via enterprise; JSON | wrapped (`censys-python`) — *tiers are the barrier* |
| **Shodan** | Ports/banners/service metadata, facets, DNS, streaming | FREEMIUM (credits)→ENT | REST + streaming; JSON | wrapped — *credits/bulk gated* |
| **Netlas.io** | Host/cert/domain search, responses corpus | FREEMIUM→PAID | REST; JSON | partial / **GAP** |
| **Onyphe** | Scan + geoloc + threat context by IP/domain | FREEMIUM→PAID | REST; JSON | **GAP** |
| **BinaryEdge** | Internet scan data, exposed services | FREEMIUM→PAID | REST; JSON | partial |
| **ZoomEye** | Scan data (strong CN/APAC coverage) | FREEMIUM→PAID | REST; JSON | partial |
| **Fofa** | Scan data, powerful query grammar | PAID | REST; JSON | **GAP** |
| **Hunter.how** | Scan/asset search | FREEMIUM→PAID | REST; JSON | **GAP** |
| **LeakIX** | Exposed services + leak indicators per host | REG→PAID | REST; JSON | partial |
| **Shadowserver** | Daily reports on exposed/compromised assets **in your netblocks/ASN** | FREE but **OWN/VETTED** | Report subscription (email/API) after ownership vetting; CSV/JSON | **GAP** — high-value, underused |
| **Rapid7 Project Sonar / Open Data** | Historic internet-wide scan/DNS datasets | *verify: public access discontinued* | (was bulk download) | historical only |

---

## 2. Certificate Transparency & TLS corpora
CT logs are the single best free source for discovering subdomains/hostnames from issued certs.

| Source | Recon use | Access | Mechanism / format | OSS |
|---|---|---|---|---|
| **crt.sh** | Domain→certs→subdomains; **direct public PostgreSQL** for bulk | FREE | Web/JSON **+ Postgres** (`psql` to crt.sh DB) | wrapped for web; **GAP** for direct DB (underused) |
| **CertStream** (Calidog) | Real-time CT firehose → newly-issued domains/subdomains live | FREE | WebSocket stream; JSON | wrapped (`certstream`) — *the stream is the asset* |
| **CT log operators** (Google Argon/Xenon, Cloudflare Nimbus, Sectigo Sabre/Mammoth, Let's Encrypt Oak, DigiCert) | Bulk `get-entries` for exhaustive cert history | FREE | RFC 6962 HTTP API; JSON | partial — **GAP** for bulk ingest |
| **SSLMate Cert Spotter** | CT monitoring for **your** domains + API | FREEMIUM→PAID | REST; JSON | partial |
| **Meta/Facebook CT Monitor** | Alerts on certs issued for your domains | FREE (REG) | Portal/alerts | n/a |
| **Cloudflare Merkle Town** | CT ecosystem dashboard/stats | FREE | Web | n/a |
| **Censys certificates dataset** | Cert corpus w/ parsed fields, pivot by SAN/fingerprint | FREEMIUM→ENT | REST/bulk; JSON | via Censys |

---

## 3. Passive DNS (pDNS)
Historical domain↔IP resolutions — pivot infrastructure, find related hosts, track changes.

| Source | Recon use | Access | Mechanism / format | OSS |
|---|---|---|---|---|
| **DomainTools DNSDB** (formerly **Farsight** — *acquired 2021, verify branding/endpoints*) | Gold-standard pDNS; historical A/AAAA/CNAME/MX/NS/etc. | PAID→ENT | REST + DNSDB Scout; JSON | wrapped clients — *data gated* |
| **CIRCL Passive DNS** | Community pDNS | FREE for **VETTED** (CSIRT/researcher) | REST; JSON | wrapped |
| **SecurityTrails** | DNS history, current/historical records, subdomains | FREEMIUM→PAID | REST; JSON | wrapped — *tiers gated* |
| **VirusTotal pDNS** | Resolutions/siblings for a domain/IP (part of VT) | FREEMIUM→ENT | REST; JSON | wrapped |
| **Microsoft Defender TI** (ex-RiskIQ/PassiveTotal) | pDNS, WHOIS history, host pairs, trackers | FREEMIUM→ENT | REST/portal; JSON | partial |
| **Zetalytics** | pDNS + email/domain telemetry | PAID | REST; JSON | **GAP** |
| **OpenINTEL** | Large-scale **active** DNS measurement archive | VETTED (academic) | Bulk (Parquet/Avro) | **GAP** |
| **Cisco Umbrella Investigate** | DNS-centric domain intel & co-occurrences | ENT | REST; JSON | partial |

---

## 4. DNS zone-file access programs
Full zone files = every delegated domain in a TLD. Enumerate your org's domains, find look-alikes.

| Source | Recon use | Access | Mechanism / format | OSS |
|---|---|---|---|---|
| **ICANN CZDS** (Centralized Zone Data Service) | Full zone files for most gTLDs (per-TLD approval) | FREE but **VETTED** (apply, registries approve) | Portal + API + download; zone-file (DNS master) | **GAP** — no turnkey OSS pipeline |
| **Verisign `.com`/`.net` TLD ZFA** | Largest zones | via CZDS (**VETTED**) | Download; zone-file | **GAP** |
| **ccTLD zone access** (varies: IIS `.se`/`.nu`, `.ch`/`.li`, `.dk`, others) | Country-code zones where offered | FREE/REG/**VETTED** (registry-specific) | Download/rsync; zone-file | **GAP** |

---

## 5. WHOIS / RDAP / domain registration intelligence
Registration data, and the pivots that matter: reverse-WHOIS (by registrant) and historical WHOIS.

| Source | Recon use | Access | Mechanism / format | OSS |
|---|---|---|---|---|
| **RDAP** (RIR + registry servers) | Structured registration for domain/IP (WHOIS successor) | FREE | REST; JSON | wrapped |
| **WhoisXML API** | Bulk WHOIS, **reverse WHOIS**, WHOIS history, DNS, subdomains | PAID | REST + bulk; JSON/CSV | partial — *data gated* |
| **DomainTools Iris** | Premier domain investigation: reverse/historical WHOIS, pivots | ENT | REST/portal; JSON | **GAP** |
| **Registrar/registry bulk WHOIS / ICANN RDDS** | Bulk registration data | **AFFIL**/agreement | Bulk | **GAP** |
| **ViewDNS / Whoxy** | Cheaper reverse/historical WHOIS | FREEMIUM→PAID | REST; JSON | partial |

---

## 6. IP / ASN / BGP / netblock ownership & routing
Map IPs→netblocks→org, and see how your prefixes are announced. Mostly free, mostly bulk, mostly no OSS.

| Source | Recon use | Access | Mechanism / format | OSS |
|---|---|---|---|---|
| **RIR bulk data** (ARIN, RIPE, APNIC, LACNIC, AFRINIC) | Netblock↔org; RIPE DB dumps are free | FREE (ARIN bulk via agreement) | Bulk WHOIS/RDAP; text/JSON | partial — **GAP** for ingest |
| **RIPEstat** | One-stop IP/ASN/BGP/abuse/geo data | FREE | REST; JSON | partial |
| **RouteViews** | BGP routing tables & archives | FREE | Bulk MRT | **GAP** |
| **RIPE RIS** | BGP collectors / routing history | FREE | Bulk MRT + REST | **GAP** |
| **Team Cymru IP→ASN** | Fast IP→ASN→org mapping | FREE (fair-use) | WHOIS/DNS/bulk; text | wrapped |
| **PeeringDB** | Network/peering/facility → infra footprint | FREE (REG) | REST; JSON | wrapped |
| **bgp.tools** | ASN/prefix lookups, clean API | FREEMIUM | REST; JSON | partial |
| **bgpview.io** | ASN/prefix/IP data | FREE | REST; JSON | wrapped |
| **CAIDA** | AS relationships, prefix2AS, ITDK | VETTED (academic) | Bulk | **GAP** |
| **Hurricane Electric BGP toolkit** | Web ASN/prefix explorer | FREE | Web | n/a |

---

## 7. IP geolocation & network enrichment
"Where/whose is this IP, and does it matter" — geo, ASN, org, and anonymization/scanner attribution.

| Source | Recon use | Access | Mechanism / format | OSS |
|---|---|---|---|---|
| **MaxMind GeoIP2 / GeoLite2** | IP→geo/ASN | FREEMIUM (*GeoLite2 now needs account+license — verify*) | MMDB / API | wrapped |
| **IPinfo** | IP→geo/ASN/company/privacy(VPN/proxy) | FREEMIUM (*free tier degraded — verify*) | REST + MMDB | wrapped |
| **Spur.us** | VPN/proxy/residential-proxy detection (best-in-class) | PAID | REST + feeds; JSON | **GAP** |
| **GreyNoise** | Is an IP internet background-noise / mass-scanner; RIOT (common business svcs) | FREEMIUM→PAID | REST; JSON | wrapped — *triage gold* |
| **ipdata / ipregistry / DB-IP / IP2Location** | Geo/ASN/threat enrichment | FREEMIUM→PAID | REST/DB | partial |

---

## 8. Attack-surface / subdomain / domain intelligence
Aggregated recon datasets (subdomains, associated domains, tech). Many *have* OSS clients — the data tier is the wall.

| Source | Recon use | Access | Mechanism / format | OSS |
|---|---|---|---|---|
| **SecurityTrails** | Subdomains, DNS/WHOIS history, associated domains | FREEMIUM→PAID | REST; JSON | wrapped |
| **FullHunt** | Attack-surface/asset API | FREEMIUM→PAID | REST; JSON | partial |
| **Chaos** (ProjectDiscovery) | Free bug-bounty subdomain dataset + API | FREE (REG) | REST + bulk; JSON | wrapped |
| **DNSDumpster / HackerTarget** | Quick subdomain/DNS recon | FREEMIUM | Web/REST | partial |
| **BuiltWith** | Tech profiling + **reverse tech lookup** | FREEMIUM→PAID | REST; JSON | partial |
| **PublicWWW** | Source-code search (find sites using your codes/strings) | PAID | REST; JSON | **GAP** |
| **Hunter.io** | Email addresses for a domain | FREEMIUM→PAID | REST; JSON | wrapped |
| **Robtex / RapidDNS** | DNS/IP pivots | FREEMIUM | Web/REST | partial |
| *Spyse* | *(defunct — verify/avoid)* | — | — | — |

---

## 9. Cloud / infrastructure attribution
Free provider IP-range publications → attribute IPs to cloud tenancy; SAN datasets surface cloud-hosted domains.

| Source | Recon use | Access | Mechanism / format | OSS |
|---|---|---|---|---|
| **Cloud IP ranges** (AWS `ip-ranges.json`, GCP `cloud.json`, Azure ServiceTags, Oracle, DigitalOcean, Cloudflare, Fastly) | IP→provider/service/region attribution | FREE | Published JSON | partial — **GAP** for unified ingest |
| **Community cloud SAN datasets** (e.g., Kaeferjaeger-style TLS-SAN scrapes of cloud ranges) | Discover cloud-hosted hostnames via cert SANs | FREE | Bulk text | **GAP** |

---

## 10. Leaked credentials / breach / dark-web exposure
Exposure tied to your **domain/accounts**. Infostealer-sourced creds are the current high-signal layer.

| Source | Recon use | Access | Mechanism / format | OSS |
|---|---|---|---|---|
| **Have I Been Pwned (HIBP)** | Breached accounts; **domain search free for verified owners** | PAID API + FREE domain search (**OWN**) | REST; JSON | wrapped |
| **DeHashed** | Search by domain/email → leaked creds (hashes/plaintext) | PAID | REST; JSON | partial |
| **SpyCloud** | Recaptured breach + **botnet/infostealer** creds (ATO prevention) | ENT | REST; JSON | **GAP** |
| **Hudson Rock (Cavalier)** | **Infostealer-infected** creds; **free domain/email checks** | FREEMIUM | REST; JSON | partial — notable free tier |
| **Intelligence X (IntelX)** | Leaks/darkweb/pastes by selector | FREEMIUM→PAID | REST; JSON | partial |
| **LeakCheck / Snusbase / Scattered Secrets** | Breach-search APIs | PAID | REST; JSON | partial / **GAP** |
| **Flare / Constella / Enzoic** | Dark-web + leak monitoring | ENT | REST/portal | **GAP** |
| **Raw combolists / breach forums** | Direct dumps | — | — | ⚠️ legal/operational caution — generally avoid |

---

## 11. Third-party / supply-chain risk ratings & external posture
Outside-in ratings/posture on your org and vendors. Enterprise, and overlapping (see the SecurityScorecard comparison doc).

| Source | Recon use | Access | Mechanism / format | OSS |
|---|---|---|---|---|
| **SecurityScorecard** | A–F external posture, factors, vendor monitoring | ENT (limited self-score) | REST/portal; JSON | **GAP** |
| **BitSight** | External security ratings | ENT | REST/portal; JSON | **GAP** |
| **UpGuard** | Ratings + BreachSight exposure | PAID→ENT | REST/portal; JSON | **GAP** |
| **Panorays / RiskRecon / Black Kite / Prevalent** | Third-party risk platforms | ENT | REST/portal | **GAP** |

---

## 12. Malware / IOC / target-reputation lookup (domain/IP/URL-centric only)
Reputation and infrastructure pivots **for a specific target**. (Broad IOC-sharing feeds are out of scope.)

| Source | Recon use | Access | Mechanism / format | OSS |
|---|---|---|---|---|
| **VirusTotal** | Domain/IP/URL report: detections, pDNS, resolutions, siblings, related samples, certs, WHOIS | FREEMIUM (4/min, 500/day)→ENT | REST; JSON | wrapped — *rate/data gated* |
| **urlscan.io** | Submit/search URLs → screenshot, DOM, resources, related domains/IPs | FREEMIUM→PAID | REST; JSON | wrapped |
| **AbuseIPDB** | IP abuse score/reports | FREEMIUM | REST; JSON | wrapped |
| **abuse.ch** (URLhaus, ThreatFox, SSLBL, Feodo) | Lookups by domain/IP/URL/hash/cert-JA3 | FREE (REG for some) | REST + bulk; JSON/CSV | partial |
| **Pulsedive** | Indicator enrichment (domain/IP/URL): risk, related, pDNS | FREEMIUM→PAID | REST; JSON | wrapped |
| **AlienVault OTX** | Pulses/indicators related to a domain/IP | FREE (REG) | REST; JSON | wrapped |
| **Cisco Talos Intelligence** | Web reputation for IP/domain | FREE | Web (no official API) | **GAP** |
| **Google Safe Browsing / Web Risk** | Is a URL/domain flagged | FREE/PAID | REST; JSON | wrapped |
| **Silent Push / Validin** | Domain infrastructure pivoting (newer) | FREEMIUM→PAID | REST; JSON | partial / **GAP** |
| **Spamhaus / SURBL** | Domain/IP blocklist status | FREE (DNS, fair-use) | DNS queries | wrapped |
| **PhishTank** | Known phishing URLs | FREE | Bulk/REST | wrapped |
| **Cisco Umbrella Top 1M / Tranco / Majestic Million** | Is a domain popular/known (triage) | FREE | Bulk CSV | partial |

---

## Cross-cutting notes

- **Where OSS already exists** (Censys, Shodan, SecurityTrails, VT, Chaos, GreyNoise, HIBP, urlscan,
  Pulsedive, OTX), the client isn't the problem — **the paid tier / API key / rate limit is**. Budget and
  key management matter more than code.
- **The real `GAP` gold** (data-access is the only barrier, little/no tooling): **ICANN CZDS zone files**,
  **crt.sh direct Postgres**, **CT bulk `get-entries`**, **Shadowserver org reports**, **RIR/RouteViews/RIS
  bulk BGP**, **DNSDB**, **cloud IP-range + SAN attribution**, **Spur**, and **infostealer-cred feeds**.
- **Ownership-gated but free** and worth the paperwork: **Shadowserver** (your ASN/CIDR reports) and
  **HIBP domain search** (verified domains).
- **Vetted/affiliation, long lead time:** **CZDS** (per-TLD approval), **CIRCL pDNS**, **CAIDA/OpenINTEL**
  (academic). Apply early.
- **Rate limits are the operational wall** for this project (many sources throttle/deny after a handful of
  requests). Use `probe-datasource-limits.sh` to empirically derive per-source delay/timeout values before
  wiring a source into any batch fetcher.

## Suggested adoption order
1. **Free, access-is-the-only-barrier:** crt.sh (web + Postgres), CT logs/CertStream, cloud IP ranges,
   RDAP, RIR/RouteViews/RIS, Team Cymru, PeeringDB, bgpview, GreyNoise (free), OTX, urlscan, AbuseIPDB,
   abuse.ch, Chaos, VT (free key), HIBP domain search, Hudson Rock.
2. **Gated-but-free, start the paperwork now:** ICANN CZDS, Shadowserver, CIRCL pDNS.
3. **Paid, prioritized by the gap they close** (not breadth): DNSDB *or* SecurityTrails (pDNS/history),
   Spur (anonymization), one scan provider tier (Censys/Shodan/Netlas), a credential feed (DeHashed/SpyCloud).
4. **Enterprise, only if the program needs it:** Iris/WhoisXML (reverse-WHOIS at scale), Defender TI,
   third-party-rating platform.

*Compiled from external-recon data-source research. Verify every access model, price, rate limit, and
availability directly with the provider before integrating.*
