# EASM URL Enumeration Toolkit

Two scripts that stand up an OSS external-attack-surface URL-enumeration pipeline and run it against a list of domains you own, emitting a CSV that maps each seed domain to the URLs discovered on it.

```
setup-recon-env.sh   # native Linux (Kali/Debian/Fedora/Arch): install the toolchain
Setup-ReconEnv.ps1   # Windows: provision WSL2 + install the toolchain (run once)
run-recon.sh         # domains.txt -> results.csv  (+ optional side artifacts)
```

On Kali/Debian/Fedora/Arch run `sudo ./setup-recon-env.sh` (add `--include-heavy` for SecLists + nuclei-templates + feroxbuster); on Windows use `Setup-ReconEnv.ps1` as below. Both provision the same toolchain and install `run-recon.sh` as the `run-recon` command.

Tool versions are **pinned** (httpx 1.12.0, katana 1.8.0, tlsx 1.4.0, dnsx 1.3.1, nuclei 3.11.1, …), because run-recon parses their output and releases change it without notice. Each run logs the versions it found and warns when a core tool is not the lab-verified one. To upgrade on purpose: `RECON_TOOLS_LATEST=1 sudo ./setup-recon-env.sh --force`, then re-run the benchmark lab (§7). `TOOL-COVERAGE.md` lists every ProjectDiscovery tool, its status and the WebInventory parity gaps.

> **Authorization.** Only run this against assets your organization owns or is explicitly authorized to assess. The default mode sends live HTTP traffic to the targets (crawl + validation). Use `--passive-only` for zero target traffic.

---

## 1. Prerequisites

- Windows 10 build 19041 (2004) or later, or Windows 11.
- Administrator rights **for the first run only** (to install/enable the WSL feature). After WSL exists, provisioning needs no elevation.
- Internet egress from the WSL distro to: `go.dev`, `github.com`, `raw.githubusercontent.com`, PyPI, and the Ubuntu apt mirrors. (If you run behind an egress allow-list, permit those.)

---

## 2. Setup (Windows, once)

Keep both files in the **same folder** so the setup script can auto-install `run-recon.sh` into the distro.

```powershell
# from an ELEVATED PowerShell the first time
powershell -ExecutionPolicy Bypass -File .\Setup-ReconEnv.ps1

# full install incl. SecLists + nuclei-templates + feroxbuster
.\Setup-ReconEnv.ps1 -IncludeHeavyTools

# upgrade all tools to latest
.\Setup-ReconEnv.ps1 -Force
```

If WSL had to be installed, the script tells you to **reboot and re-run** — that is expected on first install. The script is idempotent; re-running is safe.

**What it installs** (system-wide under `/opt/recon`, binaries/shims on `PATH` via `/usr/local/bin`):

| Layer | Tools |
|---|---|
| Passive collection | `gau`, `waybackurls`, `waymore`, `urlfinder` |
| Crawling | `katana`, `gospider`, `hakrawler` |
| Probing / validation | `httpx-toolkit` (ProjectDiscovery httpx) |
| Port discovery | `naabu` |
| Content discovery | `ffuf`, `dirsearch`, (`feroxbuster` w/ heavy) |
| JS / endpoint analysis | `linkfinder`, `secretfinder`, `xnLinkFinder`, `jsluice`, `subjs`, `getJS` |
| Params / templated checks | `arjun`, `qsreplace`, `nuclei` |
| Subdomain / DNS context | `subfinder`, `amass`, `assetfinder`, `findomain`, `dnsx`, `alterx` |
| DNS bruteforce | `shuffledns`, `puredns`, `massdns` |
| Resolver validation | `dnsvalidator` |
| Code mining | `github-subdomains`, `github-endpoints` |
| Cloud storage | `cloud_enum` (S3/Azure/GCP) |
| CMS / app scanning | `wpscan`, `droopescan`, `joomscan`, `cmseek`, `whatweb`, `nuclei` (tech/cms) |
| Certificate / origin | `tlsx` (SAN + JARM), `cdncheck` |
| ASN / CIDR | `asnmap`, `mapcidr` |
| Internet-scan pivot | `uncover` |
| Takeover / triage | `subzy`, `gowitness` |
| Secrets | `trufflehog`, `secretfinder` |
| Monitoring | `notify` |
| Glue / normalize | `anew`, `unfurl`, `gf`, `uro` |
| Wordlists (heavy) | SecLists |

Python tools are installed into isolated virtual environments (pipx-managed venvs, plus dedicated `venv`s for LinkFinder/SecretFinder), each exposed via a wrapper on `PATH`.

Parameters: `-Distro` (default `Ubuntu`), `-InstallRoot` (default `/opt/recon`), `-IncludeHeavyTools`, `-SkipWslInstall` (provision an existing WSL/distro only), `-Force`.

---

## 3. Run (WSL2)

```bash
wsl -d Ubuntu

# one domain per line; '#' comments and blank lines are ignored.
# scheme prefixes and CRLF line endings are tolerated/stripped.
printf '%s\n' example.com api.example.com > domains.txt

run-recon -i domains.txt -o results.csv
```

### Modes & tuning

```bash
run-recon -i domains.txt --passive-only        # archives only; no traffic to targets (may be stale)
run-recon -i domains.txt --no-validate         # crawl, but skip per-URL httpx enrichment
run-recon -i domains.txt --subs                # subfinder + amass + assetfinder subdomain enrichment
run-recon -i domains.txt --deep                # also run waymore (broader, slower passive)
run-recon -i domains.txt -t 10 --rate 200      # 10 domains in parallel, 200 req/s where supported
run-recon -i domains.txt --crawl-depth 3       # deeper katana crawl
run-recon -i domains.txt --max-urls 20000      # raise the per-domain validation cap (default 5000)
run-recon -i domains.txt --no-filter-static    # keep image/font/css URLs (default: filtered)
run-recon -i domains.txt --keep-work           # retain intermediate artifacts for audit
run-recon -i domains.txt --db                   # cache crawl/OSINT + persist inventory (see §6; needs one-time setup)
run-recon -i domains.txt --no-report            # skip the end-of-run HTML report (see §6)
run-recon -h
```

### Discovery (host expansion — active; assets you are authorized to assess)

```bash
run-recon -i domains.txt --resolve             # dnsx: keep only resolving hosts; routes DNS via dedicated resolvers (Pi-hole bypass)
run-recon -i domains.txt --certs               # tlsx: harvest sibling hostnames from TLS certs (SAN/CN), pre-probe + live-host feedback loop
run-recon -i domains.txt --permute             # alterx: permute discovered subdomains (implies --resolve)
run-recon -i domains.txt --brute               # shuffledns/puredns + massdns: dictionary bruteforce vs the apex
run-recon -i domains.txt --ports               # naabu: find non-standard web ports before httpx
run-recon -i domains.txt --rounds 2            # recursive: re-enumerate newly discovered subdomains
run-recon -i domains.txt --favicon             # uncover: Shodan/Censys/Fofa pivot (needs API keys)
run-recon -i domains.txt --refresh-resolvers   # regenerate the resolver list with dnsvalidator (fresh, validated)
run-recon -i domains.txt --resolvers res.txt   # custom resolver list for the DNS-heavy stages

# ASN / CIDR seeds are auto-detected in the input file and cert-scanned into hostnames.
# ASN seeds need a free ProjectDiscovery Cloud key for asnmap (export PDCP_API_KEY=...,
# or run `asnmap -auth` once); IPv6 prefixes are skipped; RANGE_TLS_PORTS sets the ports.
printf '%s\n' AS13335 192.0.2.0/24 >> domains.txt
```

### Extra URL sources

```bash
run-recon -i domains.txt --crawlers-all        # add gospider + hakrawler (wider crawl than katana alone)
run-recon -i domains.txt --js                  # mine JS for endpoints (subjs/getJS -> xnLinkFinder); urlfinder auto-runs
run-recon -i domains.txt --github --github-token gh.txt   # mine GitHub code for subdomains + endpoints (token file, 1/line)
GITHUB_TOKEN=ghp_xxx run-recon -i domains.txt --github    # or supply the token via env
```

### Analysis / triage (side artifacts written next to the CSV — not URL rows)

```bash
run-recon -i domains.txt --takeover            # CNAMEs of every candidate, dangling targets, subzy/nuclei
                                               #   -> results.csv.takeover.txt + results.csv.cname.tsv
run-recon -i domains.txt --extras              # robots.txt (paths become URL rows), security.txt, one 404 probe,
                                               #   favicon hashes -> robots/security_txt/favicon_* columns + results.csv.extras.txt
run-recon -i domains.txt --zone-exposure       # each seed's DNS zone: AXFR on every name server, NSEC walk, NSEC3
                                               #   -> results.csv.zone.txt + results.csv.zone-names.txt (names feed the scan)
run-recon -i domains.txt --screenshots         # httpx -ss / gowitness, each capture validated -> screenshots-<ts>/
                                               #   + results.csv.screenshots.tsv (ok / blank / failed / suspect)
run-recon -i domains.txt --origin              # edge detection + origin search, verified directly
                                               #   -> results.csv.origin.txt (verified origins) + results.csv.edge.tsv
run-recon -i domains.txt --vhost               # ffuf Host-header bruteforce   -> new host rows
run-recon -i domains.txt --nuclei              # templated vuln/misconfig scan -> results.csv.nuclei.txt   [opt-in]
run-recon -i domains.txt --nuclei --interactsh-server https://oast.example.internal
                                               # nuclei callbacks to YOUR server (default: callbacks off)
run-recon -i domains.txt --params              # arjun hidden-parameter search -> results.csv.params.txt   [opt-in]
run-recon -i domains.txt --secrets             # secretfinder/trufflehog on JS -> results.csv.secrets.txt  [implies --js]
run-recon -i domains.txt --buckets             # cloud_enum S3/Azure/GCP storage -> results.csv.buckets.txt
run-recon -i domains.txt --active              # active CMS/app scan of live hosts -> results.csv.cms.txt
run-recon -i domains.txt --activescan          # thorough scan: feroxbuster/ffuf over SecLists + nuclei -> results.csv.activescan.txt
SECLISTS=/opt/recon/wordlists/SecLists run-recon -i d.txt --activescan   # point at a custom SecLists root
run-recon -i domains.txt --osint               # RDAP + Shodan InternetDB + Team Cymru ASN -> results.csv.osint.txt
VT_API_KEY=xxx run-recon -i d.txt --virustotal # VirusTotal passive DNS + reputation + subdomains
run-recon -i domains.txt --osint --urlscan     # add urlscan.io historical URLs/IPs (in --all: --osint only)
run-recon -i domains.txt --social              # social-media accounts for the org brand -> results.csv.social.txt
run-recon -i domains.txt --social-user acmecorp   # search a specific username instead of the domain-derived brand
WPSCAN_API_TOKEN=xxx run-recon -i d.txt --active   # add WPScan vuln-DB data (25 req/day on the free tier)
run-recon -i domains.txt --active --cms-wordlist plugins.txt   # custom plugin/theme slug list for the native brute
```

### Monitoring & umbrella

```bash
run-recon -i domains.txt --monitor                       # diff vs newest prior recon-*.csv -> results.csv.new-assets.txt
run-recon -i domains.txt --monitor --monitor-prev old.csv --notify   # diff vs a specific CSV, push via 'notify'
run-recon -i domains.txt --all                           # full discovery + defensive set (see below)
```

`--all` enables `--subs --resolve --certs --permute --brute --ports --js --crawlers-all --takeover --zone-exposure --screenshots --origin --extras --active --activescan --osint --tls --ipv6 --enrich`. The remaining scanning stages (`--nuclei`, `--params`, `--secrets`, `--buckets`) and `--favicon` / `--vhost` / `--virustotal` / `--urlscan` / `--social` / `--monitor` stay opt-in. `--enrich` fetches the cloud IP-range feeds and makes per-IP RDAP and reverse-DNS lookups (passive, no packets to targets; PTR lookups of non-public addresses go only to resolvers you pass with `--resolvers`); `geo` still needs `--geodb`.

### Pipeline (per seed domain)

0. **DNS zone exposure** (`--zone-exposure`, once per zone, before the per-seed workers) — finds each seed's zone (SOA) and its name servers (NS), tries a zone transfer (AXFR) on every one, walks the NSEC chain of a signed zone and records NSEC3 parameters. Only the zones' own name servers are queried. Names found under a seed join that seed's candidates; names outside every seed are listed, not scanned
1. **host discovery** — passive subs (`subfinder` + `amass` + `assetfinder` + `findomain`, recursive with `--rounds`), GitHub code mining (`github-subdomains`, `--github`), DNS bruteforce (`--brute`), permutations (`--permute`), pre-probe cert SANs (`--certs`), favicon pivot (`--favicon`)
2. **DNS validation gate** — `dnsx` drops non-resolving/wildcard hosts (`--resolve`), via dedicated resolvers
3. **passive URL collection** — `gau`, `waybackurls`, `urlfinder`, GitHub endpoints (`--github`), (`waymore` in `--deep`)
4. **strict scope filter** — keep a URL only if its host is the seed or a subdomain of it (drops CDNs, look-alikes, third parties)
5. **active** — port discovery (`naabu`, `--ports`) → live-host probe (`httpx`) → crawl (`katana`, plus `gospider`/`hakrawler` with `--crawlers-all`), JS mining (`--js`), content fuzz (`--fuzz`), vhost brute (`--vhost`)
6. **cert feedback loop** — `tlsx` on the live hosts harvests new sibling names, resolves them, feeds them back as host rows (`--certs`)
7. **per-URL enrichment** — `httpx -json` (status/length/server/title/tech)
8. **post-probe analysis** (side artifacts) — TLS posture and chain validation (`--tls`) / AAAA resolution (`--ipv6`) / takeover / screenshots (validated) / edge detection and origin verification (`--origin`) / nuclei / params / secrets / **active CMS scan (`--active`)** / **thorough active scan (`--activescan`)** / cloud buckets (`--buckets`)
9. **aggregate → CSV** — `python3` (robust quoting/escaping) joins per-URL enrichment, TLS posture, AAAA, and per-IP attribution (cloud/RDAP/geo with `--enrich`); then optional **monitoring diff** (`--monitor`)

Active stages (5–8) are skipped under `--passive-only`; enrichment (7) is skipped under `--no-validate`.

### Capability matrix

| Flag | Stage | Tool(s) | Output |
|---|---|---|---|
| `--subs` | passive subdomains | subfinder, amass, assetfinder, findomain | host rows |
| `--rounds N` | recursive discovery | (re-runs the above) | host rows |
| `--github` | code mining | github-subdomains, github-endpoints | host + URL rows (`github`) |
| `--brute` | DNS bruteforce | shuffledns/puredns + massdns | host rows (`bruteforce`) |
| `--refresh-resolvers` | resolver validation | dnsvalidator | fresh resolver list |
| `--permute` | permutations | alterx (+dnsx) | host rows (`alterx`) |
| `--certs` | cert SAN/CN + feedback loop | tlsx | host rows (`tlsx`, `tlsx-live`) |
| `--resolve` | DNS validation gate | dnsx | filters hosts |
| `--favicon` | internet-scan pivot: certificates naming the seed, then hosts sharing a live host's favicon (Shodan/Fofa mmh3, Censys MD5) | uncover, tlsx | host rows (`favicon`), `.favicon.txt`; hits become `--origin` candidates |
| ASN/CIDR seeds | range cert scan | asnmap, mapcidr, tlsx | seed hostnames |
| `--ports` | port discovery | naabu | host:port → httpx |
| `--crawlers-all` | extra crawl | gospider, hakrawler | URL rows |
| `--js` | JS endpoint mining | subjs/getJS, xnLinkFinder | URL rows (`js`) |
| (auto) | passive URLs | gau, waybackurls, urlfinder | URL rows |
| `--fuzz` | content discovery | feroxbuster/ffuf | URL rows |
| `--vhost` | vhost bruteforce | ffuf | host rows (`vhost`) |
| `--takeover` | dangling CNAME / takeover | dnsx (CNAMEs of every candidate) + subzy + nuclei `-tags takeover` | `.takeover.txt`, `.cname.tsv` |
| `--extras` | robots.txt, security.txt, 404 probe, favicon hashes | httpx `-path -irrb` (one pass) | URL rows (`robots`), cols `robots`, `security_txt`, `favicon_*`, `.extras.txt` |
| `--zone-exposure` | DNS zone exposure | dig: SOA/NS, AXFR per name server, NSEC walk, NSEC3PARAM | `.zone.txt`, `.zone-names.txt`; names join the candidates |
| `--screenshots` | visual triage | httpx -ss (browser routed like httpx) / gowitness | `screenshots-<ts>/`, `.screenshots.tsv` (status per host) |
| `--origin` | edge detection + origin search | httpx (headers, body hash, favicon), tlsx -jarm, cdncheck, dnsx (A+AAAA), dig (SPF/MX), curl `--resolve` | `.origin.txt` (verified, and protected origins), `.edge.tsv` |
| `--tls` | TLS posture | tlsx + chain validation (Python `ssl`, system trust store) | CSV cols `tls_version`..`tls_flags` (joined to https rows) |
| `--tls-full` | TLS + version/cipher enum | tlsx -version-enum -cipher-enum | adds `WeakTLS`/`WeakCipher` (noisier) |
| `--ipv6` | AAAA resolution | dnsx -aaaa | CSV col `ipv6` (`;`-joined v6 addrs per host) |
| `--enrich` | per-IP attribution | cloud IP-range feeds + RDAP + reverse DNS + MaxMind | CSV cols `cloud`, `rdap_org`, `ptr`, `geo` |
| `--geodb PATH` | geo country source | mmdblookup (libmaxminddb) | sets `geo`; implies `--enrich` |
| `--nuclei` | vuln/misconfig scan (callbacks off unless `--interactsh-server`) | nuclei | `.nuclei.txt` |
| `--params` | hidden parameters | arjun | `.params.txt` |
| `--secrets` | secrets in JS | secretfinder/trufflehog | `.secrets.txt` |
| `--buckets` | cloud storage | cloud_enum (S3/Azure/GCP) | `.buckets.txt` |
| `--active` | CMS/app scanning | wpscan/droopescan/joomscan/cmseek/whatweb + nuclei | `.cms.txt` |
| `--activescan` | thorough active scan | feroxbuster/ffuf over SecLists + nuclei | `.activescan.txt` |
| `--osint` | passive OSINT | RDAP + Shodan InternetDB + Team Cymru ASN | `.osint.txt` |
| `--virustotal` | passive DNS / reputation | VirusTotal domain report (`VT_API_KEY`) | `.virustotal.txt` |
| `--urlscan` | historical URLs/IPs | urlscan.io search | `.urlscan.txt` |
| `--social` | social-media accounts | tookie-osint (org brand) | `.social.txt` |
| `--monitor` | drift detection | (diff) + notify | `.new-assets.txt` |

---

## 4. Output CSV schema

`results.csv`:

| column | meaning |
|---|---|
| `seed_domain` | the input domain this URL was attributed to |
| `url` | discovered URL |
| `host` | hostname parsed from the URL |
| `sources` | which collectors found it (`gau;wayback;katana;waymore`) |
| `status_code` | httpx HTTP status (blank if not validated) |
| `content_length` | httpx response length |
| `webserver` | `Server` header |
| `title` | HTML `<title>` |
| `technologies` | httpx tech detection, `;`-joined |
| `ip` | the IP the host resolved to (from httpx's A record; blank if not validated) |
| `asn` | origin ASN of that IP, e.g. `AS15133` (Team Cymru; free, no key) |
| `asn_org` | ASN owner/org, e.g. `EDGECAST, US` or `AMAZON-02, US` |
| `tls_version` | negotiated TLS version (`--tls`), e.g. `TLS 1.3`; blank for http / non-TLS |
| `tls_cipher` | negotiated cipher (or the weak ciphers found with `--tls-full`) |
| `cert_not_after` | leaf certificate expiry (ISO 8601) |
| `cert_issuer` | certificate issuer org/CN |
| `tls_flags` | `;`-joined hygiene flags: `WeakTLS`, `WeakCipher`, `CertExpired`, `CertExpiring` (≤30 days, `CERT_WARN_DAYS`), `SelfSigned`, `CertNameMismatch`, `CertUntrusted` (the chain does not verify against the system trust store, or tlsx's list of bad CAs; `TLS_CHAIN_CHECK=0` turns the chain check off), `CertRevoked`, `Wildcard` |
| `ipv6` | AAAA records for the host (`--ipv6`), `;`-joined; blank if none / not resolved |
| `cloud` | cloud provider owning the IP (`--enrich`), by longest-prefix match against the published ranges: `AWS`, `GCP`, `Azure`, `Cloudflare`, `OracleCloud`, `DigitalOcean` |
| `rdap_org` | network/registrant org for the IP from RDAP (`--enrich`), e.g. `AMAZON-AES` |
| `geo` | ISO-3166 country code for the IP (`--enrich --geodb`), e.g. `US` |
| `cpe` | `;`-joined CPE 2.3 identifiers for the detected products (always on), e.g. `cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*` |
| `redirect_location` | the `Location` header of a redirect (always on; columns from here to `http_flags` come from the enrichment request's own headers and body, so they cost no extra request) |
| `response_ms` | response time of that request, in milliseconds |
| `body_sha256` | SHA-256 of the response body |
| `content_type` | media type of the response, e.g. `text/html` |
| `powered_by` | `X-Powered-By` header, e.g. `PHP/8.2.17` |
| `auth` | `WWW-Authenticate` scheme and realm, e.g. `Basic realm="Legacy VPN"` |
| `cookies` | names of the cookies the response sets (`;`-joined; values are never stored) |
| `cookie_issues` | cookies without `Secure` or `HttpOnly`, e.g. `wordpress_test_cookie:no-HttpOnly` |
| `missing_sec_headers` | for HTML responses: which of `Content-Security-Policy`, `X-Frame-Options` (satisfied by CSP `frame-ancestors`), `X-Content-Type-Options` and, on HTTPS, `Strict-Transport-Security` are absent |
| `hsts_max_age` | `max-age` of the HSTS header (HTTPS only) |
| `alt_svc` | `Alt-Svc` header (e.g. HTTP/3 advertised) |
| `http_flags` | `CleartextAuth` (Basic/Digest over plain HTTP), `PlainHttp` (an HTML page served on plain HTTP without a redirect) |
| `favicon_mmh3`, `favicon_md5` | the host's favicon hashes, Shodan-compatible mmh3 and MD5 (`--extras`, `--favicon` or `--origin`) |
| `ptr` | reverse DNS of `ip` (`--enrich`) |
| `robots` | robots.txt summary, e.g. `200 disallow=2 allow=0 sitemap=1` (`--extras`) |
| `security_txt` | `present contact=… expires=…`, `expired …`, `missing` (`--extras`) |

The `tls_*` columns are populated only for `https` rows when `--tls` is on (tlsx is matched to the row by
`host:port`, default 443). They mirror WebInventory's TLS posture flags, and the HTML report surfaces each
flag as a severity-rated finding on the owning host.

The `ipv6`/`cloud`/`rdap_org`/`geo` columns extend ownership validation to the network layer. `--ipv6` adds a
dnsx AAAA pass per live host. `--enrich` attributes each resolved IP: `cloud` is a longest-prefix match
against the providers' own published IP-range feeds (fetched once and cached under
`~/.cache/run-recon/cloud_ranges.tsv`, 7-day TTL; override with `RECON_CLOUD_CACHE`); `rdap_org` is the
network org from `rdap.org` (cached per IP in the DB like ASN, so repeat runs don't re-query); `geo` is the
country ISO code read from a **local** MaxMind DB via `mmdblookup`. Geo is pluggable because GeoLite2 needs a
(free) MaxMind account and EULA — pass the `.mmdb` with `--geodb /path/GeoLite2-Country.mmdb`; without it the
other three still populate and `geo` stays blank. Active IPv6 *probing* is intentionally not done here: it
depends on the runner having working IPv6 egress, and dead-on-v4-but-listed results would be misleading —
`ipv6` reports what resolves, which is the reliable signal.

The `cpe` column (always on) emits **CPE 2.3** identifiers for the products httpx detects — from the tech
list (Wappalyzer `Name:version`) and the `Server` header (`token/version`, trailing junk like `(Ubuntu)`
stripped) — through a curated, rule-based product→CPE table ported from WebInventory's approach. A known
version lands in the version field; an unknown one leaves it `*` (a product-only CPE). A few products that
NVD splits across vendor strings (nginx → both `f5:nginx` and `nginx:nginx`) emit both so a CVE under either
still correlates. Extend or correct the table without editing the script via `--cpe-map FILE` (a TSV of
`name<TAB>cpe:2.3:a:vendor:product`, `#` comments allowed), merged over the built-ins. These CPEs are the
input to the offline NVD/KEV/EPSS vulnerability join (`recon-db.sh vulns`, FPV-07; see §6). As always with banner-derived
CPEs: a distro that backports fixes keeps the upstream version string, so treat matches as a prioritized
worklist, not confirmed vulnerabilities.

The `ip`/`asn`/`asn_org` columns exist for **ownership validation**: after a run, confirm that live hosts
resolve into IPs and ASNs your organization actually controls. A quick check for anything *not* on your
expected ASNs (skipping the header and blank ASNs):

```bash
# list host + IP + ASN/org for anything NOT in your known ASNs (edit the grep -v list)
tail -n +2 results.csv | awk -F, 'NF>=12 && $11!=""' \
  | grep -vE ',AS(15133|16509|8075),' \
  | cut -d, -f3,10,11,12 | sort -u
```

Resolution is on by default (passive — DNS + Team Cymru, no packets to the target); pass `--no-asn` to skip
it, or raise `ASN_MAX` (default 2000) if you have more unique IPs than the per-run cap. Lookups are cached
per unique IP.

The CSV is written inside the distro. Open it from Windows via
`\\wsl.localhost\Ubuntu\home\<user>\results.csv` or write it under `/mnt/c/...`.

### Run record, exit status and side files

Every run writes `<out>.run.json`: run-recon version, the command line (proxy credentials replaced by
`***`), start time and duration, seed count and per-seed counts (candidates, resolved, live hosts), the
versions of httpx/katana/tlsx/dnsx, the resolvers and the result of their check, line counts of every side
artifact, all warnings, and the exit status. The HTML report's run header is built from it.

| Exit status | Meaning |
|---|---|
| `0` | the run finished with at least one URL row |
| `2` | bad arguments or input |
| `3` | the run finished with **no results** (0 URL rows). The log ends with "Finished with NO results" instead of "Complete.", and the report shows a banner |

The resolver preflight looks up the first seed, so a resolver that answers SERVFAIL or REFUSED for it is
reported as failed (not "passed"), and an NXDOMAIN seed is called out. Each seed also gets a warning when
none of its candidate names resolves, or when no name answers the live probe.

Side files next to the CSV, by flag: `.takeover.txt` + `.cname.tsv` (`--takeover`), `.zone.txt` +
`.zone-names.txt` (`--zone-exposure`), `.origin.txt` + `.edge.tsv` (`--origin`), `.extras.txt` (`--extras`),
`.favicon.txt` (`--favicon`), `.screenshots.tsv` +
`screenshots-<ts>/` (`--screenshots`), `.nuclei.txt`, `.params.txt`, `.secrets.txt`, `.buckets.txt`,
`.cms.txt`, `.activescan.txt`, `.osint.txt`, `.virustotal.txt`, `.urlscan.txt`, `.social.txt`,
`.new-assets.txt`, `.run.json` (always) and `.report.html`.

**Zone exposure findings** (`.zone.txt`, one line per zone):

| Finding | Meaning |
|---|---|
| `zone-transfer-open [high]` | a name server hands the whole zone to anyone (AXFR); one line per open server |
| `nsec-zone-walkable [medium]` | the zone is signed with NSEC, so following the chain lists every name (capped at `ZONE_WALK_MAX`, default 5000) |
| `nsec3-hashes-exposed [low]` | NSEC3: hashed names can be collected and cracked offline; the parameters (iterations, salt, opt-out) are recorded, nothing is cracked |
| `dnssec-unanchored [low]` | the zone is signed but its parent publishes no DS record, so validating resolvers cannot check the signatures |
| `zone-checked [info]` | none of the above: evidence that the check ran (signed or not, transfers refused on n/n servers, `ds=yes/no` when signed, `unreachable=N` for addresses that never answered) |

Every address of every name server is tried, IPv4 and IPv6, and the NSEC walk moves on to the next name
server when one gives no chain (a lame or unreachable server no longer hides a walkable zone).

**Extras findings** (`.extras.txt`, `--extras`). One `httpx -path` pass per seed requests the root page,
`/favicon.ico`, `/robots.txt`, `/.well-known/security.txt` (then `/security.txt`) and one random path on every
live root, as WebInventory's "safe extras" do. robots.txt `Disallow`/`Allow` paths (without wildcards) and
sitemaps become URL rows with source `robots`, so they are probed and enriched like crawled URLs. The favicon
is the icon the root page declares (`<link rel="icon">`; an inline `data:` icon is decoded, one at another
path on the same host is fetched in a single follow-up run), else `/favicon.ico`; an HTML page served as
`/favicon.ico` does not count. Its Shodan-compatible mmh3 and MD5 are computed from the bytes, so
`--extras --favicon` pivots on them without another request.

| Finding | Meaning |
|---|---|
| `security-txt-expired [low]` | security.txt exists but its `Expires` date has passed (RFC 9116) |
| `security-txt-invalid [low]` | security.txt has no `Expires` field |
| `catch-all-200 [info]` | the random path answered 200: every crawled or fuzzed path on this host looks real (soft 404) |
| `error-page [info]` | status, Server header and title of the 404 page; `reveals=` names a server version the page shows and the Server header does not |

A missing security.txt is recorded in the `security_txt` column, not as a finding. Cost: one short httpx
run per seed (about 0.85 s of CPU, mostly start-up; v1.19 needed two), plus one only for hosts whose icon
lives elsewhere (`BENCHMARK.md`).

**Origin findings** (`.origin.txt`). For each live host, `--origin` records the edge in `.edge.tsv`
(several `Server` headers such as `Caddy, nginx/1.21.6`, `Via`, CDN headers such as `cf-ray`, the cdncheck
tag, JARM, favicon mmh3, title). A lone `Server` header names the edge only for products that exist to sit
in front of origins (Cloudflare, Akamai, CloudFront, Sucuri, Imperva, Fastly, AWS ELB, BIG-IP, DDoS-Guard,
Edgecast); a general web server such as Caddy or HAProxy alone proves nothing (behind one, the origin still
shows as a second `Server` value). It then collects candidate origin addresses:

| Source (`via=`) | Addresses |
|---|---|
| `direct.`/`origin.`/`backend.`/`origin-` names | their A **and AAAA** records |
| `spf` | the seed's SPF `ip4:`/`ip6:` entries (ranges up to 16 addresses), following `include:` and `redirect=` (depth 3, at most 10 lookups, as RFC 7208 allows) |
| `mx` | the seed's MX hosts |
| `range-cert` | in ASN/CIDR seed mode, addresses in your ranges whose certificate names the site |
| `history:virustotal`, `history:urlscan` | past A/AAAA records from VirusTotal (`--virustotal`) and addresses urlscan.io saw the site on (`--urlscan`) |
| `favicon` | hosts sharing the site's favicon (`--favicon`) |
| `zone` | names from `--zone-exposure` |

Each candidate gets the site's own request on every port in `ORIGIN_PORTS` (default `443 80`; 80, 8080,
8000, 8008 and 8888 over plain HTTP), sent straight to it with `curl --resolve host:port:ip` (so the Host
header and SNI carry the site's name), and the answer is compared with the edge's: body SHA-256, then
title + length, then title alone. Matches are reported, and so is an origin-style name whose address does
not serve the site:

| Finding | Meaning |
|---|---|
| `origin-exposed [high]` | the site behind a detected edge answers directly at this address: the edge's protections can be bypassed |
| `origin-alternate [low]` | no edge detected, and the same site is also served at this address |
| `origin-candidate [low]` | same title, different body: verify by hand |
| `origin-protected [info]` | a `direct.`/`origin.`/`backend.` name exists, but its address does not serve the site (`reason=` per port: `refused`, `timeout`, `tls-refused`, `reset`, `status-403-other-content`...): the origin is there and locked down. Not reported when another address of the same site was found |

At most `ORIGIN_MAX_CHECKS` (default 200) host/address pairs are tried per seed. With `--proxy`, the
comparison request goes through httpx and the proxy instead.

**Screenshots** (`.screenshots.tsv`: host, file, status, reason, bytes). httpx's headless Chrome does not
use httpx's `-r` or `-proxy`, and it ignores `NO_PROXY`: names meant to be reached directly went to the
proxy, and the "screenshot" was the proxy's error page. run-recon now passes the browser `--proxy-server`
(from `--proxy`) and a `--proxy-bypass-list` built from `NO_PROXY`, and uses an installed Chrome or
Chromium. The browser also resolves names with the system resolver, not `--resolvers`: with `--resolvers`,
it gets `--host-resolver-rules` mapping each host to the address your resolvers gave, so a name only they
know (split horizon, the lab) renders, and renders the host httpx probed. Each capture is then checked:
`ok`; `blank` (the page itself is empty); `failed` (no image, or an empty image of a page with content);
`suspect` (the browser rendered a different title than the probe saw, or the image is identical to that of
a host with a different page). The report never shows a failed or blank capture as a screenshot, and marks
suspect ones.

Without httpx (or with `SCREENSHOT_TOOL=gowitness`), gowitness 3 takes the captures: explicit
`https://host:443` and `http://host:80` URLs (a bare name would be shot four ways), the go-rod driver (the
default chromedp driver timed out taking screenshots under concurrency in the lab), and its JSON lines as
the evidence for each capture; one capture is kept per host, https first. Its browser takes the
environment proxy and `NO_PROXY` itself but has no equivalent of `--host-resolver-rules`.

---

## 5. Continuous monitoring (drift detection)

The point of EASM is *change over time*, not a one-shot snapshot. The pipeline has drift detection built in — `--monitor` diffs the current run's URLs against a prior CSV and writes only the new ones:

```bash
# nightly via cron; --monitor auto-diffs against the newest earlier recon-*.csv in the out-dir
0 3 * * *  /usr/local/bin/run-recon -i /home/me/domains.txt -D /home/me/recon-runs --monitor --notify >> /home/me/recon.log 2>&1
```

`--monitor` writes `results.csv.new-assets.txt`; add `--notify` to push that list through ProjectDiscovery `notify` (Slack/Discord/webhook, configured in `~/.config/notify/`). Point at a specific baseline with `--monitor-prev old.csv`.

Feed the validated URL set straight into templated scanning (or just use `--nuclei`):

```bash
cut -d, -f2 results.csv | tail -n +2 | httpx -silent | nuclei -t ~/nuclei-templates/
```

---

## 6. HTML report & database cache

### HTML report (on by default)

At the end of every run, `run-recon.sh` builds a single self-contained
`<out>.report.html` next to the CSV. It ties together everything gathered about
each host — the CSV inventory (IP / ASN / org / status / tech), the findings
from the side-artifact files, and screenshots — and highlights
vulnerabilities, weaknesses and misconfigurations up front:

- a **run header** from `<out>.run.json` (version, command line, start and duration, tool versions,
  resolvers and their check, exit status, the run's warnings), and a **banner** when the run produced no
  results;
- a **summary dashboard** (seeds, names, live hosts, finding counts by severity, top networks, the DNS
  zones checked, and — when a vuln join is present — **KEV** and **Known CVE** counts);
- a **Findings table** (nuclei results, subdomain takeovers, DNS zone exposure, exposed origins, exposed
  secrets and buckets, TLS findings, and **known CVEs from the vuln join**) ordered most-severe-first, each
  linked to the host it affects. Certificate expiry is graded by days left at the time of the run: expired
  = High, under 7 days = Medium, under 30 days = Low. Without a vuln join the report says
  **"Known vulnerabilities: not checked"** and lists the versioned CPEs that would be checked, and apart
  from them the CPEs with no version (the product was identified, its version was not, so no CVE match);
- a **name inventory**: every name seen, live or not, with its DNS state (resolves, dangling CNAME,
  zone record, seed that does not resolve), HTTP status and CNAME; aliases are listed under their target;
- **per-host cards** with the page title, IP and IPv6, ASN and network, server, edge → origin software →
  verified origin, JARM and favicon hash, certificate issuer and days left, CNAME chain and aliases,
  technologies and CPEs, the screenshot (or why there is none), all findings tied to the host, and a sample
  of its URLs. Names that are not live but have a finding (a dangling CNAME) get a card too;
- a footer linking the raw artifact files.

**Vulnerability findings.** If a vuln join exists next to the CSV (`<csv>.vulns.csv`, from
`recon-db.sh vulns` — see §6's database section), the report folds each CVE in as a severity-rated finding on
the owning host: **KEV entries are rated Critical** (actively exploited), otherwise the CVSS severity/score
sets the level, bumped to at least High when EPSS shows a high real-world exploit probability (≥ 0.5). Each
finding line shows the CVE, CVSS, EPSS, a `KEV`/`KEV/ransomware` flag, the match confidence and a short
description. The join CSV is auto-detected; override with `--vulns FILE`.

```bash
run-recon -i domains.txt -o results.csv --screenshots --nuclei --takeover --osint
# -> results.csv.report.html   (open in a browser)

# suppress it:
run-recon -i domains.txt -o results.csv --no-report

# or generate one after the fact from an existing run's files:
./generate-report.sh -o report.html results.csv

# ...including the offline vuln join as KEV/CVSS/EPSS findings:
./recon-db.sh vulns results.csv --nvd-feed ./nvd --kev-file kev.json --epss-file epss.csv.gz
./generate-report.sh results.csv      # auto-detects results.csv.vulns.csv
```

Automated severities are heuristic — always review findings manually. The
generator needs `python3`; it lives next to `run-recon.sh` and is invoked
automatically, so keep the two together.

### PostgreSQL cache/store (`--db`, reuses Kali's Metasploit Postgres)

`--db` turns on a cache/store backed by the PostgreSQL service Kali already runs
for Metasploit (`msfdb`). It creates a **separate `recon` database** on that same
service and uses it to:

- **skip re-crawling** — the passive-URL set per domain (gau / waybackurls /
  waymore / urlfinder) and the subdomain-enum union (subfinder / amass /
  assetfinder / findomain) are cached, so repeat runs don't re-hit
  Wayback / CommonCrawl / OTX or the ~30 subfinder sources;
- **skip re-probing the targets** — the active HTTP/TLS stages are cached per
  URL or per host, which is usually the bulk of a re-run's outbound traffic:
  httpx per-URL enrichment (status/title/tech/webserver/IP, keyed by URL), the
  httpx live-host probe, naabu open ports, the katana crawl, and tlsx JARM are
  all reused within `CACHE_TTL`. Screenshots are cached as the **image bytes**
  per host, so a cached host still shows a real screenshot in the report without
  re-rendering. Each stage only re-runs the tool on the keys that miss the cache,
  and dead keys are negative-cached; a stage that times out is *not* cached (so a
  partial result never poisons the next run);
- **stop hammering API providers** — RDAP, Shodan InternetDB, VirusTotal,
  urlscan.io, GitHub (subdomains/endpoints), wpscan, cloud_enum and per-IP
  Team Cymru ASN are all cached per key;
- **persist each run's host inventory** into `recon_hosts` for later reference.

> **Freshness vs. traffic.** Caching the active probes means a re-run reuses the
> last status code / title / screenshot for up to `CACHE_TTL` (default 7 days).
> For change-detection runs, lower `CACHE_TTL` (or purge) to force fresh probing.
> The screenshot byte-cache trades DB space for skipped renders — it can grow to
> hundreds of MB on large runs; `./recon-db.sh purge N` drops old rows.

Alongside the cache, three **fail-fast** mechanisms cut the timeouts that bite on
a cold run (where the cache is empty):

- a **per-source circuit breaker** — after `CB_THRESHOLD` timeouts (default 3) a
  source is skipped for the rest of the run, so one slow provider can't cost you
  N×timeout across every seed;
- **negative caching** — confirmed-empty lookups are remembered for `NEG_TTL`
  (default 1 day) so dead keys aren't re-queried (and don't re-eat the timeout);
- **Retry-After awareness** — OSINT calls use curl `--retry`, honoring a 429/503
  `Retry-After` instead of blindly timing out; and the most rate-limited sources
  (GitHub / wpscan / VirusTotal) are serialized across workers.

Two more timeout levers, independent of the DB:

- `run-recon --dns-cache`'s companion — `setup-recon-env.sh --dns-cache` sets up a
  local **unbound** caching resolver and a resolvers file; point the DNS-heavy
  stages at it with `--resolvers /opt/recon/resolvers.txt` so they dedupe DNS
  transparently and local hits never time out;
- `run-recon --proxy http://127.0.0.1:3128` routes the GET-heavy stages
  (curl / whatweb / gau / httpx) through a caching HTTP(S) proxy you run
  (e.g. a squid with SSL-bump, or mitmproxy). The installer does **not** bundle
  one — an HTTPS-intercepting cache needs a CA install and is too invasive to set
  up by default — so run your own and pass its URL.

Tunable via env: `CACHE_TTL` (positive-cache TTL), `NEG_TTL` (negative-cache TTL),
`CB_THRESHOLD` (breaker), `BRUTE_MAX` (cap the `--brute` wordlist).

Everything is **fail-soft**: if psql or the DB is unavailable, the run simply
proceeds uncached (with a warning) — `--db` never breaks a run.

**Setup is automatic:** `setup-recon-env.sh` installs `recon-db.sh` (and
`generate-report.sh`) next to `run-recon.sh` and runs `recon-db.sh init` for you
(pass `--no-db` to skip). `init` sets up the store by method order:

1. **Primary — a dedicated `recon` role + database on the local PostgreSQL,**
   provisioned the same way `msfdb` provisions Metasploit's own: create a login
   role *with a random password*, grant it `CREATEDB`, then create a UTF-8
   database (from `template0`) owned by it, connecting as the role over
   `127.0.0.1`. This uses password auth over TCP, so it does **not** depend on
   `pg_hba.conf` peer/ident, and it's completely independent of Metasploit. It
   needs the postgres superuser (`sudo -u postgres`) once to create the role/db.
2. **Backup — reuse Metasploit's msfdb credentials** from `database.yml`
   (default `/usr/share/metasploit-framework/config/database.yml`, then
   `~/.msf4/database.yml`; runs `msfdb init` if needed). It tries a separate
   `recon` database and, if that can't be reached (e.g. msfdb's `pg_hba.conf`
   only authorizes `msf` for the `msf` database), stores the namespaced
   `recon_cache` / `recon_hosts` tables **in the `msf` database itself** (no
   collision with Metasploit's tables).
3. **Otherwise** it reports and exits non-zero, and run-recon simply runs
   without the cache.

The resolved connection (including the password) is saved to
`~/.config/recon/db.env` (chmod 600) and auto-loaded.

```bash
sudo ./recon-db.sh init          # provisions the dedicated recon DB (or falls back to msfdb)
```

You can override everything with standard libpq env vars (`PGHOST` / `PGUSER` /
`PGPASSWORD` / …) or `RECON_DB_DSN`; tune the dedicated role/endpoint with
`RECON_DB_USER` / `RECON_DB_NAME` / `RECON_DB_HOST` / `RECON_DB_PORT`, or point
`MSF_DB_YML` at a different `database.yml`.

**Use it:**

```bash
run-recon -i domains.txt -o results.csv --osint --db
CACHE_TTL=86400 run-recon -i domains.txt -o results.csv --db   # 1-day freshness (default 7 days)
```

**Inspect / maintain the store directly:**

```bash
./recon-db.sh stats             # cache + host row counts, sources, runs stored
./recon-db.sh hosts admin       # stored hosts matching a pattern (across ALL runs)
./recon-db.sh latest admin      # current state: newest run wins per URL (older data kept)
./recon-db.sh import ./old-runs # import historic run CSVs (a dir or files), oldest first
./recon-db.sh vulns out.csv --nvd-feed ./nvd --kev-file kev.json --epss-file epss.csv.gz
./recon-db.sh clean ./out --dry-run  # preview pruning blank intermediate files (keeps report data)
./recon-db.sh fix-collation     # rebuild indexes + refresh collation after a glibc upgrade
./recon-db.sh purge 30          # drop cache rows older than 30 days
```

**Data retention — pruning blank files (`clean`).** A normal run is already tidy: the workspace tree is
deleted at the end, and empty side-artifacts (`<csv>.nuclei.txt` etc. for stages that found nothing) are
removed. But a `--keep-work` run keeps the whole `_work-*` tree — per-domain `raw/<host>/` dirs (dozens of
intermediate files each, many empty), empty `done/<host>` markers, and empty `parts/` files — which over many
domains is thousands of blank files. `clean` prunes them:

```bash
./recon-db.sh clean ./results-dir            # prune zero-byte / whitespace-only files, remove emptied dirs
./recon-db.sh clean ./results-dir --dry-run  # preview first (lists every file it would remove)
./recon-db.sh clean run.csv --rows           # also write run.cleaned.csv with blank (no host/url) rows dropped
```

It walks each path, removes zero-byte and whitespace-only files, and deletes directories left empty — but it
**never touches the data a report needs**: `.csv`, `.html`, `.json` (provenance) and screenshot images
(`.png/.jpg/...`) are preserved regardless of size, and any non-empty file is kept. `--dry-run` shows exactly
what would go without deleting anything; `--rows` additionally writes a `<csv>.cleaned.csv` with fully-blank
data rows (no host and no URL) dropped, leaving the original CSV untouched. It needs no database, so it runs
on any output tree or archived run. A good retention habit: `--keep-work` for the run you're debugging, then
`clean` once you've pulled what you need.

**Collation version mismatch (after a glibc upgrade).** On a rolling distro like
Kali, an `apt upgrade` that bumps glibc leaves Postgres warning that the `recon`
database `has a collation version mismatch` — the collation version recorded when
the DB was created no longer matches the OS library. Your data is intact (it's a
warning, not corruption), but text-index sort order can go subtly stale. `init`
now detects this up front and points you at the one-step fix:

```bash
./recon-db.sh fix-collation     # REINDEX DATABASE, then ALTER DATABASE … REFRESH COLLATION VERSION
```

It runs as the `recon` DB owner (no `sudo` in the common dedicated-DB case) and
falls back to the postgres superuser when needed (e.g. tables living in the `msf`
database). It reindexes **before** refreshing — refreshing alone silences the
warning but leaves stale indexes. If the warning persists afterward it's coming
from a shared catalog (`template1`/`postgres`/`msf`, all created under the old
glibc); the command prints a loop to refresh every database at once. Expect this
to recur each time Kali rolls glibc forward.

**Importing historic runs.** `import` loads a backlog of past run CSVs into
`recon_hosts`. Each file becomes its own run — the `run_ts` comes from a
`recon-<TS>.csv` filename, or the file's mtime otherwise — and files are loaded
**oldest first**. Columns are matched by header **name**, so older/narrower exports
(before the enrichment or IP/ASN columns existed) still load, with any missing
columns left empty. Nothing is overwritten destructively: every run's rows are kept
(query the full history with `hosts`), and the **newest run wins per URL** in the
`latest` current-state view. Re-importing the same file is a no-op (existing
`(run_ts, url)` rows are left intact).

```bash
./recon-db.sh import /archive/recon-*.csv        # explicit files
./recon-db.sh import /archive/2025 /archive/2026 # scan directories for *.csv
./recon-db.sh latest                             # newest-per-URL across everything
```

**Offline vulnerability join (`vulns`, FPV-07).** `vulns` correlates a run CSV's
`cpe` column with NVD, CISA KEV and FIRST EPSS data **you download yourself** —
nothing is fetched and nothing is sent to any target, so it's safe to run against a
results file from an authorized scan. It needs no database.

```bash
# one-time: download the feeds (NVD CVE JSON 2.0 per year + modified, KEV, EPSS)
#   https://nvd.nist.gov/vuln/data-feeds   (nvdcve-2.0-YYYY.json.gz + nvdcve-2.0-modified.json.gz -> ./nvd/)
#   https://www.cisa.gov/.../known_exploited_vulnerabilities.json
#   https://epss.cyentia.com/epss_scores-current.csv.gz
./recon-db.sh vulns results.csv --nvd-feed ./nvd --kev-file kev.json --epss-file epss.csv.gz
# -> results.vulns.csv (+ results.vulns.csv.provenance.json);  -o overrides the output path
```

Output is **one row per service and CVE** — `host, ip, port, url, status_code,
products, cpe, cve, kev, kev_date_added, kev_due_date, kev_ransomware, epss,
epss_percentile, cvss_score, cvss_severity, cvss_version, published, match,
description` — sorted **KEV first, then EPSS, then CVSS**. The `match` column records
how sure the row is (ported from WebInventory): `version` / `range` (the service's
version is in scope), `all-versions` (NVD names the product with no version limit),
`… (platform not verified)` (the CVE needs an AND platform — e.g. a specific OS — that
these CPEs can't confirm), and `product-only` (the service exposed no version; listed
**only** for KEV CVEs, to keep the noise down). Matching is version-aware: numeric
compare including the CPE update field (`9.3:p1` matches a service reporting `9.3p1`),
`versionStart*/End*` ranges, pre-release ordering (`1.0rc1` < `1.0`), and `2.4` == `2.4.0`;
when a CVE appears in both a yearly feed and the modified feed, the **newest record
wins**, and Rejected CVEs are skipped. A `.provenance.json` sidecar records each feed's
file name, SHA-256 and record count, the KEV catalog version and the EPSS model
version and score date, so a report ties back to exactly the data behind it. These are
**banner-derived** matches — a distro that backports a fix keeps the upstream version
string — so treat the output as a prioritized worklist, confirmed with an authenticated
scanner (Qualys/Tenable), not as proof of exposure.

Both the primary (dedicated `recon` role) and the backup (msfdb's role) connect
with **password auth over `127.0.0.1`**, so neither depends on `pg_hba.conf`
peer/ident. The one thing that can still block the *primary* is a locked-down
`pg_hba.conf` with no `host … 127.0.0.1/32 …` rule for the new role — in which
case `init` automatically falls through to the msfdb backup.

---

## 7. Benchmark & regression lab

`bench-run-recon.sh` + `lab/` are a container test range and a benchmark harness built on
WebInventory's regression lab and `PERFORMANCE.md`, so the two tools can be compared on the same
services. The range is WebInventory's farm mix at **pinned** versions: nginx 1.21.6, WordPress
6.4.3 on Apache/PHP, a 120 KB single-page app and Jenkins 2.426.1. It runs behind a Caddy TLS
ingress, with lab DNS for RFC 6761 `.test` names, and binds to loopback only. `lab/expected.csv`
holds the status, technologies, CPEs, TLS flags and IPv6 addresses run-recon must report. Run it on
a host you own, never against anything else.

```bash
./bench-run-recon.sh up --farm 50                        # lab + 50-vhost farm; installs WordPress, waits for Jenkins
sudo sh -c './bench-run-recon.sh hosts >> /etc/hosts'    # once: names for tools that use the system resolver
./bench-run-recon.sh bench --runs 3 --flags "--tls --ipv6"                 # medians + accuracy vs expected.csv
./bench-run-recon.sh bench --runs 3 --farm --flags "--tls --ipv6 -t 10"    # load
./bench-run-recon.sh bench --runs 3 --flags "--tls --ipv6" --baseline-script old/run-recon.sh   # A/B two versions
./bench-run-recon.sh compare run-a.csv run-b.csv --exact # field-by-field identity
./bench-run-recon.sh checks                              # takeover, zone and origin fixtures, end to end
./bench-run-recon.sh down
```

The method is WebInventory's: 3 runs, medians, CPU of the whole process tree, every run scored
against ground truth, leave-one-out A/B, and a change is kept only if it is **faster and produces
field-for-field identical output**. Measured on a 2 vCPU VM with the real toolchain (details and
the full checklist in `BENCHMARK.md`):

| scenario | v1.15.2 | v1.16.0 | accuracy v1.15.2 → v1.16 |
|---|---:|---:|---|
| lab (4 seeds) | 70.2 s | 23.3 s (3.0x) | lost the Jenkins seed in 2 of 12 runs → every run correct |
| farm (50 seeds, `-t 5`) | 363.1 s | 156.5 s (2.3x) | lost one host's TLS posture → correct |
| farm, `-t 10` | | 92.3 s (1.7x vs `-t 5`) | 3/3, output identical to `-t 5` |
| lab, `--db` warm | | 2.6 s (9.8x vs cold) | 3/3, output identical to cold |

**v1.18.0** (details in `BENCHMARK.md`): the default path is as fast as v1.17.0 and its output is identical
except for dropped crawl junk (`…/%5C/…` URLs); `--tls` now validates certificate chains, which costs about
2 s on the 50-seed farm (`TLS_CHAIN_CHECK=0` to skip). `./bench-run-recon.sh checks` runs the takeover, zone
and origin fixtures end to end.

**v1.19.0** (Batch 2): the 17 HTTP columns come from the request the enrichment pass already sends, so
the default path stays as fast as v1.18.0 and every existing column is identical (lab and farm).
`./bench-run-recon.sh checks` now also runs the `http` fixtures.

The v1.16 speed-up is from not querying internet archives for special-use names such as `.test`,
which cannot exist there. The lab also exposed nine accuracy bugs, all fixed in v1.16 (listed in
`BENCHMARK.md`), including hosts blanked under heavy load (`-t 20`), now recovered by a
late retry. `lab/README.md` covers ports, DNS and proxies.

---

## 8. Caveats & notes

- **Progress & wall-clock guards.** Each pipeline phase prints a stage marker with elapsed time (e.g. `> content discovery (--fuzz) [example.com 00:03:12]`), a heartbeat every `HEARTBEAT`s shows overall progress (`... running 01:20:00 (2/5 domains complete)`), and each domain reports `done (N urls, HH:MM:SS)`. Suppress with `--no-progress`. Because the per-request `-timeout` flags on the underlying tools do **not** bound total runtime, every stage also runs under a wall-clock cap so a slow source, a huge SecLists wordlist, or a recursive `feroxbuster` can't hang the run for hours. Defaults (seconds, env-overridable; `0` disables): `STAGE_TIMEOUT=900`, `PASSIVE_TIMEOUT=600`, `BRUTE_TIMEOUT=1800`, `FUZZ_TIMEOUT=1800`, `SCAN_TIMEOUT=2400`. `--activescan`/`--all` are the most likely to hit these — raise `FUZZ_TIMEOUT`/`SCAN_TIMEOUT` for a thorough long run, lower them for a quick pass.
- **Takeover check, callbacks and stdin (v1.17).** `--takeover` now looks up the CNAME of every candidate name, including names that no longer resolve (a dangling CNAME returns NXDOMAIN, so the old live-hosts-only check missed exactly those). Dangling targets are graded `[high]` for takeover-prone services and `[medium]` otherwise; subzy and nuclei then fingerprint every name that has a CNAME. nuclei never calls public interactsh servers unless you set `NUCLEI_OAST=public`. katana now uses `--resolvers` and `--proxy` like the other tools (v1.16 crawled through the system resolver and straight past a jump-host proxy). run-recon closes its stdin at start-up, because tlsx, katana and `mapcidr -aggregate` read stdin even when given a file, and the ASN/CIDR stage could otherwise wait forever when started from CI or `ssh host run-recon` without a terminal. Text cells in the CSV that start with `= + - @` get a leading apostrophe (formula-injection guard); the report and the DB import remove it.
- **Load, retries and thread count.** httpx retries a failed request twice (`HTTP_RETRIES=2`), and URLs or TLS hosts that still return nothing get one more pass after a short pause (`LATE_RETRY=1`). Neither costs anything when nothing fails. Those failures are never negative-cached under `--db`, so a blip is retried on the next run instead of staying blank for `NEG_TTL`. On a 2 vCPU box, `-t 10` was 1.7x faster than the default `-t 5` with identical output. `-t 20` lost 1–3 hosts per run until the late retry was added. Raise `-t` for internal or lab seeds. On public seeds, more workers also means more parallel archive and API queries, so watch for HTTP 429 before raising it. Internal IPs are never sent to Team Cymru, RDAP or InternetDB. Special-use names (`.test`, `.internal`, `.local`, `.home.arpa`, …) skip internet archives and subdomain APIs; set `SKIP_SPECIAL_USE=0` to query them anyway.
- **OSINT enrichment is passive and mostly key- and `jq`-gated.** `--osint`/`--virustotal`/`--urlscan` query third-party APIs *about* your domains/IPs — no packets to the target — so they run even under `--passive-only` and are safe by default. `--osint` is free and needs no key (RDAP + Shodan InternetDB + Team Cymru); `--virustotal` needs `VT_API_KEY` (free tier ~4 req/min, 500/day) and `--urlscan` takes an optional `URLSCAN_API_KEY`. All parse JSON with **`jq`** (a base package the installer provides) — without `jq` the RDAP/InternetDB/VT/urlscan lookups are skipped (the awk-based Team Cymru ASN still runs). The much larger menu of external OSINT sources — passive-DNS bulk, zone-file programs, breach providers, third-party ratings, paid scan tiers — is catalogued in `DATA-SOURCES.md`; most need custom fetchers, and the biggest quick win is pasting API keys into the scaffolded `subfinder` provider config to unlock Censys/Shodan/VirusTotal/SecurityTrails/etc. for passive subdomain discovery.
- **Passive ≠ live.** Archived URLs frequently 404; that's why the default mode re-validates with `httpx`. Conversely, stale archive hits are valuable — forgotten admin panels / deprecated APIs that may still be reachable.
- **`httpx` means ProjectDiscovery httpx, invoked as `httpx-toolkit`.** Two unrelated tools share the name `httpx`: PD's Go toolkit (what this pipeline needs — it fills the `status_code`/`title`/`technologies` columns) and the Python `httpx` HTTP client, which owns `/usr/bin/httpx` on Kali. To avoid the collision, run-recon calls the binary **`httpx-toolkit`** by default (the name Kali's `apt install httpx-toolkit` uses; the installer also exposes its go-installed PD httpx under that name). If yours is named plain `httpx` or lives at a custom path, point at it with `HTTPX_BIN=/path/to/httpx run-recon ...`.
- **Attribution.** The scope filter enforces host ∈ seed domain, but shared hosting / CDNs can still host third-party content under your name. Confirm ownership (IP/ASN/cert/DNS) before acting on findings. This matters most for **ASN/CIDR seed mode** and `--favicon`, which pull hostnames from certificates/internet-scan data that you should verify you own.
- **`--brute` needs `massdns`.** The installer builds it from source; if that fails, `--brute` falls back to `puredns` (also needs massdns) and otherwise no-ops with a warning. Large bruteforce runs benefit from a fresh resolver list (`--resolvers`).
- **`--github` needs a GitHub token.** `github-subdomains`/`github-endpoints` hit the authenticated code-search API; without a token (`--github-token FILE` or `GITHUB_TOKEN`) they're skipped. Use a token with no scopes (public search only), and ideally several in a `.tokens`-style file — GitHub rate-limits code search hard. This stage is passive with respect to your targets (it queries GitHub, not them).
- **`--buckets` is a different asset class and hits third-party clouds.** `cloud_enum` probes AWS/Azure/GCP namespaces derived from your domain's keyword — it does not touch your target's infra, but it does query cloud providers, so only run it for names you're authorized to assess, and treat findings as leads (confirm ownership before claiming a bucket). Output is storage URLs in `results.csv.buckets.txt`, kept out of the main URL CSV on purpose.
- **`--refresh-resolvers` trades time for accuracy.** `dnsvalidator` validates a public-resolver baseline (a few minutes) so `--brute`/`--resolve` don't silently drop real subdomains behind a dead resolver. Skip it for quick runs; use it for thorough ones. A custom `--resolvers FILE` takes precedence and is never overwritten.
- **`--active` is loud and touches your app layer.** It fingerprints each live host (whatweb → nuclei tech-detect → native curl), then runs the matching CMS scanner (wpscan/droopescan/joomscan) or cmseek, plus `nuclei -tags tech,cms` for version→CVE mapping. These are real, attributable requests — plugin/theme brute forcing in particular is noisy and can trip WAFs, rate limits, and IDS. Run it only against assets you're authorized to test; it's gated behind `--active` (and `--all`) and disabled under `--passive-only` for that reason. Targets are capped per seed (`CMS_MAX`, default 25) to bound traffic.
- **WPScan vuln data needs a token; nuclei is the durable OSS fallback.** Without `WPSCAN_API_TOKEN`, wpscan still enumerates plugins/themes/users/version but skips vulnerability lookups; the free tier is ~25 requests/day. The stage therefore leans on the MIT-licensed nuclei-templates corpus (`-tags tech,cms`) as its always-available vuln layer, and falls back to native curl/ffuf probes (REST user enum, `readme.html`/`CHANGELOG.txt`/`joomla.xml` version reads, `wp-content/plugins|themes/FUZZ` brute) when the specialist CLIs aren't installed.
- **CMS version→CVE mapping over-reports.** Both wpscan and nuclei infer risk from detected product/version, so back-ported security fixes (common on managed WordPress) show as "vulnerable" when they aren't. Treat `.cms.txt` findings as leads to confirm, not confirmed vulnerabilities — the same inference caveat that applies to any version-based scanner.
- **`--activescan` is the heaviest, loudest stage — and it's in `--all`.** It runs content discovery with feroxbuster (ffuf fallback) across several large SecLists wordlists *plus* a broad nuclei scan over every live host — thousands of requests per host, very visible to WAFs/IDS. Discovered URLs are deduped/normalized with **uro** (falls back to `sort -u`) before nuclei runs, so the scan targets a clean, non-redundant list (live hosts + filtered discovered URLs) rather than raw fuzzer noise. It's distinct from `--fuzz` (one list, results feed the URL CSV): `--activescan` is a self-contained scan whose content hits and nuclei findings go to `results.csv.activescan.txt`. It needs feroxbuster/ffuf, nuclei, and the SecLists collection — install all three with `setup-recon-env.sh --include-heavy` (or point `SECLISTS` at an existing tree). Gated behind `--activescan`, included in `--all`, and disabled under `--passive-only`. Run it only against assets you're authorized to test.
- **`--social` discovers the org's social-media footprint** via **tookie-osint**, searching the brand username (derived from the seed domain, e.g. `acme.com` → `acme`, or set explicitly with `--social-user`) across many platforms and writing the found account URLs to `results.csv.social.txt`. It queries the social platforms (not your target), so it's passive w.r.t. the target and runs even under `--passive-only`; it's opt-in (not in `--all`) because it makes many outbound requests. Output parsing is best-effort — verify tookie-osint's CLI/output on your box, since that project's interface changes.
- **Scanning stages are opt-in and change the tool's nature.** `--nuclei`, `--params`, and `--secrets` turn a discovery tool into an active scanner. They're off by default and gated behind explicit flags for a reason — only run them against confirmed-owned hosts.
- **A few tool invocations are best-effort.** The mock suite validates wiring and graceful degradation for every stage, but real-binary flag exactness for the newer/less-central tools (`subzy`, `cdncheck`, `gowitness`, `arjun`, `trufflehog`, `uncover`) should be smoke-tested against your installed versions — CLIs drift between releases.
- **`Setup-ReconEnv.ps1` was authored without a PowerShell linter in the loop.** It targets both Windows PowerShell 5.1 and PowerShell 7+; the native Linux path is `setup-recon-env.sh`. Review before running in a locked-down environment; you may need to adjust `ExecutionPolicy`.
- **Default run does not fuzz or scan.** `ffuf`/`feroxbuster`/`nuclei` are installed but not wired into the default pipeline (they're noisy and host-specific). Add them deliberately against confirmed-owned hosts using the SecLists lists under `/opt/recon/wordlists/SecLists`.
- **Be a good citizen.** Respect source rate limits / ToS; some passive sources (urlscan, VirusTotal, IntelX in `--deep`) want API keys for meaningful quota — configure them in the respective tool configs (`~/.config/waymore/`, etc.).

## 9. Companion references & tools

- **`DATA-SOURCES.md`** — an integration menu of external-recon/OSINT data sources (internet-wide scan,
  certificate transparency, passive DNS, DNS zone files, WHOIS/RDAP, IP/ASN/BGP, IP enrichment,
  attack-surface/subdomain intel, cloud attribution, leaked-credential/breach exposure, third-party
  posture, and domain/IP/URL reputation). Each is tagged with its access model and — importantly — whether
  open-source tooling already wraps it or **the data/access itself is the barrier** (`GAP`). Use it as a menu
  when deciding which sources to build custom fetchers around.

- **`probe-datasource-limits.sh`** — a diagnostic that derives safe **per-request timeout** and
  **inter-request delay** values for those data sources (many throttle or deny after only a few requests).
  It measures latency, parses `Retry-After` / `X-RateLimit-*` headers, and runs a gentle rate ramp that
  stops at the first throttle and backs off. Its **`--recon-osint`** mode drives the exact endpoints the
  `--osint`/`--virustotal`/`--urlscan` stages hit and emits **run-recon's own variable names**, so the
  output wires straight back in via `--limits`:

  ```bash
  # 1) discover limits for the OSINT endpoints (authed presets auto-attach headers when keys are set)
  export VT_API_KEY=... URLSCAN_API_KEY=...        # optional
  ./probe-datasource-limits.sh --recon-osint --emit-config limits.env
  # 2) run recon with the derived per-source timeouts + delays applied
  run-recon -i domains.txt --osint --virustotal --urlscan --limits limits.env
  ```

  `limits.env` sets `RDAP_/INTERNETDB_/VT_/URLSCAN_` `*_TIMEOUT` and `*_DELAY` (seconds). run-recon's OSINT
  lookups honor them per source (each defaults to `STAGE_TIMEOUT` / no delay); the InternetDB per-IP loop and
  the VirusTotal calls are spaced by their `*_DELAY`. Team Cymru (ASN) is DNS-based and `--social`
  (tookie-osint) hits many sites, so neither is HTTP-rate-probed. You can also probe arbitrary endpoints:

  ```bash
  # probe your own sources (name<TAB>url per line), pass API keys as headers, emit a config
  ./probe-datasource-limits.sh --file sources.tsv -H "x-apikey: $VT_KEY" --emit-config limits.env
  # headers + latency only, no rate ramp (safest; won't burn quota):
  ./probe-datasource-limits.sh --url "https://crt.sh/?q=example.com&output=json" --polite
  ```
