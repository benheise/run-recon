# Tool coverage and WebInventory parity (run-recon v1.17.0)

Three questions, answered from evidence gathered on 2026-11-05:

1. Which ProjectDiscovery tools does run-recon use, at which versions, and which were checked
   against the benchmark lab with the real binaries?
2. What did running those binaries show that the mocked test suite could not?
3. How does run-recon compare with WebInventory v2.3.0 (from its product sheet), and what is
   planned?

## 1. ProjectDiscovery tools

The list is pdtm's own catalog: 27 tools, read from the API pdtm uses (`api.pdtm.sh/api/v1/tools/`,
found in pdtm v0.1.5's source; its README lists none). "Lab" means the pinned binary ran against the
container lab in this release and its output was checked.

| Tool | pdtm current | run-recon use | Pinned in setup | Lab-verified | Notes |
|---|---|---|---|---|---|
| httpx | 1.12.0 | live probe + per-URL enrichment | 1.12.0 | yes | |
| katana | 1.8.0 | crawl | 1.8.0 | yes | 10 s idle floor per seed (see BENCHMARK.md) |
| tlsx | 1.4.0 | TLS posture, SAN harvest, JARM (`--origin`), ASN/CIDR cert scan | 1.4.0 | yes | 1.2.2 → 1.4.0 A/B below |
| dnsx | 1.3.1 | resolve gate, wildcard filter, AAAA, takeover CNAMEs, OSINT IPs | 1.3.1 | yes | 1.3 changed `-rcode` output (finding 5) |
| nuclei | 3.11.1 | `--nuclei`, `--active`, `--activescan`, `--takeover` | 3.11.1 | flags only | `-ni` / `-iserver` checked against local listeners; community templates are not reachable from the lab host |
| asnmap | 1.2.0 | ASN seeds → CIDRs | 1.2.0 | yes | needs a free PDCP API key (`PDCP_API_KEY`) |
| mapcidr | 1.1.97 | aggregate CIDR seeds | 1.1.97 | yes | |
| subzy (not PD) | — | `--takeover` fingerprints | 1.2.1 | yes | |
| subfinder | 2.17.0 | `--subs` | 2.17.0 | binary only | its sources are internet APIs; `.test` seeds skip them |
| urlfinder | 0.0.3 | passive URLs | 0.0.3 | no | internet archives |
| naabu | 2.7.0 | `--ports` | 2.7.0 | yes (v1.20) | lab: `https://nginx.test:8443` found and probed (`bench-run-recon.sh discovery`) |
| alterx | 0.1.0 | `--permute` | 0.1.0 | yes (v1.20) | lab: `grafana.nginx.test`, which only a permutation guesses |
| shuffledns | 1.2.1 | `--brute` (needs massdns, built from source) | 1.2.1 | yes (v1.20) | lab: `backup-db.nginx.test` from the lab wordlist |
| cdncheck | 1.4.0 | `--origin` | 1.4.0 | yes (v1.20) | lab edge untagged; `104.16.0.1 [waf] [cloudflare]` in the format `--origin` parses |
| uncover | 1.2.1 | `--favicon` (cert-name search and, since v1.19, the favicon-hash pivot) | 1.2.1 | yes, without keys (v1.20) | no keys: one warning instead of silence; searches with keys stay V7 (Kali) |
| notify | 1.0.7 | `--monitor --notify` (`-bulk`, `NOTIFY_CONFIG` → `-pc`) | 1.0.7 | yes (v1.20) | lab: one message to a loopback webhook naming the new asset |
| chaos-client | 0.5.2 | via subfinder's `chaos` source (key in its provider config) | — | — | |
| nuclei-templates | 10.5.1 | `nuclei -update-templates` (setup `--include-heavy`) | not pinned | — | templates update on their own schedule |
| interactsh-client / -server | 1.4.1 | not called directly; `--interactsh-server URL` points nuclei at your own server | — | — | |
| cloudlist | 1.5.1 | `--cloudlist [CFG]` (v1.20) | 1.5.1 | yes (v1.20) | lab: the Terraform provider reads `lab/cloud.tfstate` offline; real cloud accounts stay a Kali check |
| tldfinder | 0.0.2 | `--tld-variants` (v1.20), `-dm tld` | 0.0.2 | suite only | it queries public DNS whatever `-r` says, so it cannot run inside the lab |
| vulnx | 2.0.2 | `--vulnx` (v1.20) | 2.0.2 | yes (v1.20) | real API (no key) on the lab's CPEs; no version matching, so product-level leads; the module is `github.com/projectdiscovery/vulnx/v2` |
| depx | 0.1.1 | not wired | — | — | supply-chain intelligence for lockfiles, SBOMs and GitHub orgs. Useful for DevSecOps pipelines, not for an external attack-surface scan |
| pdtm | 0.1.5 | not used | — | — | it installs the latest release and offers no version selection, while run-recon parses tool output and needs pinned versions |
| proxify, simplehttpserver, aix | — | not needed | — | — | `--proxy` covers proxying |

**Pinning.** `setup-recon-env.sh` and `Setup-ReconEnv.ps1` now install every Go tool at a fixed
version (34 modules; none at `@latest`). `RECON_TOOLS_LATEST=1 ./setup-recon-env.sh --force`
upgrades deliberately; re-run the lab before trusting the result. Every run logs the versions of
httpx, katana, tlsx and dnsx and warns when one differs from the lab-verified version.

## 2. What the real binaries showed (v1.17 shakedown)

| # | Finding | Evidence | Fix |
|---|---|---|---|
| 1 | **Every seed got a false "takeover" finding.** The filter `vulnerable\|takeover` matched subzy's settings banner (`[ Yes ] Show only potentially vulnerable subdomains`) | real subzy 1.2.1 output | only `[ VULNERABLE ]` result lines are kept |
| 2 | **The takeover check skipped exactly the names that matter.** subzy only saw live hosts, and the resolve gate dropped names that no longer resolve, but a dangling CNAME returns NXDOMAIN | lab fixture `orphan.test → gone.cloud.test` | CNAMEs of every candidate from before the resolve gate (dnsx); NXDOMAIN targets flagged; subzy and nuclei fingerprint every name that has a CNAME |
| 3 | **A rejected asnmap key could hang a terminal run.** asnmap 1.2 asks for a new key on `/dev/tty` when the API answers "unauthorized". It also prints that prompt on stdout, so it landed in the CIDR list and went to tlsx. Without any key, ASN expansion failed with no explanation | real asnmap, no key and an invalid key | key check up front; asnmap runs without a controlling terminal (`setsid`); only CIDR lines are kept; "key rejected" reported as such |
| 4 | **ASN ranges were expanded IP by IP.** `mapcidr -cl` without `-aggregate` prints every address (a /30 became 4 lines; an ASN with a /12, about a million). IPv6 prefixes went to the cert scan too | real mapcidr | `-aggregate`; IPv6 prefixes skipped and counted (a /32 is 2^96 addresses) |
| 5 | **dnsx 1.3 changed its output.** With `-rcode noerror,nxdomain`, 1.3.1 no longer prints NXDOMAIN rows (1.2.2 did); `-cname` prints only names that have one | both versions against the lab zone | the takeover check uses only the two queries that behave the same on both |
| 6 | **An open stdin could stall the range expansion.** tlsx (given a CIDR list), katana and `mapcidr -aggregate` read stdin even when given `-l FILE`. Per-seed workers were never exposed (xargs gives them `/dev/null`), but the ASN/CIDR stage runs in run-recon's main process: started with stdin left open and no terminal (CI runners, `ssh host run-recon …` without `-t`), its cert scan could wait until killed | tlsx 1.2.2 and 1.4.0 with a CIDR list and an open pipe: still waiting after 40 s; with `/dev/null`, done in 1 s. ASN seeds with stdin held open: 200 s timeout before the fix, 15 s after | run-recon closes stdin once at start-up (`exec < /dev/null`); every tool inherits it |
| 7 | **katana ignored `--resolvers` and `--proxy`.** httpx, dnsx and tlsx got the configured resolvers and proxy; katana used the system resolver and connected directly, so names known only to your resolvers (internal DNS, a Pi-hole bypass, the lab) gave an empty crawl, and with `--proxy` (a jump host) the crawl traffic bypassed the proxy | after the lab host restarted without its `/etc/hosts` entries, v1.16.0 crawled 1 URL of `wp.test` instead of 87 in 3 of 3 runs, while v1.17 crawled all 87; with `-proxy`, katana's `CONNECT wp.test:443` reached a local proxy listener (katana also requests `http://burpsuite/` through the proxy: its Burp CA check) | katana gets `-r` and `-proxy` like the other tools |
| 8 | **nuclei sent callbacks to public servers.** By default nuclei registers with oast.pro, oast.live, … for templates that make the target call back | nuclei 3.11.1 help text; with `-iserver` pointed at a local listener, nuclei sent `POST /register` there | `-ni` by default; `--interactsh-server URL` (+ `NUCLEI_ITOKEN`) for your own server; `NUCLEI_OAST=public` only by explicit opt-in |
| 9 | **Under load, the live probe lost HTTPS.** httpx tries HTTPS first and falls back to HTTP; when all HTTPS attempts failed in a load spike, the host was recorded as `http://` only and its TLS posture was never checked | farm at `-t 10`: `f31` came back `http://` only, missing `CertExpiring` (1 of 3 runs). v1.15.2 lost `f41` the same way | hosts that answered only on plain HTTP get one HTTPS-only try after a pause; a success replaces the `http://` URL |
| 10 | **The main CSV had no formula-injection guard.** Titles and headers come from the scanned site, so a title like `=HYPERLINK(…)` became a live formula in Excel (requirement FPV-01; the vulns CSV already had the guard) | code review against the WebInventory product sheet | text cells starting with `= + - @`, tab or CR get a `'` prefix; the report and the DB import strip it again |

## 3. WebInventory v2.3.0 parity

run-recon is an external attack-surface pipeline; WebInventory is an internal, agentless service
inventory. Some differences are by design. "Planned" items keep the default traffic unchanged and
arrive behind a switch, as WebInventory's opt-in probes do.

| WebInventory capability (product sheet §) | run-recon v1.17 (v1.18 and v1.19 changes in bold) | Status |
|---|---|---|
| Fail-closed scope, `-Scope`, `-ListTargets` (A1) | per-seed scope filter on discovered names; **v1.20: `--scope FILE` (names, `*.names`, IPv4/IPv6 ranges, ASNs, `!` exclusions): seeds and the file checked before anything is sent (exit 2), `--drop-out-of-scope`, `--list-targets` dry run; discovered names, names resolving into excluded ranges, addresses run-recon picks itself (origin candidates, scan hits, range sweeps), the crawl (katana `-cs`/`-cos`), the screenshot browser (`MAP * ~NOTFOUND`), nuclei/whatweb/cmseek redirects all held to it; `<out>.scope.txt` lists what was held back** | parity (redirects are not followed rather than followed and checked; gospider/hakrawler skipped under `--scope`) |
| Connect scan, any-port HTTP/TLS detection (A2, A3) | naabu `--ports`, then httpx | parity in approach; naabu not yet lab-run |
| HTTP fields (A4): FinalUrl, RedirectChain, Auth, Cookies, CookieFlagIssues, MissingSecHeaders, HstsMaxAge, AltSvc, BodySha256, ResponseMs | status, length, title, server, technologies; **v1.19: `redirect_location`, `response_ms`, `body_sha256`, `content_type`, `powered_by`, `auth`, `cookies`, `cookie_issues`, `missing_sec_headers`, `hsts_max_age`, `alt_svc`, `http_flags` (`CleartextAuth`, `PlainHttp`), from the enrichment request itself (no extra traffic)**; **v1.20: `final_url` and `redirect_chain` (`code->URL | …`, same-host hops followed through the run's own records, and with `--extras` through the ones it did not probe; off-host hops listed, not followed, as in WebInventory), `login_form` (httpx `-er` on the same request) with `Form` in `auth` and `CleartextAuth` for a form on plain HTTP or posting to `http://`** | parity |
| Favicon mmh3 / MD5 (A5) | **v1.19: `favicon_mmh3`, `favicon_md5` with `--extras`, `--favicon` or `--origin`; `--favicon` searches the hash on Shodan/Fofa (mmh3) and Censys (MD5) through uncover** | parity (opt-in here; on by default in WebInventory) |
| robots.txt, security.txt, 404 probe (A6) | **v1.19: `--extras`: `robots` and `security_txt` columns, robots paths as URL rows, `security-txt-expired/invalid [low]`, `catch-all-200`, error-page versions** | parity (opt-in) |
| OPTIONS / risky methods (A7), identification paths (A8) | nuclei tech templates under `--active` | partial |
| TLS posture (A9): version matrix, ciphers, weak ciphers, key/sig strength, chain validation | negotiated version/cipher, expiry, self-signed, name mismatch; **v1.18: chain validation against the system trust store (`CertUntrusted`), `CertExpiring` at 30 days like `-CertWarnDays`**; **v1.20: `--tls-enum` runs WebInventory's plan (one ClientHello per version, TLS 1.3 to SSL 3.0, and one offering only weak suites, each stopped at the ServerHello) → `tls_supported`, `tls_ciphers`, `tls_weak_cipher`, `WeakTLS`, `WeakCipher`; tlsx `-cert` → `cert_key`, `cert_sig_alg`, `cert_not_before`, `WeakKey`, `WeakSig`, `CertNotYetValid`, `DefaultCert` (WebInventory's rules + ingress-nginx and Traefik); the chain check retries at OpenSSL security level 0 when the local default refuses the handshake** | parity (detail in columns, flags without the `:detail` suffix) |
| SAN vhosts (A10) | SANs feed discovery (tlsx), vhost brute (`--vhost`) | different approach |
| Reverse DNS (A11) | **v1.19: `ptr` column under `--enrich`; non-public addresses asked only of your `--resolvers`** | parity (opt-in, as in WebInventory) |
| Fingerprinting engine, CPEs (A12) | httpx tech detection (Wappalyzer data) + rule-based CPE emission (FPV-06) | parity for web; no Recog banners |
| Version advisories (A13) | offline NVD/KEV/EPSS join (`recon-db.sh vulns`); **v1.20: WebInventory's 184 CPE alias groups (`cpe-aliases.json`: Jira Server/Data Center, Varnish's vendor strings, …)** | covered by the join |
| JARM (B1) | tlsx `-jarm` under `--origin`, **v1.18: a host attribute in `<out>.edge.tsv`, no longer reported as an "exposed origin"** | parity; JA4S not planned (FoxIO licence) |
| SMB / RDP / SNMP identity (B2–B4) | none | not planned: internal-network probes. For EASM, port-level exposure of 445/3389/161 from naabu is the finding |
| Screenshots (B5) | httpx `-ss` / gowitness; **v1.18: the browser gets `--proxy-server` / a `NO_PROXY` bypass list, and each capture is validated (`<out>.screenshots.tsv`)**; **v1.20: `--host-resolver-rules` from `--resolvers`; gowitness 3 validated from its JSON lines (go-rod driver, explicit URLs)** | parity in routing and evidence; no per-page scope proxy |
| Jump-host proxy (B6) | `--proxy` | parity |
| Pace, retries, resilience (C1) | rate, threads, retries, late retry; **v1.20: SIGINT/SIGTERM stop every stage and keep the work dir (exit 130/143); `--resume` continues with the seeds that finished (state file with command-line/input/scope hashes, a lock while running)** | parity (resume per seed, not per check) |
| Outputs (C2): JSONL with evidence, delta, run.json, SHA-256 manifest | CSV, HTML report, side artifacts, `--monitor` new-asset diff; **v1.18: `<out>.run.json` (version, command line, tool versions, resolvers, per-seed counts, warnings, exit status); exit 3 for a run with no results**; **v1.20: `<out>.manifest.sha256` (every file the run wrote, `sha256sum -c` format) and `<out>.delta.tsv` (per service: new, removed, 17 fields compared)** | parity except JSONL with per-detection evidence |
| Hostile-content handling (C3) | report escapes data; CSV formula guard added in v1.17 | parity for CSV |
| Inventory store (D): first/last seen, change log, hash-chained ledger | PostgreSQL cache + per-run host rows; **v1.20: the compared fields stored per run, `recon_runs` (seeds covered, columns present), `recon-db.sh history` (first/last seen, gone since) and `changes` (events), also offline over run CSVs (`--csv`)** | parity except the hash-chained ledger (the manifest hashes each run's files) |
| Offline vulnerability correlation (E) | `recon-db.sh vulns` (NVD 2.0, KEV, EPSS, match confidence) | parity |
| Lab, A/B, "faster and identical" | `bench-run-recon.sh` + `lab/`; **v1.18: zone and origin fixtures, `bench-run-recon.sh checks`** | parity |
| (no WebInventory equivalent) DNS zone exposure | **v1.18: `--zone-exposure` (AXFR per name server, NSEC walk, NSEC3 parameters)** | new |
| (no WebInventory equivalent) origin behind a CDN/WAF | **v1.18: `--origin` edge detection + verified origin search (`origin-exposed`)** | new |

## 4. Plan

| Batch | Contents | Status |
|---|---|---|
| 1 | nuclei callbacks off by default; asnmap key check and visible errors; CNAME/dangling takeover check; katana honours `--resolvers`/`--proxy`; stdin closed for all tools; late HTTPS retry in the live probe; CSV formula guard; pinned tool versions with a lab-verified warning | **done in v1.17.0** |
| 2 | httpx fields (final URL, redirect target, security headers, cookie flags, HSTS, Alt-Svc, body hash, response time, favicon mmh3) as appended CSV columns; real favicon pivot; reverse DNS; opt-in robots/security.txt | **done in v1.19.0** (see `PLAN.md`) |
| 3 | Email and DNS posture (SPF, DMARC, MTA-STS, DNSSEC, CAA, dangling MX/NS); cloudlist inventory diff; tldfinder seed expansion; lab fixtures for naabu, alterx, shuffledns, cdncheck, uncover, notify | **done in v1.20.0**: `--dns-posture`, `--cloudlist`, `--tld-variants` (listed only), `--vulnx`; `bench-run-recon.sh posture` and `discovery` |
| 4 | Evidence and history: scope file + dry run, run manifest and run.json, field-level delta, first/last seen in recon-db | run.json done in v1.18.0; **the rest done in v1.20.0**: `--scope`, `--list-targets`, `.manifest.sha256`, `.delta.tsv`, `recon-db.sh history/changes/diff`, `--resume` |
| 5 | Redirect chains and login forms (B2.8); TLS version matrix and certificate strength (T1, T2); CPE aliases (X1) | **done in v1.20.0**: `final_url`, `redirect_chain`, `login_form`; `--tls-enum`; `cert_key`, `cert_sig_alg`, `cert_not_before` and four TLS flags; `cpe-aliases.json`; `bench-run-recon.sh tls` |
| 6 | JSON output and result shipping to Tideline (PLAN P1–P3, recon-platform-plan §11) | **done in v1.20.0**: `--json` (13 record kinds, `schemas/`), `run_id`, `--engagement`, `--job-id`, `--ship` with `ship-recon.sh`; `lab/mock-tideline.py`; `bench-run-recon.sh ship` |
| report review | `REPORT-REVIEW.md`: `--zone-exposure`, verified `--origin`, screenshot routing and validation, run integrity (seed-resolving preflight, per-seed warnings, exit 3, run.json), report rebuild (names, cards, graded TLS), TLS chain validation, crawl-junk filter | **done in v1.18.0** |
