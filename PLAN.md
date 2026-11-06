# run-recon plan

The tracked list of open work for the run-recon toolkit (run-recon.sh, generate-report.sh,
recon-db.sh, bench-run-recon.sh, the lab and the test suite). Each item says how it will be
checked. The method stays WebInventory's: lab fixtures, 3 runs, medians, and a change to the
default path is kept only if it is no slower and its output is identical (or the difference is a
justified accuracy fix).

**Status:** Done · In progress · Planned · Blocked (needs something from Ben) · Won't do
**Last updated:** 2026-11-05, run-recon 1.18.0 released, Batch 2 in progress

## 0. Source of truth

| ID | Item | Status | Check |
|---|---|---|---|
| R1 | Git repository, `main` = v1.18.0 (tagged), generated lab files ignored | Done (local) | `git log`, tag `v1.18.0` |
| R2 | Push to GitHub (private `benheise/run-recon`) | Blocked: this session cannot create repositories; Ben creates an empty private repo, then it is attached and pushed | `main`, tags and branches on GitHub |
| R3 | Each batch on its own branch, merged by pull request | In progress (`batch-2-http-fields`) | PR per batch |

## 1. Batch 2: HTTP detail (WebInventory A4, A5, A6, A11)

| ID | Item | Status | Check |
|---|---|---|---|
| B2.1 | HTTP fields as appended CSV columns, from the existing enrichment request (no extra traffic): redirect target, response time, body SHA-256, content type, X-Powered-By, auth scheme/realm, cookies, cookie flag gaps, missing security headers, HSTS max-age, Alt-Svc, HTTP flags (`CleartextAuth`, `PlainHttp`) | In progress | suite; lab fixtures (headers, cookies, basic auth over HTTP); default-path A/B: existing columns identical |
| B2.2 | Favicon mmh3 + MD5 per host (columns), from `--extras`, `--favicon` or `--origin` | In progress | lab: ci.test (Jenkins favicon) |
| B2.3 | Real favicon pivot: `--favicon` searches the favicon hashes (Shodan/Fofa mmh3, Censys MD5) through uncover, cert-scans the hits for in-scope names, and feeds the hits to `--origin` as candidates | In progress | suite (uncover mock); needs API keys on Kali |
| B2.4 | Reverse DNS (`ptr` column) under `--enrich` | In progress | suite; lab PTR fixture |
| B2.5 | `--extras` (opt-in, WebInventory's "safe extras"): robots.txt (paths become URL rows), security.txt (RFC 9116 Contact/Expires), one random-path 404 probe (catch-all 200, error-page server) → columns + `<out>.extras.txt` | In progress | lab fixtures: robots + expired/valid security.txt + catch-all host |
| B2.6 | Report: HTTP posture on host cards; findings for cleartext auth, expired security.txt, plain HTTP | In progress | suite |
| B2.7 | Docs, A/B vs v1.18.0, lab checks, PR | Planned | BENCHMARK.md v1.19 section |

## 2. Needs a run on Ben's Kali VM (internet required)

| ID | Item | Status | Check |
|---|---|---|---|
| V1 | Passive collectors (gau, waybackurls, urlfinder, subfinder sources) on real seeds | Planned | rows from each source |
| V2 | `--zone-exposure` against Ben's own zones | Planned | expected `zone-checked` / no false positives |
| V3 | `--origin` behind a real CDN (e.g. Cloudflare) | Planned | edge detected; origin found only if it really answers |
| V4 | TLS chain check with Kali's trust store: no false `CertUntrusted` on public certificates | Planned | public sites clean |
| V5 | Screenshots with Kali's Chromium; Kali's httpx accepts `-esb`, `-ho`, `-system-chrome` | Planned | `.screenshots.tsv` all ok |
| V6 | Higher `-t`, rate limits, and the `--db` cache on public seeds | Planned | no blanks; warm run faster |
| V7 | `--favicon` pivot with real uncover keys | Planned | hits cert-scanned, names in scope |

## 3. Follow-ups from v1.18

| ID | Item | Status | Check |
|---|---|---|---|
| F1 | `origin-protected`: record candidates that refuse the direct request | Planned | lab fixture: a backend that drops non-edge traffic |
| F2 | More origin candidates: SPF `include:`, IPv6 (AAAA, `ip6:`), ports beyond 80/443, ASN-seed ranges, historical DNS | Planned (favicon hits arrive with B2.3) | suite |
| F3 | Zone check: AAAA of name servers, walk from every name server, DS / DNSSEC chain status | Planned | suite |
| F4 | NSEC3 lab fixture (a BIND or Knot container; CoreDNS cannot serve NSEC3) | Planned | `bench-run-recon.sh zone` covers nsec3 |
| F5 | Screenshots use the probe's addresses (`--host-resolver-rules`), so the browser resolves like httpx | Planned | lab names without /etc/hosts |
| F6 | Validate gowitness captures like httpx's | Planned | suite |
| F7 | Report: a lone `Server: Caddy` is not an edge; versionless CPEs counted apart; "did not resolve" warning mentions a dangling CNAME | Planned | suite |
| F8 | Chain check in one pass for all hosts (cuts ~5 s CPU on the farm) | Planned | farm A/B |
| F9 | Setup scripts install ldnsutils (lab) | Planned | fresh Kali |

## 4. Batch 3: email and DNS posture, more discovery

| ID | Item | Status | Check |
|---|---|---|---|
| B3.1 | SPF, DMARC, MTA-STS, CAA records per seed | Planned | lab zone fixtures |
| B3.2 | Dangling MX / NS (delegation to a name that does not exist) | Planned | lab fixtures |
| B3.3 | cloudlist inventory diff (your cloud accounts vs what the scan found) | Planned | needs cloud credentials |
| B3.4 | tldfinder seed expansion; vulnx | Planned | |
| B3.5 | Lab coverage for naabu, alterx, shuffledns, cdncheck, uncover, notify | Planned | lab |

## 5. Batch 4: evidence and history

| ID | Item | Status | Check |
|---|---|---|---|
| B4.1 | Fail-closed scope file + dry run (`--scope FILE`, `--list-targets`), like WebInventory `-Scope` / `-ListTargets` | Planned | suite |
| B4.2 | SHA-256 manifest of every output file | Planned (run.json done in 1.18) | suite |
| B4.3 | Field-by-field diff between runs | Planned | suite |
| B4.4 | First seen / last seen and change events in recon-db | Planned | suite |
| B4.5 | Resume an interrupted run | Planned | suite |

## 6. TLS parity with WebInventory (A9)

| ID | Item | Status | Check |
|---|---|---|---|
| T1 | Supported-version matrix and ciphers by version (tlsx `-ve`/`-ce` mapping) | Planned | lab |
| T2 | Weak key / signature (`WeakKey`, `WeakSig`), `CertNotYetValid`, `DefaultCert` | Planned | lab fixture certs |

## Done (for reference)

- **1.18.0:** `--zone-exposure`; verified `--origin` with `.edge.tsv`; screenshot routing and validation;
  seed-resolving preflight, per-seed warnings, exit 3, `run.json`; TLS chain validation and the 30-day
  threshold; crawl-junk filter; report rebuild; lab fixtures and `bench-run-recon.sh checks`.
- **1.17.0:** ProjectDiscovery coverage batch 1 (nuclei callbacks off, asnmap key check, CNAME takeover
  check, katana resolvers/proxy, stdin closed, late HTTPS retry, CSV formula guard, pinned versions).
