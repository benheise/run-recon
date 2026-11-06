# run-recon plan

The tracked list of open work for the run-recon toolkit (run-recon.sh, generate-report.sh,
recon-db.sh, bench-run-recon.sh, the lab and the test suite). Each item says how it will be
checked. The method stays WebInventory's: lab fixtures, 3 runs, medians, and a change to the
default path is kept only if it is no slower and its output is identical (or the difference is a
justified accuracy fix).

**Status:** Done · In progress · Planned · Blocked (needs something from Ben) · Won't do
**Last updated:** 2026-11-06, follow-ups F1–F10 done on `followups-v1.18` (PR #3), Batch 3 on
`batch-3-email-dns` (PR #4), Batch 4 on `batch-4-evidence` (PR #5) and Batch 5 on `batch-5-redirects-tls`
(PR #6, stacked on #5). That was the last open batch work (B2.8, T1–T2, plus X1): v1.20.0 can be released once the
pull requests are merged. The V-list (section 2) still needs Ben's Kali VM; section 8 is planned for after
the release.

## 0. Source of truth

| ID | Item | Status | Check |
|---|---|---|---|
| R1 | Git repository, `main` = v1.18.0, generated lab files ignored | Done | `git log` |
| R2 | Push to GitHub (private `benheise/run-recon`) | Done: `main` pushed; releases v1.18.0 and v1.19.0 published. Tags cannot be pushed from Claude's sessions (HTTP 403), so releases/tags are created in the GitHub UI | tags `v1.18.0`, `v1.19.0` on GitHub |
| R3 | Each batch on its own branch, merged by pull request | Done for Batch 2 (#1, merged); follow-ups #3; Batch 3 #4; Batch 4 #5; Batch 5 #6 (stacked on #5) | PR per batch |

## 1. Batch 2: HTTP detail (WebInventory A4, A5, A6, A11)

| ID | Item | Status | Check |
|---|---|---|---|
| B2.1 | HTTP fields as appended CSV columns, from the existing enrichment request (no extra traffic): redirect target, response time, body SHA-256, content type, X-Powered-By, auth scheme/realm, cookies, cookie flag gaps, missing security headers, HSTS max-age, Alt-Svc, HTTP flags (`CleartextAuth`, `PlainHttp`) | Done (1.19.0) | 533/533 tests; `bench-run-recon.sh http`; A/B: existing columns identical on lab and farm |
| B2.2 | Favicon mmh3 + MD5 per host (columns), from `--extras`, `--favicon` or `--origin` | Done (1.19.0) | lab: ci.test (Jenkins favicon 81586312) |
| B2.3 | Real favicon pivot: `--favicon` searches the favicon hashes (Shodan/Fofa mmh3, Censys MD5) through uncover, cert-scans the hits for in-scope names, and feeds the hits to `--origin` as candidates | Done (1.19.0); live check is V7 | suite (uncover mock); needs API keys on Kali |
| B2.4 | Reverse DNS (`ptr` column) under `--enrich`; non-public addresses only via your `--resolvers` | Done (1.19.0) | suite; lab reverse zone |
| B2.5 | `--extras` (opt-in, WebInventory's "safe extras"): robots.txt (paths become URL rows), security.txt (RFC 9116 Contact/Expires), one random-path 404 probe (catch-all 200, error-page server) → columns + `<out>.extras.txt` | Done (1.19.0) | lab: robots + expired/valid security.txt + catch-all host |
| B2.6 | Report: HTTP posture on host cards; findings for cleartext auth, expired security.txt, plain HTTP | Done (1.19.0) | suite |
| B2.7 | Docs, A/B vs v1.18.0, lab checks, PR | Done (#1 merged, v1.19.0 released) | BENCHMARK.md v1.19 section |
| B2.8 | Followed redirect chain (final URL across hops) and password-form detection | Done (`batch-5-redirects-tls`): `final_url`, `redirect_chain` (same-host hops through the run's records, `--extras` fetches the rest; off-host listed, not followed), `login_form` from httpx `-er` on the enrichment request, `Form` in `auth`, `CleartextAuth` for a form on plain HTTP or posting to `http://` | suite; lab: `bench-run-recon.sh http` (redir.test, plainlogin.redir.test) |

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
| V8 | `--dns-posture` on Ben's own domains; `--tld-variants` and `--cloudlist` with real accounts | Planned | no false positives on a correctly configured domain |
| V9 | `--scope` with Ben's real ASNs and ranges (asnmap prefixes, origin candidates in and out of them); `--resume` of a long run interrupted mid-way; `--monitor --db` week over week | Planned | `.scope.txt` lists only what is really outside; resumed CSV complete; `.delta.tsv` shows real changes only |

## 3. Follow-ups from v1.18

| ID | Item | Status | Check |
|---|---|---|---|
| F1 | `origin-protected`: record candidates that refuse the direct request | Done (`followups-v1.18`) | lab: `origin.spa.test` → 403 → `origin-protected [info]` with per-port reasons; suite |
| F2 | More origin candidates: SPF `include:`, IPv6 (AAAA, `ip6:`), ports beyond 80/443, ASN-seed ranges, historical DNS | Done: AAAA, SPF `ip6:`/`include:`/`redirect=`, `ORIGIN_PORTS`, `range-cert`, VirusTotal/urlscan history | suite |
| F3 | Zone check: AAAA of name servers, walk from every name server, DS / DNSSEC chain status | Done: + `unreachable=N`, `dnssec-unanchored [low]`, `ds=yes/no` | suite; lab zone check |
| F4 | NSEC3 lab fixture (a BIND or Knot container; CoreDNS cannot serve NSEC3) | Done: `nsec3.test` on BIND 9.18 | `bench-run-recon.sh zone` PASS |
| F5 | Screenshots use the probe's addresses (`--host-resolver-rules`), so the browser resolves like httpx | Done | lab: `secret-admin.walk.test` 0-byte capture in 1.19.0 → `ok` |
| F6 | Validate gowitness captures like httpx's | Done: gowitness 3 JSON lines, explicit URLs, go-rod driver, `SCREENSHOT_TOOL` | lab (real gowitness 3); suite |
| F7 | Report: a lone `Server: Caddy` is not an edge; versionless CPEs counted apart; "did not resolve" warning mentions a dangling CNAME | Done | suite |
| F8 | Chain check in one pass for all hosts (cuts ~5 s CPU on the farm) | Done: once on the merged records, one handshake per (address, port, name) | suite; farm A/B: 1.14x wall, −24% CPU with `--extras`, output identical |
| F9 | Setup scripts install ldnsutils (lab) | Done (apt `ldnsutils`, dnf `ldns-utils`, pacman `ldns`) | fresh Kali (V-list) |
| F10 | `--extras` in one httpx pass per seed (hash `/favicon.ico` locally, parse `<link rel=icon>` from the root body): saves ~0.85 s CPU per seed, the main cost on seed-heavy runs (farm: +40 s wall today) | Done | lab: Jenkins favicon 81586312 (same as httpx); farm A/B: 1.14x wall, −24% CPU with `--extras`, output identical |

## 4. Batch 3: email and DNS posture, more discovery

| ID | Item | Status | Check |
|---|---|---|---|
| B3.1 | SPF, DMARC, MTA-STS, CAA records per seed | Done: `--dns-posture` (+ TLS-RPT; in `--all`) | lab: `bench-run-recon.sh posture` PASS (posture.test, good.posture.test); suite |
| B3.2 | Dangling MX / NS (delegation to a name that does not exist) | Done (+ lame NS, MX without address) | lab: `mx-dangling`, `ns-dangling`, `ns-lame` (BIND refuses); suite |
| B3.3 | cloudlist inventory diff (your cloud accounts vs what the scan found) | Done: `--cloudlist [CFG]` | lab: Terraform provider on `lab/cloud.tfstate`; real accounts on Kali |
| B3.4 | tldfinder seed expansion; vulnx | Done: `--tld-variants` (listed only, never scanned) and `--vulnx` (product-level leads) | suite; vulnx against the real API on the lab's CPEs; tldfinder needs public DNS (Kali) |
| B3.5 | Lab coverage for naabu, alterx, shuffledns, cdncheck, uncover, notify | Done | lab: `bench-run-recon.sh discovery` PASS |

## 5. Batch 4: evidence and history

| ID | Item | Status | Check |
|---|---|---|---|
| B4.1 | Fail-closed scope file + dry run (`--scope FILE`, `--list-targets`), like WebInventory `-Scope` / `-ListTargets` | Done (`batch-4-evidence`): + `--drop-out-of-scope`, `<out>.scope.txt`; names, address exclusions, addresses run-recon picks, crawl, browser, redirects held to the scope | suite; lab: `bench-run-recon.sh scope` (origin access log shows no request to an excluded address) |
| B4.2 | SHA-256 manifest of every output file | Done: `<out>.manifest.sha256` (`sha256sum -c` format; older same-prefix files left out and named) | suite |
| B4.3 | Field-by-field diff between runs | Done: `--monitor` → `<out>.delta.tsv` (per service; new/removed/17 fields), report section; `recon-db.sh diff` | suite; lab: `bench-run-recon.sh history` |
| B4.4 | First seen / last seen and change events in recon-db | Done: `recon-db.sh history` / `changes` (store or `--csv`), compared fields stored per run, `recon_runs` | suite; real PostgreSQL 16 (migration from a 1.19 store); lab: `history` with `--db` |
| B4.5 | Resume an interrupted run | Done: SIGINT/SIGTERM keep the work dir (exit 130/143), `--resume` (state hashes, flock while running) | suite; lab: `bench-run-recon.sh resume` (resumed CSV `--exact` equals an uninterrupted run) |

## 6. TLS parity with WebInventory (A9)

| ID | Item | Status | Check |
|---|---|---|---|
| T1 | Supported-version matrix and ciphers by version | Done (`batch-5-redirects-tls`): `--tls-enum` (`--tls-full` its alias; in `--all`), WebInventory's plan in run-recon's own ClientHellos (tlsx `-ve`/`-ce` dropped: `-ci` cannot offer weak suites) → `tls_supported`, `tls_ciphers`, `tls_weak_cipher` | suite (a local TLS speaker); lab: `bench-run-recon.sh tls`, cross-checked with tlsx per version |
| T2 | Weak key / signature (`WeakKey`, `WeakSig`), `CertNotYetValid`, `DefaultCert` | Done (`batch-5-redirects-tls`): tlsx `-cert` + a stdlib DER reader → `cert_key`, `cert_sig_alg`, `cert_not_before`; the chain check retries at OpenSSL level 0 | suite (openssl-made certificates); lab fixture certificates (`lab/gen-tls-certs.py`) |

## 7. Cross-checks with WebInventory

| ID | Item | Status | Check |
|---|---|---|---|
| X1 | CPE alias groups in the vulns join (the WebInventory 2.4.0 cross-check: run-recon missed Jira Server/Data Center and Varnish's other vendor strings) | Done (`batch-5-redirects-tls`): `cpe-aliases.json` (WebInventory's 184 groups, commit a8383ec) next to `recon-db.sh`; provenance records it | suite (a CVE filed under `jira_server` joins `atlassian:jira`; `CPE_ALIASES_FILE=` off; found through the installed symlink) |

## 8. After the 1.20.0 release: result shipping (recon-platform-plan §11)

The run-recon side of the platform plan (`claude/recon-platform-plan-v0.4.md` in the project). Not started.

| ID | Item | Status | Check |
|---|---|---|---|
| P1 | JSONL per record kind (services and hosts, URLs, findings, DNS posture, edge and origin, screenshot classes, warnings), from the code that writes the CSV, same field names | Planned | suite; schema contract test |
| P2 | `run_id` (UUID v4) and `--engagement ID` in run.json and the manifest | Planned | suite |
| P3 | `--ship URL` with `--ship-cert`/`--ship-key`/`--ship-ca` (mTLS, signed manifest, `ship-state.json`), its own exit code; `ship-recon.sh` to re-ship, resume and export | Planned | suite against a mock ingest; `bench-run-recon.sh ship` (the shipped run equals the local CSV) |

## Done (for reference)

- **1.20.0 (unreleased, Batches 3–5 and the follow-ups):** see sections 3–7.

- **1.19.0 (Batch 2):** 17 HTTP columns from the enrichment request (no extra traffic); favicon hashes;
  real favicon-hash pivot feeding `--origin`; `ptr` under `--enrich`; `--extras` (robots.txt, security.txt,
  404 probe); report HTTP posture and findings; `bench-run-recon.sh http`; httpx cache key `httpx_json_v2`.

- **1.18.0:** `--zone-exposure`; verified `--origin` with `.edge.tsv`; screenshot routing and validation;
  seed-resolving preflight, per-seed warnings, exit 3, `run.json`; TLS chain validation and the 30-day
  threshold; crawl-junk filter; report rebuild; lab fixtures and `bench-run-recon.sh checks`.
- **1.17.0:** ProjectDiscovery coverage batch 1 (nuclei callbacks off, asnmap key check, CNAME takeover
  check, katana resolvers/proxy, stdin closed, late HTTPS retry, CSV formula guard, pinned versions).
