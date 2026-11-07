# Outcrop plan (formerly run-recon)

The tracked list of open work for the Outcrop toolkit, named run-recon until 1.21 (outcrop.sh, with run-recon.sh as
its wrapper; generate-report.sh,
recon-db.sh, bench-run-recon.sh, the lab and the test suite). Each item says how it will be
checked. The method stays WebInventory's: lab fixtures, 3 runs, medians, and a change to the
default path is kept only if it is no slower and its output is identical (or the difference is a
justified accuracy fix).

**Status:** Done · In progress · Planned · Blocked (needs something from Ben) · Won't do
**Last updated:** 2026-11-07. The repository is now `benheise/Outcrop` (renamed from `benheise/run-recon`;
GitHub redirects the old URLs). Follow-ups F1–F10 (PR #3), Batch 3 (#4), Batch 4 (#5), Batch 5 (#6), Batch 6
(#7, section 8: JSON output and shipping to Tideline, brought forward at Ben's request) and `release-v1.20.0` (#8,
`VERSION` 1.20.0) are all merged. Only #3 reached `main`: each stacked PR merged into the branch below it, because
GitHub retargets a stacked PR only when its base branch is deleted. PR #9 landed `release-v1.20.0` on `main` and #10
the Outcrop rename after it; the v1.20.0 tag goes on #9's merge commit (`3923832`), not on `main`'s head. The V-list
(section 2) still needs Ben's Kali VM. Section 10 adds the items from the AutoAR review (2026-11-07); its first group (OA1–OA6) is Batch 7, on
`batch-7-request-policy`. Still to run there: the release A/B against `main` and a clean `policy` check (the lab's
Docker daemon reached the session's two-hour limit first).

## 0. Source of truth

| ID | Item | Status | Check |
|---|---|---|---|
| R1 | Git repository, `main` = v1.18.0, generated lab files ignored | Done | `git log` |
| R2 | Push to GitHub (`benheise/Outcrop`, renamed from `benheise/run-recon` on 2026-11-07; now public) | Done: `main` pushed; releases v1.18.0 and v1.19.0 published; v1.20.0 on `main` since #9 (tag it on `3923832`; release notes drafted). Tags cannot be pushed from Claude's sessions (HTTP 403), so releases/tags are created in the GitHub UI | tags `v1.18.0`, `v1.19.0` on GitHub; `v1.20.0` after #9 |
| R3 | Each batch on its own branch, merged by pull request | Done for Batch 2 (#1, merged); follow-ups #3; Batch 3 #4; Batch 4 #5; Batch 5 #6 (stacked on #5); Batch 6 #7 (stacked on #6); release #8 (stacked on #7); all merged, #4–#8 into their stack bases, so #9 landed the stack on `main`; #10 (Outcrop 1.21) merged; Batch 7 targets `main` directly. Next time: turn on "Automatically delete head branches" (GitHub then retargets the next PR to `main` as each merges), or merge only the top of a stack | PR per batch |

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

## 8. Batch 6: JSON output and result shipping to Tideline (recon-platform-plan §11)

The run-recon side of the platform plan (`claude/recon-platform-plan-v0.5.md` in the project). Tideline is
the platform's name (`claude/naming-research.md`); the protocol identifiers use it (`tideline-envelope/1`,
`Tideline-Signature`, `urn:tideline:sensor:<id>`). **Decided 2026-11-06 (Ben): these names stay and are frozen**
(SHIPPING.md, "Frozen identifiers"; the suite pins them and checks `schemas/SHA256SUMS`). Planned for after the
release, brought forward at Ben's request. Details: SHIPPING.md.

| ID | Item | Status | Check |
|---|---|---|---|
| P1 | `--json`: JSON lines per record kind with the CSV's and TSVs' field names: urls and services (from the CSV builder itself, unguarded), findings, DNS posture, edges, CNAMEs, zone names, screenshot classes, cloud assets, vulnx, delta, warnings, seeds; JSON Schemas (2020-12) in `schemas/` | Done (`batch-6-json-ship`) | suite: parity with the CSV, the findings parser, the schema contract (field lists read from the source); lab A/B |
| P2 | `run_id` (UUID v4, kept across `--resume`), `--engagement`, `--job-id` in run.json and the manifest | Done | suite (incl. `--resume`) |
| P3 | `--ship URL` with `--ship-cert`/`--ship-key`/`--ship-ca`/`--ship-proxy`: mTLS pinned to the Tideline CA (an empty `--capath`: `--cacert` alone still trusts the system store), signed `tideline-envelope/1` (ES256), gzip parts hashed as in the run's manifest, `ship-state.json`, exit 4; preflight before the scan; `ship-recon.sh` ship/status/export/envelope/check | Done | suite against `lab/mock-tideline.py` (delivery, re-ship, resume, refusals, pinning, export); `bench-run-recon.sh ship` (the shipped records equal the local CSV row for row) |
| P4 | WebInventory's side (`-ShipTo`, `Send-WebInventoryRun.ps1`, `Register-WebInventorySensor.ps1`) against the same envelope; Outcrop vendoring `schemas/schemas/` and `schemas/SHA256SUMS` from benheise/Tideline at tag `schemas-v1.0.0` (released 2026-11-07; project doc `claude/tideline-schemas-v1.md`) | WebInventory's side is in Hinterland 2.6.0, but its envelopes do not validate against `schemas-v1.0.0` yet (Tideline plan TA15); Outcrop's vendoring Planned | contract test of both tools' lab output; `sha256sum -c` of the vendored copy |

## 9. v1.21: the Outcrop name

The repository was renamed `benheise/Outcrop` on 2026-11-07, and Ben chose to carry the name into the tool in
1.21, after the v1.20.0 release.

| ID | Item | Status | Check |
|---|---|---|---|
| O1 | `outcrop.sh` is the command (installed as `outcrop`); `run-recon.sh` stays as a wrapper that execs it (same arguments, environment, exit status and PID), installed as `run-recon`, so existing scripts and cron jobs keep working. The name changes in help, messages, the report header (for runs from 1.21 on), the setup scripts and the current docs | Done (`outcrop-v1.21`, PR #10) | suite: the wrapper's version, a symlinked install, exit status, the same CSV, a missing outcrop.sh |
| O2 | Unchanged on purpose: the frozen machine ids (`tool` = `run-recon` in run.json and the Tideline envelope; the `run-recon.*/1` schemas); output names (`recon-<ts>.csv`); the companion scripts (`generate-report.sh`, `recon-db.sh`, `ship-recon.sh`); the dev scripts (`bench-run-recon.sh`, `test-run-recon.sh`); the cloud-feed cache path; history sections of the docs | Decided | suite pins the tool id |

## 10. From the AutoAR review

AutoAR (h0tak88r/AutoAR) is a Go bug-bounty pipeline. Its web and HTTP side was reviewed for ideas (project
doc `claude/autoar-web-research.md`). Three takeaways apply here:

- a few cheap detectors AutoAR has and Outcrop lacks;
- lessons from AutoAR's own defects;
- engine patterns.

The platform's share is in the Tideline plan, section 15 (TA1–TA15). AutoAR's intrusive defaults are not adopted:

- S3 write and delete probes;
- 403 bypasses;
- default credentials;
- exploit checks.

A change to a default path still follows the method above.

**Blind spots (do these first)**

| ID | Item | Status | Check |
|---|---|---|---|
| OA1 | User-Agent A/B. httpx, katana and nuclei send their default User-Agents (only wpscan sets one). AutoAR found WAFs answering 404 or 406 to nuclei's User-Agent and 200 to a browser's, on a host with a confirmed exposure | Done (`batch-7-request-policy`): behind ModSecurity + OWASP CRS 4.30, `--nuclei --fuzz` on three hosts, 3 runs a mode: `--fuzz` found 0 paths with the tools' own User-Agents (CRS blocked all 336 feroxbuster requests) and 177 with Outcrop's or Chrome's; nuclei 7 findings in every mode (it already randomizes its User-Agent). Default: `browser` (Ben, 2026-11-07) | lab: `bench-run-recon.sh ua --runs 3` |
| OA2 | `waf_blocked` warnings. A block page (403, 406, 429 or 503 carrying a known WAF vendor's page) becomes a warning naming the host and vendor, not a result. Needs the warning `kind` field (Tideline TA9) | Done (`batch-7-request-policy`): 12 vendors from the enrichment response (status, headers, title, body markers by a second `-er`); `<out>.health.tsv`, report, `warnings.jsonl` `kind` (warning schema x-minor 1, ahead of Tideline's schemas-v1.1.0) | suite (each vendor, the controls); lab: `bench-run-recon.sh waf` PASS (9 vendor fixtures, a plain 403, a page that names vendors) |
| OA3 | ffuf fallback calibration. When feroxbuster is missing, `--fuzz` and `--activescan` fall back to ffuf, and neither ffuf call passes `-ac`, so a host that answers 200 for every path fills the results. feroxbuster filters wildcards by default, and `--vhost` already passes `-ac` | Done: `-ac` in the `--fuzz` and `--activescan` ffuf fallbacks and in the `--active` WordPress slug brute (the same gap) | suite (argv) |
| OA4 | Throttle accounting. Count connection resets, timeouts, TLS name errors and 429s per host from the tools' output, write them to `warnings.jsonl`, and mark a host over a threshold `throttled` in the report. AutoAR filtered exactly these errors out of its logs | Done: per host, from httpx `-probe` (failed requests to `hx_failed.jsonl`, never rows) and katana/nuclei `-elog`; `THROTTLE_MIN`=5, `THROTTLE_PCT`=10; kind `throttled` | suite; lab: `bench-run-recon.sh throttle` PASS (nginx `limit_req`, a dropped connection) |
| OA5 | One request policy. The User-Agent, extra headers, rate and timeouts are set once and applied to every tool invocation (httpx, katana, nuclei, ffuf, feroxbuster, gospider, hakrawler and the rest). AutoAR fixed its User-Agent in one code path and missed the one its main workflow uses | Done: `--user-agent browser\|outcrop\|tool\|STRING` (default `browser`, Chrome 157; `outcrop` is WebInventory's form), `--header`, `--req-timeout`; `_policy_init` builds each tool's flags; HTTP cache entries per policy; header values never recorded. Exceptions, measured: httpx's screenshot browser (own User-Agent), gospider (lowercases it), subzy (no option), subjs (no header option), nuclei raw templates (0.1% of nuclei's requests) | suite: every HTTP tool's argv, and a static check of all 36 invocations; lab: `bench-run-recon.sh policy` (ingress access log) |
| OA6 | SIGTERM stops the traffic. An interrupted or timed-out run signals its tools' process group, so no child keeps sending after Outcrop exits. B4.5 keeps the work dir; this makes sure the scan itself stops. Tideline's job deadline (TA1) relies on it | Done: freeze, SIGTERM, SIGKILL after `STOP_GRACE` (10 s); the tree plus processes carrying the run's `OUTCROP_RUN` tag; main-process stages through `_fg`; `--max-runtime` (exit 124, `timed-out`) | suite (a tool ignoring SIGTERM, a daemonized child, the deadline, a hanging main-process stage); lab: `bench-run-recon.sh stop` PASS (0 packets after exit) |

**New detectors**

| ID | Item | Status | Check |
|---|---|---|---|
| OA7 | Cloudflare 1016 in `--takeover`. A name that resolves into Cloudflare's ranges and answers 530 with "error code: 1016" has a proxied record whose origin is gone, a takeover class that CNAME checks miss. Read from the httpx response the run already has: no extra request | Planned | lab fixture answering 530 / 1016; suite |
| OA8 | `--mcp` (opt-in). POST a JSON-RPC `initialize` to the six common MCP paths, then list tools, resources and prompts, and never call `tools/call`. Report a server with no auth and tools named like exec or shell. Use a current protocol version (AutoAR sends `2024-11-05`) and carry the session header between requests | Planned | lab: an MCP server with and without auth; suite |
| OA9 | API docs, GraphQL consoles and Docker files in `--extras`: Swagger and OpenAPI documents, GraphQL UI pages, `docker-compose.yml` and `Dockerfile`, each confirmed by keywords in the body, not by the status code. GET only; GraphQL introspection (a POST) only under `--active` | Planned | lab: exposed and soft-404 fixtures; no false positive on the catch-all host |
| OA10 | Backup names derived from the domain in `--fuzz` (`example.com.zip`, `www_example.tar.gz` and the like). Send HEAD, and count a hit only on 200, a Content-Length over 100 and an archive MIME type; fall back to a 1-byte ranged GET when HEAD is refused | Planned | lab: a real archive, a soft-404 host and a host that refuses HEAD |
| OA11 | URL tags. gf-style tags (sqli, ssrf, redirect, lfi and so on) as a new column on URL rows, never as findings. Offline: no traffic | Planned | suite; the schema field (Tideline TA9) |
| OA12 | JS endpoint diff in `--monitor` with `--js`. Endpoints that appeared in bundles since the previous run become `new_js_endpoint` delta rows, for Tideline's drift view (TA11) | Planned | lab: a bundle that changes between two runs; `bench-run-recon.sh history` |
| OA13 | Lame delegation below the seeds. `--dns-posture` checks the seeds and their zones today. Also check delegated child zones found among the candidates: a name that returns SERVFAIL or REFUSED is asked again at its own name servers | Planned | lab: a delegated child zone whose name server refuses |
| OA14 | Dependency confusion in `--js`. Package names from exposed `package.json` files and bundles are looked up in the npm registry only, with no traffic to the target; an unclaimed scoped name is a finding | Planned | suite with a registry mock |
| OA15 | WordPress slug availability in `--active`. Detected plugin and theme slugs are looked up on wordpress.org; one that is not there can be claimed by someone else | Planned | suite with an API mock |
| OA16 | SaaS tenants. Check in DNS whether company-named tenants exist (Atlassian, Zendesk and the like) and list them, never scan them, the way `--tld-variants` works | Planned | suite; live check on Kali |

**Speed**

| ID | Item | Status | Check |
|---|---|---|---|
| OA17 | Tech-scoped nuclei, as an option. Pass httpx's technologies as nuclei tags instead of running the whole template set at `NUCLEI_SEV`. Outcrop already runs one pass; AutoAR runs `http/` and then three of its subtrees again | Planned | lab A/B: findings per minute, and every finding of the full run still found |
| OA18 | Stage events. Each stage writes its start, end and counts to run.json or a JSON-lines file, for Tideline's run timeline (TA3) | Planned | suite; lab run |
| OA19 | Post-probe analyses at once. `--takeover`, `--dns-posture`, `--extras`, `--origin`, `--screenshots` and `--tls` read the same httpx output; run them at once behind one shared connection budget | Planned | farm A/B: faster wall time, identical output, the `--rate` budget held |

**Housekeeping**

| ID | Item | Status | Check |
|---|---|---|---|
| OA20 | Lab names. The lab writers behind Tideline's `schemas/fixtures/run-recon/` use `ex.com` and `nex.com`, which are registered to third parties, and `2.2.2.2`, an allocated address. Use reserved names (`example.com`, `.test`) and the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) | Planned | suite; Tideline's `regen.sh` rebuilds the fixtures |

## Done (for reference)

- **1.20.0 (Batches 3–6 and the follow-ups; `VERSION` set by PR #8):** see sections 3–8.

- **1.19.0 (Batch 2):** 17 HTTP columns from the enrichment request (no extra traffic); favicon hashes;
  real favicon-hash pivot feeding `--origin`; `ptr` under `--enrich`; `--extras` (robots.txt, security.txt,
  404 probe); report HTTP posture and findings; `bench-run-recon.sh http`; httpx cache key `httpx_json_v2`.

- **1.18.0:** `--zone-exposure`; verified `--origin` with `.edge.tsv`; screenshot routing and validation;
  seed-resolving preflight, per-seed warnings, exit 3, `run.json`; TLS chain validation and the 30-day
  threshold; crawl-junk filter; report rebuild; lab fixtures and `bench-run-recon.sh checks`.
- **1.17.0:** ProjectDiscovery coverage batch 1 (nuclei callbacks off, asnmap key check, CNAME takeover
  check, katana resolvers/proxy, stdin closed, late HTTPS retry, CSV formula guard, pinned versions).
