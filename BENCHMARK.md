# run-recon benchmark & regression lab: method, results, checklist

This is WebInventory's `PERFORMANCE.md` process applied to run-recon: build a lab
with known answers, measure the current version, write a checklist of candidate
changes, A/B each one, and keep a change only if it is **faster and produces
field-for-field identical output**. Accuracy fixes are the one exception: they
are kept because the output changes, and every changed field is accounted for
below.

Every number here was taken with the real ProjectDiscovery toolchain against the
container lab in `lab/`, using `bench-run-recon.sh`. Re-run them on your Kali VM
before quoting them.

## How it was measured

- **Machine:** 2 vCPU / 8 GB Linux VM (kernel 6.18), Docker 29.9 (runc), the
  same class of box as WebInventory's "2 vCPU Linux container". Bash 5.2,
  Python 3.13.
- **Toolchain:** httpx 1.12.0, katana 1.8.0, tlsx 1.2.2, dnsx 1.2.2,
  subfinder 2.17.0, naabu 2.7.0 (the official release binaries), gau 2.2.4 and
  waybackurls (built from source). uro, anew and waymore were not installed;
  run-recon reports them as "degraded" and they are not used by these scenarios.
- **Lab (4 seeds):** `nginx.test`, `wp.test`, `spa.test`, `ci.test` behind a Caddy
  TLS ingress, with lab DNS (CoreDNS) for `.test`. Pinned backends: nginx 1.21.6,
  WordPress 6.4.3 on Apache 2.4.57 / PHP 8.2.17, nginx serving a 120 KB SPA,
  Jenkins 2.426.1 on Jetty 10.0.17. This is WebInventory's farm mix. Ground truth:
  `lab/expected.csv`.
- **Farm (50 seeds):** `f01..f50.farm.test`, round-robin over the same four
  backends. Ground truth: `lab/expected-farm.csv` (generated with the vhosts).
- **Flags:** `--tls --ipv6` on every scenario (TLS posture and AAAA are part of
  the ground truth), plus `--resolvers lab/resolvers.txt --no-report`.
- **Method:** 3 runs per scenario, medians. Wall clock and CPU (user + system of
  the whole run-recon process tree, every tool it starts included) come from GNU
  `time -v`. Each run executes in a fresh working directory.
- **Accuracy:** every run is scored against ground truth: each expected host must
  be present with the expected status, technologies, CPEs, TLS flags and IPv6
  addresses. One missed field fails the run.
- **Identity (the A/B bar):** `compare A B --exact` compares two runs' CSVs field
  by field on `(seed_domain, url)`. `cert_not_after` is ignored because Caddy
  reissues its 12-hour lab certificates.
- **Baseline:** v1.15.2 as delivered before this work, frozen. The candidate is
  v1.16.0. **Leave-one-out:** the candidate with one change switched back, run in
  the same session, so each item's contribution is measured on its own.

## Headline: v1.15.2 vs v1.16.0

| Scenario | v1.15.2 wall s | v1.16 wall s | speed-up | v1.15.2 CPU s | v1.16 CPU s | peak RSS MB (old→new) | accuracy v1.15.2 | accuracy v1.16 |
|---|---:|---:|---:|---:|---:|---|---|---|
| lab (3 runs) | 70.17 | 23.27 | **3.02x** | 12.64 | 12.71 | 243→241 | 3/3 here; **10/12** across all sessions | 3/3; every run in every session |
| farm, `-t 5` (1 run each) | 363.10 | 156.49 | **2.32x** | 84.07 | 80.03 | 232→237 | 0/1: one host lost its TLS posture | 1/1 (3/3 in the `-t 5` scenario) |

The final v1.16 build (with the late retry, item 8) measured 22.78 s wall and
12.85 s CPU on the lab, and its output was `--exact` identical to the A/B
candidate's. A v1.15.2 farm run takes six minutes, so the farm baseline was run
once.

The speed-up comes from one accepted change: v1.15.2 waited 10–116 s per seed
on public archives (Wayback, Common Crawl, OTX, urlscan) for names under `.test`,
which cannot exist on the internet. Medians of the v1.15.2 lab baseline across
four sessions were 45.7, 54.6, 64.9 and 70.2 s; that spread is all archive
latency. v1.16's lab medians stayed between 23.2 and 24.0 s. CPU is flat
because the time removed was spent waiting, not computing.

**Accuracy finding: v1.15.2 lost data under concurrency.** In 2 of its 12 lab runs
the Jenkins seed came back with no status, no technologies and no CPEs. Jenkins is
the slowest backend, and v1.15.2 ran httpx with no retries, so one transient
failure blanked the row silently. Its farm run lost a host the same way:
`f41`'s HTTPS probe failed once, httpx fell back to `http://`, and the host lost
its TLS posture. v1.16 matched ground truth in every lab run, in every farm run at
`-t 5` and `-t 10` (13 runs), and in every `-t 20` run once the late retry was in
(6 runs). This is the same class of problem WebInventory's farm exposed in v2.0.2.

**Output changed (103 fields in the lab A/B), by design.** v1.15.2's rows were
partly wrong: `http://` rows carried the HTTPS response, and some rows carried
another page's record. Every one of the 103 changed fields traces to one of three
accuracy fixes (findings 2, 6 and 7 below). The accepted speed change was A/B'd
on its own and changed nothing.

## Where the time goes (v1.16, lab)

| stage | per seed | note |
|---|---:|---|
| passive collectors (gau, waybackurls, urlfinder) | 0 s | skipped for special-use names. v1.15.2: 10–116 s, archive latency, empty results |
| live-host probe (httpx) | ~1 s | |
| crawl (katana, depth 2) | 11 s (15 s for wp.test, 87 URLs) | katana 1.8 idles a full `-timeout` (10 s) after its last page. That floor dominates every small seed |
| TLS posture (tlsx) + AAAA (dnsx) | ~1 s | |
| enrichment (httpx -json) | 1–2 s (7 s for wp.test's 87 URLs) | |
| aggregation (CSV, CPE, joins) | < 1 s | |

On the farm the katana floor is the ceiling: 50 seeds × ~11 s spread over `-t`
workers. At `-t 5` that is ~110 s of the ~158 s run.

## Concurrency (farm, 50 seeds)

| `-t` | wall s | CPU s | peak RSS MB | accuracy | speed-up vs `-t 5` |
|---:|---:|---:|---:|---|---:|
| 5 (default) | 158.25 | 80.58 | 239 | 3/3 | 1.00x |
| 10 | 92.33 | 79.31 | 243 | 3/3 | 1.71x |
| 20, before the late retry | 72.17 | 81.45 | 243 | **1/3** (3 and 11 fields lost) | 2.19x |
| 20, `LATE_RETRY=0` (leave-one-out, same session as the next row) | 72.75 | 81.68 | 244 | 3/3 | 2.18x |
| 20, v1.16 (late retry) | 72.01 | 83.50 | 240 | 3/3 (6/6 over two sessions) | 2.20x |

CPU stays at about 80 s whatever `-t` is: the work is the same and only the
waiting overlaps. `-t 10` overlaps most of the katana idle time. Output at
`-t 5`, `-t 10` and a loss-free `-t 20` run is `--exact` identical.

**Accuracy finding: `-t 20` on 2 vCPU blanked hosts.** Before the late retry, 2
of 3 runs lost data. f17, f23 and f35 came back with no status, technologies or
CPEs, f21 lost its TLS flags, and f30's root row was blank. Each time, httpx or
tlsx failed all three of its attempts. httpx's retries fire back to back, so all
three land in the same load spike. The late retry (finding 8) waits a jittered
2–5 s and tries those URLs once more. In the six `-t 20` runs since, it fired twice
(f31 and f08, both single-page hosts whose only URL had failed). Both rows were
recovered, and both runs matched ground truth; without it, those two hosts would
have been blank. Losses are bursty: the leave-one-out build happened to get 3/3
in its session, which is why the evidence is the recovered rows rather than a
3-run accuracy score. Healthy runs pay nothing: if httpx or tlsx returned a
record for every input, no check runs (`-t 10`: 79.3 s CPU, as before).

## Database cache (`--db`), cold vs warm

PostgreSQL 16, set up with `recon-db.sh init` (the dedicated-role path). The
cache was purged before the cold run.

| scenario | wall s | CPU s | peak RSS MB | accuracy | output |
|---|---:|---:|---:|---|---|
| no `--db` (same session) | 23.99 | 12.95 | 237 | 3/3 | reference |
| `--db`, cold (purged) | 25.08 | 16.78 | 248 | 1/1 | identical to no `--db` |
| `--db`, warm (3 runs) | **2.57** | 3.06 | 32 | 3/3 | identical to cold and to no `--db` |

The warm run is **9.8x** faster than the cold one. The cache served the live
probe, the katana crawl, the TLS posture and the per-URL enrichment (102 entries:
4 + 4 + 4 + 90). Only the AAAA lookups and the aggregation ran, so the katana idle
floor disappears. A cold `--db` run costs 1.1 s more wall time and 3.8 s more CPU
than a run without the cache (psql round trips and cache writes). Each run's 90
rows went into `recon_hosts` through the real psql `\copy` path. That was the first
check of the `db_load_csv` column fix against a real PostgreSQL.

A warm run sends nothing to the targets: status, titles, technologies and TLS
posture come from the cache for up to `CACHE_TTL` (7 days). That is by design
(README §6). For change detection, lower `CACHE_TTL` or purge first. The passive
collectors had nothing to cache here, because special-use names skip them. The
passive-URL cache, the bigger win on public seeds, has to be measured on Kali.

## Shakedown findings (bugs the lab exposed)

Running the real toolchain against known answers found nine defects that the
mocked unit suite could not. All are fixed in v1.16 and each has a regression test
in `test-run-recon.sh` (the "shakedown" and "farm" sections).

| # | defect | evidence | fix |
|---|---|---|---|
| 1 | **AAAA parser read resolver chatter as addresses.** dnsx prints the EDNS OPT pseudo-section in `all`; the parser split it into tokens. | `spa.test` and `ci.test` (no AAAA records) got junk in the `ipv6` column | use `aaaa`, fall back to `AAAA` records in `all`, keep only values that parse as IPv6 |
| 2 | **`http://` rows got the HTTPS response.** Without `-nfs`, httpx tries HTTPS first whatever scheme the input has. | 85 of the 103 changed fields are on `http://` rows; 51 of them are just `HTTP/3` disappearing. Caddy advertises HTTP/3 only over HTTPS, so a real HTTP response cannot carry it | `-nfs` on the enrichment pass |
| 3 | **IP column held the hostname.** httpx 1.6+ puts the hostname in `host` and the IP in `host_ip`, with no `a`. | ASN/geo lookups were fed hostnames | read `host_ip` first |
| 4 | **Internal IPs were sent to third parties.** Loopback and RFC 1918 addresses went to Team Cymru (DNS), RDAP and, with `--osint`, Shodan InternetDB. | lab runs sent 127.0.0.1 to Team Cymru (`1.0.0.127.origin.asn.cymru.com`) | only `is_global` addresses are looked up; private ones are filtered out of the OSINT IP list |
| 5 | **Live hosts dropped when the crawl was empty.** | a run without katana produced 0 rows for 4 live seeds | each live host with no crawled URL gets a row (source `live`) |
| 6 | **No retries, so silent blank rows under load.** | while 4 crawls ran: 10 of 100 enrichment probes failed with `-retries 0`, 0 of 100 with `-retries 2`. v1.15.2 lost the Jenkins seed in 2 of 12 lab runs | `HTTP_RETRIES=2` on the probe and enrichment passes. Retries only fire on failures, so no time cost was measurable |
| 7 | **The URL join depended on input order.** `urlkey` dropped the query string, and exact and normalised keys shared one first-wins map. | the same records fed in 6 orders gave 6 different CSVs (1 after the fix). Three different oEmbed URLs all showed `content_length` 2204 (true values 2031, 2195, 2040); `https://wp.test` showed the 301/empty redirect record instead of 200 "Lab WordPress" | query-preserving key; exact, normalised and host-root tiers in separate maps; records sorted before indexing |
| 8 | **Load spikes beat httpx's retries.** The three attempts fire back to back, so all land in the same spike. | farm at `-t 20`: 1–3 hosts blank in 2 of 3 runs | late retry: URLs (enrichment) and hosts (TLS posture) that returned nothing get one more pass after a jittered 2–5 s pause (`LATE_RETRY=1`) |
| 9 | **`--db` negative-cached failed requests.** Enrichment and TLS-posture misses were stored as "no record" for `NEG_TTL` (1 day). | a load-induced blank would have been served from the cache on the next day's runs | those two stages store positive results only; the live probe and crawl keep their negative cache |

Finding 7 also had to be fixed before any A/B could be trusted. The first
leave-one-out run of the special-use skip reported 9 differing fields that were
pure join noise.

## The checklist

"Accepted" means faster in the A/B with identical output. "Accepted (accuracy)"
means kept because it makes the output correct.

| # | Recommendation | Source | Test | Result | Verdict |
|---|---|---|---|---|---|
| 1 | Skip passive internet sources (archives, subdomain APIs, GitHub) for RFC 6761/special-use names (`.test`, `.internal`, `.local`, `.home.arpa`, …); `SKIP_SPECIAL_USE=0` restores them | stage profile | lab, leave-one-out, 3 runs | 38.01 → 23.43 s (1.62x); output identical; 3/3 both | **Accepted** |
| 2 | Scheme-correct enrichment (`-nfs`) | shakedown #2 | lab A/B, diff attribution | 85 `http://` fields now describe the HTTP response | **Accepted (accuracy)** |
| 3 | httpx retries (`HTTP_RETRIES=2`) | shakedown #6 | concurrency experiment, 100 probes per setting; lab/farm accuracy | failures 10/100 → 0/100; v1.15.2 10/12 lab runs correct, v1.16 every run | **Accepted (accuracy)** |
| 4 | Deterministic, query-preserving URL join | shakedown #7 | same records in 6 orders | 6 distinct CSVs → 1 | **Accepted (accuracy)**, required for A/B |
| 5 | Live-host fallback rows | shakedown #5 | run without katana | 0 rows → one row per live host | **Accepted (accuracy)** |
| 6 | Read `host_ip`; validate AAAA values | shakedown #1, #3 | real dnsx/httpx output shapes | correct `ip` / `ipv6` columns | **Accepted (accuracy)** |
| 7 | No third-party lookups for non-public IPs | shakedown #4 | resolver log | no Cymru/RDAP/InternetDB query for private addresses | **Accepted (privacy)** |
| 8 | Late retry for enrichment and TLS posture (`LATE_RETRY=1`) | farm accuracy at `-t 20` | farm `-t 20` leave-one-out, 2 sessions; lab and `-t 10` for cost | 2 hosts recovered that would have been blank; `-t 20` 1/3 → 6/6. Lab and `-t 10` output identical, CPU unchanged (12.85 s, 79.3 s) once a no-python check skips healthy runs | **Accepted (accuracy)** |
| 9 | Store only positive enrichment/TLS results under `--db` | finding 9 | mocked DB test | no `!neg` entry written for a failed URL | **Accepted (accuracy)** |
| 10 | Raise the default `-t` from 5 | farm scaling | farm at 5/10/20, 3 runs each | `-t 10` 1.71x faster, identical output, 3/3; `-t 20` 2.20x and accurate only with item 8 | **Not changed**: on public seeds more workers means more parallel archive and API queries, and Wayback/Common Crawl rate-limit (429). The lab cannot measure that, so it is a Kali A/B. Use `-t 10` for internal or lab seeds |
| 11 | Lower katana `-timeout` to cut its 10 s idle floor | stage profile | not adopted | the floor is katana waiting for slow responses; a lower value drops slow but real pages, the reason WebInventory rejected its item 13 | **Rejected (accuracy)** |
| 12 | One katana run for all seeds instead of one per seed | stage profile | not adopted | would pay the 10 s floor once, but per-seed workers are the unit of scope, caching and failure isolation; at `-t 10` the floor is already overlapped | **Not adopted** |
| 13 | Run the passive collectors in parallel per seed | stage profile | not testable here | Wayback and Common Crawl are unreachable from the lab host, and special-use seeds skip them; parallel queries also raise 429 risk | **Kali A/B** |
| 14 | Negative-cache an empty passive-URL set (and read the `subs!neg` / `certsan!neg` entries, which are written but never read) | `--db` scenario, code review | not adopted | gau exits 0 when its providers fail, so "no URLs" cannot be told apart from "archive unreachable". Caching that would hide real URLs for `NEG_TTL` (1 day). Needs a per-provider success signal first | **Not adopted** (accuracy risk) |
| 15 | DB cache warm reuse | `--db` scenario | cold vs warm | warm 2.57 s vs cold 25.08 s (9.8x); output identical to cold and to a run without the cache; a cold run costs +1.1 s wall, +3.8 s CPU | **No change needed** |

## How this compares with WebInventory

- **Same services, same answers.** The lab is WebInventory's farm mix (nginx, a
  WordPress site, a 120 KB SPA, TLS Jenkins) at pinned versions. The expected
  products and NVD CPE names are the ones WebInventory's rules identify for those
  services: `f5:nginx`, `wordpress:wordpress`, `apache:http_server`, `php:php`,
  `jenkins:jenkins`, `eclipse:jetty`, each with its version. run-recon v1.16 emits
  all of them in every run.
- **Same method.** Same machine class, 3 runs, medians, process-tree CPU,
  field-by-field accuracy against ground truth, leave-one-out A/B, and the
  "faster and identical" bar.
- **Same lesson.** Both baselines lost data under load: WebInventory v2.0.2 in
  every farm run (450–720 fields), run-recon v1.15.2 in 2 of 12 lab runs (the
  Jenkins seed). In both cases the fix was an accuracy fix, not a speed change.
- **Semantic gap: untrusted certificates.** WebInventory's `CertUntrusted`
  validates the chain. tlsx's `untrusted` only means "issued by a known untrusted
  or interception CA", so run-recon does not flag a private CA such as Caddy's.
  Both tools flag the 12-hour certificates as expiring.
- **Different shape.** WebInventory is a port scanner. Its `tarpit`, `closed` and
  `filtered` scenarios measure connect handling, which run-recon delegates to
  naabu and does not do by default. run-recon's farm is 50 vhosts behind one
  ingress, not 200 services on 50 hosts.
- **Not run here:** WebInventory itself. Its code is not available in this
  environment. For numbers side by side, run it on the same Kali box under
  PowerShell 7 against `lab/targets.txt` on ports 80 and 443, and score its
  products and CPEs against `lab/expected.csv`.

## What did not change

- The default probe set, timeouts, rate limit, thread count and output schema.
- Public seeds get exactly the same passive sources as before. The skip applies
  only to special-use names.
- The three new knobs default to the new behaviour: `HTTP_RETRIES=2` (`0` = one
  attempt, the old behaviour), `LATE_RETRY=1` and `SKIP_SPECIAL_USE=1`. Each is
  also the leave-one-out switch for its A/B.

## Reproduce

```bash
./bench-run-recon.sh up --farm 50
sudo sh -c './bench-run-recon.sh hosts >> /etc/hosts'
./bench-run-recon.sh bench --runs 3 --flags "--tls --ipv6"                          # lab
./bench-run-recon.sh bench --runs 3 --farm --flags "--tls --ipv6 -t 10"             # farm
./bench-run-recon.sh bench --runs 3 --flags "--tls --ipv6" \
    --baseline-script /path/to/old/run-recon.sh --results results.psv               # A/B vs an older version
SKIP_SPECIAL_USE=0 ./bench-run-recon.sh bench --runs 3 --flags "--tls --ipv6"       # with passive sources
./bench-run-recon.sh down
```

`--baseline-script` runs both versions in the same session, prints the speed-up
and the `--exact` verdict, and appends one line per scenario to `--results`.
`lab/README.md` covers ports, DNS and proxies.

## Validated here vs on your Kali VM

- **Here:** everything above, on the real toolchain, against the container lab.
- **On Kali:** anything that needs the internet. That covers the passive
  collectors (Wayback and Common Crawl are unreachable from this host), rate
  limits at higher `-t`, the DB cache on public seeds, and the archive queries
  that the special-use skip removes. Those are items 10, 13 and 14 in the
  checklist.

## v1.17.0: ProjectDiscovery coverage batch

Same lab, same method (3 runs, medians, process-tree CPU, ground-truth accuracy, `--exact` identity).
This batch changes opt-in stages (`--takeover`, `--nuclei`, ASN seeds) and fixes found by running the
real binaries; the default path had to stay as fast and produce identical output. The full finding list
and the WebInventory parity table are in `TOOL-COVERAGE.md`.

### Default path: v1.16.0 vs v1.17.0 (both on tlsx 1.4.0 + dnsx 1.3.1)

| Scenario | v1.16.0 wall s | v1.17.0 wall s | v1.16.0 CPU s | v1.17.0 CPU s | accuracy v1.16 / v1.17 | `--exact` |
|---|---:|---:|---:|---:|---|---|
| lab, `--tls --ipv6` | 23.79 | 23.18 | 11.91 | 11.97 | 3/3 / 3/3 | identical |
| farm, `-t 10` | 95.24 | 96.16 | 86.08 | 87.05 | 3/3 / 3/3 | identical (63 rows) |

Within run-to-run spread (farm runs 91.6–97.9 s on both sides). The new start-up version check costs
about 0.24 s (four tools in parallel). In one v1.17 farm run the new HTTPS retry in the live probe fired
for `f45` (HTTPS had failed under load) and recovered it.

### Tool versions: tlsx 1.2.2 → 1.4.0, dnsx 1.2.2 → 1.3.1 (same run-recon)

| Scenario | 1.2.2 wall s | 1.4.0/1.3.1 wall s | 1.2.2 CPU s | 1.4.0/1.3.1 CPU s | accuracy 1.2.2 / new | `--exact` |
|---|---:|---:|---:|---:|---|---|
| lab | 25.69 | 24.14 | 13.88 | 14.20 | 3/3 / 3/3 | identical |
| farm, `-t 10` | 96.74 | 99.20 | 84.97 | 90.71 | 2/3 / 3/3 | 1 row differs: a katana crawl artifact (`…/%5C/wp.test%5C/…emoji…js`), same katana on both sides |

The 1.2.2 farm miss was the live-probe HTTPS fallback (finding 9), not a tool difference. The newer
versions cost about 6% more CPU on the farm; their output is identical, so they are pinned (pdtm's current
catalog). dnsx 1.3 changed `-rcode` output, which the takeover check had to work around (finding 5): an
example of why every version is pinned and logged.

### Takeover check (lab CNAME fixtures)

`bench-run-recon.sh takeover`: `orphan.test → gone.cloud.test` flagged as a dangling CNAME, the healthy
`alias.test → nginx.test` not flagged, CNAME inventory complete, subzy banner not recorded. **PASS**, with
the same findings on dnsx 1.2.2 and 1.3.1.

### Two results from this session, corrected

- A first v1.16.0 lab A/B lost the `wp.test` crawl (1 URL instead of 87, 86 fields different). The cause
  was katana ignoring `--resolvers` (finding 7): the lab host had restarted without its `/etc/hosts`
  entries, and v1.16.0's katana used the system resolver. It was not stdin, as first suspected: per-seed
  workers get `/dev/null` from xargs. With `/etc/hosts` restored, v1.16.0 and v1.17.0 are identical (table above).
- The `--interactsh-server` path aborted its worker under `set -e` (a false last test in a helper), and
  three new checks called an undefined `die`. Both were caught by the suite before release.

## v1.18.0: report review fixes, zone exposure, verified origin

Same lab, same method. v1.18 adds two opt-in checks (`--zone-exposure`, a rebuilt `--origin`), fixes
the eleven issues in `REPORT-REVIEW.md`, and adds chain validation to `--tls`. Two output changes were
intended and are the only ones the A/B found: URLs built from JSON-escaped paths are dropped (all paths),
and every lab certificate is now `CertUntrusted` (`--tls`). Baseline: v1.17.0, frozen.

### A/B: v1.17.0 vs v1.18.0

| Scenario | v1.17.0 wall s | v1.18.0 wall s | v1.17.0 CPU s | v1.18.0 CPU s | accuracy v1.17 / v1.18 | `--exact` differences |
|---|---:|---:|---:|---:|---|---|
| lab, default flags | 25.21 | 20.24 | 10.20 | 9.71 | n/a (no `--tls`) | 3 rows, all `wp.test/%5C/…` crawl junk |
| lab, `--tls --ipv6` | 23.15 | 23.67 | 10.90 | 10.94 | 3/3 / 3/3 (old ground truth); 0/3 / 3/3 with `CertUntrusted` | 3 junk rows + `CertUntrusted` on all 35 https rows |
| farm, `--tls --ipv6 -t 10` | 86.57 | 88.84 | 67.34 | 71.84 | 0/3 / 3/3 (new ground truth) | 13 junk rows (one per WordPress vhost) + `CertUntrusted` on 50 rows |
| farm, `--tls --ipv6 -t 10`, `TLS_CHAIN_CHECK=0` (leave-one-out) | 87.59 | 86.72 | 68.75 | 67.00 | (no `CertUntrusted`, by design) | 13 junk rows only |

- **Default path:** no slower (the 25.2 s baseline median includes a 28 s outlier; CPU is within 5%). The 3
  dropped rows are the crawl artifacts the report review found (`http://wp.test/%5C/wp.test%5C/index.php`).
- **Chain validation cost:** with it off (leave-one-out row), v1.18 matches v1.17 (86.7 s vs 87.6 s, CPU
  67.0 s vs 68.8 s) and only the junk rows differ. With it on, the farm takes 88.8 s / 71.8 s CPU: about
  2 s wall and 5 s CPU for 50 seeds (one Python process and one TLS handshake per host, 16 in parallel),
  about 0.5 s on the lab. It is an accuracy fix in an opt-in stage, so it is kept; `TLS_CHAIN_CHECK=0` turns
  it off.
- **Ground truth updated:** `lab/expected.csv` and the farm generator now expect `CertExpiring;CertUntrusted`
  (Caddy's local CA is not in the system trust store; WebInventory flags it the same way). v1.17 scores 0/3
  against it by design.

### Lab fixture checks (real tools)

`bench-run-recon.sh checks` → **PASS** on all three:

| Check | Result |
|---|---|
| takeover | `orphan.test` dangling, `alias.test` not flagged, CNAME inventory complete |
| zone | `xfr.test`: `zone-transfer-open [high]`, 8 records, `hidden-ops` and `staging-api-2019` harvested; `walk.test`: `nsec-zone-walkable [medium]`, 5 names incl. `secret-admin`; `test.`: `zone-checked [info]` only; harvested names probed and in the CSV |
| origin | `origin-exposed [high] host=nginx.test origin=127.0.0.5 port=80 via=direct.nginx.test,spf match=body-sha256 edge=Caddy`; nothing for spa.test / wp.test; `edge.tsv` names Caddy → nginx/1.21.6 and Caddy → Apache/2.4.57 (Debian) |

### What the lab showed while building this

- **The resolver preflight passed a broken DNS.** When the lab zone failed to load, CoreDNS answered SERVFAIL
  for every name; v1.17's check only needed *a* reply, so it passed, and the run wrote 0 rows and said
  "Complete.". v1.18 resolves the first seed and exits 3 on an empty run. (The same thing happened again
  in this session after a restart: a synced copy of the Corefile reverted to the `test.zone` version; the new
  preflight would have stopped it at once.)
- **Headless Chrome ignored `NO_PROXY`.** The v1.17 lab screenshots were the outbound proxy's error page or
  0-byte files. With `--proxy-bypass-list` the browser reached the lab: nginx 33.6 KB, WordPress 1.28 MB,
  Jenkins 60 KB, SPA 4.7 KB; the 12 zone-fixture names served by Caddy's default site are `blank`.
- **`ldns-walk` stops at the apex against CoreDNS**, because of how CoreDNS answers denials; asking each
  owner name for its NSEC record walks the whole chain and is what run-recon does.
- **CoreDNS cannot serve an NSEC3-signed zone**, and a failed reload keeps the previous configuration live,
  so NSEC3 is covered by the suite's mocks only.
