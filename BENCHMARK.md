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

## v1.19.0: Batch 2, HTTP detail

Same lab, same method; baseline v1.18.0 frozen from the repository tag. Batch 2 appends 17 columns and
adds opt-in stages (`--extras`, the favicon-hash pivot in `--favicon`, `ptr` under `--enrich`). The
default path gets the header-derived columns from the request it already sends (`httpx -irh -hash
sha256`), so it had to stay as fast with identical output on every existing column.

The lab changed for this batch (robots.txt, security.txt and security-header fixtures in the
Caddyfile, a basic-auth `/private/` and `vpn-legacy.walk.test`, a reverse zone). Both versions ran
against the same lab, so the A/B holds; absolute times are not comparable with the v1.18 section
(the same v1.18.0 farm run took 94.4 s here and 88.8 s there; the lab host restarted between the two).

### A/B: v1.18.0 vs v1.19.0

| Scenario | v1.18.0 wall s | v1.19.0 wall s | v1.18.0 CPU s | v1.19.0 CPU s | accuracy | `--exact` on existing columns |
|---|---:|---:|---:|---:|---|---|
| lab, default flags | 22.52 | 21.94 | 11.01 | 11.28 | n/a (no `--tls`) | identical (87 rows) |
| lab, `--tls --ipv6` | 23.11 | 23.22 | 12.58 | 12.59 | 3/3 / 3/3 | identical (87 rows) |
| farm, `--tls --ipv6 -t 10` | 94.39 | 94.90 | 84.09 | 84.19 | 3/3 / 3/3 | identical (50 rows) |

Within run-to-run spread on all three. `compare --exact` lists the 17 new columns as "only in B (new, not
compared)". `response_ms` is now treated as volatile by `--exact`, like `cert_not_after`.

### Cost of `--extras` (v1.19.0, same flags with and without)

| Scenario | without wall s | with wall s | without CPU s | with CPU s | `--exact` |
|---|---:|---:|---:|---:|---|
| farm (50 single-host seeds), `--tls --ipv6 -t 10` | 92.99 | 132.69 | 83.15 | 170.93 | only `robots` (50), `security_txt` (50), `favicon_*` (12 Jenkins vhosts) differ |

`--extras` sends 4 GETs per live root plus the favicon fetch, and starts two httpx processes per seed. Each
httpx run costs about 0.85 s of CPU however few requests it makes (measured: 0.84 s for one host), so the
cost follows the number of **seeds**, not hosts: the farm, with one host per seed, is the worst case (+40 s
wall, about 2x CPU on 2 vCPUs). Merging the favicon fetch into the paths pass was measured and rejected:
httpx then fetches the favicon once per path (4x the favicon requests). A single pass with `/favicon.ico`
hashed locally is listed in `PLAN.md` (F10).

### Lab fixture checks (real tools)

`bench-run-recon.sh checks` → **PASS** on all four (takeover, zone, origin, http). The new `http` check:

| Fixture | Result |
|---|---|
| nginx.test (nginx defaults) | all four security headers missing; body SHA-256, response time, Alt-Svc h3 recorded |
| spa.test (full headers) | nothing missing (CSP `frame-ancestors` covers X-Frame-Options), HSTS max-age 31536000 |
| vpn-legacy.walk.test | `Basic realm="Legacy VPN"` over HTTP → `CleartextAuth` |
| nginx.test robots.txt → `/private/` | URL row with source `robots`, 401 Basic over HTTPS, not flagged cleartext |
| security.txt | nginx.test expired → `security-txt-expired [low]`; spa.test present |
| www.walk.test | `catch-all-200` from the 404 probe |
| ci.test | Jenkins favicon mmh3 `81586312`; session cookie Secure + HttpOnly (no issue) |
| wp.test | `wordpress_test_cookie` without HttpOnly (and without Secure on HTTP) |
| reverse zone | `ptr=ingress.lab.test` for 127.0.0.1 via the lab resolver |

### Found while building this

- **The suite's own mocks produced invalid JSON.** printf turned `\n` and `\"` inside the mock's JSON strings
  into raw characters, so every enriched record was dropped; 17 tests failed until the mock escaped them.
  The aggregator unit test, which writes its input with Python, passed throughout.
- **dockerd started with `nohup … &` does not survive the end of a turn in this environment**, which looked
  like the lab "breaking" between sessions. Started as a tracked background process it stays up. The new
  run-integrity checks reported it correctly: "no resolver answered", per-seed "none resolved", exit 3.

## v1.20.0: the v1.18 follow-ups (F1–F10)

Same lab and method; baseline v1.19.0 frozen from its tag (`938f58e`). The lab gained three fixtures for
this work (`origin.spa.test` → a 403-only address, `nsec3.test` on BIND 9.18, nothing else changed), and
both versions ran against the same lab.

### A/B: v1.19.0 vs v1.20.0-dev

| Scenario | v1.19.0 wall s | v1.20 wall s | v1.19.0 CPU s | v1.20 CPU s | accuracy | `--exact` |
|---|---:|---:|---:|---:|---|---|
| lab, `--tls --ipv6` | 24.15 | 22.55 | 12.70 | 12.89 | 3/3 / 3/3 | identical (87 rows; 8 `body_sha256` noise) |
| farm, `--tls --ipv6 --extras -t 10` | 128.75 | 113.05 | 174.42 | 132.37 | 3/3 / 3/3 | identical (50 rows; 3 `robots` noise) |

The lab is within run-to-run spread, as it should be: nothing on the default path changed except the chain
check, which now runs once on the merged records (F8). On the farm, `--extras` now costs one httpx run per
seed instead of two (F10): 42 s of CPU saved over 50 seeds, 0.84 s each, exactly one httpx start-up per
seed, and 1.14x on wall time. The favicon hashes it computes in Python are the values httpx's `-favicon`
gave (Jenkins: `81586312`), so the `favicon_*` columns are identical.

**The noise floor.** `compare --exact` now takes `--noise OTHER-RUN`, and `bench` passes the baseline's other
runs: a field that already differs between runs of the **same** version is noise, not a difference between
versions, and is listed instead of compared. On the lab that is 8 `body_sha256` values of WordPress oEmbed
responses, which embed a random secret per request (two v1.20 runs differ on the same 8 fields); on the farm,
the `robots` column of 3 WordPress vhosts, whose robots.txt fetch is occasionally slow enough to time out.
Before this, the lab A/B reported "DIFFERENT (8 fields)" for two identical builds.

### Lab fixture checks (real tools)

`bench-run-recon.sh checks` → **PASS** on all four. New in the zone and origin checks:

| Fixture | Result |
|---|---|
| nsec3.test (BIND 9.18, NSEC3 1 0 5 1A2B3C4D) | `nsec3-hashes-exposed [low] params="1 0 5 1A2B3C4D"`, names not walked, `dnssec-unanchored [low]` |
| walk.test | as before, plus `dnssec-unanchored [low]` (no DS in `test.`) |
| origin.spa.test → 127.0.0.6 (403 to everything, 443 closed) | `origin-protected [info] ... reason=443:refused,80:status-403-other-content` |
| ci.test favicon, now hashed locally | mmh3 `81586312` |

Screenshots, checked by hand against the lab (no bench check yet): `secret-admin.walk.test`, which only the lab
DNS knows, was a 0-byte capture with v1.19.0 and is `ok` with v1.20 (`--host-resolver-rules`). gowitness 3
(latest, built from source) captured the lab with explicit URLs and the go-rod driver, 4 of 4 in two runs; with
its default chromedp driver, 4 of 5 runs got no image at all (the screenshot step timed out; status and title
were recorded).

### Found while building this

- **The origin verifier dropped fields after an empty one.** It split candidate lines with `IFS=tab read`, and
  tab is IFS whitespace, so an empty title collapsed into the next field and shifted the body hash, length and
  edge. A site without a title was compared on the wrong values. Lines are now split on `\x1f`. The protected
  origin fixture (`origin.spa.test`, a 403 page without a title) exposed it: its status code read as empty.
- **An awk `NR == FNR` idiom misfires when the first file is empty**: every line of the second file is taken as
  part of the first. It suppressed every `origin-protected` line until the test with no exposed origin caught it.
- **dnsx `-a -aaaa`** answers both families in one record; the mock answered only the last flag it saw.

## v1.20.0: Batch 3, email and DNS posture and discovery coverage

Same lab and method. The baseline is the follow-ups branch (`followups-v1.18`, frozen with `git archive`), so
the A/B isolates Batch 3. The lab gained the `posture.test` zone, two MTA-STS policies, a Terraform state, port
8443 on the ingress and two discovery names in `db.test`; both versions ran against the same lab.

### A/B and cost

| Scenario | baseline wall s | Batch 3 wall s | baseline CPU s | Batch 3 CPU s | accuracy | `--exact` |
|---|---:|---:|---:|---:|---|---|
| lab, `--tls --ipv6` (vs follow-ups) | 24.08 | 23.55 | 12.39 | 12.44 | 3/3 / 3/3 | identical (87 rows) |
| farm, `--tls --ipv6 -t 10`, without → with `--dns-posture` (same version) | 92.73 | 93.52 | 81.12 | 83.57 | 3/3 / 3/3 | identical (50 rows) |

The default path did not change. `--dns-posture` costs under a second of wall time and 2.5 s of CPU on 50
seeds: it runs once in the main process, mostly dig calls, and only names with MX or SPF records (and each
zone apex) get the mail checks.

### Lab fixture checks (real tools)

`bench-run-recon.sh checks` → **PASS** on all six (takeover, zone, origin, http, posture, discovery).

| Check | Fixture | Result |
|---|---|---|
| posture | posture.test | `spf-permissive [high]`, `mx-dangling [high]`, `ns-dangling [high]`, `ns-lame [medium] reason=refused` (BIND), `mta-sts-mx-mismatch [medium]`, `dmarc-none [low]`, `dmarc-no-rua`, `mta-sts-testing`, `tlsrpt-missing` (info); no CAA or lame finding for what is correct |
| posture | good.posture.test | no finding; the MTA-STS `enforce` policy fetched with Caddy's CA passed through `--mta-sts-ca` |
| posture | without `--mta-sts-ca` | `mta-sts-policy-unreachable [medium] reason=untrusted-certificate`: verification is on |
| posture | cloudlist, Terraform state | `127.0.0.1` matched to the inventory; `127.0.0.8` → `cloud-asset-unseen [info]` |
| discovery | naabu, ports 80,443,8443 | `https://nginx.test:8443` probed and inventoried |
| discovery | alterx | `grafana.nginx.test` (source `alterx`); absent from the baseline run |
| discovery | shuffledns + massdns (built from source) | `backup-db.nginx.test` (source `bruteforce`) |
| discovery | cdncheck | loopback edge untagged; `104.16.0.1 [waf] [cloudflare]` |
| discovery | `--monitor --notify` | the `:8443` URL is a new asset; one message reached the loopback webhook |
| discovery | uncover, no keys | "requires keys but no keys were found", now one run-recon warning |

vulnx 2.0.2 against its real API (no key) on the lab's CPEs listed 8 products, e.g. `f5:nginx` 41 CVEs (3 in
KEV), `apache:http_server` 352 (23 in KEV), `jenkins:jenkins` 294 (9 in KEV). These counts cover every version
of the product, which is why `--vulnx` reports leads, not findings. tldfinder could not be run inside the lab:
in `-dm tld` mode it resolves through public DNS whatever `-r` says.

### Found while building this

- **`--origin` with `--ports` compared against the wrong service.** The reference response of a host was its
  first https record, which on the discovery fixture was the `:8443` service (another page, another Server
  header): `edge.tsv` then said "no edge" for nginx.test. The reference is now the default port's response.
- **The suite's dig mock answered the resolver preflight's header before any fixture**, so every posture
  answer read as NOERROR and NXDOMAIN-based checks could not fire. The posture fixtures now answer first.
- **`cloudlist` writes a default provider config on first run**, so "no config" could not be tested against
  `$HOME`; the test runs with an empty `HOME`.

## v1.20.0: Batch 4, evidence and history

Same lab and method. The baseline is the Batch 3 branch (`batch-3-email-dns`, frozen with `git archive`), so the
A/B isolates Batch 4. No lab fixture changed; the three new checks use the existing names.

### A/B: the default path

| Scenario | runs per side | Batch 3 wall s | Batch 4 wall s | Batch 3 CPU s | Batch 4 CPU s | `--exact` |
|---|---:|---:|---:|---:|---:|---|
| lab, `--tls --ipv6` (3 sessions, one with the order swapped) | 9 | 24.42 | 25.09 | 15.23 | 15.68 | identical (87 rows), all sessions |
| farm, `--tls --ipv6 -t 10` (2 sessions, one swapped) | 6 | 97.6 | 99.4 | 93.4 | 95.6 | identical (50 rows), both sessions |
| lab, interleaved run by run (old / new, 4 rounds) | 4 | 24.67 | 24.07 | 14.81 | 14.43 | — |
| 6 farm seeds without WordPress, 2 interleaved blocks of 5 | 10 | 18.00 | 17.95 | 10.95 | 10.85 | — |
| farm, `--passive-only` (framework cost only), 2 blocks of 5 | 10 | 2.39 | 2.55 | 4.34 | 4.55 | — |

The output of the default path is identical. The session medians differ by 2–3 %, which is inside the lab's spread
(one run of either version reached 29–31 s), and the difference disappears when the versions are interleaved run
by run. The 6-seed control shows Batch 4 0.1 s lower in CPU. The only cost that shows up consistently is a fixed
one, measured on `--passive-only` runs. It comes from what a run now does once, at the start and the end: two
short hashes for the state file, and the manifest. On a 50-seed run that is about 0.2 s of CPU. The check for
ignored input lines was then changed to start Python only when a line does not count as a seed.

One farm run of Batch 4 (1 of 12) lost WordPress's version on f06: httpx's technology detection saw a page
without the version marker under load. The enrichment code did not change in this batch.

### Lab fixture checks (real tools)

`bench-run-recon.sh checks` → **PASS** on all nine (takeover, zone, origin, http, posture, discovery, scope,
resume, history), with `RECON_DB_DSN` pointing at a PostgreSQL 16 database for the history check.

| Check | What was run | Result |
|---|---|---|
| scope | `--list-targets`, ci.test outside the scope | exit 2; `ci.test` OUT OF SCOPE, no work dir |
| scope | `--origin --screenshots`, names only | no origin contacted; `127.0.0.5` in `.scope.txt` as held back; the browser (Chrome rules with `MAP * ~NOTFOUND`) still renders nginx.test |
| scope | the two origin addresses allowed | `origin-exposed` nginx.test → 127.0.0.5 and `origin-protected` spa.test, as without `--scope` |
| scope | `!127.0.0.5`, `!backup-db.nginx.test`, brute wordlist finding both | neither name in the CSV; `direct.nginx.test` held back with its address. **The origin's own access log: unchanged during the run (31 → 31, and 39 → 39 in the full `checks` run)**; the same run without `--scope`: +5 |
| scope | `!mta-sts.posture.test` | the MTA-STS policy was not fetched ("outside --scope" in the posture table) |
| resume | 4 lab seeds, `-t 1 --tls`, SIGTERM after 2 | exit 143, state `interrupted`; `--resume` ran the other 2; **CSV `--exact` equal to an uninterrupted run** (87 rows; body hashes of wp.test as the noise floor) |
| history | spa backend stopped between two runs | `.delta.tsv`: spa.test status 200 → 502, title, server, technologies, CPE; nothing for the three other hosts; the report's Changes section |
| history | `recon-db.sh changes` / `history` | the same events from the run CSVs (`--csv`) and from the PostgreSQL store (`--db`); nginx.test present with first/last seen |

The store was also checked by hand against PostgreSQL 16: a 1.19-shaped `recon_hosts` table with one row was
migrated in place by the first import, three runs imported, and `changes` did not compare `cpe` against the old
run (its CSV never had the column).

katana's crawl-scope flags were checked on a loopback server before relying on them: with `-fs rdn`, a page
linking to two siblings and an outside name; `-cos` kept a sibling out, `-cs` restricted the crawl further (it
applies on top of `-fs`), and `-cos` wins over `-cs`.

### Found while building this

- **`--monitor --db` could not see a change.** The cache served the live probe and enrichment records from the
  previous run (7-day TTL), so the history check's stopped backend still read 200. Under `--monitor`, every
  target-facing result is now measured afresh and only stored (`CACHE_FRESH_ACTIVE`); passive lookups still
  come from the cache.
- **A pipeline in the new screenshot code aborted the worker.** `{ ...; [ scope ] && cat; } | sort` ends with a
  false test when there is no scope, and under `pipefail` + `set -e` that killed the seed's worker before the
  CMS and active scans. The suite's `--all` case caught it.
- **The heartbeat's `sleep` kept the work-dir lock.** Killing the heartbeat subshell orphaned its `sleep`, which
  still held the inherited lock descriptor, so an immediate `--resume` saw the run as still running. The
  heartbeat now starts without the descriptor and is killed after the process tree.
- **Children forked during the kill.** Killing a worker's children first let the worker start its next stage
  before it was killed itself. The tree is now frozen (SIGSTOP), listed again, terminated and continued.
- **A resume racing the live run** (found by the first version of the suite test, which signalled a subshell
  instead of run-recon) deleted the live run's seed directory. The work-dir lock makes `--resume` refuse a run
  that is still going.
- **The suite's AAAA test extracts code by a marker** (`-aaaa -json -silent`); the new dnsx call used the same
  argument order and was picked up first. The new calls use another order.

## v1.20.0: Batch 5, redirect chains, login forms and TLS parity

Same lab and method. The baseline is the Batch 4 branch (`batch-4-evidence`, frozen with `git archive`), so the
A/B isolates Batch 5. New fixtures: the redirect and login-form names in the Caddyfile, and the `tlslab` nginx
with four TLS fixtures (`lab/tls-nginx.conf`, certificates from `lab/gen-tls-certs.py`).

### A/B: the default path

| Scenario | runs per side | Batch 4 wall s | Batch 5 wall s | Batch 4 CPU s | Batch 5 CPU s | `--exact` |
|---|---:|---:|---:|---:|---:|---|
| lab, `--tls --ipv6` (2 sessions, one with the order swapped) | 6 | 22.79 | 22.31 | 10.00 | 10.04 | 2 fields differ, both justified (below) |
| farm, `--tls --ipv6 -t 10` (2 sessions, one swapped) | 6 | 85.40 | 86.61 | 64.88 | 65.37 | identical (50 rows), both sessions |
| farm, interleaved run by run (old / new, 4 rounds) | 4 | 85.78 | 86.09 | 65.11 | 65.07 | — |

The timings match within the run-to-run spread. In the farm sessions, the side that ran first was slower in both
(Batch 5 +1.3 s CPU when it went first, −0.2 s when it went second); run by run, the two are equal. Two fields differ, both on one row:
`http://wp.test/wp-login.php`, WordPress's login page, served on plain HTTP. It now carries `auth=Form` and
`http_flags=PlainHttp;CleartextAuth`. That is the new login-form detection reporting a real finding, the one
WebInventory reports as `Auth=Form` and `CleartextAuth`. The first session's comparison also listed four rows
"only in" one side. They were crawl variance in the baseline itself: Batch 4's own three runs had 87, 87 and 85
rows, and against an 87-row Batch 4 run the only differences were the two fields.

The new columns cost no request on the default path. `-er` adds one regex pass over each body inside httpx,
`-cert` adds the PEM to each tlsx record, and the CSV builder reads it with a stdlib DER parser. None of these
shows up beyond the noise.

### The opt-in paths

| Scenario | runs per side | without wall s | with wall s | without CPU s | with CPU s | what differs |
|---|---:|---:|---:|---:|---:|---|
| lab `--tls --ipv6 --extras`: Batch 4 → Batch 5, interleaved (6 rounds) | 6 | 23.68 | 26.22 | 13.39 | 14.04 | wp.test's two login rows (`Form`, `CleartextAuth`) |
| lab: `--tls --ipv6` → `--tls-enum --ipv6` (Batch 5) | 3 | 22.48 | 23.09 | 10.22 | 10.57 | `tls_supported`, `tls_ciphers` on every https row (35 rows) |
| farm: `--tls --ipv6 -t 10` → `--tls-enum --ipv6 -t 10` | 3 | 87.30 | 86.20 | 66.03 | 68.04 | the same two columns, 50 rows |

- **`--extras`** now follows redirects past the hops the run did not probe. That costs one httpx start (about
  1 s wall and 0.7 s CPU, all of it startup) per seed with such a hop. On the lab only wp.test has one
  (`/wp-admin/` → `wp-login.php?redirect_to=…`), and wp.test is the slowest seed, so the whole run waits
  for it. A seed with no redirect in its records starts nothing (a `grep` first), and after the first round
  a further round runs only when a hop itself redirected. The swapped sessions showed the same order effect
  as the farm; the interleaved rounds above are the measurement.
- **`--tls-enum`** costs one Python process per seed and six short handshakes per https host: about 0.35 s
  of CPU on the lab and 2 s on the 50-seed farm, with no change in wall time on the farm.

### Lab fixture checks (real tools)

| Check | What was run | Result |
|---|---|---|
| tls | `--tls-enum` on legacy/future/default/modern`.tls.test` | legacy: `tls_supported=TLS 1.2;TLS 1.1;TLS 1.0`, `tls_weak_cipher=TLS 1.2:TLS_RSA_WITH_NULL_SHA`, `RSA 1024` / `sha1WithRSAEncryption`, `WeakTLS;WeakCipher;WeakKey;WeakSig;SelfSigned`; future: `CertNotYetValid`; default: `DefaultCert`; modern: none, `EC P-256` |
| tls | the same matrix from tlsx (`-sm ctls -min-version V -max-version V`, one run per version) | agrees on every fixture |
| tls | the container's openssl, `-cipher NULL-SHA` | `Cipher is NULL-SHA`: legacy really accepts it |
| tls | legacy's chain | `CertUntrusted` (`self-signed certificate`) from the level-0 retry; Batch 4 gave no verdict |
| http | `https://redir.test/` (302 → `/login`) | `final_url=https://redir.test/login` through a hop `--extras` fetched; `login_form=http://redir.test/session`, `Form`, `CleartextAuth` on the HTTPS row |
| http | `https://redir.test/old` (301 → `https://elsewhere.test/`) | listed in `redirect_chain`, not followed |
| http | `http://redir.test/session` (from the form's action, via the crawl) | `301->https://redir.test/session` followed |
| http | `http://plainlogin.redir.test/` | `login_form=http://plainlogin.redir.test/login`, `PlainHttp;CleartextAuth` |
| http | (not a fixture) WordPress | `http://wp.test/wp-admin/` → `wp-login.php` on plain HTTP: `Form`, `CleartextAuth` |

`bench-run-recon.sh checks` → **PASS** on all ten (takeover, zone, origin, http, tls, posture, discovery, scope,
resume, history), the history check with `RECON_DB_DSN` pointing at a PostgreSQL 16 database. The daemon of
the lab's containers stopped during the full run, after the first seven had passed; scope, resume and history
were run again once it was back, and passed.

### Found while building this

- **`--tls-full` produced no CSV with tlsx 1.4.0, in every release since 1.17.** tlsx 1.4's
  `cipher_enum` holds a dictionary per version (`{"weak": [...], "secure": [...]}`), and the CSV builder
  passed that dictionary to the cipher-name check, which raised `AttributeError`. Reproduced with the CSV
  builders of v1.17.0, v1.19.0 and Batch 4 on a real `-ce` record. `--tls-full` is now an alias of
  `--tls-enum` and no longer calls `-ce`, and the parser flattens the dictionary anyway.
- **tlsx `-ce` misses suites.** On `legacy.tls.test` it listed the four CBC-SHA suites but not `NULL-SHA`,
  which the server accepts (the container's openssl negotiates it).
- **tlsx cannot offer weak suites.** With `-ci`, ctls refuses the names (`TLS_RSA_WITH_RC4_128_MD5 not
  supported`). ztls accepts them but sends a ClientHello with no cipher suites at all: the lab nginx logged `no
  ciphers specified`. The openssl mode ignored the list. So the weak-cipher probe, like the version matrix, is
  run-recon's own ClientHello, stopped at the ServerHello as WebInventory's is. It is independent of the local
  OpenSSL, which can no longer offer SSL 3.0 or RC4.
- **tlsx's `expired` is false for a certificate that is not valid yet.** `CertNotYetValid` comes from
  `not_before`; `CertExpired` now also from `not_after`.
- **The chain check gave no verdict on the weakest hosts.** The local OpenSSL (security level 2) refused the
  legacy fixture's handshake before verifying anything, so a self-signed RSA 1024 host went without
  `CertUntrusted`. One retry at level 0 fixes it; it only runs after such a refusal.
- **tlsx 1.4.0's default scan mode can hang on an open stdin.** When a handshake fails in `auto` mode, tlsx
  falls back to `openssl s_client`, which reads stdin: 40 s and more with stdin left open, under a second with
  `/dev/null`. run-recon already closes stdin at start-up (TOOL-COVERAGE finding 6), so only the bench's own
  tlsx cross-check was exposed; it now uses `-sm ctls` and a timeout.
- **Caddy's `redir /login 302` is a matcher.** In the first version of the fixture, `/login` was read as a path
  matcher and `302` as the target, so `/` answered an empty 200; it is `redir * /login 302`.
- **The lab image's OpenSSL has no 3DES or RC4.** Debian's OpenSSL 1.1.1n is built without them, so
  `legacy.tls.test` accepts `NULL-SHA` as its weak suite, which gives the same `WeakCipher`.
- **A suite file named `enum.py` shadowed Python's `enum` module** for the scripts next to it. The extracted
  probe is `tlsenum_probe.py` and runs with `-I`.

## v1.20.0: Batch 6, JSON output and shipping to Tideline

Same lab and method. The baseline is the Batch 5 branch (`batch-5-redirects-tls`, frozen with `git archive`), so
the A/B isolates Batch 6. Each comparison ran interleaved: the two sides alternated run by run, and the order
switched each round. Batch 5 showed this to be the reliable measurement; back-to-back sessions carry an order
effect.

### A/B

| Scenario | runs per side | A wall s | B wall s | A CPU s | B CPU s | `--exact` (noise floor from A's next run) |
|---|---:|---:|---:|---:|---:|---|
| lab `--tls --ipv6`: Batch 5 (A) → Batch 6 (B) | 6 | 23.26 | 22.75 | 10.21 | 10.13 | identical, 87 rows, every round compared |
| lab: Batch 6 `--tls --ipv6` (A) → the same with `--json` (B) | 6 | 22.25 | 22.79 | 10.07 | 10.18 | identical CSV |

- **Default path.** It is unchanged. The only addition is `run_id` in run.json, one read of
  `/proc/sys/kernel/random/uuid`, which is within the noise.
- **The noise floor.** It is needed on the lab. WordPress's oEmbed responses carry a random per-request
  `secret`, so their `body_sha256` differs between any two runs of the same version: eight fields, set
  aside by `compare --noise`. One round (the fourth) also had crawl variance in the baseline (85 rows
  instead of 87) and is not counted; Batch 5 saw the same.
- **`--json`.** It costs about 0.1 s of CPU on the lab: one `json.dumps` per row in the CSV builder, and
  one short Python pass over the side files before the manifest. The CSV is byte-identical.
- **The farm.** The farm A/B was cut short when the lab's Docker daemon reached its time limit after one
  run (Batch 5 default, 87.40 s wall / 65.24 s CPU, in line with the Batch 5 figures above). `--json`'s
  per-row cost scales with rows, not seeds.

### Shipping cost

`ship-recon.sh ship` of the lab run (12 parts: 6 JSONL files, the manifest, 4 screenshots; 1.7 MB raw,
1.34 MB gzip, mostly the PNGs) to the mock ingest on loopback, three times under new `run_id`s:
**0.87–0.90 s wall, 0.24–0.26 s CPU** (ship-recon, curl, openssl), all three delivered and verified. The cost is
one curl process and one TLS handshake per part, about 70 ms each. A seed-heavy run with hundreds of
screenshots pays that per image, sequentially. Reusing connections (curl `--next`, or one HTTP/2
connection) is the obvious improvement once a real Tideline exists to measure against. It does not
touch the scan: shipping starts after the run's manifest is written.

### Lab checks (real tools)

| Check | Result |
|---|---|
| ship (new) | PASS. A lab run with `--tls --ipv6 --takeover --dns-posture --screenshots` was shipped to `lab/mock-tideline.py`: 12 parts, all stored byte for byte; 87 URL records equal to the CSV row for row; 4 screenshots as `image/png`; one open (201), 12 PUTs (204), one complete (202). A second delivery: 200 and nothing re-sent. A 503 on part 2: exit 4, then a retry that sends only parts 2–12 |
| takeover, zone, origin, posture, resume | PASS on the final code |
| http, tls, discovery, scope | PASS on the final code, after the lab came back in a new session (the first session's Docker daemon reached its time limit) |
| history, with the PostgreSQL 16 store | PASS after a fix to the check itself (below); then PASS again at once, with the stale cache that had made it fail |

### Found while building this

- **curl's `--cacert` does not pin.** curl still loads the system CA directory: `curl -v` shows
  `CAfile: <yours>` and `CApath: /etc/ssl/certs`. A request with a CA that has nothing to do with the
  server succeeded through the agent proxy, whose CA is in the system store. With an empty `--capath` it
  failed with `self-signed certificate in certificate chain`. ship-recon passes an empty `--capath` and
  `-q`. The suite proves the pin with `SSL_CERT_DIR` and `CURL_CA_BUNDLE` pointing at a store that would
  accept the server. This bears on WebInventory's shipper too: plan §5 says the sensor validates
  against the pinned root, not the machine store.
- **curl does not retry a connection reset mid-upload** (exit 56) without `--retry-all-errors`. That
  flag would also retry refusals, so ship-recon exits 4 instead and the next run resumes from
  `ship-state.json`.
- **The history check's baseline run read a stale cache.** With `--db`, its first run read target results
  cached by an earlier run, up to `CACHE_TTL` (7 days) old. The previous history check had stopped the spa
  backend for its second run, so the cache held spa.test at 502. The check then saw no 200 → 502 change, and
  certificates cached before a lab restart showed up as `cert_not_after` changes. The baseline run now sets
  `CACHE_FRESH_ACTIVE=1`, the same re-measuring `--monitor --db` does. run-recon itself was right: this was
  the check's own isolation.
- **The suite pulls the CSV builder out by a pattern anchored at `^python3 -`.** Exporting the `--json`
  switch kept that line as it was. A prefix assignment (`RR_JSON=… python3 - …`) would have silently
  hidden the builder from four test sections.

## v1.20.0 release: A/B against v1.19.0

The release against the previous one: v1.19.0 (`git archive v1.19.0`) against the release branch, on the
default path (`--tls --ipv6`), interleaved run by run with the order switched each round.

| Scenario | runs per side | v1.19.0 wall s | v1.20.0 wall s | v1.19.0 CPU s | v1.20.0 CPU s | `--exact` on the columns both write |
|---|---:|---:|---:|---:|---:|---|
| lab | 6 | 22.84 | 22.50 | 9.81 | 10.04 | 2 fields differ, every round: `wp-login.php`'s `auth=Form` and `CleartextAuth` (87 rows) |
| farm, `-t 10` | 3 | 86.12 | 85.02 | 64.39 | 64.28 | identical, 50 rows, every round |

- **Output.** Every existing column is identical, on the lab and on the farm. The only exception is
  WordPress's login page, served on plain HTTP, where Batch 5's login-form detection reports a real
  finding. The nine new columns are appended after `security_txt`. The noise floor (WordPress oEmbed's
  random secret, eight `body_sha256` values) comes from a second run of v1.19.0.
- **Timing.** Wall and CPU are equal within the spread. On the lab, v1.20.0 spends about 0.2 s more CPU on
  the leaf-certificate parsing and the password-form regex that Batch 5 added to requests the run
  already makes. On the farm, the CPU is the same.
- **Lab checks.** All eleven pass on the release code (Batch 6's lab checks above).

## v1.21.0: Batch 7, the request policy and run health

Measured in the lab with the real toolchain:
- httpx 1.12.0, katana 1.8.0, nuclei 3.11.1 with nuclei-templates v10.5.1;
- ffuf 2.1.0, feroxbuster 2.11.0, gospider 1.1.6, hakrawler (master, Aug 2026), subjs, getJS 2;
- xnLinkFinder 8.2 and arjun.

The WAF front is ModSecurity v3 with the OWASP Core Rule Set 4.30 (image
`owasp/modsecurity-crs:4.30.0-nginx-202610180210`) at its defaults: paranoia 1, inbound anomaly threshold 5.

**What each tool sends by default** (a logging server; `--user-agent tool` keeps these):

| Tool | Its own User-Agent | With the policy |
|---|---|---|
| httpx | a random browser string per run (e.g. Firefox 108) | the policy's (`-H`) |
| katana | Chrome 113 on macOS | the policy's (`-H`) |
| nuclei | a random browser string per request | the policy's (`-H`), except raw templates |
| ffuf | `Fuzz Faster U Fool v2.1.0-dev` | the policy's (`-H`) |
| feroxbuster | `feroxbuster/2.11.0` | the policy's (`-a`) |
| gospider | `Go-http-client/1.1` (robots.txt), a random one (pages), `colly` (JavaScript) | lowercased (`-u`), and no headers on JavaScript |
| hakrawler | Firefox 78 | the policy's (`-h`) |
| arjun | Firefox 83 | the policy's (`--headers`) |
| subzy | `Go-http-client/1.1` | no option |
| curl | `curl/8.5.0` | the policy's (`-A`) |
| httpx's screenshot browser | Chrome 114 on macOS | its own (the extra headers do go) |

**OA1, the User-Agent A/B** (`bench-run-recon.sh ua --runs 3`). `wp.crs.test`, `ci.crs.test` and `nginx.crs.test`
behind the CRS, with `--nuclei --fuzz` (a 14-path WordPress list). Medians of 3 runs per mode:

| `--user-agent` | URL rows | `--fuzz` hits | nuclei findings | CRS: requests / blocked | fuzz requests blocked | wall s |
|---|---:|---:|---:|---:|---:|---:|
| `tool` (1.20) | 3 | 0 | 7 | 36,586 / 20,466 | 336 (all) | 160 |
| `outcrop` | 180 | 177 | 7 | 36,704 / 20,439 | 0 | 161 |
| `browser` | 180 | 177 | 7 | 36,823 / 20,509 | 0 | 161 |

- **`--fuzz`.** CRS rule 913100 blocks feroxbuster's (and ffuf's) own User-Agent, so in 1.20 the content
  discovery found nothing behind the WAF, and nothing in the output said so.
- **nuclei.** 3.11 already sends random browser User-Agents, so its findings did not depend on the mode.
  CRS blocked about 56% of its requests in every mode, on their payloads.
- **The default.** Ben chose `browser` (Chrome 157).

**The checks** (`checks` now has fifteen):

| Check | Result |
|---|---|
| `waf` | PASS: nine vendor block pages each reported `waf_blocked` with the right vendor, in the log and in `warnings.jsonl`; the plain 403 and the page that names vendors not reported |
| `throttle` | PASS: `throttle.test` throttled (429: 4, resets: 3, of 13 requests; the crawl ran into the limit first), the dropped `/closed` counted as a reset |
| `stop` | PASS: SIGTERM during a fuzz pass over the 50-host farm; exit 143 after 200 ms; a 2 s capture during the run saw 178 packets, a 10 s capture after the exit saw 0; no process of the run left |
| `policy` | see below |

**`policy`.** Two runs over nginx, spa and wp, with the ingress's access log on:

1. **Every stage but nuclei:** `--extras --origin --takeover --tls --crawlers-all --js --screenshots --fuzz --params`,
   1,149 requests in all. The rest carried the policy's User-Agent and the `--header`, apart from:

   | Requests | From | Why |
   |---:|---|---|
   | 22 | httpx's screenshot browser | its own User-Agent |
   | 25 | gospider | lowercased User-Agent |
   | 3 | subjs | User-Agent, no header |
   | 1 | the bench's own readiness probe (curl) | it fell inside the log window; the window now starts after it |

2. **nuclei alone:** 36,236 of 36,272 requests carried the policy. The other 36 came from raw (`unsafe`)
   templates:
   - CVE-2024-23897's `/cli` requests (no User-Agent);
   - a few templates that send no User-Agent or set their own.

The check now accepts those documented exceptions. A clean run of it, and the release A/B against `main` on
the default path, are still to do: the lab's Docker daemon reached the session's two-hour limit before them.
