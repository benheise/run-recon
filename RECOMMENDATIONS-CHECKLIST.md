# run-recon caching / API-minimization / timeout-reduction — implementation checklist

Status: COMPLETE. run-recon.sh -> v1.14.0, setup-recon-env.sh -> v1.8.0. Suite 206/206.
Backbone: a single `cache_or_run` choke point (cache + negative cache + circuit breaker + per-source
flock) plus a run-shared `seen_once` dedup and `cb_*` breaker state under $WORKDIR/.cb.

## A. Extend the DB cache to the uncached API-hitting stages
- [x] **A1** Subdomain-enum cache — subfinder/amass/assetfinder/findomain union cached per seed (`subs`), enum skipped on a fresh hit. Suite-tested.
- [x] **A2** Team Cymru ASN persistence — aggregator warms its IP->ASN cache from the DB (handoff file) and syncs new lookups back; osint_scan digs cached too. Verified end-to-end (asn row synced).
- [x] **A3** GitHub cache — github-subdomains (via cache_or_run) and github-endpoints (manual, file output) cached per domain, with breaker.
- [x] **A4** wpscan cache — routed through cache_or_run per target URL (also gets breaker + serialization).
- [x] **A5** cloud_enum cache — routed through cache_or_run per domain.
- [x] **A6** Cert-SAN cache — tlsx SAN/CN harvest cached per seed.

## B. Negative caching
- [x] **B1** Confirmed-empty results stored under a `<source>!neg` namespace with NEG_TTL (default 1 day) and skipped on the next run. Baked into cache_or_run; unit-tested (empty->neg->skip).

## C. Fail-fast (cold-run timeout fixes)
- [x] **C1** Per-source circuit breaker — counts `_to` timeouts (exit 124) in run-shared state; opens after CB_THRESHOLD (default 3) and skips the source's remaining calls. Unit-tested (2 timeouts -> open -> skip).
- [x] **C2** Retry-After — OSINT curls now pass `--retry 2 --retry-delay 1`; modern curl honors the Retry-After header on 429/503 and backs off instead of blind re-timeout.
- [x] **C3** Per-source concurrency ceiling — cache_or_run serializes CB_SERIALIZE sources (github/wpscan/virustotal) across workers via a per-source flock, so parallelism can't trip their rate limits.

## D. Infrastructure-level dedupe
- [x] **D1** Local caching resolver — `setup-recon-env.sh --dns-cache` installs + configures unbound (127.0.0.1, prefetch, cache) and writes a resolvers file for `run-recon --resolvers`.
- [x] **D2** HTTP proxy hook — `run-recon --proxy URL` sets HTTP(S)_PROXY (curl/whatweb/gau/wget) and httpx `-proxy`. Suite-tested. NOTE: intentionally a hook for the user's own caching proxy (squid ssl-bump / mitmproxy); the installer does NOT auto-bundle an HTTPS-intercepting cache (it needs a CA install and is too invasive to do by default) — documented in the README.

## E. Reduce fanout at the source
- [x] **E1** Cross-seed dedup — all new caches are keyed globally (domain/host/IP), so a value fetched for one seed is reused for any other; plus `seen_once` queries each IP once per run (mapping stays in the CSV). Unit-tested.
- [x] **E2** Brute wordlist cap — `BRUTE_MAX=N` truncates the shuffledns/puredns wordlist. Suite-tested.
- [x] **E3** Resolve-each-thing-once — `seen_once` on OSINT IPs + the per-seed subs/cert/crawl caches mean shared work isn't repeated across seeds.

## Cross-cutting
- [x] Tests — cache_or_run (hit/miss/negative), circuit breaker, seen_once (unit); A1/A2/E2/D2 (suite). Suite 206/206.
- [x] Docs (README §6 expanded) + CHECKLIST v1.14.0 entry + version bumps.
