# run-recon.sh — Gap-Closure + Coverage Checklist (v1.6.0)

Every gap, recommendation, and scoped-out item from the gap analysis, plus the
supporting-script and documentation work. Boxes are checked as each is completed.

## Tier-1 completion
- [x] 1. `tlsx` cert **feedback loop** — post-probe cert grab on live hosts, re-feed sibling names (`--certs` becomes two-phase)

## Missing discovery steps (highest surface impact)
- [x] 2. **Port discovery** (`naabu`) before `httpx` — catch non-standard web ports (`--ports`)
- [x] 3. **DNS dictionary bruteforce** (`shuffledns`/`puredns` + `massdns`) — wordlist brute vs. apex (`--brute`)
- [x] 4. **ASN/CIDR seed mode** (`asnmap` + `mapcidr`) — accept ASN/CIDR seeds, expand, cert-scan/resolve

## Missing sources
- [x] 5. **More passive subdomain sources** (`amass`, `assetfinder`) — folded into `--subs`
- [x] 6. **JS-mined endpoints/hostnames** (`subjs`/`getJS` → `xnLinkFinder`/`jsluice`) (`--js`)
- [x] 7. **Alt crawlers + `urlfinder`** (`gospider`, `hakrawler`, `urlfinder`) (`--crawlers-all`; urlfinder auto)

## Defensive / triage
- [x] 8. **Subdomain-takeover detection** (`subzy`) (`--takeover`)
- [x] 9. **Screenshots** (`httpx -screenshot`, else `gowitness`) (`--screenshots`)

## Advanced / optional
- [x] 10. **Origin-behind-CDN discovery** (`tlsx -jarm` + `cdncheck`) (`--origin`)
- [x] 11. **Favicon / internet-scan pivoting** (`uncover`) (`--favicon`; needs API keys)
- [x] 12. **Iterative/recursive rounds** — feed discovered subs back as seeds (`--rounds N`)
- [x] 13. **Continuous monitoring** — diff new assets vs. a prior CSV, optional `notify` (`--monitor`)
- [x] 14. **Vhost brute-forcing** (`ffuf` Host-header) (`--vhost`)

## Previously scoped-out — now included as opt-in, OFF by default
- [x] 15. **Vulnerability/misconfig scanning** (`nuclei`) (`--nuclei`)
- [x] 16. **Parameter discovery** (`arjun`) (`--params`)
- [x] 17. **Secret scanning** (`secretfinder`/`trufflehog` on JS) (`--secrets`)

## Convenience
- [x] 18. `--all` umbrella flag enabling the full discovery + defensive/triage set

## Supporting scripts & documentation
- [x] 19. Installer `setup-recon-env.sh`: add `naabu`, `massdns`, `shuffledns`, `puredns`, `amass`, `assetfinder`, `findomain`, `asnmap`, `mapcidr`, `cdncheck`, `uncover`, `subzy`, `gowitness`, `jsluice`, `notify`, `trufflehog` (+ verification)
- [x] 20. PowerShell provisioner `Setup-ReconEnv.ps1`: tool parity
- [x] 21. Test suite `test-run-recon.sh`: mocks + scenarios for every new stage
- [x] 22. `README.md`: capability table + usage examples
- [x] 23. Final: `bash -n` all scripts, run full suite green, sync to work dir, present

---

## Completion record

- **run-recon.sh** → v1.4.0 (1184 lines). All 17 capability items implemented as opt-in,
  graceful-degradation stages; scanning stages (nuclei/params/secrets) OFF by default.
- **setup-recon-env.sh** → v1.3.0. GO_TOOLS extended with 14 tools; massdns built from
  source; findomain fetched; verification list updated.
- **Setup-ReconEnv.ps1** → tool parity (embedded-bash goinstall + massdns/findomain + verify).
- **test-run-recon.sh** → 35 scenarios / **124 assertions, all passing** (was 64). New mocks:
  amass, assetfinder, shuffledns, puredns, massdns, naabu, asnmap, mapcidr, urlfinder,
  gospider, hakrawler, subjs, getJS, xnLinkFinder, subzy, gowitness, cdncheck, uncover,
  nuclei, arjun, secretfinder, trufflehog, notify.
- **README.md** → discovery/sources/analysis/monitoring flag docs, capability matrix, refreshed caveats.
- `bash -n` clean on all three bash scripts.

### Invocation verification pass (checked against upstream docs; fixes applied)
Verified every flagged tool's current CLI and corrected the drifted ones:
- **subzy** `run --targets <file> --hide_fails` — correct, no change.
- **cdncheck** `-resp -silent` over stdin — correct (both flags real), no change.
- **httpx `-ss`** — added `-srd <dir>` so screenshots land in a known directory (the cwd trick was unreliable).
- **gowitness** v3 `scan file -f <file>` — added `--screenshot-path <dir>` (v3 default is `~/screenshots`).
- **uncover** returns **IP:port**, not hostnames → `--favicon` now cert-scans those IPs with tlsx to recover in-scope hostnames.
- **arjun** stdout is param names, not URLs → now uses `-oT <file>` and ingests that file.
- **trufflehog** — dropped `--no-update` (errors "cannot be repeated" on v3.88+ builds).
- **shuffledns/puredns** `-mode bruteforce` / `bruteforce <wl> <domain> -r` — correct; dropped puredns `-q` (unneeded; stdout already clean).
- **Go toolchain bumped 1.22.5 → 1.24.5** in both installers — shuffledns and other current PD tools now require go1.24+.

All fixes are covered by the mock suite (favicon IP→cert pivot, arjun `-oT`, httpx `-srd`, gowitness `--screenshot-path`, puredns fallback). Remaining real-install smoke-test items are low-risk defaults (bundled Chrome for httpx `-ss`; uncover/secretfinder API-key configuration).

---

## v1.5.0 — coverage additions (GitHub mining, findomain, dnsvalidator, cloud buckets)

- [x] **GitHub code mining** — `github-subdomains` (host rows, source=github) + `github-endpoints`
      (URL rows, source=github) via `--github`; token from `--github-token FILE` or `GITHUB_TOKEN`.
      Passive w.r.t. the target; disabled with a clear warning if no token.
- [x] **findomain** folded into `--subs` (runs alongside subfinder/amass/assetfinder; source=findomain).
- [x] **dnsvalidator** — `--refresh-resolvers` regenerates the resolver list (validated public resolvers)
      before the run; a custom `--resolvers FILE` still takes precedence and is never overwritten.
- [x] **Cloud bucket enumeration** — `cloud_enum` (S3/Azure/GCP) via `--buckets`; findings-only output to
      `<out>.buckets.txt`. A different asset class (storage, not URLs); kept out of the URL CSV.
- [x] Installer: `github-subdomains`/`github-endpoints` (Go), `cloud_enum` (git-venv), `dnsvalidator`
      (pipx-from-git) + verification list; **installer v1.4.0**.
- [x] PowerShell provisioner: parity for all four.
- [x] Test suite: mocks + scenarios for findomain, github mining (with and without token), cloud buckets
      (incl. progress-line filtering), and resolver refresh → **140 assertions / 39 scenarios, all passing**.
- [x] README: install-table rows, usage examples, capability-matrix rows, and caveats (token handling,
      cloud-provider scope, resolver-refresh tradeoff).

### CLI verification (checked against upstream before wiring)
- **github-subdomains** `-d <domain> -t <token>` (stdout) — confirmed.
- **github-endpoints** `-d <domain> -t <token> -o <file>` (writes to `-o`; env `GITHUB_TOKEN` fallback) — confirmed.
- **findomain** `-t <domain> -q` (clean stdout) — confirmed.
- **cloud_enum** `-k <keyword>` (repeatable; prints `OPEN … BUCKET:` findings) — confirmed; artifact greps findings only.
- **dnsvalidator** `-tL <baseline> -threads N -o <file>` — confirmed.

**run-recon.sh → v1.5.0.** The pipeline now spans passive-multi-source + recursion + GitHub code +
DNS bruteforce + permutations + certs (two-phase) + ASN/CIDR + favicon for host discovery; gau/wayback/
urlfinder/GitHub/JS/crawlers for URLs; naabu ports; dnsx gate; httpx enrich; and takeover/screenshots/
origin/vhost/nuclei/params/secrets/**cloud-buckets** analysis, with monitoring. Cloud buckets is the one
deliberately-separate asset class; everything else feeds the URL CSV or a scoped side artifact.

---

## v1.6.0 — active CMS/app-layer scanning (`--active`)

- [x] New `cms_scan` stage on live hosts: fingerprint (whatweb → nuclei tech-detect → native curl) →
      classify WordPress/Drupal/Joomla/other → per-CMS deep enum → `nuclei -tags tech,cms` vuln mapping.
      Two-tier per the build plan: shell out to wpscan/droopescan/joomscan/cmseek when present; native
      curl/ffuf primitives (REST user enum, readme/CHANGELOG/joomla.xml version reads, `wp-content/
      {plugins,themes}/FUZZ` brute) otherwise. Findings → `<out>.cms.txt`.
- [x] `--active` flag + `--cms-wordlist FILE`; folded into `--all`; disabled under `--passive-only`.
- [x] Graceful-degradation preflight (which CMS tools present; WPScan-token note; wordlist note); the
      stage still runs on the native tier with none installed.
- [x] Installer (**v1.5.0**): droopescan (pipx), cmseek (git-venv), wpscan (gem), joomscan (git clone),
      whatweb + ruby (base pkgs); PowerShell provisioner parity.
- [x] Tests: mocks for whatweb/wpscan/droopescan/joomscan/cmseek; full-dispatch, native-ffuf-fallback,
      generic-cmseek, `--all`-inclusion, and `--passive-only`-gating scenarios →
      **154 assertions / 40 scenarios, all passing**.
- [x] README: install-table row, usage examples, capability-matrix row, pipeline step, caveats
      (traffic/attribution, WPScan 25 req/day cap vs nuclei-templates MIT, version→CVE over-reporting).

**run-recon.sh → v1.6.0.** Full build detail and the checked-off task list live in `CMS-BUILD-CHECKLIST.md`.
This is the "active depth" capability the SecurityScorecard comparison flagged: app-layer enumeration a
passive ratings platform structurally won't do against your estate.

---

## v1.6.1 / installer v1.5.1 — bug-fix pass (real-install issues + shellcheck)

Fixes found by running the toolkit on a live Kali box and by a full shellcheck audit.

- [x] **trufflehog install fixed** (root cause of the `[!] FAILED trufflehog` on install). It is **not
      `go install`-able** — its `go.mod` contains `replace` directives, which `go install pkg@version`
      rejects ("...would cause it to be interpreted differently than if it were the main module"). Removed
      it from `GO_TOOLS`; it now installs from the official **release-binary script** in `install_extras`
      (and the PowerShell provisioner). secretfinder remains the primary secret scanner, so this is
      non-fatal either way.
- [x] **Test fallback scenarios fixed on real installs** (root cause of the `--fuzz`→ffuf and
      `--brute`→puredns failures you saw, which passed on a bare box). The harness ran with
      `PATH="$MOCKBIN:$PATH"`, so hiding a mock to exercise a fallback exposed the **real** tool behind it
      (Kali ships `feroxbuster`/`shuffledns`) and ran that instead. Now the harness builds a `$SYSBIN`
      that symlinks every PATH executable **except** the ones it mocks, and runs with
      `PATH="$MOCKBIN:$SYSBIN"` — real recon tools are masked, coreutils stay available, so hiding a mock
      truly removes the tool. Verified by planting real `feroxbuster`/`shuffledns` on PATH: **154/154 still pass.**
- [x] **Go toolchain guard** — `install_go` now upgrades Go when the installed version predates
      `GOTOOLCHAIN=auto` (Go 1.21); older Go can't auto-fetch per-module toolchains, which several tools
      now require. Go ≥ 1.21 (e.g. your 1.22.5) is left untouched.
- [x] **run-recon SC2010** — replaced the `ls -1t … | grep` newest-`recon-*.csv` detection (for the
      `--monitor` diff) with a glob + `-nt` comparison (no `ls` parsing; handles odd filenames).
- [x] **run-recon SC2054** — annotated the one false positive (`-mc 200,204,…` is a single comma-separated
      ffuf argument, not array element separators).
- [x] **shellcheck: all three scripts clean at `-S warning`**; remaining info-level notes are intentional
      (numeric-var word splitting, ASCII `tr`, literal `\n` in help text).

No behavior change to the enumeration itself; run-recon → **v1.6.1**, installer → **v1.5.1**.

---

## v1.7.0 — `--activescan` (thorough active scan over SecLists)

- [x] New `activescan` stage on live hosts: content discovery with **feroxbuster** (ffuf fallback) across a
      curated set of **SecLists** lists (`raft-large-directories`, `raft-large-files`, `quickhits`,
      `api/api-endpoints`, `common`) **plus a broad nuclei run** (`-severity low,medium,high,critical`).
      Findings → `<out>.activescan.txt`. Rooted at `$SECLISTS` (default `/opt/recon/wordlists/SecLists`,
      env-overridable); only existing lists are used.
- [x] `--activescan` flag; **wired into `--all`**; disabled under `--passive-only`; graceful-degradation
      preflight (needs feroxbuster/ffuf and/or nuclei; warns when SecLists is absent — nuclei still runs).
- [x] Distinct from `--fuzz` (one list → URL CSV): `--activescan` is a self-contained, heavier scan → side artifact.
- [x] Installer already covers it via `--include-heavy` (SecLists + feroxbuster; nuclei/ffuf are base tools) — no installer change.
- [x] Tests: SecLists fixture tree + scenarios for the feroxbuster+nuclei path, the ffuf fallback
      (feroxbuster hidden), `--all` inclusion, and `--passive-only` gating → **163 assertions / 42 scenarios, all passing**
      (also verified with real `feroxbuster`/`shuffledns` planted on PATH).
- [x] README: capability-matrix row, usage examples, pipeline step, and a caveat (heaviest/loudest stage,
      in `--all`, needs `--include-heavy`, distinct from `--fuzz`).

Note: a test-only regex bug surfaced during this work — an assertion pattern `content(` is an invalid ERE
(unescaped `(`), so `grep -E` errored and the check failed even though the artifact was correct. Switched
those to fixed-string matching. The feature itself was correct throughout.

run-recon.sh → **v1.7.0**.

---

## v1.7.1 — httpx-toolkit by default (drop the httpx identity detection)

Kali packages ProjectDiscovery httpx as `httpx-toolkit` because the Python `httpx` client owns
`/usr/bin/httpx`. The old runtime "is this the real PD httpx?" detection (`_pd_httpx`, `-tech-detect`
probing, impostor warnings) was unreliable and, worse, the installer's `go install httpx` step was being
**skipped** whenever the Python `httpx` was present (`have httpx` matched it), so PD httpx never landed.

- [x] **run-recon** now defaults to `HTTPX_BIN=httpx-toolkit` and calls it via plain `have`/`$HTTPX_BIN`.
      Removed `_pd_httpx` and every call site, the startup `-tech-detect` impostor preflight, and the
      export of the dead function. `HTTPX_BIN=/path/to/httpx` still overrides for other environments.
- [x] **installer**: dropped `httpx` from the generic go-tools loop (it skipped on the Python binary);
      added an explicit `install_httpx` step that provisions PD httpx **as `httpx-toolkit`** — prefers an
      existing `httpx-toolkit` (Kali apt), else `go install`s PD httpx and symlinks
      `/usr/local/bin/httpx-toolkit -> httpx`. Verify list now checks `httpx-toolkit`.
- [x] **PowerShell provisioner**: symlinks `httpx-toolkit -> httpx` after the go install; verify list updated.
- [x] **tests**: removed the obsolete impostor-detection scenario; added a scenario proving run-recon
      calls `httpx-toolkit` **by default** (no `HTTPX_BIN` set), does **not** use the python-named `httpx`,
      and still enriches correctly. **164 assertions / 43 scenarios, all passing** (incl. with a real
      `httpx` planted on PATH).
- [x] **README**: install-table + a caveat explaining the naming clash and the `httpx-toolkit` default.

run-recon.sh → **v1.7.1**.

---

## v1.8.0 — progress/timers + wall-clock timeouts (fixes the multi-hour "hang")

The "pause after the initial checks" was not an infinite loop: domains run under `xargs -P`, and every
tool's `-timeout 10` is a *per-request* limit, not a total-runtime cap. So `amass`, DNS bruteforce, and
especially `feroxbuster`/`ffuf` over large SecLists lists (`--activescan`/`--all`, recursive `--depth 2`
across every live host) could grind for hours with **no output** — looking hung. Fixed by bounding every
stage and surfacing live progress.

- [x] **`_to <secs> <cmd>`** timeout wrapper (SIGTERM at the cap, SIGKILL +15s; no-op if `timeout` absent).
      Wrapped **51** tool invocations: passive collectors, `amass`, `subfinder`, `findomain`, `assetfinder`,
      `github-subdomains/-endpoints`, `gau`, `waybackurls`, `waymore`, `urlfinder`, DNS brute
      (`shuffledns`/`puredns`), `alterx`, `naabu`, `httpx` probe + enrichment, `katana`/`gospider`/`hakrawler`,
      JS mining, `feroxbuster`/`ffuf` (fuzz, vhost, activescan, CMS brute), `tlsx`, `subzy`, `gowitness`,
      `uncover`, `arjun`, `secretfinder`, `trufflehog`, `nuclei` (all sites), `cloud_enum`, CMS tools
      (`whatweb`/`wpscan`/`droopescan`/`joomscan`/`cmseek`). `feroxbuster` also gets its own `--time-limit`.
- [x] Per-stage caps: `STAGE_TIMEOUT=900`, `PASSIVE_TIMEOUT=600`, `BRUTE_TIMEOUT=1800`, `FUZZ_TIMEOUT=1800`,
      `SCAN_TIMEOUT=2400` (seconds; env-overridable; `0` = unlimited).
- [x] **Progress:** 16 `stage` markers (phase + elapsed, per domain), a background **heartbeat** every
      `HEARTBEAT=20`s (`... running HH:MM:SS (done/total domains)`), per-domain `done (N urls, HH:MM:SS)`,
      and an overall `all domains processed in HH:MM:SS`. `--no-progress` / `PROGRESS=0` to silence.
      Heartbeat runs only in the parent, is killed via trap, and never outlives the run.
- [x] Verified live: a `feroxbuster` mock that sleeps 3000s completes in **4s** under `FUZZ_TIMEOUT=3`
      instead of hanging; stage markers + heartbeat + completion all print. Suite: **164/164** unchanged.
- [x] README: progress + wall-clock-guard section, with the knobs for long vs quick runs.

run-recon.sh → **v1.8.0**.

---

## OSINT data-source research + rate-limit diagnostic

Scope note: this project is **pure external-recon / OSINT information gathering** — no CVE/CVSS/NVD or
vuln-scoring, and no collaborative threat-sharing (ISAC/AIS). Threat-intel sources are in scope only where
they enrich a specific domain/IP/URL (e.g., a VirusTotal domain report).

- [x] **DATA-SOURCES.md** — integration menu of external-recon data sources across 12 categories
      (internet-wide scan; CT/TLS; passive DNS; DNS zone files; WHOIS/RDAP; IP/ASN/BGP; IP geo/enrichment;
      attack-surface/subdomain; cloud attribution; leaked-credential/breach; third-party ratings;
      domain/IP/URL reputation). Each entry flags access model (`FREE`/`REG`/`FREEMIUM`/`PAID`/`ENT`/`VETTED`/
      `OWN`/`AFFIL`), mechanism/format, and — per the ask — whether OSS already wraps it or the **data/access
      is the barrier** (`GAP`). Includes the gated-but-notable sources (CZDS zone files, Shadowserver org
      reports, DNSDB, RIR/RouteViews/RIS bulk BGP, HIBP domain search) and a phased adoption order. Status
      flags (Rapid7 Sonar closed, Censys Platform migration, Farsight→DomainTools, MaxMind/IPinfo free-tier
      cuts) are marked *verify*.
- [x] **probe-datasource-limits.sh** — diagnostic that derives safe per-source **timeout** and **delay**
      values (the operational wall for this project: many sources throttle/deny after a few hosts). Per
      source it (1) measures latency over spaced samples → `timeout = ceil(p95×2)`, floored/capped, bumped to
      the ceiling if timeouts occur; (2) parses `Retry-After` / `X-RateLimit-*` headers; (3) runs a **gentle
      slow→fast rate ramp that stops at the first 429/403/503/timeout and backs off** (honoring `Retry-After`,
      with cooldowns so steps stay independent) → `delay` from the last clean rate. Safe by design (`--polite`
      = headers+latency only, no ramp); supports `--url`/`--file`/`-H` (API keys), `--emit-config` (sourceable
      `NAME_TIMEOUT`/`NAME_DELAY`), and `--json`. `bash -n` + shellcheck clean; validated against local servers
      for latency, header parsing, throttle detection, timeout (`ERR28`), and connection-refused (`ERR7`).

---

## v1.9.0 — passive OSINT enrichment (integrates the OSINT data-source research)

The research found that most premium OSINT sources (Censys, Shodan, VirusTotal, SecurityTrails, FullHunt,
Netlas, Chaos, ...) are **already queryable via `subfinder`'s provider config** — the barrier is API keys,
not tooling. So the work is (a) operationalizing keys and (b) adding enrichment stages for data those
tools don't capture. All new stages are **passive w.r.t. the target** (third-party lookups) and run even
under `--passive-only`.

- [x] **`osint_scan` stage** — three sub-stages, all curl/dig/jq (base deps):
  - `--osint` (free, no key): **RDAP** registration (registrar/created/expires/NS/status) + per-live-IP
    **Shodan InternetDB** (`internetdb.shodan.io` — passive ports/hostnames/tags; its CVE `vulns` field is
    intentionally dropped, out of scope) + **Team Cymru** IP-to-ASN (org name reveals cloud). `-> <out>.osint.txt`
  - `--virustotal` (`VT_API_KEY`): VT domain report — reputation, passive DNS records, subdomains. `-> <out>.virustotal.txt`
  - `--urlscan` (optional `URLSCAN_API_KEY`): urlscan.io historical page URLs + IPs. `-> <out>.urlscan.txt`
  - jq-dependent lookups are gated on `have jq` *before* the fetch (no wasted requests); the awk-based ASN runs jq-free.
- [x] `--osint` folded into `--all`; IPs bounded by `OSINT_MAX` (25). Preflight warns on missing `VT_API_KEY`/`jq`.
- [x] **Installer**: `scaffold_subfinder_config` writes a commented `~/.config/subfinder/provider-config.yaml`
      (virustotal/securitytrails/censys/shodan/fullhunt/netlas/chaos/github/...) if absent — the key unlock.
      curl/jq/dnsutils are already base packages. PowerShell provisioner mirrors the scaffold.
- [x] **Docs**: `DATA-SOURCES.md` (the full research menu, sorted by type, access-model + OSS-gap tagged) now
      has an "Already wired into run-recon" block; README gets capability-matrix rows, usage, and a caveat.
- [x] Tests: gating scenarios (`--osint` runs under `--passive-only`; `--virustotal` needs a key; `--urlscan`
      enables) → **170/170**. Wiring verified in a standalone demo (curl/dig/jq endpoints mocked): RDAP +
      InternetDB fetched, Team Cymru ASN parsed correctly; jq-gating confirmed (no wasted curls when jq absent).

Note: the jq JSON parsing can't be exercised in this sandbox (no `jq` binary available to install here), but
`jq` is a base package on Kali and the filters are validated by inspection; the awk-based ASN path and all
wiring/gating are demonstrated. run-recon.sh → **v1.9.0**.

---

## v1.10.0 — IP + ASN attribution columns (ownership validation)

Adds three columns to the CSV so you can confirm each host resolves into infrastructure your org controls.

- [x] **CSV schema**: appended `ip`, `asn`, `asn_org` (appended, not inserted — every existing column
      position and downstream consumer is unaffected).
  - `ip` — the address httpx actually connected to (added `-a` to the enrichment call; blank when a row
    isn't validated, e.g. `--passive-only`/`--no-validate`).
  - `asn` / `asn_org` — origin ASN number + owner via the free **Team Cymru** DNS service (no key),
    resolved in the aggregator, **cached per unique IP** and bounded by `ASN_MAX` (2000).
- [x] Passive (DNS + Team Cymru; no traffic to the target). On by default; `--no-asn` disables it. New
      banner line shows `ip+asn=on/off`; help + CSV-schema docs updated.
- [x] **README**: schema rows + an `awk`/`grep` recipe to flag hosts *not* on your expected ASNs.
- [x] Tests: `dig` mock answering Team Cymru (origin + AS-name) and A-record queries; httpx mocks now emit
      an `a` field; new assertions confirm the header carries `ip/asn/asn_org` and that a row resolves to
      `93.184.216.34 / AS15133 / "EDGECAST, US"`. Passive-only "empty enrichment" assertions still hold
      (attribution columns are appended). → **172/172**.
- [x] Verified end-to-end: two hosts correctly resolve to *different* IPs/ASNs
      (`AS15133 EDGECAST` vs `AS63949 Akamai/Linode`), and CSV quoting handles the comma in the org name.

run-recon.sh → **v1.10.0**.

---

## v1.11.0 — uro in the activescan→nuclei path + tookie-osint social discovery

- [x] **uro wired into `--activescan`** (it was already used in `resolve_hosts`, but not here). Feroxbuster/ffuf
      hits are now `tee`'d to a raw list, deduped/normalized with **uro** via a new `uro_filter` helper
      (`sort -u` fallback), and **nuclei scans the cleaned list + live hosts** instead of only live hosts.
      The artifact records a `uro filtered content: N -> M URLs` summary line. Demonstrated: 5 raw hits
      (`/admin`, `/admin/`, dup, `?id=1`, `?id=2`) collapsed to 2, and nuclei fed `activescan_targets.txt`.
- [x] **tookie-osint added as `--social`** (new OSINT sub-stage in `osint_scan`): searches the org brand
      username (derived from the seed domain, e.g. `acme.com` → `acme`, or `--social-user NAME`) across
      social platforms and writes found account URLs to `<out>.social.txt`. Passive w.r.t. the target
      (queries the platforms), runs even under `--passive-only`, opt-in (not in `--all`), `_to`-bounded,
      stdin closed to avoid interactive hangs. Best-effort output parsing (Sherlock-style `[+]` lines).
- [x] **Installer**: `tookie-osint` added to git-venv tools + verify list; PowerShell provisioner mirrors it.
      uro needs no installer change (already in `PIPX_TOOLS`).
- [x] Docs: README capability-matrix rows, usage, and caveats (uro in activescan; `--social` behavior +
      verify-the-CLI note); DATA-SOURCES "already wired" block updated.
- [x] Tests: `uro` and `tookie-osint` mocks; new assertions — uro invoked on the activescan URL list, uro
      summary written, nuclei targets the cleaned list; `--social` enabled/parsed, brand derived from the
      domain, `--social-user` override, non-hits excluded, and graceful gating when tookie-osint is absent.
      → **181/181**.

Note: tookie-osint's CLI/output can vary by version; the invocation is defensive (timeout + closed stdin +
lenient parsing) but should be verified on the Kali box. run-recon.sh → **v1.11.0**.

---

## v1.12.0 — probe-datasource-limits.sh drives the OSINT stages + feeds run-recon

Closes the loop between the rate/timeout probe and the OSINT stages it was written for.

- [x] **Probe `--recon-osint` mode**: auto-builds the exact endpoints run-recon hits — RDAP
      (`rdap.org/domain/<sample>`), Shodan InternetDB (`internetdb.shodan.io/<sample-ip>`), VirusTotal
      (domains API), urlscan (search API) — with `--sample-domain`/`--sample-ip` overrides.
- [x] **Authenticated-endpoint presets**: per-source headers (not global) — attaches `x-apikey` for VT and
      `API-Key` for urlscan automatically when `VT_API_KEY`/`URLSCAN_API_KEY` are exported; VT is skipped
      with a note if no key; urlscan probes unauthenticated otherwise. New `SHDRS`/`CUR_HDRS`/`VPREFIX`
      arrays; `probe_once` now uses the per-source header set.
- [x] **Emits run-recon's variable names**: `RDAP_/INTERNETDB_/VT_/URLSCAN_` `*_TIMEOUT`+`*_DELAY`, prefixed
      with `export` in recon mode so the file works with both `run-recon --limits FILE` and `source FILE`.
      Team Cymru (DNS) and tookie-osint (multi-site) are noted as out of HTTP-probe scope.
- [x] **run-recon consumes it**: new per-source `*_TIMEOUT`/`*_DELAY` vars (default `STAGE_TIMEOUT`/0) that
      `osint_scan` honors — each OSINT curl uses its own `_to "$X_TIMEOUT"`, and a new `_delay` helper spaces
      the InternetDB per-IP loop and the VT calls. New `--limits FILE` sources the probe output after arg
      parsing (unconditional `export` overrides the defaults); per-source vars + `_delay` are exported to workers.
- [x] Docs: README companion section rewritten around the `--recon-osint → --limits` workflow; help text
      documents `--limits` + the per-source env vars.
- [x] Verified end-to-end (mock curl): correct endpoints; authed headers attach per-source (x-apikey only on
      VT, API-Key only on urlscan); emitted config carries run-recon names; `--limits` loads and the
      unconditional `export` overrides the `:=` default (VT_TIMEOUT 900 → 17). Tests: `--limits` load +
      missing-file handling → **183/183**.

run-recon.sh → **v1.12.0**; probe-datasource-limits.sh extended (308 lines).

---

## v1.12.1 — BUGFIX: invalid httpx `-a` flag blanked all enrichment columns

Symptom: CSV had only columns A-D (seed_domain,url,host,sources); every httpx-derived column
(status_code..technologies) and the ip/asn/asn_org columns were empty, with no obvious error.

- [x] **Root cause**: the enrichment call passed `-a` (added in v1.10.0 to capture the IP), but `-a` is
      **not a valid ProjectDiscovery httpx flag** (the IP flag is `-ip`; the resolved IP is already in the
      default `-json` `host` field). httpx's goflags parser exits on an unknown flag, so httpx returned zero
      records -> every column downstream of httpx was blank. Errors went to `$raw/httpx.err` (only visible
      with `--keep-work`), so nothing surfaced on the console beyond the easily-missed "0 records" warning.
- [x] **Fix**: removed `-a` from the enrichment invocation. The IP now comes from httpx's default JSON
      `host` (fallback order in the aggregator hardened to `a` -> `ip` -> `host`, all validated as IPv4).
- [x] **Regression guard**: the `httpx`/`httpx-toolkit` test mocks now reject unknown flags exactly like
      goflags (whitelisting only the flags run-recon actually sends). Re-introducing `-a` now fails the
      suite with 6 enrichment failures (previously it passed silently). Mocks emit `host`=IP like real httpx.
- [x] Verified: suite **183/183**; end-to-end with a realistic httpx that rejects `-a` and emits `host`=IP
      yields a fully-populated CSV (A-L) with no "0 records" warning.

run-recon.sh → **v1.12.1**.

---

## v1.13.0 — MAJOR: HTML report, PostgreSQL cache/store, wiring

Three-part feature release. New files: `generate-report.sh`, `recon-db.sh`.

### 1. HTML report (`generate-report.sh`, on by default)
- [x] Bash wrapper + embedded python3 renderer (mirrors the CSV-aggregator pattern); all
      output HTML-escaped. Standalone: `./generate-report.sh [-o OUT] [--shots DIR] [--title T] <csv>`.
- [x] Reads the CSV inventory + every side-artifact (`<csv>.{nuclei,activescan,takeover,secrets,
      buckets,origin,params,cms,osint,virustotal,urlscan,social,new-assets}.txt`) and screenshots.
- [x] Self-contained dark-theme report: summary dashboard (host/live/finding/severity counts, top
      ASNs), a highlighted Findings table (nuclei/takeover/secrets/buckets/origin, most-severe-first,
      each linked to its host), per-host cards (IP/ASN/tech/status + linked screenshot thumbnail +
      that host's findings + sample URLs), footer artifact links.
- [x] Severity: nuclei lines parsed for `[critical|high|medium|low|info]`; other kinds get sensible
      defaults (takeover/secrets=high, buckets/origin=medium, else info).
- [x] Host attribution: target-URL findings tie to the URL's host; OSINT/reference findings
      (social/vt/osint) tie to the seed. Screenshots matched host→png by normalized-substring.
      Auto-detects the newest `screenshots-*` dir next to the CSV.
- [x] Two bugs found+fixed in review: social account URLs mis-attributed to the reference host
      (github.com) instead of the seed; OSINT sub-source tokens (rdap/shodan-internetdb/asn) were
      being stripped — now only a leading token exactly equal to the kind is dropped.

### 2. run-recon → report wiring
- [x] `REPORT=1` default; `--no-report` to skip. Locates `generate-report.sh` next to `$RECON_DIR`
      (or on PATH); runs after side-artifact aggregation + screenshot move + monitoring, before
      workdir cleanup. Banner + help updated. Degrades with a warning if the script is missing.

### 3. PostgreSQL cache/store (`recon-db.sh` + `--db`)
- [x] Reuses Kali's Metasploit postgres service; creates a separate `recon` DB. Two tables:
      `recon_cache(source,key,value,fetched_at)` (TTL'd) and `recon_hosts(run_ts,url,...)` (inventory).
- [x] Fail-soft library: `db_available`/`db_schema`/`db_cache_get`/`db_cache_put`/`db_load_csv`/
      `db_setup`; single-quote SQL escaping (injection-safe); client-side `\copy` for CSV load.
      CLI: `sudo ./recon-db.sh init|schema|stats|hosts|purge`. Connection via PG* env or `RECON_DB_DSN`;
      `init` writes `~/.config/recon/db.env` (auto-loaded).
- [x] **Ordering fix**: worker dispatch (line ~1071) precedes `$SELF`, so compute `RECON_DIR` early
      via `${BASH_SOURCE[0]}` and source `recon-db.sh` UNCONDITIONALLY before the dispatch (functions
      inert unless `USE_DB=1`); export `USE_DB CACHE_TTL` + PG* to workers.
- [x] `--db` gates calls; post-parse the main process checks `db_available`/`db_schema` and downgrades
      to an uncached run on any problem. Wired: passive-crawl URL union cached per domain (skips
      re-crawl of Wayback/CommonCrawl/OTX); RDAP / InternetDB / VirusTotal (+subdomains) / urlscan
      cached per key; run CSV loaded into `recon_hosts` at the end. `CACHE_TTL` default 604800 (7 days).

### Installer / tests / docs
- [x] `setup-recon-env.sh` → v1.6.0: `postgresql-client` (apt) / `postgresql` (dnf/pacman) for psql.
- [x] Tests: **202/202** (+19). New: report generation (findings/severity/screenshot/ASN/sub-source
      preservation/anchors), run-recon auto-report + `--no-report`, `--db` graceful degradation (psql
      absent), `--db` wiring via mock psql (cache consulted, `source='urls'`, `recon_hosts` load).
      Added `assert_exists` helper and a `psql` mock.
- [x] Verified end-to-end with a stateful psql mock: two-pass crawl-cache round-trip — run 1 crawls +
      stores; run 2 serves from the DB cache and **skips the crawl** (rigged-to-fail gau never called).
- [x] `bash -n` + shellcheck clean across run-recon.sh, generate-report.sh, recon-db.sh, installer.
- [x] README §6 added (HTML report + DB setup/usage); trailing sections renumbered; Modes list updated.

run-recon.sh → **v1.13.0**;  setup-recon-env.sh → **v1.6.0**;  new: generate-report.sh, recon-db.sh.

---

## setup-recon-env.sh v1.7.0 — one-stop-shop: installs all scripts + provisions the DB

Make the installer a single entry point: after it runs, `run-recon --db` and the HTML
report work with no extra manual steps.

- [x] **Installs all three scripts together** (phase 8): `run-recon.sh` + `generate-report.sh`
      + `recon-db.sh` into `$INSTALL_ROOT/bin` with `/usr/local/bin` symlinks (`run-recon`,
      `generate-report`, `recon-db`). Critical because run-recon resolves its report generator and
      DB library relative to its own path — installing only run-recon would leave `--db`/report
      broken from the installed command. Missing companions warn but don't fail.
- [x] **Provisions the recon DB** (new phase 8b, default on; `--no-db`/`--skip-db` to skip):
      detects a local postgres server (reuses Kali's msf service; installs `postgresql` only if
      entirely absent, best-effort per distro), then runs `recon-db.sh init`. Runs init as the
      invoking user (`sudo -u "$SUDO_USER" -H` when the installer itself is root) so the role +
      `~/.config/recon/db.env` land in the right home. Fully non-fatal — any failure downgrades to
      "`--db` runs uncached" with guidance. Honors `--dry-run`.
- [x] `postgresql-client` stays in base packages; `psql` added to the verification list; banner/dry-run
      plan shows companion-script + DB-setup status; next-steps summary shows `--db`/report usage.
- [x] Verified: `bash -n` + shellcheck clean; dry-run plan renders DB/companion status; `recon-db.sh
      init` degrades cleanly with no postgres; phase-8b success/failure/`--no-db` branches all behave
      (failure is non-fatal). run-recon suite unaffected (202/202).
- [x] README §6 updated: DB setup is now automatic via the installer; manual `recon-db.sh init` is a
      documented fallback.

setup-recon-env.sh → **v1.7.0**.

---

## v1.14.0 — caching / API-minimization / timeout-reduction batch

Implements the full recommendations checklist (see RECOMMENDATIONS-CHECKLIST.md). Backbone:
a `cache_or_run` choke point (cache + negative cache + circuit breaker + per-source flock),
`seen_once` run-shared dedup, and `cb_*` breaker state under `$WORKDIR/.cb`.

- [x] **A. Cache coverage** extended to every remaining API-hitting stage: subdomain-enum union
      (subfinder/amass/assetfinder/findomain) per seed; per-IP Team Cymru ASN (aggregator warms from
      the DB via a handoff file and syncs back); GitHub subdomains+endpoints; wpscan; cloud_enum;
      tlsx cert-SANs. The 5 existing OSINT fetches (rdap/internetdb/vt/vt-subs/urlscan) were routed
      through `cache_or_run`.
- [x] **B. Negative caching** — confirmed-empty results stored under `<source>!neg` with `NEG_TTL`
      (default 1d); dead keys skipped on the next run.
- [x] **C. Fail-fast** — per-source circuit breaker (`CB_THRESHOLD` timeouts -> skip source for the
      run); curl `--retry` so 429/503 `Retry-After` is honored; per-source flock serialization of
      github/wpscan/virustotal across workers.
- [x] **D. Infra** — installer `--dns-cache` sets up a local unbound caching resolver + resolvers
      file; run-recon `--proxy URL` wires HTTP(S)_PROXY + httpx `-proxy` (bring-your-own caching proxy).
- [x] **E. Fanout** — global-keyed caches + `seen_once` (query each IP once per run; mapping stays in
      the CSV); `BRUTE_MAX` caps the brute wordlist.
- [x] New env knobs: `NEG_TTL`, `CB_THRESHOLD`, `CB_SERIALIZE`, `PROXY`/`--proxy`, `BRUTE_MAX`; all
      exported to workers. Banner + help updated.
- [x] Tests: cache_or_run (hit/miss/negative), circuit breaker, seen_once (standalone unit); A1 subs
      cache, A2 ASN sync, E2 brute cap, D2 proxy (suite). A2 verified end-to-end. **Suite 206/206.**
- [x] `bash -n` + shellcheck clean across run-recon.sh, setup-recon-env.sh, test-run-recon.sh.
- [x] README §6 expanded; RECOMMENDATIONS-CHECKLIST.md tracks per-item status.

run-recon.sh → **v1.14.0**;  setup-recon-env.sh → **v1.8.0**.

---

## recon-db.sh — reuse msfdb credentials (database.yml) for DB setup

`db_setup` (`recon-db.sh init`, used by the installer) previously created a new role via the
postgres superuser and relied on `pg_hba.conf` peer/ident — which could fail. It now prefers
Metasploit's already-provisioned, password-authenticated `msf` role.

- [x] Parse `username`/`password`/`host`/`port`/`database` from msfdb's `database.yml`
      (`MSF_DB_YML`, default `/usr/share/metasploit-framework/config/database.yml`, then
      `$MSF_DATABASE_CONFIG`, `~/.msf4/database.yml`, `/home/$SUDO_USER/.msf4/database.yml`).
      Helpers: `_msf_yml_path`, `_yml_first`, `_msf_read_creds`, `_msf_creds_work`.
- [x] If the file is missing or the creds don't authenticate, run **`msfdb init`** (`_run_msfdb_init`,
      as `$SUDO_USER` when the caller is root) and re-read.
- [x] Create the `recon` database using the msf role (needs CREATEDB), else via the postgres
      superuser owning it to the msf role. Connection is password/TCP, so it does NOT depend on
      pg_hba peer/ident.
- [x] Resolved connection (incl. password) written to `~/.config/recon/db.env` via `_write_db_env`,
      **chmod 600**; `PGHOST`/`PGPORT` omitted on the legacy path so it uses the socket + peer.
- [x] Legacy superuser-role path retained as the final fallback (no msfdb present). SQL identifiers
      quoted (`_ident`); fixed an invalid `GRANT ... TO quote_ident()`.
- [x] Verified: parser on a real-format `database.yml`; `db_setup` msf-cred path (creates recon +
      0600 db.env with password); `msfdb init` fallback (absent yml -> init -> reuse); legacy
      sudo-postgres fallback (no PGHOST/PGPASSWORD -> peer/socket). `bash -n` + shellcheck clean.
      run-recon suite unaffected (206/206). README §6 + recon-db.sh header updated.

---

## v1.15.0 — upfront service health checks for --db and --resolvers

When `--db` or `--resolvers` is in play, run-recon now runs a "Preflight: verifying required
services are operational..." step before the work, so a down dependency is caught immediately
instead of surfacing as a wall of timeouts mid-run.

- [x] **PostgreSQL (--db):** the existing DB gate was reworked into an explicit health check —
      `db_available && db_schema` is the verdict; on failure it probes `pg_isready`, then the
      systemd unit / `pg_lsclusters` to explain *why* (server down vs. our DB/creds), warns with a
      concrete fix (`systemctl start postgresql && recon-db.sh init`), and degrades to an uncached run.
- [x] **DNS resolvers (--resolvers / any active dedicated set):** new `_svc_resolver_check` probes
      the first few resolvers with `dig @<r> +time=2 +tries=1` (exit 0 = the server replied, even
      NXDOMAIN/REFUSED). If none answer it warns that DNS-heavy stages will stall, with guidance
      (is unbound up? drop --resolvers / --refresh-resolvers). Skips cleanly if `dig` is absent.
- [x] **Fail-soft, not fail-hard:** both checks warn/degrade and the run continues. Fixed a `set -e`
      bug where the bare `_svc_resolver_check` call aborted the whole run on a down resolver — now in
      a condition context (`|| _rescheck=$?`).
- [x] Tests: `--resolvers` triggers the preflight and passes when resolvers reply; a dead-resolver
      case (dig exit 9) warns *and still completes* + produces the CSV; `--db` success/`down` messages
      updated. **Suite 211/211.** `bash -n` + shellcheck clean. Help + version bumped to 1.15.0.

---

## v1.15.1 — full bug-check + optimization pass (functionality + tests unchanged)

Ran a real shellcheck (it turned out not to be installed, so prior "clean" reports were vacuous)
plus a manual deep review and py_compile/pyflakes on the embedded Python. Findings:

Bugs fixed
- [x] **Cache poisoning on timeout/error (HIGH):** `cache_or_run` cached `$out` whenever it was
      non-empty, *regardless of exit code* — so a timed-out or errored fetch that emitted partial
      output was stored as a valid result for the full TTL (7 days). Now caches (positive or
      negative) only on a clean exit (rc=0); rc!=0 leaves the entry uncached to retry. Verified: a
      partial-output timeout no longer serves stale partial data on the next call.
- [x] **Fragile `grep -c ... || echo N` counting (4 sites):** `grep -c` prints `0` *and* exits 1 on
      an empty file, so `|| echo N` appended a second value (`"0\nN"`) that breaks arithmetic
      (cb_open's threshold test, crawl-cache/NDOMAINS/RES_ROWS counts). Latent (files were non-empty
      in practice) but fixed to `|| true` + a default.
- [x] **Resolver health check last-line bug (MED):** `_svc_resolver_check`'s `while read` skipped the
      last line of a resolvers file with no trailing newline (common for hand-made files) — a
      single-resolver file then tested zero and mis-reported. Fixed with `|| [ -n "$r" ]`.
- [x] **db_load_csv path (LOW):** the CSV path was interpolated raw into `\copy FROM '...'`; a single
      quote in the `-o` path would break the command. Now guarded with a clear skip.

Optimization
- [x] **ASN sync:** previously re-wrote the *entire* Team Cymru cache (warm + new) to the DB with one
      `psql` call *per IP* every run (e.g. 500 IPs -> 500 psql spawns with zero new data). Now the
      aggregator writes only newly-resolved IPs and the sync uses a single batched `db_bulk_cache`
      upsert (pure-bash quote escaping). Repeat runs sync ~0 rows; a cold run does 1 statement.

Verification: shellcheck genuinely warning-clean across all 6 scripts (one SC2120 disable for the
intentionally-optional `_msf_read_creds` arg); embedded Python compiles; `db_bulk_cache`, the
partial-timeout fix, and the no-trailing-newline resolver fix unit-tested. Also confirmed `rm -rf`
targets are always-set + quoted, all `cd` are error-handled, `_shq` escaping is correct, and
`WORKDIR` is derived after `OUT_DIR` exists. **Suite 211/211.**

run-recon.sh → **v1.15.1**.

---

## v1.15.2 — second bug-check pass (under-reviewed files + runtime edge cases)

Focused on what the first pass under-covered: the report generator's Python logic, the probe
script, runtime behavior on malformed input, and whether the test suite is actually
mutation-sensitive (not full of false-positive tests).

Bugs fixed
- [x] **Aggregator crash on non-object JSON (HIGH):** a line in httpx.jsonl that is valid JSON but
      not an object (e.g. `[]`, a string, a number) hit `dict.get` on a non-dict and raised
      AttributeError -> the entire aggregation aborted and the run produced no CSV. One stray/
      unexpected httpx line (error object variant, tool-version quirk, corruption) would lose the
      whole run. Fixed with an `isinstance(j, dict)` skip + a regression test (verified it fails
      without the guard). map.tsv parsing was already robust.
- [x] **Probe `--file` last-line bug (MED):** the `name url` loader skipped the last entry when the
      file had no trailing newline. Fixed with `|| [ -n "$line" ]` (same class as the resolver fix).
- [x] **RESOLVER_OK_ADDR set -u fragility (defensive):** the success message referenced it bare;
      hardened to `${RESOLVER_OK_ADDR:-...}` so a future refactor can't trip `set -u` and abort.
- [x] **db_bulk_cache read loop (defensive):** hardened the general-purpose helper's `while read`
      for a final line with no newline.

Verified (no bugs)
- [x] generate-report.sh is XSS-safe: adversarial `<script>`/`<img onerror>`/`<b>` payloads in
      titles/findings all render escaped (raw dangerous tags = 0); handles empty, malformed
      (short-row), and unicode CSVs without crashing.
- [x] Test suite is mutation-sensitive: neutering the resolver check and disabling the report call
      each produced the expected failures (the harness catches regressions, no tautological tests).
- [x] Probe retry-after arithmetic is guarded (`^[0-9]+$` before `-gt`); all other `while read`
      loops consume tool-generated files (trailing newline guaranteed).

**Suite 212/212** (+1 regression test). shellcheck warning-clean; embedded Python compiles.
run-recon.sh → **v1.15.2**.

---

## recon-db.sh — fix real-world DB setup failure (msf creds work, separate 'recon' DB unreachable)

Reported console errors: msf creds authenticated to the 'msf' database, but every attempt to reach
a separate 'recon' database failed (as msf AND via a new 'kali' role), so init failed outright.
Root cause: msfdb's pg_hba.conf commonly authorizes the 'msf' role only for the 'msf' database, so
'msf' can't authenticate to 'recon' regardless of ownership; the 'kali'/peer path then failed because
init had been run via sudo (peer auth ran as OS-user root, not role 'kali').

- [x] **msf-database fallback:** when a separate 'recon' DB can't be reached with msf creds, store the
      namespaced recon_cache / recon_hosts tables IN the 'msf' database (already proven reachable; no
      CREATE DATABASE, no sudo, no new pg_hba rule; no collision with Metasploit's tables). db.env then
      records PGDATABASE=msf. The separate 'recon' DB is still tried first, so setups that allow it are
      unaffected.
- [x] **env-leak hardening:** the superuser create is now `_psql_super` =
      `sudo -u postgres env -u PGHOST -u PGPORT -u PGUSER -u PGPASSWORD -u PGDATABASE psql ...`, so it
      authenticates as 'postgres' via peer and can't be contaminated by the exported msf creds. Used in
      both the msf and legacy superuser paths.
- [x] `_write_db_env` now records `${PGDATABASE:-$RECON_DB_NAME}` so the fallback's DB is saved.
- [x] Verified with mocks: Ben's scenario (recon unreachable) -> falls back to msf DB, db.env
      PGDATABASE=msf; happy path (recon reachable) -> still uses the separate recon DB. Header docs +
      help range updated. **Suite 212/212**, shellcheck clean.

---

## recon-db.sh — grant privileges on the new 'recon' DB (complements, doesn't replace, the fallback)

Follow-up to the DB-setup fix: add the privilege grants that fix the *SQL-layer* failure modes for a
separate 'recon' database, while keeping the msf-DB fallback for the *authentication-layer* (pg_hba)
case that no GRANT can fix.

- [x] Superuser create now also runs (idempotently): `ALTER DATABASE recon OWNER TO msf` (fixes a
      pre-existing DB owned by someone else) and, connected to recon, `ALTER SCHEMA public OWNER TO
      msf` + `GRANT ALL ON SCHEMA public TO msf`. The schema grant matters on **PostgreSQL 15+**, which
      no longer grants CREATE on the public schema to non-owners -- without it a connected msf could
      still fail at CREATE TABLE.
- [x] Key distinction (documented for Ben): pg_hba.conf governs whether a role may *authenticate* to a
      database and is NOT modifiable via SQL, so a GRANT cannot unblock it. The reported error was a
      `SELECT 1` (connect-time) failure, i.e. the auth layer -> grants wouldn't have fixed it, the
      fallback does. Grants fix the privilege layer (PG15 public schema, ownership) so the separate DB
      is used whenever authentication permits.
- [x] Verified with a corrected sudo mock (the earlier mock wrongly stripped `env -u` flags): Scenario
      A (pg_hba blocks msf->recon) -> msf-DB fallback (PGDATABASE=msf); Scenario B (recon reachable,
      PG15 CREATE denied until grant) -> separate recon DB used (PGDATABASE=recon). Suite 212/212,
      shellcheck clean.

---

## recon-db.sh — dedicated 'recon' DB as PRIMARY method (msfdb-style), msf reuse as backup

Re-architected db_setup per request: create our own database/role on the local PostgreSQL as the
primary method (copying how msfdb provisions its DB), with the msf-credential reuse demoted to backup,
and no-DB as the final fallback.

Researched msfdb's actual `init_db` method (Metasploit docs): `create user msf with password '…'` ->
`alter role msf createdb` -> `alter role msf with password '…'` -> `createdb -O msf -h 127.0.0.1 -U msf
-E UTF-8 -T template0 msf`. Copied that pattern.

- [x] **`_new_recon_db` (PRIMARY):** via the postgres superuser, create-or-repair a login role
      (`RECON_DB_USER`, default `recon`) `WITH LOGIN CREATEDB PASSWORD <random>` (idempotent DO block =
      msfdb's create + alter createdb + alter password); then `createdb -O recon -h 127.0.0.1 -U recon
      -E UTF-8 -T template0 recon` (as the role, msfdb-style), with a superuser `CREATE DATABASE …
      ENCODING 'UTF8' TEMPLATE template0` fallback; then PG15+ public-schema grants; then write db.env
      and verify by connecting as the role over TCP. Password auth over 127.0.0.1 -> no peer/ident
      dependency, independent of Metasploit. `_gen_pass` = 32 alnum chars from /dev/urandom (openssl /
      hash fallbacks).
- [x] **BACKUP:** the existing msfdb-credential path (separate `recon` DB, or `msf` DB with namespaced
      tables). **FINAL:** report + return 1; run-recon degrades to an uncached run.
- [x] New config: `RECON_DB_USER` / `RECON_DB_HOST` / `RECON_DB_PORT` (recon / 127.0.0.1 / 5432).
      Removed the old peer/ident "dedicated role for the current user" path (the password-auth primary
      supersedes it and fixes the run-as-root peer failure).
- [x] Verified with mocks (correct sudo mock): S1 postgres+sudo -> dedicated recon DB, db.env
      PGUSER=recon/PGDATABASE=recon, `createdb` invoked exactly as msfdb; S2 no sudo -> backup -> msf DB
      (PGDATABASE=msf); S3 nothing -> no DB, returns 1. Header/README/help updated. **Suite 212/212**,
      shellcheck clean.

---

## recon-db.sh — bug/optimization pass on the new dedicated-DB code

Focused review of the just-added primary DB provisioning (`_new_recon_db`, `_gen_pass`, restructured
`db_setup`), with edge-case mock tests for each failure path.

Bugs / robustness fixed
- [x] **Stale db.env on primary failure:** `_new_recon_db` wrote db.env *before* verifying, so a failed
      attempt (e.g. the new role can't authenticate over TCP) left db.env pointing at an unusable DB.
      Now it verifies (`db_available && db_schema`) and writes db.env ONLY on success. Verified: total
      failure leaves no db.env.
- [x] **Locale-brittle superuser CREATE DATABASE:** the createdb-absent fallback used
      `ENCODING 'UTF8' TEMPLATE template0`, which fails on a server whose default locale isn't
      UTF-8-compatible (needs matching LC_*). The fallback now inherits the server defaults; the
      primary `createdb` path still matches msfdb's `-E UTF-8 -T template0` when createdb is present.
- [x] **`_gen_pass` exit-status footgun:** returned non-zero on empty output (harmless today —
      recon-db.sh has no `set -e` and run-recon never calls it — but a footgun if `db_setup` is ever
      called under `set -e`). Now always exits 0; caller checks for emptiness.

Optimization
- [x] **`_sql_esc` -> pure bash:** was forking a `sed` per call, and it runs 2-3x per
      `db_cache_get`/`db_cache_put` (i.e. per OSINT lookup per IP). Replaced with `${s//\'/\'\'}`
      (proven byte-for-byte equivalent across empty/quote/multi-quote inputs). Removes a fork from the
      hot cache path; `_ident`/`_shq` left as-is (setup-only, not hot).

Verified (no bugs)
- [x] Superuser-create fallback emits valid SQL and succeeds when createdb is absent.
- [x] Password-reset recovery: a stale db.env with the wrong password + an existing role -> the
      idempotent `ALTER ROLE ... PASSWORD` rotates it and db.env is rewritten to match (rc=0).
- [x] Cache round-trip with single quotes in source/key/value is correct after the `_sql_esc` change.
- [x] `db_schema` runs once (main-process preflight); parallel workers never repeat it.
- [x] Updated two installer messages that still described the old msf-reuse primary.

**Suite 212/212**, all scripts shellcheck-clean, embedded Python compiles.

---

## generate-report.sh — fix screenshots not appearing (host-in-subdirectory layout)

Reported: screenshots weren't included in the report even though `--screenshots` ran and the PNGs
existed on disk.

Root cause: the host<->image matching normalized only `os.path.basename(p)` (the filename). Some
screenshot layouts put the host in a *directory* component with a generic filename (e.g.
`screenshots-<ts>/screenshot/<host>/screenshot.png`), so the host wasn't in the basename and nothing
matched. The host-in-filename layout (e.g. gowitness `https_host.png`) worked, which is why it was
intermittent.

- [x] Match on the path RELATIVE to the screenshots dir (includes host subdirectories), not just the
      basename. Backward-compatible: host-in-filename still matches.
- [x] Match longer (more specific) hostnames first and claim each image once, so a subdomain's
      screenshot isn't also grabbed by a shorter apex whose normalized form is a substring of it.
- [x] Regression test added (host-in-subdirectory fixture); verified it fails on the old basename-only
      code. **Suite 213/213**, report Python compiles, shellcheck clean.

Note: screenshot matching depends on the CSV `host` column being populated (it drives the per-host
cards). If enrichment columns are empty the host column is still derived from the URL, so matching
works regardless of enrichment.

---

## run-recon.sh (aggregator) — robust httpx enrichment join + diagnostics

Investigated empty enrichment columns (E-L). The aggregator itself is correct (verified: with matching
URLs, E-L populate). The failure modes are upstream: (A) httpx produced no JSON records, or (B) httpx's
url/input didn't exactly match the crawled URLs so the join silently missed. The join used only exact
url / url.rstrip("/") matching, which breaks on default ports, trailing slashes, and http->https
redirects (httpx reports the final `url`).

- [x] **Robust join:** index httpx records by exact url/input, a normalized key (`urlkey`: lowercased
      scheme+host, default port dropped, trailing slash stripped), AND by host. Lookup tries exact ->
      normalized -> host-level (best-effort) so port/slash/scheme differences still enrich.
- [x] **Diagnostics (never silent):** the aggregator now prints HTTPX_RECS / ENRICHED and writes a clear
      stderr message: "httpx produced 0 JSON records ... check it's httpx-toolkit not python3-httpx"
      (case A) vs "parsed N record(s) but NONE matched ... example httpx key=X vs crawled url=Y" (case
      B), plus a partial-match note. This tells the operator exactly which failure they have.
- [x] Regression tests (extract the embedded aggregator, feed mismatched URLs): port/slash normalized
      match, http->https host-fallback match, and both diagnostics. Mutation-verified (removing the host
      fallback fails the redirect case while normalization still passes). **Suite 217/217.**

Likely real-world cause for Ben: httpx enrichment producing 0 records while screenshots exist implies
the enrichment path is hitting the wrong/failing httpx (screenshots came from gowitness fallback, or
httpx.jsonl is empty). The new stderr diagnostic will state which case it is on the next run; if it's a
URL-shape mismatch, the robust join now fixes it outright.

---

## run-recon.sh — cache the active HTTP/TLS probing layer (6 stages)

Extended the DB cache from the passive/OSINT layer to the active per-run probing, which was the bulk of
repeat outbound traffic on sequential runs. All six requested stages now cache:

1. **httpx per-URL enrichment** (highest value) — the JSON record is cached keyed by URL; only
   cache-miss URLs are re-probed. Fresh records are keyed by their `input`; dead URLs negative-cached.
2. **httpx live-host probe** — cached per host authority (host[:port]).
3. **naabu ports** — cached per host (open host:port lines).
4. **katana crawl** — cached per live host; only miss hosts' live URLs are re-crawled. The store filters
   to keys actually crawled so katana's root-domain scope can't overwrite another host's full cache.
5. **tlsx JARM** — cached per host.
6. **screenshots** — the PNG **bytes** are cached per host (base64) and restored into the run's
   screenshot dir, so a cached host still yields a real image in the report without re-rendering. Fresh
   renders go to a staging dir so only new files are matched/cached; dead hosts negative-cached.

Mechanism (new, shared): `db_cache_mget` (recon-db.sh) does a one-round-trip batched read via a temp
table + `\copy`; `cache_split` / `cache_store` (run-recon.sh) partition a keyfile into cache-hits vs
misses and store fresh results grouped by key. Values are **base64-encoded** so multi-line-per-key blobs
survive the line-oriented batched cache. Every stage is **rc-gated**: the tool's fresh results are used
this run, but `cache_store` runs only on a clean exit (rc=0), so a timeout (rc=124) never poisons the
cache — same rule as `cache_or_run`. Screenshots use dedicated `_ss_restore` / `_ss_save` helpers.

- [x] Verified round-trips against a real psql mock: enrichment (run 2 probes **0** URLs), naabu
      multi-line values, screenshot bytes (restored PNG == original), and negative caching (dead
      keys skipped on run 2).
- [x] Regression tests: `--db` runs now assert every new source is consulted (`httpx_json`,
      `live_probe`, `katana`, `naabu_ports`, `tlsx_jarm`, `screenshot`). **Suite 223/223.**
- [x] DB-off path unchanged (cache_split with USE_DB!=1 -> run everything); existing enrichment /
      katana / JARM tests still pass. shellcheck-clean, all embedded Python compiles.
- [x] README §6 updated (new caches + the freshness/traffic and screenshot-storage tradeoffs).

Tradeoffs (documented): cached active probes reuse the last status/title/screenshot for up to
`CACHE_TTL` (lower it or purge for change-detection); the screenshot byte-cache trades DB space for
skipped renders (can be hundreds of MB on large runs; `recon-db.sh purge N`). Enrichment caching keys on
httpx echoing `input` verbatim; if a future httpx normalized `input`, those keys just miss (safe: no
caching, re-probe) rather than mis-joining.

---

## recon-db.sh — import historic run CSVs (oldest-first, newest-wins, schema-drift tolerant)

Added `recon-db.sh import <csv-or-dir>...` to load a backlog of past run outputs into recon_hosts, and
`recon-db.sh latest [pattern]` for the current-state view.

Design: recon_hosts is already **versioned** (PK `(run_ts, url)`), so the non-destructive fit is to load
each historic CSV as its own run and let the newest run be authoritative — rather than physically
overwriting and losing history.

- [x] `import`: collects CSVs (dirs scanned for `*.csv`), derives a sortable `run_ts` per file
      (`recon-<TS>.csv` filename, else file mtime), loads **oldest first** via the existing
      `db_load_csv` (ON CONFLICT DO NOTHING — re-import is a no-op). Distinct timestamps disambiguated
      so two files never silently merge.
- [x] **Schema-drift tolerant:** `_import_normalize` rewrites each CSV to the canonical 12-column schema
      by matching source columns by header **name** (+ a few aliases), so older/narrower exports load
      with missing columns empty. (The raw `\copy` in `db_load_csv` is positional and would reject them.)
- [x] `latest [pattern]`: `SELECT DISTINCT ON (url) ... ORDER BY url, run_ts DESC` — the newest run wins
      per URL. Full history stays queryable via `hosts`.
- [x] Verified end-to-end against a stateful psql mock: a 3-column CSV and a 6-column CSV both import; a
      URL whose status changed 200->500 across runs shows **500** in `latest` while the old **200** row
      remains in `hosts`; mtime fallback works for non-`recon-` filenames.
- [x] Regression test added (schema drift + newest-wins + history preserved + stale-not-current).
      **Suite 228/228**, shellcheck-clean, all 6 embedded Python blocks compile. README updated.

Note: this imports the **inventory** (recon_hosts), not the cache — it makes historic data queryable,
it does not by itself make future runs skip work. Cache-warming from historic data would be a separate
feature (and carries a real staleness question), offered but not built.

---

## recon-db.sh — fix-collation command + init mismatch detection

After a glibc upgrade on Kali, Postgres warns that the `recon` DB has a collation version mismatch
(recorded collation version no longer matches the OS library). Data is intact; text-index sort order
can go stale. Added one-command remediation and up-front detection.

- [x] `db_collation_mismatch`: version-independent detection — primary is a PG15+ catalog comparison
      (`datcollversion <> pg_database_collation_actual_version(oid)`); if that function/column is absent
      (older PG) it falls back to capturing the WARNING Postgres emits on connect.
- [x] `recon-db.sh fix-collation` (`db_fix_collation`): `REINDEX DATABASE` **then**
      `ALTER DATABASE … REFRESH COLLATION VERSION` (reindex first — refreshing alone leaves stale
      indexes). Runs as the DB owner first (no sudo in the common dedicated-`recon` case), falls back to
      the postgres superuser (`_psql_super`) when the owner can't (e.g. tables inside the `msf` DB), and
      prints the manual superuser one-liner if both fail. Verifies the warning cleared afterward and, if
      a shared catalog (`template1`/`postgres`/`msf`) still mismatches, prints a refresh-every-DB loop.
- [x] `init` now detects the mismatch on the already-reachable path and points to `fix-collation`.
- [x] Header command list + `help` range updated (header grew 3 lines; `sed -n '2,47p'` now captures the
      full block — verified help renders its tail). CLI `unknown command` hint updated.
- [x] Verified end-to-end against a stateful psql mock: catalog detection, warning-capture fallback,
      init notice, owner happy-path (no sudo), owner-denied→superuser fallback, and post-fix clearance.
- [x] Regression test added (6 assertions: init detects, points to fix, runs as owner, verifies, state
      cleared, init quiet after fix).

Also fixed a **suite portability** issue surfaced in this environment: an ambient `GITHUB_TOKEN`/
`GH_TOKEN` (injected here for the `gh` CLI) made the "--github without a token" case see a token and
fail. The suite now `unset`s both at startup so it's independent of the host environment; the
with-token test passes a token file and is unaffected.

**Suite 234/234**, all scripts shellcheck-clean, all 6 embedded Python blocks compile.

Caveat: mock-validated, not run against real PostgreSQL/glibc. The `pg_database_collation_actual_version`
catalog path and the owner-vs-superuser privilege behavior are the two things worth a quick check on the
Kali box (`./recon-db.sh init` to see the notice, then `./recon-db.sh fix-collation`).

---

## run-recon.sh — TLS posture via tlsx (L7-05); first installment of the WebInventory-parity work

Added a TLS posture stage (parity with WebInventory's tls/jarm hygiene flags). Scoped as the first of a
5-part request; the other four (IPv6/AAAA, geo/RDAP/cloud enrichment, CPE+NVD/KEV/EPSS join) are sequenced
for following turns.

- [x] `--tls` (and `--tls-full` for version/cipher enumeration) -> new stage in `analyze_hosts` that runs
      tlsx `-json -tls-version -cipher -expired -self-signed -mismatched -untrusted -wildcard-cert`
      (`-version-enum -cipher-enum` with `--tls-full`) over the https authorities derived from the live
      URLs. Reuses the cache infra (cache_split/cache_store) with a new `jsonauthority` mode, rc-gated so a
      timeout can't poison the cache — same pattern as the JARM stage.
- [x] Aggregator: 5 new CSV columns (`tls_version`, `tls_cipher`, `cert_not_after`, `cert_issuer`,
      `tls_flags`) appended after `asn_org` (existing column positions preserved). tlsx records indexed by
      `host:port` + host; joined to https rows by the URL's authority (default 443). Flag logic mirrors
      WebInventory: `WeakTLS` (< TLS 1.2, negotiated or enumerated), `WeakCipher` (RC4/3DES/DES/NULL/
      EXPORT/anon/MD5), `CertExpired`, `CertExpiring` (<=21d), `SelfSigned`, `CertNameMismatch`,
      `CertUntrusted`, `CertRevoked`, `Wildcard`. Date parsing is tz-aware (no deprecated `utcnow()`).
- [x] Report: TLS flags surfaced as severity-rated findings on the owning host (reuses the findings UI).
- [x] **Export fix:** `TLS_POSTURE`/`TLS_ENUM` added to the worker export list (line ~2188) — without it
      the flags defaulted to 0 in the xargs workers and the stage silently never ran. Caught by the
      end-to-end test.
- [x] Tests (13 assertions): standalone aggregator flag logic with computed cert dates (healthy / weak
      TLS+cipher / expired / self-signed+mismatch+untrusted / http-empty), end-to-end `--tls` + `--tls-full`
      wiring (tlsx `-tls-version`/`-version-enum`/`-cipher-enum`, CSV join, header), and report surfacing.
      Mutation-verified (dropping RC4 from the weak-cipher set fails the WeakCipher test).
- [x] **Suite 247/247**, all scripts shellcheck-clean, all 6 embedded Python blocks compile. README updated.

Caveats: mock-validated, not run against real tlsx — the tlsx `-json` field names (`tls_version`,
`cipher`, `not_after`, `self_signed`/`mismatched`/`untrusted`, `version_enum`/`cipher_enum`) are parsed
defensively (multiple aliases, empty on absence), but the exact shape should be confirmed on Kali with a
real `tlsx -json` run. `--tls-full` enumeration is noisier (many handshakes/host) — gated separately.

## run-recon.sh — IPv6 + cloud + RDAP + geo enrichment (FPV-08, DNS-06, DSC-11); installment 2

Second of the 5-part request: per-row network-layer attribution + IPv6. Four new CSV columns.

- [x] `--ipv6` -> AAAA stage in `analyze_hosts` (dnsx `-aaaa -json`), parsed to `host<TAB>v6;v6` parts,
      assembled to `aaaa.tsv`, joined into the new `ipv6` column. `IPV6` added to the worker export list
      (same class of bug as the TLS `TLS_POSTURE` export miss — caught by an e2e `-aaaa` assertion).
      Active v6 *probing* deliberately omitted: it needs working v6 egress on the runner and would emit
      misleading dead results; resolution is the reliable signal.
- [x] `--enrich` -> three per-IP columns in the aggregator:
      - `cloud`: longest-prefix match against the providers' published IP-range feeds (AWS/GCP/Azure/
        Cloudflare/Oracle/DigitalOcean), each format parsed in a `fetch_cloud_ranges` helper. Feeds are
        fetched once and cached to `~/.cache/run-recon/cloud_ranges.tsv` (7-day TTL, `RECON_CLOUD_CACHE`
        override; atomic `.tmp`+`mv`, keeps a stale copy if a refresh fails).
      - `rdap_org`: network/registrant org from `rdap.org` (top-level `name`, else registrant/admin/owner
        vCard `fn`). Cached per IP in the DB (`source='rdap_ip'`) with the exact warm-from-DB / resolve-
        misses / sync-back-new handoff used for ASN; budget-bounded by `ASN_MAX`.
      - `geo`: ISO country via `mmdblookup` against a **local** MaxMind DB. Pluggable (`--geodb PATH`,
        implies `--enrich`) because GeoLite2 needs a MaxMind account + EULA; blank without a DB.
- [x] Enrichment file paths handed to the aggregator via **env vars** (`AAAA_FILE`, `CLOUD_RANGES_FILE`,
      `RDAP_CACHE_FILE`, `GEO_DB`, `ENRICH`), mirroring the `ASN_CACHE_FILE` pattern — no argv churn.
- [x] `--all` now also implies `--ipv6 --enrich` (TLS posture already added in installment 1).
- [x] **Bug found + fixed (pre-existing, latent):** `recon-db.sh db_load_csv` staged the run CSV into a
      fixed 12-column `_stage` via `\copy ... FORMAT csv`. The CSV grew to 17 cols (TLS) then 21 (this
      work), so real psql would reject it with *"extra data after last expected column"* on every live
      `--db` run. The bash psql mock doesn't enforce column count, so the suite never caught it. Fixed by
      routing `db_load_csv` through the existing `_import_normalize` (match-by-header-name -> canonical 12
      cols), which also keeps older/narrower CSVs loading. Regression test added that loads a real 21-col
      header.
- [x] Tests (+14 -> **261/261**): standalone aggregator (AAAA join, longest-prefix cloud /16-over-/8, RDAP
      top-level `name` + registrant vCard `fn`, geo via mocked mmdblookup, warm-cache *no re-query* refute,
      sync-back-to-file), e2e `--ipv6 --enrich --geodb` (AAAA stage runs, feeds fetched+cached, all four
      columns joined), `--all` implies both, and the full-width `db_load_csv` regression. Added a
      suite-wide **network-safe `curl` mock** (OSINT/CMS/cloud/RDAP all route through curl) so the suite
      makes zero real egress and is deterministic; `run_case` now isolates `RECON_CLOUD_CACHE` per case.
- [x] All scripts shellcheck-clean (`-S warning`); all 3 touched embedded Python blocks compile
      (aggregator, `fetch_cloud_ranges`, AAAA parser). README updated (flags, CSV schema, `--all`).

Caveats: mock-validated, not run against real dnsx/curl/mmdblookup. The cloud-feed JSON shapes are parsed
defensively but the providers do change their formats (Azure's dated download URL especially — scraped from
the details page, best-effort); confirm on Kali. RDAP org naming varies by RIR. Geo needs the operator to
supply a GeoLite2 `.mmdb`. The DB `rdap_ip` cache is unbounded by age until `recon-db.sh purge` runs.

## run-recon.sh — CPE 2.3 emission (FPV-06); installment 3, part 1

First half of the final 5-part item. Rule-based CPE emission (Ben chose the heavier/more-precise port over a
fuzzy product→CPE guess map). The offline NVD/KEV/EPSS join (FPV-07) is part 2, a separate command.

- [x] New always-on `cpe` column (CPE 2.3, `;`-joined), appended after `geo` so existing column positions are
      untouched. Pure offline transform of data httpx already collected — no new tool, no network, no flag to
      remember.
- [x] `build_cpes()` in the aggregator: product+version candidates from the httpx tech list (Wappalyzer
      `Name:version`) and the `Server` header (`token/version`, regex-anchored so trailing `(Ubuntu)` /
      multi-token junk is dropped and a Coyote-style banner doesn't mint a bogus Tomcat version). Version
      sanitized to a leading numeric token; unknown version -> `*` (product-only CPE).
- [x] Curated product→CPE table (~55 products: web servers/proxies, languages/runtimes, app frameworks,
      CMS, JS libs, devops UIs, mail/ftp), ported from WebInventory's rule approach. NVD-split vendors emit a
      LIST (nginx -> `f5:nginx` + `nginx:nginx`) so a CVE under either vendor correlates. Joomla kept as the
      NVD-canonical `joomla\!`.
- [x] `--cpe-map FILE` / `CPE_MAP_FILE`: TSV (`name<TAB>cpe:2.3:a:vendor:product`, `#` comments) merged over
      the built-ins so a site can add/correct products without editing the script (mirrors WebInventory
      `-RulesFile`). Exported to the aggregator alongside `ASN_CACHE_FILE`.
- [x] Tests (+12 -> **273/273**): standalone aggregator (nginx version from a junk Server header, dual-vendor
      nginx, PHP/WordPress from tech, Microsoft-IIS token, `Microsoft ASP.NET` normalization, CPE_MAP_FILE
      override, Coyote-not-mismapped refute, header position) and e2e (default run emits product-only CPEs,
      header present). All scripts shellcheck-clean; all 3 embedded Python blocks compile.

Caveats: CPE vendor/product strings are themselves a known source of NVD-match error (IIS CVEs often live
under the Windows OS CPE; nginx is split; some products have no stable NVD CPE and are intentionally absent —
the table is a starting set, extend via `--cpe-map`). run-recon only has httpx's distilled tech list + Server
+ title per row, not raw headers/cookies/favicon, so this ports WebInventory's CPE *format and table*, not
its full 475-rule C# fingerprint engine. Versions are banner-derived (backport caveat applies).

## run-recon.sh / recon-db.sh — offline NVD/KEV/EPSS vulnerability join (FPV-07); installment 3, part 2

The back half: a `recon-db.sh vulns` subcommand that joins the run CSV's `cpe` column with NVD CVE JSON 2.0
feeds + CISA KEV + FIRST EPSS that the operator downloads. Offline — nothing fetched, nothing sent to a
target. Ported from WebInventory's `-StoreQuery Vulnerabilities`. Completes the final 5-part request.

- [x] New `recon-db.sh vulns <run.csv> --nvd-feed DIR [--kev-file F] [--epss-file F] [-o OUT]`. No DB needed
      (pure file join); embedded `python3 -I` (isolated — the feeds are downloaded files). Writes
      `<csv>.vulns.csv` + a `.provenance.json` sidecar. Wired into the CLI dispatch, header-comment usage and
      the unknown-command hint.
- [x] **Version-aware matching** (the hard part): vendor+product must match; numeric segment compare with the
      CPE **update field** folded in (`9.3:p1` == service `9.3p1`); `versionStart*/End*` ranges; **prerelease
      ordering** (`rc/beta/alpha/...` sort *before* the release, patch/vendor letters *after* — `1.0rc1` <
      `1.0` < `1.0.2k`); `2.4` == `2.4.0`. Implemented as a token key `(tag, val)` with tag 0=prerelease /
      1=numeric / 2=post, padded and compared natively.
- [x] **Match confidence** column: `version` / `range` / `all-versions` / `… (platform not verified)` for
      AND-configs whose other node (usually an OS `cpe:2.3:o:…`, which run-recon never emits) can't be
      confirmed / `product-only` (service exposed no version — emitted **only** for KEV CVEs).
- [x] **Newest-record-wins** across yearly + modified feeds: two-pass (dedupe by CVE on `lastModified`, then
      join) so the newer record's whole payload (description, CVSS, config) wins — not just a higher match
      rank. Rejected CVEs skipped (judged on the winning record). Streaming prefilter keeps only CVEs naming
      an inventory product. (Bug caught in dev: a stray leftover `nvd_meta.append` in the pass-2 loop inflated
      the provenance feed list — removed.)
- [x] KEV (dateAdded/dueDate/ransomware + catalogVersion) and EPSS (score/percentile + model_version/
      score_date from the `#`-comment header) loaded; `.gz` or plain. Output sorted **KEV → EPSS → CVSS**.
      FPV-01 formula-injection guard on exported text fields; control chars stripped; descriptions capped.
- [x] Provenance sidecar: per-feed file name + SHA-256 + record count, KEV catalogVersion, EPSS model/date,
      service and row counts.
- [x] Tests (+16 -> **289/289**): a hand-made NVD/KEV/EPSS fixture set exercising every match type, the
      update field, newest-wins (NEW vs OLD record), product-only KEV-gating, platform-not-verified, Rejected
      skip, KEV-first sort, the provenance sidecar, a no-CPE input, the `.gz` EPSS branch, and the missing-
      `--nvd-feed` usage error. recon-db.sh shellcheck-clean; the embedded `PYVULN` block compiles.

Caveats: fixture-validated, not yet run against the real ~447k-record NVD corpus (WebInventory clocks that at
~60 s in C#; the Python here `json.load`s one feed file at a time to bound memory — fine for an occasional
offline run, but confirm timing on Ben's box). CPE vendor-string mismatches (the part-1 caveat) cap recall.
Platform AND-configs are always "not verified" because run-recon emits only `a:` CPEs, never the `o:` OS CPE —
honest, but PHP-on-Windows-style CVEs never reach full confidence here. Banners can be backported; this is a
prioritized worklist, not confirmation — pair with an authenticated scanner.

**Installment status:** the original 5-part request is now complete — (1) WebInventory web-feature parity +
(2) TLS posture [installment 1], (4) ASN/geo/RDAP/cloud + (5) IPv6/AAAA [installment 2], (3) CPE + NVD/KEV/
EPSS join [installment 3]. Everything mock/fixture-validated on the sandbox; the standing caveat across all
of it is a real run on Kali against live tools + real feeds.

## generate-report.sh — vuln-join CVEs as report findings

Follow-on to installment 3: the HTML report now folds the offline vuln join into its findings UI (closing
scan → CPE → CVE → report).

- [x] `generate-report.sh` auto-detects `<csv>.vulns.csv` (override `--vulns FILE`) and emits one finding per
      (host, CVE) through the existing findings machinery (same path TLS flags use).
- [x] Severity: **KEV → Critical**; else CVSS severity/score (≥9 crit, ≥7 high, ≥4 med, >0 low); EPSS ≥ 0.5
      bumps a sub-High finding to High. Finding line: CVE, CVSS, EPSS, `KEV`/`KEV/ransomware`, match
      confidence, short description. `vuln` added to the highlighted (top-table) kinds.
- [x] Summary dashboard gains **KEV** and **Known CVEs** cards when a join is present. Footer links the vulns
      CSV. No join present → report builds exactly as before (no CVE section).
- [x] Tests (+9 -> **298/298**): KEV→Critical badge, non-KEV CVE, ransomware flag, KEV card, auto-detect vs
      explicit `--vulns`, and the no-join path (builds clean, no CVE findings). shellcheck-clean.

## recon-db.sh — `clean` data-retention sweep (blank-file pruning)

Reported symptom: thousands of blank files/records across hosts. Investigation: a normal run is already
tidy (the `_work-*` tree is deleted at the end; empty `<csv>.<kind>.txt` side-artifacts are pruned at
line ~3012). The proliferation comes from **`--keep-work`**, which keeps the whole tree: per-domain
`raw/<host>/` (~40 intermediates each, many `: >`-initialised empties), empty `done/<host>` markers, and
empty `parts/` files — N domains × dozens = thousands of blanks. The fix is an explicit retention command
(the user asked to "evaluate a retention/cleanup process"), not more teardown in the hot path.

- [x] New `recon-db.sh clean <path>... [--dry-run] [--rows]` (embedded `python3 -I`, no DB). Walks each path,
      removes zero-byte and whitespace-only files, and deletes directories left empty (bottom-up).
- [x] **Preserves everything the report consumes:** never deletes `.csv`, `.html`/`.htm`, `.json`, or image
      files (`.png/.jpg/.jpeg/.gif/.webp/.svg/.pdf`) whatever their size; keeps every non-empty file. Refuses
      to sweep `/` or `$HOME`. Files >64 KB are treated as data without reading them.
- [x] `--dry-run` lists every removal and the freed-bytes/dir summary without deleting. `--rows` additionally
      writes `<csv>.cleaned.csv` dropping data rows with no host AND no url — **without mutating the original**
      (the "blank records" half of the report, done conservatively so report data is never lost).
- [x] Wired into the CLI dispatch, header-comment usage, and the unknown-command hint.
- [x] Tests (+17 -> **315/315**): dry-run deletes nothing; apply removes zero-byte / whitespace-only / empty
      markers / empty parts / stale empty artifacts; preserves CSV / HTML / empty-but-image / non-empty
      intermediates / screenshots; prunes the emptied `done/` dir; `--rows` writes a de-blanked copy and
      leaves the original intact. (Fixed a test-harness trap: the size-based `assert_exists`/`assert_absent`
      give false results on intentionally zero-byte fixtures — added existence-based `_exists`/`_gone`.)
      shellcheck-clean; `PYCLEAN` block compiles.

## bench-run-recon.sh + lab/ — container lab, real benchmarks, A/B (WebInventory method)

The first pass only scaffolded the harness. This pass ran it: the real ProjectDiscovery toolchain against the
container lab, WebInventory's method (3 runs, medians, process-tree CPU, field-by-field accuracy, leave-one-out,
keep a change only if faster AND identical). Results and the full checklist: `BENCHMARK.md`.

- [x] **Lab running for real.** `lab/docker-compose.yml`: CoreDNS (authoritative for `.test`) + Caddy TLS ingress
      + nginx 1.21.6, WordPress 6.4.3/Apache 2.4.57/PHP 8.2.17 (+MariaDB), a 120 KB SPA, Jenkins 2.426.1/Jetty
      10.0.17. RFC 6761 `.test` names, loopback only. `up` generates the SPA, a 50-vhost farm and its ground
      truth, installs WordPress (throwaway password, not stored) and waits for Jenkins. `LAB_DNS_IP` moves the
      lab DNS off 127.0.0.1:53 when Pi-hole/dnsmasq holds it; harness health checks use plain HTTP, so no
      certificate check is ever skipped.
- [x] **Ground truth confirmed on the real tools.** `lab/expected.csv` (status, technologies, CPEs, TLS flags,
      IPv6) for httpx 1.12 / tlsx 1.2.2 / dnsx 1.2.2 / katana 1.8. `CertExpiring` everywhere (12 h Caddy
      leaves); no `CertUntrusted` because tlsx's "untrusted" is a bad-CA list, not chain validation — recorded
      as a semantic gap with WebInventory.
- [x] **Headline (v1.15.2 → v1.16.0):** lab 70.17 → 23.27 s (3.02x), CPU flat, accuracy 3/3 both in that A/B
      (v1.15.2 10/12 across all sessions, v1.16 every run). Farm (50 seeds, `-t 5`) 363.1 → 156.5 s (2.32x);
      v1.15.2 lost a host's TLS posture under load, v1.16 matched ground truth.
- [x] **Accepted (faster + identical):** skip passive internet sources for special-use names (`SKIP_SPECIAL_USE`,
      default 1). Leave-one-out: 38.01 → 23.43 s (1.62x), output identical, 3/3 both.
- [x] **Shakedown fixes (accuracy; each changed field accounted for):** AAAA parser read resolver chatter;
      `http://` rows got the HTTPS response (`-nfs`); IP column held the hostname (`host_ip`); private IPs sent
      to Cymru/RDAP/InternetDB (now `is_global` only); live hosts dropped when the crawl was empty (live
      fallback rows); no httpx retries (`HTTP_RETRIES=2`: 10/100 → 0/100 failures under load); URL join depended
      on input order (6 orders → 6 CSVs, now 1). All 103 lab A/B differences trace to these.
- [x] **Concurrency (farm):** `-t 5` 158.3 s, `-t 10` 92.3 s (1.71x), both 3/3, output identical; `-t 20` 72.2 s
      but only 1/3 accurate — hosts blanked under load on 2 vCPU (WebInventory's farm finding, again).
- [x] **Late retry (`LATE_RETRY=1`, accuracy):** httpx's 3 attempts fire back to back inside one load spike, so
      URLs/TLS hosts that returned nothing get one more pass after a jittered 2–5 s pause. `-t 20`: 6/6 runs
      accurate over two sessions; it fired twice and recovered both hosts (f31, f08) that would have been blank.
      A record-count check skips it on healthy runs (lab 12.85 s CPU, `-t 10` 79.3 s — unchanged; output identical).
      Default stays `-t 5` (public seeds fan out to rate-limited archives; a Kali A/B).
- [x] **`--db` scenario (real PostgreSQL 16, `recon-db.sh init`):** warm 2.57 s vs cold 25.08 s (**9.8x**) —
      live probe, crawl, TLS posture and enrichment served from cache; output `--exact` identical to cold and to
      a run without the cache. Cold costs +1.1 s wall / +3.8 s CPU. 90 rows per run stored via the real `\copy`
      path (first real-psql check of the `db_load_csv` fix). Warm runs send nothing to targets for `CACHE_TTL`.
- [x] **Negative cache no longer keeps load-induced blanks:** enrichment and TLS-posture misses happen only on
      hosts the live probe just confirmed, so they are failed requests; caching them as "no record" served a
      blank row for `NEG_TTL` (1 day). `cache_store … noneg` for those two stages.
- [x] **Not adopted, with reasons (BENCHMARK.md):** lower katana `-timeout` (accuracy, = WebInventory #13); one
      katana run for all seeds (architecture); parallel passive collectors (Kali A/B); negative-caching empty
      passive-URL sets (gau exits 0 when providers fail — would cache outages). Found: `subs!neg` and
      `certsan!neg` are written but never read.
- [x] Tests: +14 → **362/362** (late retry on / off / healthy, TLS late retry, `missing_keys` unit checks, `--db` writes no negative entry for a failed URL; earlier this pass: AAAA shapes, `host_ip` + no third-party lookups for private IPs, deterministic join, `-nfs`, special-use skip). All scripts `bash -n` + shellcheck clean; `docker compose config` valid.

Scope note: WebInventory itself was not run (its code is not in this environment); the comparison is the same
service mix, the same ground truth and the same method. Anything needing the internet (passive collectors, rate
limits at higher `-t`, the DB cache on public seeds) is a Kali A/B.

## v1.17.0 — ProjectDiscovery coverage, takeover check, callbacks, pinning (batch 1 of TOOL-COVERAGE.md)

Source: pdtm's catalog (27 tools, read from the API pdtm v0.1.5 uses) and the WebInventory v2.3.0 product
sheet. Every item below was run with the real binary against the lab unless marked otherwise. Details:
`TOOL-COVERAGE.md`; numbers: `BENCHMARK.md` (v1.17 section).

- [x] **Coverage inventory.** 27 pdtm tools mapped (use, pin, lab status). Not wired yet: cloudlist, tldfinder,
      vulnx (planned); depx is supply-chain intelligence (DevSecOps, not EASM); pdtm itself can't pin versions.
- [x] **nuclei callbacks off by default** (`-ni`). `--interactsh-server URL` (+ `NUCLEI_ITOKEN`, never logged) for a
      self-hosted server; `NUCLEI_OAST=public` only by explicit opt-in. Verified on nuclei 3.11.1 with local
      listeners: with `-ni` the callback template never ran; with `-iserver` the only registration went there.
- [x] **asnmap:** key check up front (`PDCP_API_KEY` or `asnmap -auth`); a rejected key made asnmap prompt on
      `/dev/tty` (a terminal run would hang) and print the prompt on stdout into the CIDR list. Now: no terminal
      (`setsid`), CIDR lines only, "key rejected" reported.
- [x] **Range scan:** `mapcidr -aggregate` (without it every range was expanded IP by IP); IPv6 prefixes skipped;
      `RANGE_TLS_PORTS` / the `--ports` list instead of 443 only.
- [x] **Takeover check rebuilt:** CNAMEs of every candidate from before the resolve gate (dnsx), NXDOMAIN targets
      flagged (`[high]` for takeover-prone services, else `[medium]`), `<out>.cname.tsv` inventory, subzy and
      nuclei `-tags takeover` on every name with a CNAME. Fixed: subzy's settings banner was a false "takeover"
      finding for every seed. Lab fixtures in `lab/test.zone`; `bench-run-recon.sh takeover` passes.
- [x] **katana now gets `--resolvers` and `--proxy`** like httpx/dnsx/tlsx. v1.16 crawled with the system resolver and
      no proxy: names only your resolvers know gave an empty crawl (lab host without /etc/hosts: wp.test 1 URL
      instead of 87, 3/3 runs), and with a jump-host proxy the crawl went direct.
- [x] **stdin closed for every tool.** tlsx (CIDR lists), katana and `mapcidr -aggregate` read stdin even with
      `-l FILE`; workers always got /dev/null from xargs, but the main-process ASN/CIDR stage could wait forever
      when run-recon was started with stdin open and no terminal (CI, `ssh` without `-t`).
- [x] **Late HTTPS retry in the live probe:** a host that answered only on `http://` (HTTPS failed under load)
      gets one HTTPS try after a pause; the farm at `-t 10` lost a host's TLS posture this way.
- [x] **CSV formula guard (FPV-01)** on text cells; report and DB import strip it.
- [x] **Pinned tool versions** in both setup scripts (34 modules, none `@latest`); `RECON_TOOLS_LATEST=1` to upgrade
      deliberately. tlsx 1.2.2 → 1.4.0 and dnsx 1.2.2 → 1.3.1 A/B'd in the lab and the farm before pinning.
      Each run logs the four parsed tools' versions and warns on a non-lab-verified one.
- [x] Tests: +36 → **398/398** (katana gets --resolvers and --proxy; nuclei OAST modes and refusals, token never logged; asnmap no key / rejected key / aggregation / IPv6 skip / `--ports` list; CNAME takeover grades, pre-gate names, healthy alias not flagged, subzy banner not a finding, nuclei `-tags takeover -ni`, report severity + host; stdin closed). The suite also caught two bugs in this batch before release: `die` (not defined in run-recon) in three new checks, and `set -e` aborting workers when `--interactsh-server` was used without a token. All scripts `bash -n` + shellcheck clean.
- [ ] Next (batch 2): httpx fields (final URL, redirect, security headers, cookie flags, HSTS, Alt-Svc, body hash,
      response time, favicon mmh3), real favicon pivot, reverse DNS, opt-in robots/security.txt.

## v1.18.0 — report review fixes, `--zone-exposure`, verified `--origin` (REPORT-REVIEW.md)

Source: the lab report review (`REPORT-REVIEW.md`, 11 issues plus the zone-walking and origin
questions). Every item has a lab fixture or a suite test; numbers in `BENCHMARK.md` (v1.18 section).

- [x] **`--zone-exposure`** (new, opt-in, in `--all`). Per seed zone: SOA → NS → A, AXFR on every name
      server (`zone-transfer-open [high]`), NSEC walk by asking each owner name for its NSEC record
      (`nsec-zone-walkable [medium]`, capped at `ZONE_WALK_MAX`), NSEC3 parameters
      (`nsec3-hashes-exposed [low]`, nothing cracked), else `zone-checked [info]`. Only the zones' own name
      servers are queried. Names under a seed join its candidates; the rest are listed, not scanned →
      `<out>.zone.txt`, `<out>.zone-names.txt`. Lab: `xfr.test` (open AXFR), `walk.test` (NSEC-signed with
      ldns), `test.` (negative). `ldns-walk` stops at the apex against CoreDNS; the per-name NSEC query does not.
- [x] **`--origin` rebuilt.** v1.17 reported every JARM line as an "exposed origin" (4 false MEDIUM findings in
      the lab report). Now: edge detection per host into `<out>.edge.tsv` (Server chain, Via, CDN headers,
      cdncheck, JARM, favicon mmh3, title); candidates from `direct./origin./backend.` names, SPF `ip4:` (≤16
      addresses), MX and zone names; each verified with `curl --resolve host:port:ip` (Host and SNI = the
      site's name) against the edge's body SHA-256 / title + length / title. Findings only on a match:
      `origin-exposed [high]`, `origin-alternate [low]`, `origin-candidate [low]`. JARM stays cached under
      `--db`. Lab: nginx's backend published on `127.0.0.5`, leaked by `direct.nginx.test` and SPF → found,
      `body-sha256`; nothing for spa/wp.
- [x] **Screenshots were of the proxy error page or empty.** httpx's headless Chrome takes the environment
      proxy but not `NO_PROXY`, `-r` or `-proxy`. The browser now gets `--proxy-server` (from `--proxy`,
      credentials stripped with a warning) or a `--proxy-bypass-list` built from `NO_PROXY`, and an installed
      Chrome/Chromium (`-system-chrome`). Every capture is validated into `<out>.screenshots.tsv`: ok / blank /
      failed / suspect (browser title ≠ probe title, or an image identical to a different page's). Empty
      images are never cached under `--db`. Lab: real captures of nginx, wp, spa, ci; 12 Caddy default pages
      correctly `blank`.
- [x] **Run integrity.** The resolver preflight resolves the first seed: SERVFAIL/REFUSED is a failure (v1.17
      passed a lab DNS that SERVFAILed every name), NXDOMAIN is called out. Per-seed warnings when no candidate
      resolves or nothing answers the probe. 0 URL rows → "Finished with NO results" and **exit 3** (was
      "Complete." and 0). `<out>.run.json`: version, command line (proxy credentials redacted), tool versions,
      resolvers and their check, per-seed counts, artifact counts, warnings, exit status.
- [x] **TLS.** Chain validation against the system trust store (Python `ssl`, 16 in parallel, `TLS_CHAIN_CHECK=0`
      to skip) → `CertUntrusted`, as WebInventory reports it (tlsx's `untrusted` is a bad-CA list). Expiry or
      not-yet-valid alone is not a trust failure. `CertExpiring` at 30 days (`CERT_WARN_DAYS`, WebInventory's
      default; was 21). Lab ground truth updated: every lab name is `CertUntrusted` (Caddy's local CA).
- [x] **Crawl junk.** URLs containing `\/` or `%5C/` (katana `-jc` on JSON-escaped paths) are dropped before
      normalisation: the only default-path change (3 wp.test rows in the lab).
- [x] **Report rebuilt** (`generate-report.sh`): run header from run.json, no-results banner, seeds / names / live
      hosts, DNS zones table, name inventory (DNS state, CNAME, aliases under their target, cards for dangling
      names with findings), host cards (title, IPv6, server, edge → origin software → verified origin, JARM,
      favicon, issuer + days left, CNAME chain, CPEs), TLS expiry graded by days left at run time (expired High,
      <7 d Medium, <30 d Low), screenshot status, "Known vulnerabilities: not checked" + CPE list, colour codes
      stripped, zone-checked and legacy JARM lines kept as evidence rather than findings.
- [x] **Lab:** `bench-run-recon.sh zone`, `origin` and `checks` (takeover + zone + origin): **PASS**. Zone files
      renamed `db.<zone>` (a synced folder deleted `*.zone`); `up` needs ldnsutils to sign walk.test. No NSEC3
      fixture: CoreDNS cannot serve one, and a failed reload keeps the old config live.
- [x] Tests: +97 → **495/495** (zone: AXFR/NSEC/NSEC3/closed, names scanned, default sends no AXFR; origin:
      edge.tsv, SPF candidate, `curl --resolve`, no proxy, edge IP never a candidate, exposed / no match /
      title-only, report; screenshots: browser routing, proxy credentials, manifest ok/suspect/blank; run
      integrity: seed preflight NOERROR/SERVFAIL/NXDOMAIN, per-seed warnings, exit 3 + banner, run.json
      redaction; crawl junk; chain validation against a local TLS server; 30-day threshold; report v1.18). The
      suite never lets the chain check reach the network (`TLS_CHAIN_CHECK=0` in run_case). All scripts
      `bash -n` + shellcheck clean.
- [ ] Next: batch 2 of TOOL-COVERAGE.md (httpx fields as CSV columns, favicon pivot, reverse DNS,
      robots/security.txt).
