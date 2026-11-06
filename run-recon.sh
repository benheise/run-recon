#!/usr/bin/env bash
#
# run-recon.sh  --  URL enumeration for External Attack Surface Management (EASM)
#
# Reads a list of domains from a text file and produces a CSV that maps each
# input (seed) domain to the URLs discovered on it. Built to run inside the
# WSL2 environment provisioned by Setup-ReconEnv.ps1.
#
# Pipeline (per seed domain, passive-first):
#   1. (optional) subdomain enrichment           subfinder
#   2. passive URL collection                     gau (Wayback/CommonCrawl/OTX/URLScan), waybackurls
#                                                 (+ waymore in --deep mode)
#   3. normalize + dedup                          uro (falls back to sort -u)
#   4. strict scope filter (host belongs to seed) awk suffix match
#   5. (active) live-host probe + crawl           httpx, katana  (skipped in --passive-only)
#   5b.(active, --fuzz) content brute force        feroxbuster (else ffuf) on live hosts
#   6. (active) per-URL validation/enrichment     httpx -json    (skipped in --passive-only/--no-validate)
#   7. aggregate -> robust CSV                     python3 csv
#
# AUTHORIZATION: Only run this against domains your organization owns or is
# explicitly authorized to assess. Steps 5-5b-6 send live traffic to the targets;
# --fuzz in particular is loud (thousands of requests per host).
#
set -euo pipefail

VERSION="1.18.0"

# Resolve our own directory early (BEFORE the worker-dispatch block below) so we
# can locate sibling helper scripts (recon-db.sh, generate-report.sh) in both the
# parent and the re-invoked per-domain workers.
RECON_SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
RECON_DIR="$(dirname "$RECON_SELF")"

# ---------------------------------------------------------------------------
# Configuration defaults (use := so values exported by the parent survive in
# the per-domain worker subprocess; CLI flags override these in the parent).
# ---------------------------------------------------------------------------
: "${THREADS:=5}"            # parallel seed domains
: "${DEPTH:=2}"             # katana crawl depth
: "${RATE:=150}"           # requests/sec for tools that support rate limiting
: "${HTTP_RETRIES:=2}"      # httpx retries per URL on transient failure (probe + enrichment; 0 = one attempt)
: "${LATE_RETRY:=1}"        # 1 = one more, delayed pass for URLs/hosts that returned nothing (enrichment + TLS posture)
: "${MAX_URLS:=5000}"      # cap on URLs sent to httpx per domain (bounds active load)
: "${PASSIVE_ONLY:=0}"     # 1 = no katana, no httpx (purely passive / no target traffic)
: "${NO_VALIDATE:=0}"      # 1 = keep crawl but skip final per-URL httpx enrichment
: "${DO_SUBS:=0}"          # 1 = enumerate subdomains with subfinder first
: "${FILTER_STATIC:=1}"    # 1 = drop common static assets (images/fonts/css)
: "${DEEP:=0}"             # 1 = also run waymore (slower, broader passive coverage)
: "${FUZZ:=0}"             # 1 = content-discovery brute force on live hosts (feroxbuster, else ffuf)
: "${FUZZ_THREADS:=40}"    # fuzzer concurrency

# --- wall-clock caps per stage (seconds; 0 = unlimited). These bound TOTAL tool
# runtime so a slow source / huge wordlist can't hang the run for hours. Tune via
# env if you genuinely need longer. ---
: "${PROGRESS:=1}"         # 1 = show stage timers + a periodic heartbeat
: "${STAGE_TIMEOUT:=900}"  # generic per-stage cap (15m): probe/crawl/ports/misc scans
: "${PASSIVE_TIMEOUT:=600}" # each passive source (subfinder/amass/gau/waymore/...) (10m)
: "${BRUTE_TIMEOUT:=1800}" # DNS bruteforce (shuffledns/puredns + massdns) (30m)
: "${FUZZ_TIMEOUT:=1800}"  # content discovery (feroxbuster/ffuf) per invocation (30m)
: "${SCAN_TIMEOUT:=2400}"  # nuclei / active-scan template runs (40m)
: "${HEARTBEAT:=20}"       # seconds between overall-progress heartbeats (0 disables)
: "${FUZZ_EXT:=}"          # optional comma list of extensions to probe (e.g. php,bak,json)
: "${RESOLVE:=0}"          # 1 = dnsx validation gate (drop non-resolving candidate hosts)
: "${CERTS:=0}"            # 1 = tlsx active cert SAN/CN harvesting (discovers sibling hosts)
: "${PERMUTE:=0}"          # 1 = alterx permutations of candidate hosts (implies --resolve)
: "${PERMUTE_MAX:=100}"    # skip permutations when candidate hosts exceed this (avoids explosion)
: "${BRUTE:=0}"            # 1 = DNS dictionary bruteforce (shuffledns/puredns + massdns)
: "${BRUTE_WORDLIST:=}"    # subdomain bruteforce wordlist (default resolved below)
: "${PORTS:=0}"            # 1 = naabu port discovery before httpx (catches non-standard web ports)
: "${PORT_SPEC:=}"         # naabu ports: empty => web-ports preset; else e.g. "top-1000" or "80,443,8080"
: "${RANGE_TLS_PORTS:=}"   # ports for the ASN/CIDR certificate scan. Empty = 443 only, or the
                           # --ports list (numeric PORT_SPEC, else the web-ports preset) with --ports
: "${CRAWLERS_ALL:=0}"     # 1 = also run gospider + hakrawler (extra crawl coverage)
: "${JS:=0}"               # 1 = pull JS (subjs/getJS) and mine endpoints (xnLinkFinder/jsluice)
: "${TAKEOVER:=0}"         # 1 = subdomain-takeover check: CNAMEs of every candidate (dnsx), dangling
                           #     targets, takeover-prone services; subzy/nuclei fingerprints -> side artifact
: "${SCREENSHOTS:=0}"      # 1 = screenshot live hosts (httpx -screenshot, else gowitness)
: "${ORIGIN:=0}"           # 1 = edge detection + origin identification (candidates verified directly)
: "${ORIGIN_MAX_CHECKS:=200}" # cap on (host, candidate IP) pairs verified per seed
: "${CERT_WARN_DAYS:=30}"   # --tls: CertExpiring when the certificate expires within this many days (WebInventory's default)
: "${TLS_CHAIN_CHECK:=1}"   # --tls: validate each chain against the system trust store (CertUntrusted)
: "${ZONE_EXPOSURE:=0}"    # 1 = per seed zone: open AXFR, walkable NSEC chain, NSEC3 params -> side artifact
: "${ZONE_WALK_MAX:=5000}" # stop an NSEC walk after this many names
: "${TLS_POSTURE:=0}"      # 1 = TLS posture via tlsx (neg. version/cipher, cert expiry, self-signed, name mismatch)
: "${TLS_ENUM:=0}"         # 1 = also enumerate TLS versions + ciphers (noisier; adds WeakTLS/WeakCipher flags)
: "${IPV6:=0}"             # 1 = resolve AAAA records (dnsx) -> ipv6 column
: "${ENRICH:=0}"           # 1 = per-IP cloud provider + RDAP network org -> cloud, rdap_org columns
: "${GEO_DB:=}"            # path to a MaxMind GeoLite2 .mmdb for the geo column (implies --enrich; needs mmdblookup)
: "${CLOUD_TTL:=604800}"   # cloud IP-range feed cache freshness in seconds (default 7 days)
: "${RECON_CLOUD_CACHE:=${XDG_CACHE_HOME:-$HOME/.cache}/run-recon/cloud_ranges.tsv}"  # cloud-feed cache file
: "${CPE_MAP_FILE:=}"      # optional TSV extending the built-in product->CPE table (--cpe-map)
: "${FAVICON:=0}"          # 1 = favicon/internet-scan pivot (uncover; needs Shodan/Censys keys)
: "${ROUNDS:=1}"           # host-discovery rounds (>1 = recursive: re-enumerate newly found hosts)
: "${VHOST:=0}"            # 1 = virtual-host bruteforce (ffuf Host header) -> side artifact
: "${NUCLEI:=0}"           # 1 = nuclei templated scan on live URLs -> side artifact (opt-in; off)
: "${NUCLEI_SEV:=low,medium,high,critical}"  # nuclei severities to include
# nuclei out-of-band (OAST) callbacks. Some templates make the target call back to an
# interactsh server; nuclei's default is ProjectDiscovery's public servers (oast.pro,
# oast.live, ...), which would hand data about your systems to a third party.
#   off    (default) -ni: no callbacks; OAST-only templates simply do not fire
#   self   your own interactsh-server: NUCLEI_ISERVER=https://oast.example.internal
#          (+ NUCLEI_ITOKEN if it is protected; env only, never logged)
#   public nuclei's default public servers (explicit opt-in)
: "${NUCLEI_OAST:=off}"
: "${NUCLEI_ISERVER:=}"
: "${PARAMS:=0}"           # 1 = arjun parameter discovery on live URLs -> side artifact
: "${SECRETS:=0}"          # 1 = secret scanning on JS (trufflehog, else secretfinder) -> side artifact
: "${MONITOR:=0}"          # 1 = diff discovered assets against a prior CSV (--monitor)
: "${MONITOR_PREV:=}"      # prior CSV to diff against (default: newest recon-*.csv in out-dir)
: "${NOTIFY:=0}"           # 1 = pipe the new-asset diff through 'notify' if configured
: "${GITHUB:=0}"           # 1 = mine GitHub for subdomains + endpoints (needs a token)
: "${GITHUB_TOKEN_FILE:=}" # file with GitHub token(s), 1/line; else env GITHUB_TOKEN is used
: "${BUCKETS:=0}"          # 1 = cloud bucket enumeration (cloud_enum: S3/Azure/GCP) -> side artifact
: "${REFRESH_RESOLVERS:=0}"# 1 = regenerate the resolver list with dnsvalidator before running
: "${ACTIVE:=0}"           # 1 = active CMS/app-layer scanning (wpscan/droopescan/joomscan/cmseek/whatweb/nuclei)
: "${CMS_MAX:=25}"         # cap live hosts CMS-scanned per seed (bounds traffic on large surfaces)
: "${WPSCAN_API_TOKEN:=}"  # optional WPScan vuln-DB token (env); without it wpscan skips vuln data
: "${RESOLVERS:=}"         # resolver file path (set by parent; dedicated resolvers bypass local DNS)
: "${SECLISTS:=/opt/recon/wordlists/SecLists}"   # SecLists root (overridable via env)
: "${WORDLIST:=$SECLISTS/Discovery/Web-Content/raft-medium-directories.txt}"  # --fuzz wordlist
: "${BRUTE_WORDLIST:=$SECLISTS/Discovery/DNS/subdomains-top1million-110000.txt}"  # --brute / --vhost wordlist
: "${BRUTE_MAX:=0}"        # cap the brute wordlist to N entries (0 = no cap); bounds DNS volume/timeouts
: "${CMS_WORDLIST:=$SECLISTS/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt}"       # --active plugin/theme slug brute
: "${ACTIVESCAN:=0}"       # 1 = thorough active scan: feroxbuster/ffuf over several SecLists lists + nuclei

# --- passive OSINT enrichment (third-party lookups on domains/IPs; NOT traffic
# to the target, so these run even under --passive-only). Findings -> side artifacts. ---
: "${OSINT:=0}"            # 1 = free OSINT: RDAP + Shodan InternetDB + Team Cymru IP-to-ASN
: "${VIRUSTOTAL:=0}"      # 1 = VirusTotal domain report (passive DNS/reputation/subdomains); needs VT_API_KEY
: "${VT_API_KEY:=}"        # VirusTotal API key (env; free tier ~4 req/min, 500/day)
: "${URLSCAN:=0}"          # 1 = urlscan.io search (historical scans/URLs/IPs for a domain)
: "${URLSCAN_API_KEY:=}"   # urlscan.io API key (optional; raises rate limits)
: "${SOCIAL:=0}"           # 1 = social-media account discovery via tookie-osint
: "${SOCIAL_USER:=}"       # username to search (default: brand from seed domain, e.g. example.com -> example)
: "${OSINT_MAX:=25}"       # cap IPs enriched per domain (bounds third-party query volume)

# Per-source timeout (s) + inter-request delay (s) for the OSINT lookups. Default
# to STAGE_TIMEOUT / no-delay; override individually, or generate empirically with
# probe-datasource-limits.sh --recon-osint and load via --limits FILE (see below).
: "${RDAP_TIMEOUT:=$STAGE_TIMEOUT}"      ; : "${RDAP_DELAY:=0}"
: "${INTERNETDB_TIMEOUT:=$STAGE_TIMEOUT}"; : "${INTERNETDB_DELAY:=0}"
: "${VT_TIMEOUT:=$STAGE_TIMEOUT}"        ; : "${VT_DELAY:=0}"
: "${URLSCAN_TIMEOUT:=$STAGE_TIMEOUT}"   ; : "${URLSCAN_DELAY:=0}"
: "${LIMITS_FILE:=}"       # optional file of per-source *_TIMEOUT/*_DELAY (from the probe); loaded at startup

# --- optional PostgreSQL cache/store + HTML report ---------------------------
: "${USE_DB:=0}"           # 1 = use the recon-db.sh Postgres cache/store (--db); reuses Kali's msf postgres
: "${CACHE_TTL:=604800}"   # cache freshness in seconds for crawl/OSINT lookups (default 7 days)
: "${NEG_TTL:=86400}"      # negative-cache TTL for confirmed-empty results (default 1 day)
: "${CB_THRESHOLD:=3}"     # per-source circuit breaker: skip a source after this many timeouts in a run
: "${CB_SERIALIZE:=github-endpoints github-subdomains wpscan virustotal}"  # sources serialized across workers (rate-limit safety)
: "${PROXY:=}"             # optional HTTP(S) proxy URL for GET-heavy stages (--proxy); e.g. a caching squid
: "${REPORT:=1}"           # 1 = build an HTML report at the end (default on; --no-report to skip)

# --- IP + ASN attribution (adds ip/asn/asn_org columns to the CSV) -----------
# Surface each host's resolved IP and the IP's origin ASN (number + org, via the
# free Team Cymru DNS service) so you can validate that hostname<->IP<->ASN are
# your organization's infrastructure. Passive (no traffic to the target).
: "${ASN:=1}"              # 1 = resolve host IP + ASN into the CSV (--no-asn disables)
: "${ASN_MAX:=2000}"       # cap on unique IPs looked up per run (bounds Team Cymru queries)
: "${SKIP_SPECIAL_USE:=1}"   # 1 = skip passive internet sources for RFC 6761 special-use names (.test/.internal/.local/...)

# Curated SecLists content-discovery lists used by --activescan (only existing
# ones are used; rebuilt in each worker since it re-sources this file). Reference
# $SECLISTS so an env override of the SecLists root flows through automatically.
ACTIVESCAN_LISTS=(
  "$SECLISTS/Discovery/Web-Content/raft-large-directories.txt"
  "$SECLISTS/Discovery/Web-Content/raft-large-files.txt"
  "$SECLISTS/Discovery/Web-Content/quickhits.txt"
  "$SECLISTS/Discovery/Web-Content/api/api-endpoints.txt"
  "$SECLISTS/Discovery/Web-Content/common.txt"
)
: "${WORKDIR:=}"           # set by parent
: "${OUTPUT:=}"            # set by parent

STATIC_EXT="ttf,woff,woff2,eot,svg,png,jpg,jpeg,gif,ico,css,webp,bmp,tif,tiff,mp4,mp3,avi,mov,woff2"

# --- ProjectDiscovery httpx --------------------------------------------------
# Two unrelated tools are named 'httpx': ProjectDiscovery's Go toolkit and the
# python3-httpx client. Kali/Arch package PD's as 'httpx-toolkit' precisely to
# avoid colliding with python3-httpx (which owns /usr/bin/httpx), so that is the
# default here. If yours is named differently (e.g. a go-install that produced
# plain 'httpx', or an absolute path), export HTTPX_BIN to point at it.
: "${HTTPX_BIN:=httpx-toolkit}"

# ---------------------------------------------------------------------------
# Pretty logging (stderr so stdout stays clean)
# ---------------------------------------------------------------------------
_c() { [ -t 2 ] && printf '%s' "$1" || printf ''; }
log()  { printf '%s[*]%s %s\n' "$(_c $'\033[1;34m')" "$(_c $'\033[0m')" "$*" >&2; }
ok()   { printf '%s[+]%s %s\n' "$(_c $'\033[1;32m')" "$(_c $'\033[0m')" "$*" >&2; }
warn() {
  printf '%s[!]%s %s\n' "$(_c $'\033[1;33m')" "$(_c $'\033[0m')" "$*" >&2
  # every warning after the work dir exists is also kept for <out>.run.json
  if [ -n "${WORKDIR:-}" ] && [ -d "$WORKDIR" ]; then printf '%s\n' "$*" >> "$WORKDIR/warnings.txt" 2>/dev/null || true; fi
  return 0
}
err()  { printf '%s[x]%s %s\n' "$(_c $'\033[1;31m')" "$(_c $'\033[0m')" "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }
onoff() { [ "$1" = "1" ] && printf 'on' || printf 'off'; }

# --- wall-clock guards (per-request -timeout flags don't bound total runtime) --
# _to <seconds> <cmd...> : run under `timeout` so no single tool can hang the run.
# SIGTERM at the limit, SIGKILL 15s later; if timeout is unavailable, run as-is.
_to() {
  local s="${1:-0}"; shift
  if [ "${s:-0}" -gt 0 ] 2>/dev/null && have timeout; then
    timeout -k 15 "$s" "$@"
  else
    "$@"
  fi
}
# _delay <seconds> : sleep between same-source requests (rate spacing); 0 = none.
_delay() { case "${1:-0}" in 0|0.0|"") : ;; *) sleep "$1" 2>/dev/null || true;; esac; }

# --- per-source circuit breaker + concurrency ceiling (run-shared via $WORKDIR) ---
# State lives under $WORKDIR/.cb (shared across the parallel per-domain workers),
# so a source that starts timing out is skipped for the rest of the whole run.
_cbdir() { printf '%s' "${WORKDIR:-/tmp}/.cb"; }
_cbkey() { printf '%s' "${1//[^A-Za-z0-9_.-]/_}"; }
cb_fail() { local d; d="$(_cbdir)"; mkdir -p "$d" 2>/dev/null || return 0; printf 'x\n' >> "$d/$(_cbkey "$1").f" 2>/dev/null || true; }
cb_open() {  # true(0) if source $1 has reached CB_THRESHOLD timeouts this run
  local f n; f="$(_cbdir)/$(_cbkey "$1").f"; [ -f "$f" ] || return 1
  n="$(grep -c '^' "$f" 2>/dev/null || true)"; [ "${n:-0}" -ge "$CB_THRESHOLD" ]
}
_serialized() { case " $CB_SERIALIZE " in *" $1 "*) return 0;; *) return 1;; esac; }

# seen_once <namespace> <key> : succeeds (0) the FIRST time (namespace,key) is
# seen in this run and fails (1) thereafter -- a run-shared dedup across the
# parallel workers (atomic create via noclobber). Used to resolve/query shared
# infra (e.g. an IP that several seeds resolve to) only once per run.
seen_once() {
  local d f; d="${WORKDIR:-/tmp}/.seen/$(_cbkey "$1")"; mkdir -p "$d" 2>/dev/null || return 0
  f="$d/$(_cbkey "$2")"
  if ( set -o noclobber; : > "$f" ) 2>/dev/null; then return 0; else return 1; fi
}

# cache_or_run <source> <key> -- <cmd...>
# Single choke point for external lookups. In order it: (1) serves a fresh DB
# cache hit; (2) skips keys with a fresh confirmed-empty entry (negative cache);
# (3) skips a source whose circuit breaker is open; else runs <cmd> -- serialized
# via flock for rate-limited sources -- caches the value (or records a negative on
# a genuine empty), and counts timeouts (exit 124) toward the breaker. Echoes the
# value (empty on any skip). Degrades to a plain run when USE_DB=0.
cache_or_run() {
  local src="$1" key="$2"; shift 2; [ "${1:-}" = "--" ] && shift
  local out="" rc=0
  if [ "$USE_DB" = "1" ]; then
    out="$(db_cache_get "$src" "$key" "$CACHE_TTL" 2>/dev/null || true)"
    [ -n "$out" ] && { printf '%s' "$out"; return 0; }
    if db_cache_get "${src}!neg" "$key" "$NEG_TTL" >/dev/null 2>&1; then return 0; fi
  fi
  cb_open "$src" && return 0
  if _serialized "$src" && have flock; then
    mkdir -p "$(_cbdir)" 2>/dev/null || true
    { exec 9>"$(_cbdir)/$(_cbkey "$src").lock"; } 2>/dev/null || true
    flock 9 2>/dev/null || true
    out="$("$@")"; rc=$?
    flock -u 9 2>/dev/null || true; exec 9>&- 2>/dev/null || true
  else
    out="$("$@")"; rc=$?
  fi
  [ "$rc" -eq 124 ] && cb_fail "$src"
  # Only cache on a CLEAN exit. A timeout/error (rc!=0) may have emitted partial
  # output, or none for a transient reason -- caching either would poison the
  # entry for the whole TTL, so we leave it uncached to retry next run.
  if [ "$USE_DB" = "1" ] && [ "$rc" -eq 0 ]; then
    if [ -n "$out" ]; then db_cache_put "$src" "$key" "$out" 2>/dev/null || true
    else db_cache_put "${src}!neg" "$key" 1 2>/dev/null || true
    fi
  fi
  printf '%s' "$out"
}

# cache_split SRC KEYFILE HITVAL MISSKEYS
#   Partition KEYFILE (one key per line) against the DB cache for SRC (values are
#   base64-encoded blobs):
#     HITVAL   <- the decoded cached tool-output for positive hits (emit as output)
#     MISSKEYS <- the keys to actually run the tool on (positive + negative hits removed)
#   With USE_DB!=1: HITVAL empty, MISSKEYS = KEYFILE (run everything).
cache_split() {
  local src="$1" keyf="$2" hitval="$3" misskeys="$4"
  : > "$hitval"; : > "$misskeys"
  [ -s "$keyf" ] || return 0
  if [ "$USE_DB" != "1" ]; then cp "$keyf" "$misskeys"; return 0; fi
  local pos="$keyf.pos" neg="$keyf.neg"
  db_cache_mget "$src" "$CACHE_TTL" "$keyf" > "$pos" 2>/dev/null || : > "$pos"
  db_cache_mget "${src}!neg" "$NEG_TTL" "$keyf" > "$neg" 2>/dev/null || : > "$neg"
  python3 - "$keyf" "$pos" "$neg" "$hitval" "$misskeys" <<'PY' || { cp "$keyf" "$misskeys"; : > "$hitval"; }
import sys, base64
keyf, posf, negf, hitval, missf = sys.argv[1:6]
def read_kv(p):
    d = {}
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                k, _, v = line.partition("\t")
                if k:
                    d[k] = v
    except FileNotFoundError:
        pass
    return d
pos, neg = read_kv(posf), read_kv(negf)
with open(hitval, "w", encoding="utf-8") as ho:
    for v in pos.values():
        try:
            ho.write(base64.b64decode(v).decode("utf-8", "replace"))
        except Exception:
            pass
seen = set()
with open(missf, "w", encoding="utf-8") as mo, open(keyf, encoding="utf-8", errors="replace") as kf:
    for line in kf:
        k = line.rstrip("\n")
        if not k or k in seen:
            continue
        seen.add(k)
        if k not in pos and k not in neg:
            mo.write(k + "\n")
PY
}

# cache_store SRC MISSKEYS RESULTFILE MODE [noneg]
#   Group RESULTFILE lines by key (MODE derives the key from each line), cache each
#   group's blob under SRC (base64), and negative-cache the MISSKEYS that produced
#   no result. MODE: self | httpxjson | urlhost | urlauthority | hostport.
#   `noneg` skips the negative entries: for stages that only run on hosts the live
#   probe just confirmed (enrichment, TLS posture), "no result" means the request
#   failed, and caching that would keep a load-induced blank row for NEG_TTL.
#   No-op when USE_DB!=1.
cache_store() {
  local src="$1" misskeys="$2" resultf="$3" mode="$4" noneg="${5:-}"
  [ "$USE_DB" = "1" ] || return 0
  local tc="$resultf.tc" ng="$resultf.ng"
  CACHE_MODE="$mode" python3 - "$resultf" "$misskeys" "$tc" "$ng" <<'PY' || return 0
import sys, os, re, base64, json
mode = os.environ.get("CACHE_MODE", "self")
resultf, missf, tcf, ngf = sys.argv[1:5]
_scheme = re.compile(r'^[a-z][a-z0-9+.-]*://')
def keyof(line):
    if mode == "self":
        return line
    if mode == "httpxjson":
        try:
            j = json.loads(line)
        except Exception:
            return ""
        return (j.get("input") or j.get("url") or "") if isinstance(j, dict) else ""
    if mode == "urlhost":        # host (no port) from a URL
        return re.sub(r'[/:].*$', '', _scheme.sub('', line))
    if mode == "urlauthority":   # host[:port] from a URL (keep port)
        return re.sub(r'/.*$', '', _scheme.sub('', line))
    if mode == "hostport":       # host from a host:port line
        return re.sub(r':.*$', '', line)
    if mode == "jsonauthority":  # host[:port] from a tlsx JSON record
        try:
            j = json.loads(line)
        except Exception:
            return ""
        if not isinstance(j, dict):
            return ""
        h = (j.get("host") or "").lower()
        p = str(j.get("port") or "")
        return (h + ":" + p) if (h and p) else (h or "")
    return line
groups = {}
try:
    with open(resultf, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            k = keyof(line)
            if k:
                groups.setdefault(k, []).append(line)
except FileNotFoundError:
    pass
miss = set()
try:
    with open(missf, encoding="utf-8", errors="replace") as f:
        for line in f:
            k = line.rstrip("\n")
            if k:
                miss.add(k)
except FileNotFoundError:
    pass
# Only cache keys we actually ran the tool for. A tool may surface data for keys
# outside the miss set (e.g. katana's root-domain scope finding other hosts);
# caching those would overwrite their full cached value with a partial one.
with open(tcf, "w", encoding="utf-8") as o:
    for k, lines in groups.items():
        if miss and k not in miss:
            continue
        blob = ("\n".join(lines) + "\n").encode("utf-8")
        o.write(k + "\t" + base64.b64encode(blob).decode("ascii") + "\n")
got = set(k for k in groups if (not miss or k in miss))
with open(ngf, "w", encoding="utf-8") as o:
    for k in miss:
        if k not in got:
            o.write(k + "\t1\n")
PY
  [ -s "$tc" ] && db_bulk_cache "$src" "$tc" || true
  [ "$noneg" = "noneg" ] || { [ -s "$ng" ] && db_bulk_cache "${src}!neg" "$ng"; } || true
  return 0
}

# missing_keys MODE KEYFILE RESULTFILE -> the KEYFILE keys with no record in
#   RESULTFILE (MODE: httpxjson = the record's input/url; jsonauthority = tlsx
#   host:port). Used by the late-retry passes. On any error it prints every key.
#   Fast path: at least as many records as keys means nothing is missing (httpx and
#   tlsx emit one record per input), so the common healthy case starts no python.
missing_keys() {
  local _nk _nr
  _nk="$(grep -c . "$2" 2>/dev/null || true)"; _nr="$(grep -c . "$3" 2>/dev/null || true)"
  [ "${_nr:-0}" -ge "${_nk:-0}" ] && [ "${_nk:-0}" -gt 0 ] && return 0
  python3 - "$@" <<'PYMISS' 2>/dev/null || cat "$2"
import sys, json
mode, keyf, resf = sys.argv[1:4]
got = set()
try:
    with open(resf, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                j = json.loads(line)
            except Exception:
                continue
            if not isinstance(j, dict):
                continue
            if mode == "httpxjson":
                for k in (j.get("input"), j.get("url")):
                    if k:
                        got.add(k)
            else:
                h = (j.get("host") or "").lower()
                p = str(j.get("port") or "")
                if h:
                    got.add(h + ":" + p if p else h)
except FileNotFoundError:
    pass
seen = set()
with open(keyf, encoding="utf-8", errors="replace") as f:
    for line in f:
        k = line.rstrip("\n")
        if k and k not in got and k not in seen:
            seen.add(k)
            print(k)
PYMISS
}

# late_pause: a jittered 2-5 s pause before a late retry, so workers that failed in
# the same load spike do not all come back at the same instant.
late_pause() { sleep "$(( 2 + RANDOM % 4 ))"; }

# tls_chain_check FILE: validate the certificate chain of every tlsx record in FILE
# (JSON lines) against the system trust store, and rewrite FILE with the result.
# tlsx -untrusted only matches a list of known-bad CAs, so a private or unknown CA
# (Caddy's local CA, an internal PKI) passed as trusted. A record whose chain does not
# verify gets "untrusted": true (-> CertUntrusted) plus "chain_error". Expiry alone is
# not a trust failure (CertExpired covers it); no handshake leaves the record as it was.
tls_chain_check() {
  local f="$1"
  [ -s "$f" ] || return 0
  python3 - "$f" <<'PYCHAIN' 2>/dev/null || true
import sys, json, ssl, socket
from concurrent.futures import ThreadPoolExecutor
path = sys.argv[1]
recs = []
for line in open(path, encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line:
        continue
    try:
        j = json.loads(line)
    except Exception:
        recs.append(line); continue
    recs.append(j)
def check(j):
    if not isinstance(j, dict) or not j.get("host"):
        return j
    host = str(j["host"]).strip().rstrip(".")
    try:
        port = int(j.get("port") or 443)
    except Exception:
        port = 443
    addr = j.get("ip") or host
    ctx = ssl.create_default_context()
    ctx.check_hostname = False            # name mismatch has its own flag
    try:
        with socket.create_connection((addr, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                j["chain_trusted"] = True
    except ssl.SSLCertVerificationError as e:
        code = getattr(e, "verify_code", 0)
        if code in (9, 10):                # not yet valid / expired: the chain itself is fine
            j["chain_trusted"] = True
        else:
            j["chain_trusted"] = False
            j["chain_error"] = (getattr(e, "verify_message", "") or str(e))[:120]
            j["untrusted"] = True
    except Exception:
        pass                               # no handshake: say nothing
    return j
with ThreadPoolExecutor(max_workers=16) as ex:
    out = list(ex.map(check, recs))
with open(path + ".chk", "w", encoding="utf-8") as fh:
    for j in out:
        fh.write((j if isinstance(j, str) else json.dumps(j)) + "\n")
import os
os.replace(path + ".chk", path)
PYCHAIN
  return 0
}

# --- screenshot cache (stores the PNG bytes per host, so cached hosts still get a
# real image in the report without re-rendering) --------------------------------
_ss_norm() { printf '%s' "${1-}" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9'; }

# _ss_restore HOSTFILE DEST MISSFILE : write cached PNGs for HOSTFILE hosts into
# DEST as <norm>.png; hosts with no cached image (and not negatively cached) go to
# MISSFILE for rendering.
_ss_restore() {
  local hostf="$1" dest="$2" missf="$3" h b64
  : > "$missf"; mkdir -p "$dest" 2>/dev/null || true
  while IFS= read -r h || [ -n "$h" ]; do
    [ -n "$h" ] || continue
    if b64="$(db_cache_get screenshot "$h" "$CACHE_TTL" 2>/dev/null)" && [ -n "$b64" ]; then
      printf '%s' "$b64" | base64 -d > "$dest/$(_ss_norm "$h").png" 2>/dev/null \
        || printf '%s\n' "$h" >> "$missf"
    elif db_cache_get "screenshot!neg" "$h" "$NEG_TTL" >/dev/null 2>&1; then
      :   # known no-screenshot host -> skip
    else
      printf '%s\n' "$h" >> "$missf"
    fi
  done < "$hostf"
}

# _ss_save HOSTFILE SSDIR : match freshly-rendered images in SSDIR to HOSTFILE hosts
# and cache their bytes; negative-cache hosts that produced no screenshot.
_ss_save() {
  local hostf="$1" ssdir="$2"; local tc="$ssdir.sstc" ng="$ssdir.ssng"
  python3 - "$hostf" "$ssdir" "$tc" "$ng" <<'PY' || return 0
import sys, os, re, glob, base64
hostf, ssdir, tcf, ngf = sys.argv[1:5]
def norm(s): return re.sub(r'[^a-z0-9]+', '', s.lower())
hosts = []
try:
    with open(hostf, encoding="utf-8", errors="replace") as f:
        for line in f:
            h = line.strip()
            if h:
                hosts.append(h)
except FileNotFoundError:
    pass
imgs = []
for ext in ("png", "jpg", "jpeg"):
    imgs += glob.glob(os.path.join(ssdir, "**", "*." + ext), recursive=True)
nmap = []
for p in imgs:
    try:
        rel = os.path.relpath(p, ssdir)
    except Exception:
        rel = os.path.basename(p)
    try:
        if os.path.getsize(p) == 0:
            continue          # a failed capture: not worth caching
    except OSError:
        continue
    nmap.append((norm(rel), p))
used, matched = set(), {}
for h in sorted(set(hosts), key=len, reverse=True):
    nh = norm(h)
    if not nh:
        continue
    for i, (nb, p) in enumerate(nmap):
        if i not in used and nh in nb:
            used.add(i); matched[h] = p; break
with open(tcf, "w", encoding="utf-8") as o:
    for h, p in matched.items():
        try:
            with open(p, "rb") as fp:
                o.write(h + "\t" + base64.b64encode(fp.read()).decode("ascii") + "\n")
        except Exception:
            pass
with open(ngf, "w", encoding="utf-8") as o:
    for h in set(hosts):
        if h not in matched:
            o.write(h + "\t1\n")
PY
  [ -s "$tc" ] && db_bulk_cache screenshot "$tc" || true
  [ -s "$ng" ] && db_bulk_cache "screenshot!neg" "$ng" || true
  return 0
}
# fmt_hms <seconds> -> HH:MM:SS
fmt_hms() {
  local t="${1:-0}"; printf '%02d:%02d:%02d' $((t/3600)) $(((t%3600)/60)) $((t%60))
}
# uro_filter <infile> -> stdout : dedupe/normalize a URL list with uro (removes
# near-duplicate/parametrized/incremental URLs); falls back to sort -u if uro is
# absent. Used to clean noisy content-discovery output before feeding nuclei.
uro_filter() {
  local f="$1"
  [ -s "$f" ] || return 0
  if have uro; then _to "$STAGE_TIMEOUT" uro -i "$f" 2>/dev/null || sort -u "$f"
  else sort -u "$f"; fi
}
# stage <domain> <name> : mark a pipeline phase starting, with elapsed-in-worker.
# Honors PROGRESS (default on). Keeps the user oriented and shows where time goes.
stage() {
  [ "${PROGRESS:-1}" = "1" ] || return 0
  local d="$1" name="$2" now el
  now=$(date +%s 2>/dev/null || echo 0); el=$(( now - ${WORKER_START:-now} ))
  printf '%s   >%s %s  %s[%s]%s %s\n' \
    "$(_c $'\033[1;36m')" "$(_c $'\033[0m')" "$name" \
    "$(_c $'\033[2m')" "$d $(fmt_hms $el)" "$(_c $'\033[0m')" \
    "$(_c $'\033[0m')" >&2
}

# ---------------------------------------------------------------------------
# scope_filter <seed-domain>   (reads URLs on stdin, prints only in-scope URLs)
# Keeps a URL only if its hostname == seed OR endswith ".seed".
# Pure string suffix match (no regex) so dotted domains can't over-match.
# ---------------------------------------------------------------------------
scope_filter() {
  awk -v d="$1" '
    {
      u=$0
      h=u
      sub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//,"",h)   # strip scheme://
      sub(/[\/?#].*$/,"",h)                         # strip path/query/fragment
      sub(/@.*$/,"",h)                              # strip any userinfo (rare)
      sub(/:[0-9]+$/,"",h)                          # strip :port
      hl=tolower(h)
      if (hl=="") next
      if (hl==d) { print u; next }
      suf="." d
      if (length(hl) > length(suf) && substr(hl, length(hl)-length(suf)+1)==suf) { print u }
    }'
}

# ---------------------------------------------------------------------------
# prep_file <infile> <outfile> <seed>
# sort -u | (uro if present) | scope_filter
# ---------------------------------------------------------------------------
# url_junk_filter: drop URLs built from JSON-escaped paths. katana -jc (and archives)
# read "\/" in inline JSON as part of a path and produce URLs that do not exist, such
# as http://wp.test/%5C/wp.test%5C/index.php. Real URLs essentially never contain "\/".
url_junk_filter() { awk 'index($0, "\\/") == 0 && $0 !~ /%5[Cc]\//'; }

prep_file() {
  local in="$1" out="$2" seed="$3"
  if [ ! -s "$in" ]; then : > "$out"; return 0; fi
  if have uro; then
    sort -u "$in" | url_junk_filter | uro 2>/dev/null | scope_filter "$seed" > "$out" 2>/dev/null \
      || sort -u "$in" | url_junk_filter | scope_filter "$seed" > "$out"
  else
    sort -u "$in" | url_junk_filter | scope_filter "$seed" > "$out"
  fi
}

# ---------------------------------------------------------------------------
# Dedicated public resolvers. Passed to dnsx/tlsx via -r so DNS-heavy stages
# bypass a local Pi-hole (and its per-client rate limiting) entirely. Override
# with --resolvers FILE (e.g. a fresh trickest/resolvers list for big runs).
# ---------------------------------------------------------------------------
RESOLVERS_LIST=(
  1.1.1.1 1.0.0.1                 # Cloudflare
  8.8.8.8 8.8.4.4                 # Google
  9.9.9.9 149.112.112.112         # Quad9
  208.67.222.222 208.67.220.220   # OpenDNS
)

# ---------------------------------------------------------------------------
# resolve_hosts <infile> <outfile> <seed>
# DNS validation gate: keep only hostnames that actually resolve, querying the
# dedicated resolvers (bypasses a local Pi-hole). When permutations are active,
# additionally strip wildcard hits (dnsx -wd, which is JSON-only) so a single
# *.seed record can't inflate results with every guessed name. If dnsx is
# missing or errors, pass hosts through unvalidated rather than dropping them.
# ---------------------------------------------------------------------------
resolve_hosts() {
  local in="$1" out="$2" seed="$3"
  if [ ! -s "$in" ] || ! have dnsx; then cat "$in" > "$out" 2>/dev/null || : > "$out"; return 0; fi
  local rflag=()
  if [ -n "$RESOLVERS" ] && [ -s "$RESOLVERS" ]; then rflag=(-r "$RESOLVERS"); fi

  # step 1: resolve with dedicated resolvers (plaintext; -r is honored here)
  local raw="$in.res"
  if ! dnsx -l "$in" "${rflag[@]}" -silent > "$raw" 2>>"$in.dnsx.err"; then
    warn "dnsx failed; passing candidate hosts through unvalidated (see $in.dnsx.err)."
    cat "$in" > "$out"; rm -f "$raw"; return 0
  fi
  sort -u "$raw" > "$out"; rm -f "$raw"

  # step 2 (permute only): drop wildcard hits from the resolving set
  if [ "$PERMUTE" = "1" ] && [ -s "$out" ]; then
    local wc="$in.wc" filtered
    if dnsx -l "$out" -wd "$seed" -j -silent > "$wc" 2>/dev/null; then
      filtered="$(sed -n 's/.*"host":"\([^"]*\)".*/\1/p' "$wc" | sort -u)"
      [ -n "$filtered" ] && printf '%s\n' "$filtered" > "$out"
    fi
    rm -f "$wc"
  fi
}

# ---------------------------------------------------------------------------
# brute_subs <domain> <outfile> -- DNS dictionary bruteforce.
# Prefers shuffledns (needs massdns), falls back to puredns. Uses the dedicated
# resolvers so the (large) query burst never touches a local Pi-hole. Finds
# names that live only behind wildcard certs and never appear in any passive
# source. Degrades to a no-op (empty out) if no bruteforcer/wordlist present.
# ---------------------------------------------------------------------------
brute_subs() {
  local d="$1" out="$2"; : > "$out"
  if [ ! -f "$BRUTE_WORDLIST" ]; then
    warn "[$d] --brute wordlist not found ($BRUTE_WORDLIST); skipping bruteforce."; return 0
  fi
  local rflag=(); { [ -n "$RESOLVERS" ] && [ -s "$RESOLVERS" ]; } && rflag=(-r "$RESOLVERS")
  local _wl="$BRUTE_WORDLIST"
  if [ "${BRUTE_MAX:-0}" -gt 0 ]; then
    _wl="$out.wl"; head -n "$BRUTE_MAX" "$BRUTE_WORDLIST" > "$_wl" 2>/dev/null || _wl="$BRUTE_WORDLIST"
  fi
  if have shuffledns && have massdns; then
    _to "$BRUTE_TIMEOUT" shuffledns -d "$d" -w "$_wl" "${rflag[@]}" -m "$(command -v massdns)" \
      -mode bruteforce -silent 2>/dev/null | scope_filter "$d" | sort -u > "$out" || : > "$out"
  elif have puredns; then
    _to "$BRUTE_TIMEOUT" puredns bruteforce "$_wl" "$d" "${rflag[@]}" 2>/dev/null \
      | scope_filter "$d" | sort -u > "$out" || : > "$out"
  else
    warn "[$d] --brute needs shuffledns+massdns or puredns; none found; skipping."
  fi
  return 0
}

# ---------------------------------------------------------------------------
# analyze_hosts <domain> <raw> -- post-probe SIDE analyses (all opt-in). These
# do NOT feed the URL CSV; findings go to $WORKDIR/parts/<kind>.<safe>.txt
# (aggregated into <out>.<kind>.txt) and screenshots into $WORKDIR/screenshots/.
# Every block is a no-op when its flag is off or its tool is missing.
# ---------------------------------------------------------------------------
# takeover_check SEED RAW FINDINGS CNAME_TSV
#   1. dnsx CNAME lookup for every candidate name (the pre-gate list, so names that no
#      longer resolve are included), not only live hosts.
#   2. the final CNAME target of each chain is resolved; NXDOMAIN = dangling.
#   3. findings: dangling CNAMEs ([high] when the target is a takeover-prone service,
#      else [medium]: check whether the target domain can be registered or claimed);
#      every CNAME goes to CNAME_TSV (host, target, dns status, provider).
#   4. subzy and nuclei (-tags takeover, callbacks per NUCLEI_OAST) fingerprint every
#      name that has a CNAME: a deleted bucket or app often still resolves at the
#      provider and only its HTTP answer gives it away.
#   Only the two dnsx queries that behave the same on dnsx 1.2 and 1.3 are used:
#   `-cname -json` and `-rcode nxdomain` (text). dnsx 1.3 drops NXDOMAIN rows from
#   `-a -json -rcode noerror,nxdomain`, which 1.2 printed.
takeover_check() {
  local domain="$1" raw="$2" out="$3" ctsv="$4"
  local cand="$raw/takeover_cand.txt" cj="$raw/cname.jsonl" tg="$raw/cname_targets.txt" nx="$raw/cname_nx.txt"
  local cn="$raw/cname_hosts.txt" rr2=(); [ -n "$RESOLVERS" ] && rr2=(-r "$RESOLVERS")
  cat "$raw/hosts_all.txt" "$raw/hosts.txt" "$raw/live_bare.txt" 2>/dev/null \
    | tr 'A-Z' 'a-z' | grep -E '^[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?$' | sort -u > "$cand" || true
  : > "$cn"
  if [ -s "$cand" ] && have dnsx; then
    _to "$STAGE_TIMEOUT" dnsx -l "$cand" -cname -json -silent "${rr2[@]}" 2>>"$raw/dnsx_cname.err" > "$cj" || true
    python3 - "$cj" "$tg" <<'PYCN' 2>>"$raw/dnsx_cname.err" || true
import sys, json
cj, tg = sys.argv[1:3]
targets = set()
for line in open(cj, encoding="utf-8", errors="replace"):
    try:
        j = json.loads(line)
    except Exception:
        continue
    c = [x.strip().rstrip(".").lower() for x in (j.get("cname") or []) if isinstance(x, str) and x.strip()]
    if c:
        targets.add(c[-1])
with open(tg, "w") as f:
    for t in sorted(targets):
        f.write(t + "\n")
PYCN
    : > "$nx"
    if [ -s "$tg" ]; then
      _to "$STAGE_TIMEOUT" dnsx -l "$tg" -rcode nxdomain -silent "${rr2[@]}" 2>>"$raw/dnsx_cname.err" \
        | awk '{print tolower($1)}' | sed 's/\.$//' | sort -u > "$nx" || true
    fi
    python3 - "$domain" "$cj" "$nx" "$out" "$ctsv" "$cn" <<'PYTK' 2>>"$raw/dnsx_cname.err" || true
import sys, json
seed, cj, nxf, outf, ctsv, cnf = sys.argv[1:7]
# Services where a dangling CNAME has been claimable (after can-i-take-over-xyz).
# A dangling CNAME into one of these is [high]; anywhere else it is [medium].
PROVIDERS = [
    ("s3.amazonaws.com", "aws-s3"), ("s3-website", "aws-s3"), ("elasticbeanstalk.com", "aws-elasticbeanstalk"),
    ("cloudfront.net", "aws-cloudfront"), ("azurewebsites.net", "azure-app-service"),
    ("cloudapp.net", "azure-cloudapp"), ("cloudapp.azure.com", "azure-cloudapp"),
    ("trafficmanager.net", "azure-traffic-manager"), ("blob.core.windows.net", "azure-blob"),
    ("azureedge.net", "azure-cdn"), ("azure-api.net", "azure-api"), ("azurefd.net", "azure-front-door"),
    ("azurecontainer.io", "azure-container"), ("azurestaticapps.net", "azure-static-apps"),
    ("herokuapp.com", "heroku"), ("herokudns.com", "heroku"), ("github.io", "github-pages"),
    ("gitlab.io", "gitlab-pages"), ("netlify.app", "netlify"), ("netlify.com", "netlify"),
    ("vercel.app", "vercel"), ("now.sh", "vercel"), ("surge.sh", "surge"), ("bitbucket.io", "bitbucket"),
    ("ghost.io", "ghost"), ("myshopify.com", "shopify"), ("pantheonsite.io", "pantheon"),
    ("readme.io", "readme"), ("helpscoutdocs.com", "helpscout"), ("statuspage.io", "statuspage"),
    ("uservoice.com", "uservoice"), ("unbouncepages.com", "unbounce"), ("wpengine.com", "wpengine"),
    ("zendesk.com", "zendesk"), ("freshdesk.com", "freshdesk"), ("firebaseapp.com", "firebase"),
    ("web.app", "firebase"), ("pages.dev", "cloudflare-pages"), ("fly.dev", "fly"),
    ("ngrok.io", "ngrok"), ("strikinglydns.com", "strikingly"), ("cargocollective.com", "cargo"),
    ("tumblr.com", "tumblr"), ("wordpress.com", "wordpress-com"), ("teamwork.com", "teamwork"),
    ("helpjuice.com", "helpjuice"), ("smartling.com", "smartling"), ("aha.io", "aha"),
]
def provider(name):
    for suf, label in PROVIDERS:
        if name == suf or name.endswith("." + suf) or (suf == "s3-website" and ".s3-website" in name):
            return label
    return ""
def clean(x):
    return "".join(ch for ch in x if ch.isprintable() and not ch.isspace())[:253]
nx = set(l.strip().lower() for l in open(nxf, encoding="utf-8", errors="replace") if l.strip())
rows, findings = [], []
for line in open(cj, encoding="utf-8", errors="replace"):
    try:
        j = json.loads(line)
    except Exception:
        continue
    host = clean(str(j.get("host") or "").rstrip(".").lower())
    chain = [clean(x.strip().rstrip(".").lower()) for x in (j.get("cname") or []) if isinstance(x, str) and x.strip()]
    if not host or not chain:
        continue
    tgt = chain[-1]
    prov = provider(tgt) or next((provider(c) for c in chain if provider(c)), "")
    dns = "NXDOMAIN" if tgt in nx else "resolves"
    rows.append((host, ">".join(chain), dns, prov))
    if dns == "NXDOMAIN":
        if prov:
            findings.append("[%s] dangling-cname [high] host=%s cname=%s dns=NXDOMAIN provider=%s "
                            "note=the target service no longer exists; it can likely be claimed" % (seed, host, tgt, prov))
        else:
            findings.append("[%s] dangling-cname [medium] host=%s cname=%s dns=NXDOMAIN "
                            "note=the target does not exist; check whether its domain can be registered or claimed" % (seed, host, tgt))
with open(ctsv, "a") as f:
    for r in sorted(set(rows)):
        f.write("\t".join((seed,) + r) + "\n")
with open(cnf, "w") as f:
    for h in sorted(set(r[0] for r in rows)):
        f.write(h + "\n")
with open(outf, "a") as f:
    for x in sorted(set(findings)):
        f.write(x + "\n")
PYTK
  else
    # no dnsx: fall back to fingerprinting the live hosts (the v1.15 behaviour)
    cp "$raw/live_bare.txt" "$cn" 2>/dev/null || : > "$cn"
  fi
  [ -s "$cn" ] || return 0
  if have subzy; then
    # Keep only subzy's result lines ("[ VULNERABLE ]  -  <name>  [ <service> ]"). The old
    # 'vulnerable|takeover' grep also matched subzy's settings banner ("Show only
    # potentially vulnerable subdomains"), a false finding for every seed.
    _to "$STAGE_TIMEOUT" subzy run --targets "$cn" --hide_fails 2>/dev/null \
      | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' \
      | sed -nE 's/^\[ *VULNERABLE *\][[:space:]]+-[[:space:]]+([^[:space:]]+)[[:space:]]*\[[[:space:]]*(.*[^[:space:]])[[:space:]]*\].*$/\1\t\2/p' \
      | while IFS="$(printf '\t')" read -r _h _svc; do
          printf '[%s] subzy-vulnerable [high] host=%s service=%s\n' "$domain" "$_h" "$_svc"
        done >> "$out" || true
  fi
  if have nuclei; then
    nuclei_oast_args
    _to "$SCAN_TIMEOUT" nuclei -l "$cn" -tags takeover -silent "${_NO[@]}" "${rr2[@]}" 2>/dev/null \
      | sed "s#^#[$domain] nuclei-takeover #" >> "$out" || true
  fi
}

# origin_check SEED RAW FINDINGS EDGE_TSV
#   1. Edge: every live root URL is fetched once through the normal path (httpx -irh) to
#      read the Server chain ("Caddy, nginx/1.21.6"), Via and CDN headers, title, body
#      SHA-256 and favicon mmh3; tlsx -jarm (-nc) and cdncheck tags are added. One row per
#      host goes to EDGE_TSV: these are attributes, not findings.
#   2. Candidate origin IPs: A records of origin-style names (direct., origin., backend.
#      under the host and the seed), the seed's SPF ip4: entries and MX hosts, and names
#      from --zone-exposure under the seed. The host's own (edge) addresses are removed.
#   3. Verification: each candidate is asked for the site directly (curl --resolve: Host
#      and SNI = the site, connection straight to the candidate, ports 443 and 80). Same
#      body SHA-256, or same title and same body length, is a match:
#        edge detected    -> origin-exposed [high]  (the edge can be bypassed)
#        no edge detected -> origin-alternate [low] (the site is also served there)
#        same title only  -> origin-candidate [low] (verify by hand)
#      With --proxy, verification goes through the proxy with httpx and a Host header
#      (no custom SNI: an SNI-routed HTTPS origin may then be missed).
origin_check() {
  local domain="$1" raw="$2" out="$3" etsv="$4"
  local live="$raw/live_hosts.txt" ref="$raw/origin_ref.jsonl" jarm="$raw/origin_jarm.txt" cdn="$raw/origin_cdn.txt"
  local names="$raw/origin_names.txt" res="$raw/origin_res.jsonl" txt="$raw/origin_dns.txt" cand="$raw/origin_pairs.tsv"
  local rr=() rr2=(); [ -n "$RESOLVERS" ] && { rr=(-r "$RESOLVERS"); rr2=(-r "$RESOLVERS"); }
  [ -n "$PROXY" ] && rr+=(-proxy "$PROXY")
  local dres=""; [ -n "$RESOLVERS" ] && [ -s "$RESOLVERS" ] && dres="@$(grep -vE '^\s*(#|$)' "$RESOLVERS" | head -n 1 | sed -E 's/:[0-9]+$//')"
  # 1. reference fetch through the normal path (root URLs only)
  grep -E '^https?://[^/]+/?$' "$live" 2>/dev/null | sort -u > "$raw/origin_roots.txt" || true
  [ -s "$raw/origin_roots.txt" ] || return 0
  _to "$STAGE_TIMEOUT" "$HTTPX_BIN" -l "$raw/origin_roots.txt" -silent -json -irh -title -hash sha256 -favicon \
      -nfs -nc -timeout 10 -retries "$HTTP_RETRIES" -rl "$RATE" "${rr[@]}" 2>>"$raw/httpx.err" > "$ref" || true
  : > "$jarm"; : > "$cdn"
  if have tlsx; then
    awk '/^[Hh][Tt][Tt][Pp][Ss]:\/\//{u=$0; sub(/^[^:]*:\/\//,"",u); sub(/\/.*$/,"",u); if(u!~/:/)u=u":443"; print tolower(u)}' \
      "$raw/origin_roots.txt" | sort -u > "$raw/origin_tls.txt"
    if [ -s "$raw/origin_tls.txt" ]; then
      # JARM per host, cached under --db (keys: bare host; values: tlsx's "host:port [jarm]" line)
      local _jkeys="$raw/jarm_keys.txt" _jhit="$raw/jarm_hit.txt" _jmiss="$raw/jarm_miss.txt"
      cut -d: -f1 "$raw/origin_tls.txt" | sort -u > "$_jkeys"
      cache_split tlsx_jarm "$_jkeys" "$_jhit" "$_jmiss"
      cat "$_jhit" > "$jarm" 2>/dev/null || true
      if [ -s "$_jmiss" ]; then
        local _jfresh="$raw/jarm_fresh.txt" _jrc=0
        awk -F: 'NR == FNR { m[$0] = 1; next } ($1 in m)' "$_jmiss" "$raw/origin_tls.txt" > "$raw/jarm_miss_hp.txt" || true
        _to "$STAGE_TIMEOUT" tlsx -l "$raw/jarm_miss_hp.txt" -jarm -silent -nc "${rr2[@]}" 2>/dev/null \
          | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' > "$_jfresh" || _jrc=$?
        cat "$_jfresh" >> "$jarm" 2>/dev/null || true
        [ "$_jrc" -eq 0 ] && cache_store tlsx_jarm "$_jmiss" "$_jfresh" hostport
      fi
    fi
  fi
  if have cdncheck; then
    sed -E 's#^[a-zA-Z]+://##; s#[/:].*$##' "$raw/origin_roots.txt" | sort -u \
      | _to "$STAGE_TIMEOUT" cdncheck -resp -silent -nc 2>/dev/null | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' > "$cdn" || true
  fi
  # 2. candidate names -> addresses
  python3 - "$domain" "$raw/origin_roots.txt" "$WORKDIR/zone_names.txt" > "$names" <<'PYON' || true
import sys
seed, roots, zn = sys.argv[1:4]
hosts = set()
for l in open(roots):
    h = l.strip().split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    if h: hosts.add(h)
out = set()
for base in hosts | {seed}:
    for pre in ("direct", "origin", "backend"):
        out.add(pre + "." + base)
    if base.startswith("www."):
        out.add("origin-" + base)
try:
    for l in open(zn):
        f = l.rstrip("\n").split("\t")
        if len(f) >= 2 and (f[1] == seed or f[1].endswith("." + seed)) and f[1] not in hosts:
            out.add(f[1])
except FileNotFoundError:
    pass
print("\n".join(sorted(out)))
PYON
  : > "$res"
  have dnsx && [ -s "$names" ] && _to "$STAGE_TIMEOUT" dnsx -l "$names" -a -json -silent "${rr2[@]}" 2>/dev/null > "$res" || true
  : > "$txt"
  if have dig; then
    { dig +short +time=3 +tries=1 $dres TXT "$domain" 2>/dev/null | sed 's/^/TXT /'
      dig +short +time=3 +tries=1 $dres MX "$domain" 2>/dev/null | awk '{print "MX "$NF}'; } > "$txt" || true
    awk '$1=="MX"{print $2}' "$txt" | sed 's/\.$//' | while read -r _mx; do
      [ -n "$_mx" ] && dig +short +time=3 +tries=1 $dres A "$_mx" 2>/dev/null | sed "s/^/MXA $_mx /"
    done >> "$txt" || true
  fi
  # 3. pair hosts with candidates and verify
  python3 - "$domain" "$ref" "$jarm" "$cdn" "$res" "$txt" "$etsv" "$cand" "$ORIGIN_MAX_CHECKS" <<'PYOC' || true
import sys, json, re, ipaddress
seed, ref, jarm_f, cdn_f, res_f, txt_f, etsv, cand_f, maxc = sys.argv[1:10]
EDGE_HEADERS = [("cf-ray", "Cloudflare"), ("cf_ray", "Cloudflare"), ("x_amz_cf_id", "CloudFront"), ("x_amz_cf_pop", "CloudFront"),
                ("x_served_by", "Fastly"), ("x_fastly_request_id", "Fastly"), ("akamai_grn", "Akamai"), ("x_akamai_transformed", "Akamai"),
                ("x_azure_ref", "Azure Front Door"), ("x_msedge_ref", "Azure Front Door"), ("x_sucuri_id", "Sucuri"),
                ("x_iinfo", "Imperva"), ("x_cdn", "CDN"), ("x_varnish", "Varnish"), ("x_cache", "cache")]
EDGE_SERVERS = ("cloudflare", "akamaighost", "akamainetstorage", "cloudfront", "caddy", "envoy", "varnish", "sucuri",
                "imperva", "incapsula", "fastly", "awselb", "big-ip", "bigip", "f5", "haproxy", "traefik", "ats", "squid")
def clean(v):
    return "".join(ch for ch in str(v) if ch.isprintable() and ch not in "\t\r\n")[:200]
refs = {}
for line in open(ref, encoding="utf-8", errors="replace"):
    try: j = json.loads(line)
    except Exception: continue
    u = j.get("url") or j.get("input") or ""
    host = u.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    hdr = {str(k).lower(): v for k, v in (j.get("header") or {}).items()}
    server = hdr.get("server", "")
    if isinstance(server, list): server = ", ".join(map(str, server))
    parts = [x.strip() for x in str(server).split(",") if x.strip()]
    edge, osw, ev = "", "", []
    if len(parts) >= 2:
        edge, osw = parts[0], parts[-1]; ev.append("server-chain")
    for k, name in EDGE_HEADERS:
        if k in hdr:
            edge = edge or name; ev.append(k.replace("_", "-"))
    if "via" in hdr:
        edge = edge or clean(hdr["via"]); ev.append("via")
    if not edge and parts and parts[0].split("/")[0].lower() in EDGE_SERVERS:
        edge = parts[0]; ev.append("edge-server")
    h = j.get("hash") or {}
    refs.setdefault(host, []).append({"url": u, "scheme": u.split("://", 1)[0].lower(), "title": clean(j.get("title") or ""),
        "sha": (h.get("body_sha256") or "") if isinstance(h, dict) else "", "len": j.get("content_length"),
        "ip": j.get("host_ip") or "", "edge": clean(edge), "osw": clean(osw), "ev": ",".join(dict.fromkeys(ev)),
        "fav": clean(j.get("favicon") or "")})
jarm = {}
for l in open(jarm_f, encoding="utf-8", errors="replace"):
    m = re.match(r"^\s*([^\s:]+):\d+\s+\[?([0-9a-f]{62})\]?", l)
    if m: jarm[m.group(1).lower()] = m.group(2)
cdn = {}
for l in open(cdn_f, encoding="utf-8", errors="replace"):
    f = l.split()
    if f: cdn[f[0].lower()] = " ".join(x.strip("[]") for x in f[1:])
with open(etsv, "a") as o:
    for host, rs in sorted(refs.items()):
        r = next((x for x in rs if x["scheme"] == "https"), rs[0])
        o.write("\t".join([seed, host, r["edge"], r["osw"], r["ev"], jarm.get(host, ""), clean(cdn.get(host, "")),
                           r["fav"], r["title"], r["ip"]]) + "\n")
# candidate IPs with the source that named them
cands = {}
def add(ip, src):
    try: ipaddress.ip_address(ip)
    except ValueError: return
    cands.setdefault(ip, set()).add(src)
for line in open(res_f, encoding="utf-8", errors="replace"):
    try: j = json.loads(line)
    except Exception: continue
    for ip in j.get("a") or []:
        add(ip, j.get("host", "dns"))
for l in open(txt_f, encoding="utf-8", errors="replace"):
    l = l.strip()
    if l.startswith("TXT ") and "v=spf1" in l.lower():
        for tok in l.replace('"', " ").split():
            if tok.lower().startswith("ip4:"):
                v = tok[4:]
                try:
                    net = ipaddress.ip_network(v, strict=False)
                    if net.num_addresses <= 16:
                        for ip in (net.hosts() if net.num_addresses > 2 else [net.network_address]):
                            add(str(ip), "spf")
                except ValueError: pass
    elif l.startswith("MXA "):
        f = l.split()
        if len(f) >= 3: add(f[2], "mx:" + f[1])
pairs, n = [], 0
for host, rs in sorted(refs.items()):
    edge_ips = {x["ip"] for x in rs if x["ip"]}
    r = next((x for x in rs if x["scheme"] == "https"), rs[0])
    for ip, src in sorted(cands.items()):
        if ip in edge_ips: continue
        if n >= int(maxc or 200): break
        pairs.append("\t".join([host, ip, ",".join(sorted(src)), r["title"], r["sha"], str(r["len"] or ""), r["edge"]])); n += 1
open(cand_f, "w").write("".join(x + "\n" for x in pairs))
PYOC
  [ -s "$cand" ] || return 0
  local _h _ip _src _title _sha _len _edge _port _sch _body _got _gsha _glen _gtitle _match
  while IFS="$(printf '\t')" read -r _h _ip _src _title _sha _len _edge; do
    for _port in 443 80; do
      _sch=https; [ "$_port" = 80 ] && _sch=http
      _body="$raw/origin_body.$$"
      if [ -n "$PROXY" ]; then
        printf '%s://%s:%s/\n' "$_sch" "$_ip" "$_port" | _to 30 "$HTTPX_BIN" -silent -json -title -hash sha256 -nfs -nc \
          -timeout 10 -retries 0 -H "Host: $_h" -proxy "$PROXY" 2>/dev/null > "$_body.json" || true
        _got="$(python3 -c 'import sys,json
try: j=json.loads(open(sys.argv[1]).readline())
except Exception: sys.exit(0)
print("\t".join([str((j.get("hash") or {}).get("body_sha256","")), str(j.get("content_length","")), (j.get("title") or "").replace("\t"," ")]))' "$_body.json" 2>/dev/null)"
      else
        # Direct by design: the question is whether the origin answers WITHOUT the edge.
        # Like httpx, the comparison fetch accepts any certificate (cert validity is the
        # TLS posture stage's job); --noproxy keeps it off any environment proxy.
        _to 20 curl -s -k --noproxy '*' --max-time 10 --max-filesize 5000000 -o "$_body" \
          --resolve "$_h:$_port:$_ip" "$_sch://$_h:$_port/" 2>/dev/null || : > "$_body"
        if [ -s "$_body" ]; then
          _gsha="$(sha256sum "$_body" 2>/dev/null | cut -d' ' -f1)"; _glen="$(wc -c < "$_body" | tr -d ' ')"
          _gtitle="$(tr -d '\r\n' < "$_body" | sed -nE 's#.*<title[^>]*>([^<]*)</title>.*#\1#Ip' | head -c 200)"
          _got="$_gsha	$_glen	$_gtitle"
        else _got=""; fi
      fi
      rm -f "$_body" "$_body.json"
      [ -n "$_got" ] || continue
      IFS="$(printf '\t')" read -r _gsha _glen _gtitle <<< "$_got"
      _match=""
      if [ -n "$_sha" ] && [ "$_gsha" = "$_sha" ]; then _match="body-sha256"
      elif [ -n "$_title" ] && [ "$_gtitle" = "$_title" ] && [ -n "$_len" ] && [ "$_glen" = "$_len" ]; then _match="title+length"
      elif [ -n "$_title" ] && [ "$_gtitle" = "$_title" ]; then _match="title-only"; fi
      [ -n "$_match" ] || continue
      if [ "$_match" = "title-only" ]; then
        printf '[%s] origin-candidate [low] host=%s origin=%s port=%s via=%s match=title note=same title, different body: verify by hand\n' \
          "$domain" "$_h" "$_ip" "$_port" "$_src" >> "$out"
      elif [ -n "$_edge" ]; then
        printf '[%s] origin-exposed [high] host=%s origin=%s port=%s via=%s match=%s edge=%s note=the origin answers for %s directly, bypassing the %s edge; allow only the edge to reach it\n' \
          "$domain" "$_h" "$_ip" "$_port" "$_src" "$_match" "${_edge// /_}" "$_h" "$_edge" >> "$out"
      else
        printf '[%s] origin-alternate [low] host=%s origin=%s port=%s via=%s match=%s note=the same site is also served directly at this address\n' \
          "$domain" "$_h" "$_ip" "$_port" "$_src" "$_match" >> "$out"
      fi
      break
    done
  done < "$cand"
  return 0
}

analyze_hosts() {
  local domain="$1" raw="$2" safe
  safe="$(printf '%s' "$domain" | tr -c 'A-Za-z0-9.-' '_')"
  local live="$raw/live_hosts.txt" livehosts="$raw/live_bare.txt" P="$WORKDIR/parts"
  [ "$PASSIVE_ONLY" = "1" ] && return 0
  local rr2=(); [ -n "$RESOLVERS" ] && rr2=(-r "$RESOLVERS")
  # subdomain takeover: dead names are the point, so this runs even with no live host
  if [ "$TAKEOVER" = "1" ]; then
    stage "$domain" "takeover check (CNAMEs of all candidates)"
    takeover_check "$domain" "$raw" "$P/takeover.$safe.txt" "$P/cname.$safe.tsv"
  fi
  [ -s "$live" ] || return 0
  if [ "$SCREENSHOTS$ORIGIN$NUCLEI$PARAMS$SECRETS" != "00000" ]; then
    stage "$domain" "post-probe analysis (screenshots/origin/nuclei/params/secrets)"
  fi

  # edge detection + origin identification (see origin_check)
  if [ "$ORIGIN" = "1" ] && [ -s "$live" ]; then
    stage "$domain" "edge detection + origin search"
    origin_check "$domain" "$raw" "$P/origin.$safe.txt" "$P/edge.$safe.tsv"
  fi

  # TLS posture (tlsx): negotiated version/cipher, cert expiry, self-signed / name-mismatch
  # / untrusted. Writes JSON to parts/tlsx.<safe>.jsonl -> joined into the CSV (cols M-Q).
  if [ "$TLS_POSTURE" = "1" ] && have tlsx; then
    # derive https authorities (host[:port], default 443) -> stable host:port cache keys
    local _tlskeys="$raw/tls_keys.txt"
    awk '/^[Hh][Tt][Tt][Pp][Ss]:\/\//{u=$0; sub(/^[^:]*:\/\//,"",u); sub(/\/.*$/,"",u); if(u!~/:/)u=u":443"; print tolower(u)}' \
      "$live" 2>/dev/null | sort -u > "$_tlskeys" || : > "$_tlskeys"
    if [ -s "$_tlskeys" ]; then
      stage "$domain" "TLS posture (tlsx)"
      local _tlshit="$raw/tls_hit.jsonl" _tlsmiss="$raw/tls_miss.txt"
      cache_split tlsx_posture "$_tlskeys" "$_tlshit" "$_tlsmiss"   # reuse cached posture
      cat "$_tlshit" >> "$P/tlsx.$safe.jsonl" 2>/dev/null || true
      if [ -s "$_tlsmiss" ]; then
        local _tlsargs=(-l "$_tlsmiss" -json -tls-version -cipher -expired -self-signed -mismatched -untrusted -wildcard-cert -silent -timeout 10)
        [ "$TLS_ENUM" = "1" ] && _tlsargs+=(-version-enum -cipher-enum)
        _tlsargs+=("${rr2[@]}")
        local _tlsfresh="$raw/tls_fresh.jsonl" _tlsrc=0
        _to "$STAGE_TIMEOUT" tlsx "${_tlsargs[@]}" 2>>"$raw/tlsx.err" > "$_tlsfresh" || _tlsrc=$?
        # late retry: a live HTTPS host with no handshake record failed (the farm at
        # -t 20 on 2 vCPU lost hosts this way); try those once more after a pause.
        if [ "$LATE_RETRY" = "1" ] && [ "$_tlsrc" -eq 0 ]; then
          local _tlslate="$raw/tls_late.txt"
          missing_keys jsonauthority "$_tlsmiss" "$_tlsfresh" > "$_tlslate"
          if [ -s "$_tlslate" ]; then
            log "[$domain] TLS posture: $(wc -l < "$_tlslate" | tr -d ' ') host(s) gave no handshake; retrying once after a pause"
            late_pause
            local _tlsargs2=("${_tlsargs[@]}"); _tlsargs2[1]="$_tlslate"
            _to "$STAGE_TIMEOUT" tlsx "${_tlsargs2[@]}" 2>>"$raw/tlsx.err" >> "$_tlsfresh" || true
          fi
        fi
        [ "$TLS_CHAIN_CHECK" = "1" ] && tls_chain_check "$_tlsfresh"
        cat "$_tlsfresh" >> "$P/tlsx.$safe.jsonl" 2>/dev/null || true
        [ "$_tlsrc" -eq 0 ] && cache_store tlsx_posture "$_tlsmiss" "$_tlsfresh" jsonauthority noneg
      fi
    fi
  fi

  # AAAA resolution (dnsx) -> parts/aaaa.<safe>.txt (host<TAB>v6;v6) -> ipv6 CSV col
  if [ "$IPV6" = "1" ] && have dnsx && [ -s "$livehosts" ]; then
    stage "$domain" "AAAA resolution (dnsx)"
    _to "$STAGE_TIMEOUT" dnsx -l "$livehosts" -aaaa -json -silent "${rr2[@]}" 2>/dev/null \
      | python3 -c '
import sys, json, ipaddress
# Accept only strings that parse as IPv6. Real dnsx (1.2.x) returns "aaaa": null
# for names without AAAA while "all" holds raw RRs AND resolver chatter such as
# ";; OPT PSEUDOSECTION:" -- which contains ":" and used to be taken for an
# address. When "aaaa" is absent, take AAAA RRs ("name. TTL IN AAAA addr") from
# "all" by record type, never by the presence of a colon.
def v6(x):
    try:
        return ipaddress.ip_address(x.strip()).version == 6
    except Exception:
        return False
for ln in sys.stdin:
    ln = ln.strip()
    if not ln:
        continue
    try:
        j = json.loads(ln)
    except Exception:
        continue
    if not isinstance(j, dict):
        continue
    h = (j.get("host") or "").lower().rstrip(".")
    a = j.get("aaaa") or []
    if isinstance(a, str):
        a = [a]
    addrs = [x.strip() for x in a if isinstance(x, str) and v6(x)]
    if not addrs:
        for rr in (j.get("all") or []):
            if not isinstance(rr, str):
                continue
            p = rr.split()
            if len(p) >= 5 and p[-2].upper() == "AAAA" and v6(p[-1]):
                addrs.append(p[-1])
    if h and addrs:
        print(h + "\t" + ";".join(sorted(set(addrs))))
' >> "$P/aaaa.$safe.txt" || true
  fi

  # screenshots (httpx -screenshot preferred; gowitness fallback) -- byte-cached per host
  if [ "$SCREENSHOTS" = "1" ] && [ -s "$livehosts" ]; then
    local _ssdir="$WORKDIR/screenshots"; mkdir -p "$_ssdir/screenshot"
    local _sstarget="$livehosts"
    if [ "$USE_DB" = "1" ]; then
      local _ssmiss="$raw/ss_miss.txt"
      _ss_restore "$livehosts" "$_ssdir/screenshot" "$_ssmiss"   # cached PNGs -> run dir
      _sstarget="$_ssmiss"
    fi
    if [ -s "$_sstarget" ]; then
      # render misses into a staging dir so _ss_save only sees FRESH files
      local _ssfresh="$WORKDIR/ss_fresh.$safe"; mkdir -p "$_ssfresh"
      : > "$raw/ss.jsonl"
      if have "$HTTPX_BIN"; then
        # -srd sends screenshots under: <dir>/screenshot/<host>/<hash>.png. The headless
        # browser does not use httpx's -r or -proxy: it takes the environment proxy and
        # ignores NO_PROXY, so names meant to be reached directly were sent to the proxy
        # and the "screenshot" was the proxy's error page. SS_* (set in the main process)
        # give the browser the same routing; -json records what the browser rendered.
        local _ssargs=(-l "$_sstarget" -ss -srd "$_ssfresh" -silent -json -esb -o "$raw/ss.jsonl")
        [ "${SS_CHROME:-0}" = "1" ] && _ssargs+=(-system-chrome)
        [ -n "${SS_PROXY_SERVER:-}" ] && _ssargs+=(-ho "--proxy-server=$SS_PROXY_SERVER")
        [ -n "${SS_PROXY_BYPASS:-}" ] && _ssargs+=(-ho "--proxy-bypass-list=$SS_PROXY_BYPASS")
        _to "$STAGE_TIMEOUT" "$HTTPX_BIN" "${_ssargs[@]}" "${rr2[@]}" >/dev/null 2>>"$raw/ss.err" || true
      elif have gowitness; then
        _to "$STAGE_TIMEOUT" gowitness scan file -f "$_sstarget" --screenshot-path "$_ssfresh" >/dev/null 2>/dev/null || true
      fi
      [ "$USE_DB" = "1" ] && _ss_save "$_sstarget" "$_ssfresh"
      # one row per requested host: host, image path under the run's screenshot dir,
      # the probe's title, the title the browser rendered, httpx's failed flag, body length
      python3 - "$_sstarget" "$raw/ss.jsonl" "$_ssfresh" >> "$P/ss.$safe.tsv" <<'PYSS' 2>/dev/null || true
import sys, json, os, re
targets, jl, fresh = sys.argv[1:4]
def t(x):
    return re.sub(r"\s+", " ", (x or "")).strip().replace("\t", " ")
def htitle(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    return t(m.group(1)) if m else ""
got = {}
try:
    for line in open(jl, encoding="utf-8", errors="replace"):
        try:
            j = json.loads(line)
        except Exception:
            continue
        if not isinstance(j, dict):
            continue
        h = (j.get("input") or j.get("host") or "").lower().strip()
        h = re.sub(r"^[a-z]+://", "", h).split("/")[0]
        path = j.get("screenshot_path") or ""
        rel = ""
        if path:
            try:
                rel = os.path.relpath(path, fresh)
            except ValueError:
                rel = ""
            if rel.startswith(".."):
                rel = os.path.join("screenshot", j.get("screenshot_path_rel") or os.path.basename(path))
        cl = j.get("content_length")
        got[h] = (rel, t(j.get("title")), htitle(j.get("headless_body")), "1" if j.get("failed") else "0",
                  str(cl) if isinstance(cl, int) else "")
except OSError:
    pass
for h in (l.strip().lower() for l in open(targets) if l.strip()):
    rel, pt, bt, failed, cl = got.get(h, ("", "", "", "1" if os.path.getsize(jl) else "", ""))
    print("\t".join([h, rel, pt, bt, failed, cl]))
PYSS
      cp -a "$_ssfresh"/. "$_ssdir"/ 2>/dev/null || true   # merge fresh into the run dir
    fi
    # hosts whose image came from the DB cache
    if [ "$USE_DB" = "1" ] && [ -s "$livehosts" ]; then
      comm -23 <(sort -u "$livehosts") <(sort -u "${_ssmiss:-/dev/null}") 2>/dev/null \
        | while IFS= read -r _h; do [ -n "$_h" ] && printf '%s\tscreenshot/%s.png\t\t\tcached\n' "$_h" "$(_ss_norm "$_h")"; done \
        >> "$P/ss.$safe.tsv" || true
    fi
  fi

  # nuclei templated scan (opt-in; OFF by default -- widens scope to scanning)
  if [ "$NUCLEI" = "1" ] && have nuclei; then
    nuclei_oast_args
    _to "$SCAN_TIMEOUT" nuclei -l "$live" -severity "$NUCLEI_SEV" -silent "${_NO[@]}" "${rr2[@]}" 2>/dev/null \
      | sed "s/^/[$domain] /" >> "$P/nuclei.$safe.txt" || true
  fi

  # parameter discovery (arjun) on a capped set of live URLs. arjun's stdout is
  # param names, so write text output (-oT) to a file and ingest that.
  if [ "$PARAMS" = "1" ] && have arjun; then
    local pin="$raw/arjun_in.txt" pout="$raw/arjun_out.txt"
    head -n 50 "$live" > "$pin" 2>/dev/null || : > "$pin"
    _to "$STAGE_TIMEOUT" arjun -i "$pin" -oT "$pout" -q -t 10 2>/dev/null || true
    [ -s "$pout" ] && sed "s/^/[$domain] /" "$pout" >> "$P/params.$safe.txt" || true
  fi

  # secret scanning on discovered JS (secretfinder per-URL; trufflehog fallback)
  if [ "$SECRETS" = "1" ] && [ -s "$raw/jsfiles.txt" ]; then
    if have secretfinder; then
      local jsu
      while IFS= read -r jsu; do [ -z "$jsu" ] && continue
        _to "$STAGE_TIMEOUT" secretfinder -i "$jsu" -o cli 2>/dev/null || true
      done < "$raw/jsfiles.txt" | sed "s/^/[$domain] /" >> "$P/secrets.$safe.txt" || true
    elif have trufflehog; then
      # NOTE: --no-update omitted on purpose (errors "cannot be repeated" on some v3.88+ builds)
      local sd="$raw/js_bodies" i=0 jsu; mkdir -p "$sd"
      while IFS= read -r jsu; do [ -z "$jsu" ] && continue
        curl -fsSL "$jsu" -o "$sd/$i.js" 2>/dev/null || true; i=$((i+1))
      done < "$raw/jsfiles.txt"
      _to "$STAGE_TIMEOUT" trufflehog filesystem "$sd" --no-verification 2>/dev/null \
        | sed "s/^/[$domain] /" >> "$P/secrets.$safe.txt" || true
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# cms_scan <domain> <raw> -- active CMS/app-layer scanning (opt-in, --active).
# Two tiers per the build plan: shell out to specialist CLIs when present
# (wpscan/droopescan/joomscan/cmseek), else a native curl/ffuf primitive tier.
# Fingerprints each live host (whatweb -> nuclei tech-detect -> native curl),
# classifies the CMS, runs the matching deep-enum module, then maps
# versions->CVEs via nuclei's tech/cms templates (durable MIT-licensed OSS
# vuln layer; WPScan's DB needs a token and is rate-limited). Findings ->
# $WORKDIR/parts/cms.<safe>.txt (aggregated into <out>.cms.txt). Active + noisy
# -> gated by --active and skipped under --passive-only.
# ---------------------------------------------------------------------------
cms_scan() {
  local domain="$1" raw="$2" safe
  safe="$(printf '%s' "$domain" | tr -c 'A-Za-z0-9.-' '_')"
  local live="$raw/live_hosts.txt" out="$WORKDIR/parts/cms.$safe.txt"
  [ "$ACTIVE" = "1" ] || return 0
  [ "$PASSIVE_ONLY" = "1" ] && return 0
  [ -s "$live" ] || return 0
  local rr2=(); [ -n "$RESOLVERS" ] && rr2=(-r "$RESOLVERS")
  local wptok=(); [ -n "$WPSCAN_API_TOKEN" ] && wptok=(--api-token "$WPSCAN_API_TOKEN")

  local targets="$raw/cms_targets.txt"
  head -n "$CMS_MAX" "$live" > "$targets" 2>/dev/null || : > "$targets"
  stage "$domain" "active CMS scan (fingerprint + per-CMS enum)"
  local wp="$raw/cms_wp.txt" dr="$raw/cms_dr.txt" jm="$raw/cms_jm.txt" ot="$raw/cms_other.txt" all="$raw/cms_all.txt"
  : > "$wp"; : > "$dr"; : > "$jm"; : > "$ot"; : > "$all"

  # --- fingerprint + classify each host ---
  local u fp low matched base
  while IFS= read -r u; do
    [ -z "$u" ] && continue
    fp=""
    if have whatweb; then
      fp="$(_to "$STAGE_TIMEOUT" whatweb --no-errors --color=never "$u" 2>/dev/null || true)"
    elif have nuclei; then
      nuclei_oast_args
      fp="$(printf '%s\n' "$u" | _to "$STAGE_TIMEOUT" nuclei -tags tech -silent "${_NO[@]}" "${rr2[@]}" 2>/dev/null || true)"
    else
      fp="$(curl -fsSL --max-time 10 "$u" 2>/dev/null | grep -iE 'name=."?generator' | head -1 || true)"
    fi
    [ -n "$fp" ] && printf '[%s] fingerprint %s :: %s\n' "$domain" "$u" "$(printf '%s' "$fp" | tr '\n' ' ' | cut -c1-240)" >> "$out"
    low="$(printf '%s' "$fp" | tr 'A-Z' 'a-z')"; matched=0
    case "$low" in *wordpress*) echo "$u" >> "$wp"; echo "$u" >> "$all"; matched=1;; esac
    case "$low" in *drupal*)    echo "$u" >> "$dr"; echo "$u" >> "$all"; matched=1;; esac
    case "$low" in *joomla*)    echo "$u" >> "$jm"; echo "$u" >> "$all"; matched=1;; esac
    [ "$matched" = 0 ] && echo "$u" >> "$ot"
  done < "$targets"

  # --- WordPress deep enum ---
  if [ -s "$wp" ]; then
    if have wpscan; then
      while IFS= read -r u; do [ -z "$u" ] && continue
        cache_or_run wpscan "$u" -- _to "$SCAN_TIMEOUT" wpscan --url "$u" --no-banner --format cli-no-color --random-user-agent \
          --enumerate vp,vt,u --plugins-detection mixed "${wptok[@]}" 2>/dev/null \
          | grep -aiE '\[[!+]\]|version|user|plugin|theme|vulnerab' \
          | sed "s#^#[$domain] wpscan #" >> "$out" || true
      done < "$wp"
    else
      while IFS= read -r u; do [ -z "$u" ] && continue
        base="${u%/}"
        local v; v="$(curl -fsSL --max-time 10 "$base/readme.html" 2>/dev/null | grep -oiE 'version [0-9.]+' | head -1 || true)"
        [ -n "$v" ] && echo "[$domain] wp-version $u $v" >> "$out"
        curl -fsSL --max-time 10 "$base/wp-json/wp/v2/users" 2>/dev/null \
          | grep -oE '"slug":"[^"]*"' | sed "s#^#[$domain] wp-user $u #" >> "$out" || true
        curl -fsSL --max-time 10 "$base/" 2>/dev/null \
          | grep -oE "/wp-content/(plugins|themes)/[^/\"' ]+" | sort -u \
          | sed "s#^#[$domain] wp-asset $u #" >> "$out" || true
      done < "$wp"
      # native aggressive slug brute (ffuf) when wpscan is absent
      if [ -f "$CMS_WORDLIST" ] && have ffuf; then
        while IFS= read -r u; do [ -z "$u" ] && continue
          base="${u%/}"
          _to "$FUZZ_TIMEOUT" ffuf -u "$base/wp-content/plugins/FUZZ/readme.txt" -w "$CMS_WORDLIST" -mc 200 -s \
               -t "$FUZZ_THREADS" -rate "$RATE" 2>/dev/null | sed "s#^#[$domain] wp-plugin $u #" >> "$out" || true
          _to "$FUZZ_TIMEOUT" ffuf -u "$base/wp-content/themes/FUZZ/style.css" -w "$CMS_WORDLIST" -mc 200 -s \
               -t "$FUZZ_THREADS" -rate "$RATE" 2>/dev/null | sed "s#^#[$domain] wp-theme $u #" >> "$out" || true
        done < "$wp"
      fi
    fi
  fi

  # --- Drupal deep enum ---
  if [ -s "$dr" ]; then
    while IFS= read -r u; do [ -z "$u" ] && continue
      if have droopescan; then
        _to "$STAGE_TIMEOUT" droopescan scan drupal -u "$u" 2>/dev/null \
          | grep -aiE 'found|version|http' | sed "s#^#[$domain] droopescan #" >> "$out" || true
      else
        base="${u%/}"; local dv
        dv="$(curl -fsSL --max-time 10 "$base/CHANGELOG.txt" 2>/dev/null | grep -oiE 'drupal [0-9.]+' | head -1 || true)"
        [ -z "$dv" ] && dv="$(curl -fsSL --max-time 10 "$base/core/CHANGELOG.txt" 2>/dev/null | grep -oiE 'drupal [0-9.]+' | head -1 || true)"
        [ -n "$dv" ] && echo "[$domain] drupal-version $u $dv" >> "$out"
      fi
    done < "$dr"
  fi

  # --- Joomla deep enum ---
  if [ -s "$jm" ]; then
    while IFS= read -r u; do [ -z "$u" ] && continue
      if have joomscan; then
        _to "$STAGE_TIMEOUT" joomscan --url "$u" 2>/dev/null \
          | grep -aiE '\[\+\+\]|version|vulnerab|core|component' | sed "s#^#[$domain] joomscan #" >> "$out" || true
      else
        base="${u%/}"; local jv
        jv="$(curl -fsSL --max-time 10 "$base/administrator/manifests/files/joomla.xml" 2>/dev/null | grep -oiE '<version>[^<]+' | head -1 || true)"
        [ -n "$jv" ] && echo "[$domain] joomla-version $u ${jv#<version>}" >> "$out"
      fi
    done < "$jm"
  fi

  # --- generic/unknown: cmseek auto-detects many CMSs ---
  if [ -s "$ot" ] && have cmseek; then
    while IFS= read -r u; do [ -z "$u" ] && continue
      _to "$STAGE_TIMEOUT" cmseek -u "$u" --follow-redirect 2>/dev/null < /dev/null \
        | grep -aiE 'detected|version|cms' | sed "s#^#[$domain] cmseek #" >> "$out" || true
    done < "$ot"
  fi

  # --- vuln mapping: nuclei tech/cms templates on all detected-CMS hosts ---
  if [ -s "$all" ] && have nuclei; then
    sort -u "$all" -o "$all" 2>/dev/null || true
    nuclei_oast_args
    _to "$SCAN_TIMEOUT" nuclei -l "$all" -tags tech,cms -silent "${_NO[@]}" "${rr2[@]}" 2>/dev/null \
      | sed "s#^#[$domain] nuclei-cms #" >> "$out" || true
  fi
  return 0
}

# ---------------------------------------------------------------------------
# activescan <domain> <raw> -- thorough active scan (opt-in, --activescan).
# Content discovery across several SecLists wordlists (feroxbuster preferred,
# ffuf fallback) PLUS a broad nuclei run, over the live hosts. Heavier and
# noisier than --fuzz (which uses a single list and feeds the URL CSV): this is
# a self-contained scan whose hits + findings go to <out>.activescan.txt.
# Active + loud -> gated by --activescan and skipped under --passive-only.
# ---------------------------------------------------------------------------
activescan() {
  local domain="$1" raw="$2" safe
  safe="$(printf '%s' "$domain" | tr -c 'A-Za-z0-9.-' '_')"
  local live="$raw/live_hosts.txt" out="$WORKDIR/parts/activescan.$safe.txt"
  [ "$ACTIVESCAN" = "1" ] || return 0
  [ "$PASSIVE_ONLY" = "1" ] && return 0
  [ -s "$live" ] || return 0
  local rr2=(); [ -n "$RESOLVERS" ] && rr2=(-r "$RESOLVERS")

  # 1) content discovery across the curated SecLists lists (existing ones only).
  #    Raw hits are tee'd to $asurls so uro can dedupe/filter them for the nuclei feed.
  local wl wlname base asurls="$raw/activescan_urls.txt" ascln="$raw/activescan_urls.clean.txt"
  : > "$asurls"
  for wl in "${ACTIVESCAN_LISTS[@]}"; do
    [ -f "$wl" ] || continue
    wlname="$(basename "$wl")"
    stage "$domain" "activescan content ($wlname)"
    if have feroxbuster; then
      local fxa=(--stdin -w "$wl" --silent -t "$FUZZ_THREADS" --rate-limit "$RATE" --timeout 10 --depth 2 -k -C 404)
      [ "$FUZZ_TIMEOUT" -gt 0 ] 2>/dev/null && fxa+=(--time-limit "${FUZZ_TIMEOUT}s")
      cat "$live" | _to "$FUZZ_TIMEOUT" feroxbuster "${fxa[@]}" 2>/dev/null | tee -a "$asurls" \
        | sed "s#^#[$domain] content($wlname) #" >> "$out" || true
    elif have ffuf; then
      while IFS= read -r base; do [ -z "$base" ] && continue
        # shellcheck disable=SC2054  # comma-separated -mc value for ffuf, not array separators
        local afa=(-u "${base%/}/FUZZ" -w "$wl" \
                   -mc 200,204,301,302,307,308,401,403,405 \
                   -t "$FUZZ_THREADS" -rate "$RATE" -timeout 10 -s)
        _to "$FUZZ_TIMEOUT" ffuf "${afa[@]}" 2>/dev/null | awk -v b="${base%/}/" 'NF{print b $0}' | tee -a "$asurls" \
          | sed "s#^#[$domain] content($wlname) #" >> "$out" || true
      done < "$live"
    fi
  done

  # 1b) dedupe/filter discovered URLs with uro (sort -u fallback) before scanning.
  uro_filter "$asurls" 2>/dev/null | sort -u > "$ascln" || sort -u "$asurls" > "$ascln" 2>/dev/null || : > "$ascln"
  if [ -s "$asurls" ]; then
    printf '[%s] uro filtered content: %s -> %s URLs\n' "$domain" \
      "$(wc -l < "$asurls" | tr -d ' ')" "$(wc -l < "$ascln" | tr -d ' ')" >> "$out"
  fi

  # 2) broad nuclei scan over live hosts + the uro-cleaned discovered URLs
  if have nuclei; then
    stage "$domain" "activescan nuclei ($NUCLEI_SEV)"
    cat "$live" "$ascln" 2>/dev/null | sort -u > "$raw/activescan_targets.txt" || cp "$live" "$raw/activescan_targets.txt"
    nuclei_oast_args
    _to "$SCAN_TIMEOUT" nuclei -l "$raw/activescan_targets.txt" -severity "$NUCLEI_SEV" -silent "${_NO[@]}" "${rr2[@]}" 2>/dev/null \
      | sed "s#^#[$domain] nuclei #" >> "$out" || true
  fi
  return 0
}

# ---------------------------------------------------------------------------
# osint_scan <domain> <raw> -- passive OSINT enrichment via third-party sources.
# These query APIs about the target, not the target itself, so they run even
# under --passive-only. Uses curl/dig/jq (base deps). Findings -> side artifacts:
#   --osint      RDAP registration + Shodan InternetDB (ports/hostnames/tags) +
#                Team Cymru IP-to-ASN (org name also reveals cloud tenancy)  -> <out>.osint.txt
#   --virustotal VT domain report: reputation, last DNS records, subdomains      -> <out>.virustotal.txt
#   --urlscan    urlscan.io search: historical page URLs + resolved IPs          -> <out>.urlscan.txt
# ---------------------------------------------------------------------------
osint_scan() {
  local domain="$1" raw="$2" safe
  safe="$(printf '%s' "$domain" | tr -c 'A-Za-z0-9.-' '_')"
  [ "$OSINT$VIRUSTOTAL$URLSCAN$SOCIAL" != "0000" ] || return 0
  local P="$WORKDIR/parts"

  # --- free OSINT: RDAP + per-IP Shodan InternetDB + Team Cymru ASN ---------
  if [ "$OSINT" = "1" ] && have curl; then
    stage "$domain" "OSINT (RDAP + Shodan InternetDB + Team Cymru ASN)"
    local oo="$P/osint.$safe.txt" rd
    # RDAP domain registration (rdap.org bootstraps to the right server). Needs jq to parse.
    if have jq; then
      rd="$(cache_or_run rdap "$domain" -- _to "$RDAP_TIMEOUT" curl -fsS --retry 2 --retry-delay 1 --max-time 20 -H 'Accept: application/rdap+json' "https://rdap.org/domain/$domain" 2>/dev/null)"
      if [ -n "$rd" ]; then
        local reg cre exp ns st
        reg="$(printf '%s' "$rd" | jq -r '[.entities[]?|select(.roles[]?=="registrar")|.vcardArray[1][]?|select(.[0]=="fn")|.[3]][0] // "?"' 2>/dev/null || echo '?')"
        cre="$(printf '%s' "$rd" | jq -r '[.events[]?|select(.eventAction=="registration")|.eventDate][0] // "?"' 2>/dev/null || echo '?')"
        exp="$(printf '%s' "$rd" | jq -r '[.events[]?|select(.eventAction=="expiration")|.eventDate][0] // "?"' 2>/dev/null || echo '?')"
        ns="$(printf '%s' "$rd" | jq -r '[.nameservers[]?.ldhName]|join(",")' 2>/dev/null || echo '')"
        st="$(printf '%s' "$rd" | jq -r '[.status[]?]|join(",")' 2>/dev/null || echo '')"
        echo "[$domain] rdap registrar=\"$reg\" created=$cre expires=$exp ns=$ns status=$st" >> "$oo"
      fi
      _delay "$RDAP_DELAY"
    fi
    # resolve a bounded set of IPs (live hosts if we have them, else the seed)
    local src="$raw/osint_src.txt" ips="$raw/osint_ips.txt"
    if [ -s "$raw/live_bare.txt" ]; then cp "$raw/live_bare.txt" "$src" 2>/dev/null || printf '%s\n' "$domain" > "$src"
    else printf '%s\n' "$domain" > "$src"; fi
    : > "$ips"
    if have dnsx; then
      _to "$STAGE_TIMEOUT" dnsx -l "$src" -a -resp-only -silent 2>/dev/null | grep -E '^[0-9.]+$' | sort -u | head -n "$OSINT_MAX" > "$ips" || : > "$ips"
    elif have dig; then
      while IFS= read -r h; do [ -z "$h" ] && continue; dig +short A "$h" 2>/dev/null; done < "$src" \
        | grep -E '^[0-9.]+$' | sort -u | head -n "$OSINT_MAX" > "$ips" || : > "$ips"
    fi
    # only globally-routable IPs go to third-party lookups: internal addresses
    # (loopback/RFC1918/CGNAT/link-local) have no Shodan or Cymru record, and
    # querying them would leak internal topology to those services.
    if [ -s "$ips" ]; then
      python3 -c 'import sys, ipaddress
for l in sys.stdin:
    l = l.strip()
    try:
        if l and ipaddress.ip_address(l).is_global:
            print(l)
    except Exception:
        pass' < "$ips" > "$ips.pub" 2>/dev/null && mv -f "$ips.pub" "$ips"
    fi
    local ip idb ports tags hn rev tc asn asname
    while IFS= read -r ip; do
      [ -z "$ip" ] && continue
      seen_once osint_ip "$ip" || continue   # query each IP once per run (mapping stays in the CSV)
      # Shodan InternetDB (free, no key): open ports / hostnames / tags / cpes. Needs jq.
      # NOTE: its 'vulns' field (CVE IDs) is intentionally dropped -- out of scope.
      if have jq; then
        idb="$(cache_or_run internetdb "$ip" -- _to "$INTERNETDB_TIMEOUT" curl -fsS --retry 2 --retry-delay 1 --max-time 15 "https://internetdb.shodan.io/$ip" 2>/dev/null)"
        if [ -n "$idb" ]; then
          ports="$(printf '%s' "$idb" | jq -rc '.ports//[]' 2>/dev/null || echo '[]')"
          tags="$(printf '%s' "$idb" | jq -rc '.tags//[]' 2>/dev/null || echo '[]')"
          hn="$(printf '%s' "$idb" | jq -rc '.hostnames//[]' 2>/dev/null || echo '[]')"
          echo "[$domain] shodan-internetdb $ip ports=$ports hostnames=$hn tags=$tags" >> "$oo"
        fi
      fi
      # Team Cymru IP-to-ASN (free, DNS, awk-only): ASN + prefix + AS name (reveals cloud).
      if have dig; then
        rev="$(printf '%s' "$ip" | awk -F. 'NF==4{print $4"."$3"."$2"."$1}')"
        [ -n "$rev" ] && tc="$(dig +short "$rev.origin.asn.cymru.com" TXT 2>/dev/null | tr -d '"' | head -1)" || tc=""
        if [ -n "$tc" ]; then
          asn="$(printf '%s' "$tc" | awk -F'|' '{gsub(/ /,"",$1);print $1}')"
          asname="$(dig +short "AS$asn.asn.cymru.com" TXT 2>/dev/null | tr -d '"' | awk -F'|' '{print $5}' | sed 's/^[[:space:]]*//' | head -1)"
          echo "[$domain] asn $ip AS$asn \"$asname\" $(printf '%s' "$tc" | sed 's/[[:space:]]*|[[:space:]]*/ | /g')" >> "$oo"
        fi
      fi
      _delay "$INTERNETDB_DELAY"    # rate-space InternetDB (from --limits / the probe)
    done < "$ips"
  fi

  # --- VirusTotal domain report (needs VT_API_KEY) -------------------------
  if [ "$VIRUSTOTAL" = "1" ] && [ -n "$VT_API_KEY" ] && have curl && have jq; then
    stage "$domain" "VirusTotal domain report"
    local vo="$P/virustotal.$safe.txt" vt vs
    vt="$(cache_or_run virustotal "$domain" -- _to "$VT_TIMEOUT" curl -fsS --retry 2 --retry-delay 1 --max-time 20 -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/$domain" 2>/dev/null)"
    if [ -n "$vt" ]; then
      printf '%s' "$vt" | jq -r '.data.attributes | "reputation="+((.reputation//0)|tostring)+" categories="+(((.categories//{})|to_entries|map(.value))|join(","))' 2>/dev/null \
        | sed "s/^/[$domain] virustotal /" >> "$vo" || true
      printf '%s' "$vt" | jq -r '.data.attributes.last_dns_records[]? | "dns "+.type+" "+(.value|tostring)' 2>/dev/null \
        | sed "s/^/[$domain] virustotal /" >> "$vo" || true
    fi
    _delay "$VT_DELAY"
    vs="$(cache_or_run virustotal_subs "$domain" -- _to "$VT_TIMEOUT" curl -fsS --retry 2 --retry-delay 1 --max-time 20 -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/$domain/subdomains?limit=40" 2>/dev/null)"
    [ -n "$vs" ] && printf '%s' "$vs" | jq -r '.data[]?.id' 2>/dev/null | sed "s/^/[$domain] virustotal subdomain /" >> "$vo" || true
  fi

  # --- urlscan.io historical scans ----------------------------------------
  if [ "$URLSCAN" = "1" ] && have curl && have jq; then
    stage "$domain" "urlscan.io search"
    local us uhdr=(); [ -n "$URLSCAN_API_KEY" ] && uhdr=(-H "API-Key: $URLSCAN_API_KEY")
    us="$(cache_or_run urlscan "$domain" -- _to "$URLSCAN_TIMEOUT" curl -fsS --retry 2 --retry-delay 1 --max-time 20 "${uhdr[@]}" "https://urlscan.io/api/v1/search/?q=domain:$domain&size=100" 2>/dev/null)"
    [ -n "$us" ] && printf '%s' "$us" | jq -r '.results[]? | (.task.time//"?")+" "+(.page.url//"?")+" ip="+(.page.ip//"?")' 2>/dev/null \
      | sed "s#^#[$domain] urlscan #" >> "$P/urlscan.$safe.txt" || true
    _delay "$URLSCAN_DELAY"
  fi

  # --- social-media account discovery (tookie-osint) ----------------------
  # Searches the org's brand username across many social platforms. Queries the
  # platforms (not the target), so it's passive w.r.t. the target. Best-effort:
  # captures the account URLs tookie-osint reports for the username.
  if [ "$SOCIAL" = "1" ] && have tookie-osint; then
    stage "$domain" "social-media discovery (tookie-osint)"
    local suser="${SOCIAL_USER:-${domain%%.*}}"
    _to "$SCAN_TIMEOUT" tookie-osint -u "$suser" --no-color </dev/null 2>/dev/null \
      | grep -aiE '\[\+\]|found|discovered' | grep -aoE 'https?://[^ "]+' | sort -u \
      | sed "s#^#[$domain] social($suser) #" >> "$P/social.$safe.txt" || true
  fi
  return 0
}

# ===========================================================================
# special_use_domain <name> : true for names that can never appear in public URL
# archives, CT logs or passive DNS -- the IANA special-use / private-use TLDs
# (RFC 6761: test example invalid localhost; RFC 6762: local; RFC 7686: onion;
# RFC 8375: home.arpa; RFC 9476: alt; ICANN 2024: internal). Querying internet
# sources for them is pure waiting (often minutes against Wayback/CommonCrawl).
# nuclei_oast_args: fill the global array _NO with the OAST flags for every nuclei call
# (see NUCLEI_OAST). Called in each worker, since arrays cannot be exported.
nuclei_oast_args(){
  _NO=()
  case "${NUCLEI_OAST:-off}" in
    public) ;;
    self)   _NO=(-iserver "$NUCLEI_ISERVER")
            if [ -n "${NUCLEI_ITOKEN:-}" ]; then _NO+=(-itoken "$NUCLEI_ITOKEN"); fi;;
    *)      _NO=(-ni);;
  esac
  return 0   # set -e: a false last test must not abort the worker
}

special_use_domain(){
  local d; d="$(printf '%s' "${1%.}" | tr '[:upper:]' '[:lower:]')"
  case "$d" in
    test|*.test|example|*.example|invalid|*.invalid|localhost|*.localhost|local|*.local|\
    onion|*.onion|alt|*.alt|internal|*.internal|home.arpa|*.home.arpa) return 0;;
  esac
  return 1
}

# process_one <domain>   -- full pipeline for a single seed domain.
# Writes per-domain artifacts to $WORKDIR/parts/ (parallel-safe, no shared
# file writes), to be aggregated by the parent after all workers finish.
# ===========================================================================
process_one() {
  local domain="$1"
  local safe raw hosts
  WORKER_START=$(date +%s 2>/dev/null || echo 0)
  safe="$(printf '%s' "$domain" | tr -c 'A-Za-z0-9.-' '_')"
  raw="$WORKDIR/raw/$safe"
  mkdir -p "$raw" "$WORKDIR/parts"

  log "[$domain] starting"
  local _pskip=0
  if [ "$SKIP_SPECIAL_USE" = "1" ] && special_use_domain "$domain"; then
    _pskip=1
    log "[$domain] special-use name (RFC 6761 et al.): skipping passive internet sources"
  fi

  # --- Phase A: candidate host discovery -----------------------------------
  hosts="$raw/hosts.txt"
  printf '%s\n' "$domain" > "$hosts"
  : > "$raw/host_subfinder.txt"; : > "$raw/host_amass.txt"; : > "$raw/host_assetfinder.txt"
  : > "$raw/host_brute.txt"; : > "$raw/host_alterx.txt"; : > "$raw/host_tlsx.txt"
  : > "$raw/host_tlsxlive.txt"; : > "$raw/host_favicon.txt"
  : > "$raw/host_findomain.txt"; : > "$raw/host_github.txt"

  # GitHub token args (shared by github-subdomains/github-endpoints; empty unless --github + token)
  local GHTOK=()
  if [ "$GITHUB" = "1" ]; then
    if [ -n "$GITHUB_TOKEN_FILE" ] && [ -f "$GITHUB_TOKEN_FILE" ]; then GHTOK=(-t "$GITHUB_TOKEN_FILE")
    elif [ -n "${GITHUB_TOKEN:-}" ]; then GHTOK=(-t "$GITHUB_TOKEN"); fi
  fi

  # passive subdomain sources (subfinder + amass + assetfinder + findomain),
  # optionally recursive: with --rounds N>1 the hosts found each round are re-enumerated.
  if [ "$DO_SUBS" = "1" ] && [ "$_pskip" = "0" ]; then
    stage "$domain" "passive subdomains (subfinder/amass/assetfinder/findomain)"
    local _subs_cached=0
    if [ "$USE_DB" = "1" ]; then
      local _cs; _cs="$(db_cache_get subs "$domain" "$CACHE_TTL" || true)"
      if [ -n "$_cs" ]; then
        printf '%s\n' "$_cs" | scope_filter "$domain" >> "$hosts"; sort -u "$hosts" -o "$hosts" 2>/dev/null || true
        _subs_cached=1
        ok "[$domain] subdomains from DB cache ($(printf '%s\n' "$_cs" | grep -c '^') host(s)); skipping passive enum."
      fi
    fi
    if [ "$_subs_cached" = "0" ]; then
    local frontier="$raw/frontier.txt" rnew="$raw/round_new.txt" round=1 fh
    printf '%s\n' "$domain" > "$frontier"
    while [ "$round" -le "$ROUNDS" ] && [ -s "$frontier" ]; do
      : > "$rnew"
      if have subfinder; then
        _to "$PASSIVE_TIMEOUT" subfinder -dL "$frontier" -all -silent 2>/dev/null | scope_filter "$domain" \
          | tee -a "$raw/host_subfinder.txt" >> "$rnew" || true
      fi
      if have amass; then
        while IFS= read -r fh; do [ -z "$fh" ] && continue
          _to "$PASSIVE_TIMEOUT" amass enum -passive -d "$fh" 2>/dev/null \
            | grep -oiE "([a-z0-9_-]+\.)+${domain//./\\.}" || true
        done < "$frontier" | scope_filter "$domain" | tee -a "$raw/host_amass.txt" >> "$rnew" || true
      fi
      if have assetfinder; then
        while IFS= read -r fh; do [ -z "$fh" ] && continue
          _to "$PASSIVE_TIMEOUT" assetfinder --subs-only "$fh" 2>/dev/null || true
        done < "$frontier" | scope_filter "$domain" | tee -a "$raw/host_assetfinder.txt" >> "$rnew" || true
      fi
      if have findomain; then
        while IFS= read -r fh; do [ -z "$fh" ] && continue
          _to "$PASSIVE_TIMEOUT" findomain -t "$fh" -q 2>/dev/null || true
        done < "$frontier" | scope_filter "$domain" | tee -a "$raw/host_findomain.txt" >> "$rnew" || true
      fi
      sort -u "$rnew" -o "$rnew" 2>/dev/null || true
      comm -13 <(sort -u "$hosts") <(sort -u "$rnew") > "$frontier" 2>/dev/null || : > "$frontier"
      cat "$frontier" >> "$hosts"; sort -u "$hosts" -o "$hosts"
      round=$((round+1))
    done
    # cache the discovered passive-subdomain union for next time
    if [ "$USE_DB" = "1" ]; then
      cat "$raw"/host_subfinder.txt "$raw"/host_amass.txt "$raw"/host_assetfinder.txt "$raw"/host_findomain.txt 2>/dev/null \
        | sort -u > "$raw/_subs_union.txt" || true
      if [ -s "$raw/_subs_union.txt" ]; then db_cache_put subs "$domain" "$(cat "$raw/_subs_union.txt")"; else db_cache_put "subs!neg" "$domain" 1; fi || true
    fi
    fi
  fi

  # GitHub code mining: subdomains that leak in public repos/gists/CI (needs a
  # token). Passive w.r.t. the target -> runs regardless of --passive-only.
  if [ "$GITHUB" = "1" ] && [ "$_pskip" = "0" ] && have github-subdomains; then
    local _ghs
    _ghs="$(cache_or_run github_subs "$domain" -- _to "$PASSIVE_TIMEOUT" github-subdomains -d "$domain" "${GHTOK[@]}" 2>/dev/null)"
    printf '%s\n' "$_ghs" | grep -oiE "([a-z0-9_-]+\.)+${domain//./\\.}" | scope_filter "$domain" | sort -u \
      > "$raw/host_github.txt" || : > "$raw/host_github.txt"
  fi

  # DNS dictionary bruteforce (shuffledns/puredns + massdns) over the apex
  if [ "$BRUTE" = "1" ]; then
    stage "$domain" "DNS bruteforce (shuffledns/puredns)"; brute_subs "$domain" "$raw/host_brute.txt"
    cat "$raw/host_brute.txt" >> "$hosts" 2>/dev/null || true
    sort -u "$hosts" -o "$hosts"
  fi

  # permutations (alterx) over the discovered set
  if [ "$PERMUTE" = "1" ] && have alterx; then
    local _hc; _hc="$(wc -l < "$hosts" | tr -d ' ')"
    if [ "$_hc" -le "$PERMUTE_MAX" ]; then
      _to "$STAGE_TIMEOUT" alterx -silent < "$hosts" 2>/dev/null | scope_filter "$domain" | sort -u \
        > "$raw/host_alterx.txt" || : > "$raw/host_alterx.txt"
    else
      warn "[$domain] $_hc candidate hosts > --permute-max $PERMUTE_MAX; skipping permutations."
    fi
  fi

  # cert SAN/CN harvest, phase 1: candidate hosts, pre-probe (tlsx)
  if [ "$CERTS" = "1" ] && have tlsx; then
    local _certc=0
    if [ "$USE_DB" = "1" ]; then
      local _cc; _cc="$(db_cache_get certsan "$domain" "$CACHE_TTL" || true)"
      if [ -n "$_cc" ]; then printf '%s\n' "$_cc" > "$raw/host_tlsx.txt"; _certc=1; fi
    fi
    if [ "$_certc" = "0" ]; then
      local tlsxargs=(-l "$hosts" -san -cn -resp-only -silent -timeout 10)
      { [ -n "$RESOLVERS" ] && [ -s "$RESOLVERS" ]; } && tlsxargs+=(-r "$RESOLVERS")
      _to "$STAGE_TIMEOUT" tlsx "${tlsxargs[@]}" 2>>"$raw/tlsx.err" | scope_filter "$domain" | sort -u \
        > "$raw/host_tlsx.txt" || : > "$raw/host_tlsx.txt"
      if [ "$USE_DB" = "1" ]; then
        if [ -s "$raw/host_tlsx.txt" ]; then db_cache_put certsan "$domain" "$(cat "$raw/host_tlsx.txt")"; else db_cache_put "certsan!neg" "$domain" 1; fi || true
      fi
    fi
  fi

  # favicon / internet-scan pivot: uncover returns IP:port, so cert-scan those
  # IPs with tlsx to recover in-scope hostnames. Needs uncover API keys.
  if [ "$FAVICON" = "1" ] && have uncover; then
    local favips="$raw/favicon_ips.txt"; : > "$favips"
    _to "$STAGE_TIMEOUT" uncover -q "ssl:\"$domain\"" -silent 2>/dev/null \
      | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > "$favips" || : > "$favips"
    if [ -s "$favips" ] && have tlsx; then
      local ftl=(-l "$favips" -san -cn -resp-only -silent -timeout 10)
      { [ -n "$RESOLVERS" ] && [ -s "$RESOLVERS" ]; } && ftl+=(-r "$RESOLVERS")
      _to "$STAGE_TIMEOUT" tlsx "${ftl[@]}" 2>/dev/null | scope_filter "$domain" | sort -u \
        > "$raw/host_favicon.txt" || : > "$raw/host_favicon.txt"
    fi
  fi

  # merge newly-discovered candidates, then run the DNS validation gate
  cat "$raw/host_brute.txt" "$raw/host_alterx.txt" "$raw/host_tlsx.txt" "$raw/host_favicon.txt" \
      "$raw/host_github.txt" >> "$hosts" 2>/dev/null || true
  # names harvested by --zone-exposure (AXFR / NSEC walk) at or under this seed
  if [ "$ZONE_EXPOSURE" = "1" ] && [ -s "$WORKDIR/zone_names.txt" ]; then
    awk -F'\t' -v d="$domain" '{ n=$2; if (n == d || (length(n) > length(d) && substr(n, length(n)-length(d)) == "." d)) print n }' \
      "$WORKDIR/zone_names.txt" | sort -u > "$raw/host_zone.txt" || : > "$raw/host_zone.txt"
    [ -s "$raw/host_zone.txt" ] && log "[$domain] zone exposure: $(wc -l < "$raw/host_zone.txt" | tr -d ' ') name(s) from AXFR/NSEC added to the candidates"
    cat "$raw/host_zone.txt" >> "$hosts" 2>/dev/null || true
  fi
  sort -u "$hosts" -o "$hosts"
  # the takeover check needs every candidate, including names that no longer resolve
  # (a dangling CNAME returns NXDOMAIN), so keep the list from before the resolve gate
  [ "$TAKEOVER" = "1" ] && cp "$hosts" "$raw/hosts_all.txt" 2>/dev/null
  local _ncand _nres="-" _nlive="-"
  _ncand="$(grep -c . "$hosts" 2>/dev/null || true)"; _ncand="${_ncand:-0}"
  if [ "$RESOLVE" = "1" ]; then
    stage "$domain" "DNS validation (dnsx resolve gate)"; resolve_hosts "$hosts" "$hosts.validated" "$domain"
    mv "$hosts.validated" "$hosts"
    _nres="$(grep -c . "$hosts" 2>/dev/null || true)"; _nres="${_nres:-0}"
    if [ "$_nres" = "0" ]; then
      warn "[$domain] none of $_ncand candidate name(s) resolved, not even the seed: check the seed and the resolvers"
    fi
  fi

  # resolver flag for httpx calls (bypasses local DNS / Pi-hole when set)
  local rr=(); [ -n "$RESOLVERS" ] && rr=(-r "$RESOLVERS"); [ -n "$PROXY" ] && rr+=(-proxy "$PROXY")

  # --- passive collection (always; no traffic to target) -------------------
  local g="$raw/gau.txt" w="$raw/wb.txt" m="$raw/waymore.txt" k="$raw/katana.txt" fz="$raw/fuzz.txt"
  local uf="$raw/urlfinder.txt" gs="$raw/gospider.txt" hk="$raw/hakrawler.txt" js="$raw/js.txt"
  local ge="$raw/github_ep.txt"
  : > "$g"; : > "$w"; : > "$m"; : > "$k"; : > "$fz"; : > "$uf"; : > "$gs"; : > "$hk"; : > "$js"; : > "$ge"
  local fuzz_label=""

  # crawl cache (optional): if the DB holds a fresh passive-URL set for this
  # domain, reuse it and skip the passive collectors -- this is what avoids
  # re-crawling public archives (Wayback/CommonCrawl/OTX) on repeat runs.
  local _crawl_cached=0
  if [ "$USE_DB" = "1" ]; then
    local _cu; _cu="$(db_cache_get urls "$domain" "$CACHE_TTL" || true)"
    if [ -n "$_cu" ]; then
      printf '%s\n' "$_cu" > "$g"
      _crawl_cached=1
      ok "[$domain] passive URLs from DB cache ($(grep -c '^' "$g" 2>/dev/null || true) urls); skipping crawl."
    fi
  fi

  [ "$_pskip" = "0" ] && stage "$domain" "passive URL collection (gau/wayback/urlfinder$([ "$DEEP" = 1 ] && echo /waymore))"
  if [ "$_crawl_cached" = "0" ] && [ "$_pskip" = "0" ] && have gau; then
    local gauargs=(--threads 5)
    [ "$FILTER_STATIC" = "1" ] && gauargs+=(--blacklist "$STATIC_EXT")
    if [ "$DO_SUBS" = "1" ]; then
      # subdomains already in $hosts; query each host without --subs
      cat "$hosts" | _to "$PASSIVE_TIMEOUT" gau "${gauargs[@]}" 2>/dev/null >> "$g" || true
    else
      # let gau pull subdomains for the single seed
      printf '%s\n' "$domain" | _to "$PASSIVE_TIMEOUT" gau --subs "${gauargs[@]}" 2>/dev/null >> "$g" || true
    fi
  fi

  # urlfinder: PD's passive URL collector (gau-like); run alongside gau if present
  if [ "$_crawl_cached" = "0" ] && [ "$_pskip" = "0" ] && have urlfinder; then
    _to "$PASSIVE_TIMEOUT" urlfinder -d "$domain" -silent 2>/dev/null >> "$uf" || true
  fi

  # GitHub endpoint mining: URLs that leak in public code (needs a token).
  # Writes to -o file (default is <domain>.txt); read that back. Cached per domain.
  if [ "$GITHUB" = "1" ] && [ "$_pskip" = "0" ] && have github-endpoints; then
    local _ghe=""
    [ "$USE_DB" = "1" ] && _ghe="$(db_cache_get github_ep "$domain" "$CACHE_TTL" || true)"
    if [ -n "$_ghe" ]; then
      printf '%s\n' "$_ghe" >> "$ge"
    elif { [ "$USE_DB" != "1" ] || ! db_cache_get "github_ep!neg" "$domain" "$NEG_TTL" >/dev/null 2>&1; } && ! cb_open github-endpoints; then
      local _erc=0
      _to "$PASSIVE_TIMEOUT" github-endpoints -d "$domain" "${GHTOK[@]}" -o "$ge.raw" 2>/dev/null && _erc=0 || _erc=$?
      [ "$_erc" -eq 124 ] && cb_fail github-endpoints
      [ -f "$ge.raw" ] && cat "$ge.raw" >> "$ge" 2>/dev/null || true
      rm -f "$ge.raw"
      if [ "$USE_DB" = "1" ]; then
        if [ -s "$ge" ]; then db_cache_put github_ep "$domain" "$(cat "$ge")"; else db_cache_put "github_ep!neg" "$domain" 1; fi || true
      fi
    fi
  fi

  if [ "$_crawl_cached" = "0" ] && [ "$_pskip" = "0" ] && have waybackurls; then
    cat "$hosts" | _to "$PASSIVE_TIMEOUT" waybackurls 2>/dev/null >> "$w" || true
  fi

  if [ "$_crawl_cached" = "0" ] && [ "$_pskip" = "0" ] && [ "$DEEP" = "1" ] && have waymore; then
    _to "$PASSIVE_TIMEOUT" waymore -i "$domain" -mode U -oU "$m" 2>/dev/null || true
  fi

  # populate the crawl cache with this run's passive-URL union for next time
  if [ "$USE_DB" = "1" ] && [ "$_crawl_cached" = "0" ]; then
    local _cunion="$raw/_crawl_union.txt"
    cat "$g" "$w" "$m" "$uf" 2>/dev/null | sort -u > "$_cunion" || true
    [ -s "$_cunion" ] && db_cache_put urls "$domain" "$(cat "$_cunion")" || true
  fi

  # --- active: live-host probe, then ports / crawl / js / fuzz / cert-loop --
  # (skipped under --passive-only; $live is the probed live-host URL set)
  if [ "$PASSIVE_ONLY" != "1" ]; then
    local live="$raw/live_hosts.txt" probe_in="$hosts"
    : > "$live"

    # port discovery (naabu): host:port list becomes the httpx probe input,
    # so web apps on non-standard ports are not missed.
    if [ "$PORTS" = "1" ] && have naabu; then
      stage "$domain" "port discovery (naabu)"
      local naabuports="$raw/naabu.txt"; : > "$naabuports"
      local _nphit="$raw/naabu_hit.txt" _npmiss="$raw/naabu_miss.txt"
      cache_split naabu_ports "$hosts" "$_nphit" "$_npmiss"   # reuse cached host:port
      cat "$_nphit" >> "$naabuports" 2>/dev/null || true
      if [ -s "$_npmiss" ]; then
        local nargs=(-list "$_npmiss" -silent -rate "$RATE")
        if [ -n "$PORT_SPEC" ]; then nargs+=(-p "$PORT_SPEC")
        else nargs+=(-p "80,443,3000,5000,7001,8000,8008,8080,8081,8181,8443,8888,9000,9200,9443"); fi
        local _npfresh="$raw/naabu_fresh.txt" _nprc=0
        _to "$STAGE_TIMEOUT" naabu "${nargs[@]}" 2>/dev/null > "$_npfresh" || _nprc=$?
        cat "$_npfresh" >> "$naabuports" 2>/dev/null || true
        [ "$_nprc" -eq 0 ] && cache_store naabu_ports "$_npmiss" "$_npfresh" hostport
      fi
      sort -u "$naabuports" -o "$naabuports" 2>/dev/null || true
      [ -s "$naabuports" ] && probe_in="$naabuports"
    fi

    stage "$domain" "live-host probe (httpx)"
    if have "$HTTPX_BIN"; then
      local _lphit="$raw/live_hit.txt" _lpmiss="$raw/live_miss.txt"
      cache_split live_probe "$probe_in" "$_lphit" "$_lpmiss"   # reuse cached live URLs
      cat "$_lphit" >> "$live" 2>/dev/null || true
      if [ -s "$_lpmiss" ]; then
        local _lpfresh="$raw/live_fresh.txt" _lprc=0
        cat "$_lpmiss" | _to "$STAGE_TIMEOUT" "$HTTPX_BIN" -silent -rl "$RATE" -timeout 10 -retries "$HTTP_RETRIES" "${rr[@]}" 2>>"$raw/httpx.err" > "$_lpfresh" || _lprc=$?
        # late retry for the scheme: httpx tries HTTPS first and falls back to HTTP, so a
        # host that came back as http://host either serves HTTP only or failed its HTTPS
        # attempts in a load spike (the farm at -t 10 lost a host's TLS posture this way).
        # Those get one more HTTPS-only try after a pause; a success replaces http://host.
        # Hosts that answered on HTTPS are untouched, so a healthy run pays nothing; a
        # truly HTTP-only host costs one pause and one HTTPS attempt (no retries).
        if [ "$LATE_RETRY" = "1" ] && [ "$_lprc" -eq 0 ] && grep -qE '^http://[^/:]+/?$' "$_lpfresh" 2>/dev/null; then
          local _lphttp="$raw/live_http_only.txt" _lpre="$raw/live_https_retry.txt"
          sed -nE 's#^http://([^/:]+)/?$#https://\1#p' "$_lpfresh" | sort -u > "$_lphttp"
          log "[$domain] live probe: $(wc -l < "$_lphttp" | tr -d ' ') host(s) answered on HTTP only; one more HTTPS try after a pause"
          late_pause
          _to "$STAGE_TIMEOUT" "$HTTPX_BIN" -silent -rl "$RATE" -timeout 10 -retries 0 -nfs "${rr[@]}" < "$_lphttp" 2>>"$raw/httpx.err" > "$_lpre" || true
          if [ -s "$_lpre" ]; then
            awk 'NR == FNR { h = $0; sub(/^https:\/\//, "", h); sub(/[\/:].*$/, "", h); ok[tolower(h)] = 1; print; next }
                 { u = $0; h = u; sub(/^http:\/\//, "", h); sub(/\/$/, "", h)
                   if (u ~ /^http:\/\/[^\/:]+\/?$/ && (tolower(h) in ok)) next; print }' \
              "$_lpre" "$_lpfresh" > "$_lpfresh.new" && mv "$_lpfresh.new" "$_lpfresh"
          fi
        fi
        cat "$_lpfresh" >> "$live" 2>/dev/null || true
        [ "$_lprc" -eq 0 ] && cache_store live_probe "$_lpmiss" "$_lpfresh" urlauthority
      fi
    else
      sed 's#^#https://#' "$probe_in" > "$live"
    fi

    # bare-host view of the live set (for tools that want host, not URL)
    local livehosts="$raw/live_bare.txt"
    sed -E 's#^[a-z]+://##; s#/.*$##' "$live" 2>/dev/null | sort -u > "$livehosts" || : > "$livehosts"
    _nlive="$(grep -c . "$livehosts" 2>/dev/null || true)"; _nlive="${_nlive:-0}"
    if [ "$_nlive" = "0" ] && [ -s "$probe_in" ]; then
      warn "[$domain] no live web host: $(grep -c . "$probe_in") name(s) probed, none answered over HTTP(S)"
    fi

    # crawl (katana) -- cached per live host
    if have katana && [ -s "$live" ]; then
      stage "$domain" "crawl (katana, depth $DEPTH)"
      local _khosts="$raw/kat_hosts.txt" _khit="$raw/kat_hit.txt" _kmiss="$raw/kat_miss.txt" _kmissurls="$raw/kat_missurls.txt"
      sed -E 's#^[a-z]+://##; s#[/:].*$##' "$live" 2>/dev/null | sort -u > "$_khosts" || : > "$_khosts"
      cache_split katana "$_khosts" "$_khit" "$_kmiss"   # reuse cached crawl per host
      cat "$_khit" >> "$k" 2>/dev/null || true
      if [ -s "$_kmiss" ]; then
        # live URLs whose host is a cache miss (run katana on just those)
        awk 'NR==FNR{m[$0]=1;next}{h=$0;sub(/^[a-z]+:\/\//,"",h);sub(/[/:].*$/,"",h);if(h in m)print}' \
          "$_kmiss" "$live" > "$_kmissurls" 2>/dev/null || : > "$_kmissurls"
        if [ -s "$_kmissurls" ]; then
          local katargs=(-list "$_kmissurls" -d "$DEPTH" -silent -jc -kf all -fs rdn -rl "$RATE" -timeout 10)
          # same resolvers as httpx/dnsx/tlsx: without -r katana used the system
          # resolver, so with --resolvers (e.g. a Pi-hole bypass, or a lab DNS) the
          # crawl silently found nothing for names only those resolvers know
          [ -n "$RESOLVERS" ] && [ -s "$RESOLVERS" ] && katargs+=(-r "$RESOLVERS")
          [ -n "$PROXY" ] && katargs+=(-proxy "$PROXY")
          [ "$FILTER_STATIC" = "1" ] && katargs+=(-ef "$STATIC_EXT")
          local _kfresh="$raw/kat_fresh.txt" _krc=0
          _to "$STAGE_TIMEOUT" katana "${katargs[@]}" 2>/dev/null > "$_kfresh" || _krc=$?
          cat "$_kfresh" >> "$k" 2>/dev/null || true
          [ "$_krc" -eq 0 ] && cache_store katana "$_kmiss" "$_kfresh" urlhost
        fi
      fi
    fi

    # extra crawlers (gospider + hakrawler) for wider coverage
    if [ "$CRAWLERS_ALL" = "1" ] && [ -s "$live" ]; then
      stage "$domain" "extra crawlers (gospider/hakrawler)"
      have gospider  && { _to "$STAGE_TIMEOUT" gospider -S "$live" -q -d "$DEPTH" -t "$FUZZ_THREADS" 2>/dev/null | grep -oE 'https?://[^ ]+' >> "$gs" || true; }
      have hakrawler && { cat "$live" | _to "$STAGE_TIMEOUT" hakrawler -d "$DEPTH" 2>/dev/null >> "$hk" || true; }
    fi

    # JS endpoint mining (subjs/getJS pull JS URLs -> xnLinkFinder extracts endpoints)
    if [ "$JS" = "1" ] && [ -s "$live" ]; then
      stage "$domain" "JS endpoint mining (subjs/getJS/xnLinkFinder)"
      local jsfiles="$raw/jsfiles.txt"; : > "$jsfiles"
      have subjs && { cat "$live" | _to "$STAGE_TIMEOUT" subjs 2>/dev/null >> "$jsfiles" || true; }
      have getJS && { _to "$STAGE_TIMEOUT" getJS --input "$live" --complete 2>/dev/null >> "$jsfiles" || true; }
      sort -u "$jsfiles" -o "$jsfiles" 2>/dev/null || true
      if [ -s "$jsfiles" ]; then
        have xnLinkFinder && { _to "$STAGE_TIMEOUT" xnLinkFinder -i "$jsfiles" -sf "$domain" -o cli 2>/dev/null | grep -oE 'https?://[^ ]+' >> "$js" || true; }
        cat "$jsfiles" >> "$js" || true   # the JS file URLs are themselves assets
      fi
    fi

    # content-discovery fuzzing (feroxbuster preferred; ffuf fallback)
    if [ "$FUZZ" = "1" ] && [ -s "$live" ]; then
      stage "$domain" "content discovery (--fuzz)"
      if have feroxbuster; then
        fuzz_label="feroxbuster"
        # --silent => print only discovered URLs; -C 404 filters not-found; -k allows self-signed;
        # --time-limit caps feroxbuster's own (recursive) runtime as a second belt to _to.
        local fxargs=(--stdin -w "$WORDLIST" --silent -t "$FUZZ_THREADS" \
                      --rate-limit "$RATE" --timeout 10 --depth 2 -k -C 404)
        [ "$FUZZ_TIMEOUT" -gt 0 ] 2>/dev/null && fxargs+=(--time-limit "${FUZZ_TIMEOUT}s")
        [ -n "$FUZZ_EXT" ] && fxargs+=(-x "$FUZZ_EXT")
        cat "$live" | _to "$FUZZ_TIMEOUT" feroxbuster "${fxargs[@]}" 2>/dev/null >> "$fz" || true
      elif have ffuf; then
        fuzz_label="ffuf"
        # ffuf has no multi-target stdin mode; loop live hosts and rebuild full URLs
        local base ffext=""
        [ -n "$FUZZ_EXT" ] && ffext=".$(printf '%s' "$FUZZ_EXT" | sed 's/,/,./g')"
        while IFS= read -r base; do
          [ -z "$base" ] && continue
          # shellcheck disable=SC2054  # 200,204,... is one comma-separated value for ffuf -mc, not array separators
          local ffargs=(-u "${base%/}/FUZZ" -w "$WORDLIST" \
                        -mc 200,204,301,302,307,308,401,403,405 \
                        -t "$FUZZ_THREADS" -rate "$RATE" -timeout 10 -s)
          [ -n "$ffext" ] && ffargs+=(-e "$ffext")
          _to "$FUZZ_TIMEOUT" ffuf "${ffargs[@]}" 2>/dev/null | awk -v b="${base%/}/" 'NF{print b $0}' >> "$fz" || true
        done < "$live"
      fi
    fi

    # virtual-host bruteforce (ffuf Host header) -> new candidate hosts
    if [ "$VHOST" = "1" ] && [ -s "$live" ] && have ffuf && [ -f "$BRUTE_WORDLIST" ]; then
      local vtarget; vtarget="$(head -n1 "$live")"
      _to "$FUZZ_TIMEOUT" ffuf -u "$vtarget" -H "Host: FUZZ.$domain" -w "$BRUTE_WORDLIST" -ac -s \
           -mc 200,204,301,302,307,401,403 -t "$FUZZ_THREADS" -rate "$RATE" 2>/dev/null \
        | awk -v d="$domain" 'NF{print $0"."d}' | scope_filter "$domain" | sort -u \
        > "$raw/host_vhost.txt" || : > "$raw/host_vhost.txt"
    fi

    # cert feedback loop (phase 2): grab certs off the LIVE hosts, harvest new
    # sibling SAN/CN names, resolve, feed them in as discovered host rows.
    if [ "$CERTS" = "1" ] && have tlsx && [ -s "$livehosts" ]; then
      local tl2=(-l "$livehosts" -san -cn -resp-only -silent -timeout 10)
      { [ -n "$RESOLVERS" ] && [ -s "$RESOLVERS" ]; } && tl2+=(-r "$RESOLVERS")
      _to "$STAGE_TIMEOUT" tlsx "${tl2[@]}" 2>>"$raw/tlsx.err" | scope_filter "$domain" | sort -u > "$raw/tlsxlive.raw" || : > "$raw/tlsxlive.raw"
      comm -13 <(sort -u "$hosts") <(sort -u "$raw/tlsxlive.raw") > "$raw/tlsxlive.new" 2>/dev/null || : > "$raw/tlsxlive.new"
      if [ "$RESOLVE" = "1" ] && [ -s "$raw/tlsxlive.new" ]; then
        resolve_hosts "$raw/tlsxlive.new" "$raw/host_tlsxlive.txt" "$domain"
      else
        cp "$raw/tlsxlive.new" "$raw/host_tlsxlive.txt" 2>/dev/null || : > "$raw/host_tlsxlive.txt"
      fi
      rm -f "$raw/tlsxlive.raw" "$raw/tlsxlive.new"
    fi
  fi

  # per-seed counts for <out>.run.json (candidates, after the resolve gate, live)
  printf '%s\t%s\t%s\t%s\n' "$domain" "$_ncand" "$_nres" "$_nlive" > "$WORKDIR/parts/seedstat.$safe.tsv" 2>/dev/null || true

  # --- post-probe analysis (side artifacts; not part of the URL CSV) --------
  analyze_hosts "$domain" "$raw"

  # --- active CMS/app-layer scanning (opt-in, --active) --------------------
  cms_scan "$domain" "$raw"

  # --- thorough active scan: SecLists content discovery + nuclei (--activescan)
  activescan "$domain" "$raw"

  # --- passive OSINT enrichment (third-party lookups; --osint/--virustotal/--urlscan)
  osint_scan "$domain" "$raw"

  # --- cloud bucket enumeration (S3/Azure/GCP) -----------------------------
  # A different asset class (storage, not URLs); queries cloud providers, not the
  # target, so it runs regardless of --passive-only. Findings -> side artifact.
  if [ "$BUCKETS" = "1" ] && have cloud_enum; then stage "$domain" "cloud bucket enum (cloud_enum)";
    local kw; kw="$(printf '%s' "$domain" | sed 's/\.[^.]*$//')"   # base label (strip TLD)
    cache_or_run cloud_enum "$domain" -- _to "$STAGE_TIMEOUT" cloud_enum -k "$domain" -k "$kw" -t 20 2>/dev/null \
      | grep -aiE 'OPEN [A-Z]|protected [A-Z]|FOUND ' \
      | sed "s#^#[$domain] #" >> "$WORKDIR/parts/buckets.$safe.txt" || true
  fi

  # --- normalize + scope-filter each source, then merge w/ source labels ---
  prep_file "$g"  "$raw/gau.s.txt"  "$domain"
  prep_file "$w"  "$raw/wb.s.txt"   "$domain"
  prep_file "$m"  "$raw/wm.s.txt"   "$domain"
  prep_file "$k"  "$raw/kat.s.txt"  "$domain"
  prep_file "$fz" "$raw/fuzz.s.txt" "$domain"
  prep_file "$uf" "$raw/uf.s.txt"   "$domain"
  prep_file "$gs" "$raw/gs.s.txt"   "$domain"
  prep_file "$hk" "$raw/hk.s.txt"   "$domain"
  prep_file "$js" "$raw/js.s.txt"   "$domain"
  prep_file "$ge" "$raw/ge.s.txt"   "$domain"

  local combined="$raw/combined.tsv"
  : > "$combined"
  local pair f s
  for pair in "$raw/gau.s.txt:gau" "$raw/wb.s.txt:wayback" "$raw/wm.s.txt:waymore" \
              "$raw/kat.s.txt:katana" "$raw/uf.s.txt:urlfinder" \
              "$raw/gs.s.txt:gospider" "$raw/hk.s.txt:hakrawler" "$raw/js.s.txt:js" \
              "$raw/ge.s.txt:github"; do
    f="${pair%%:*}"; s="${pair##*:}"
    [ -s "$f" ] && awk -v s="$s" '{print $0"\t"s}' "$f" >> "$combined"
  done
  # fuzz hits carry the actual tool that produced them (feroxbuster or ffuf)
  if [ -n "$fuzz_label" ] && [ -s "$raw/fuzz.s.txt" ]; then
    awk -v s="$fuzz_label" '{print $0"\t"s}' "$raw/fuzz.s.txt" >> "$combined"
  fi

  # emit discovered hosts as https://host seed rows so newly-found hosts appear
  # even with no archived/crawled URLs, each attributed to its discovery stage.
  # Group 1: pre-probe sources -> keep only those that survived the resolve gate
  # (intersect with final $hosts). Group 2: post-probe sources (cert feedback
  # loop, vhost) are already final -> emit directly. Empty files are skipped, so
  # with no discovery flags nothing is emitted (default behavior unchanged).
  local hpair hf hs
  for hpair in "$raw/host_subfinder.txt:subfinder" "$raw/host_amass.txt:amass" \
               "$raw/host_assetfinder.txt:assetfinder" "$raw/host_findomain.txt:findomain" \
               "$raw/host_github.txt:github" "$raw/host_brute.txt:bruteforce" \
               "$raw/host_alterx.txt:alterx" "$raw/host_tlsx.txt:tlsx" \
               "$raw/host_favicon.txt:favicon"; do
    hf="${hpair%%:*}"; hs="${hpair##*:}"
    [ -s "$hf" ] || continue
    comm -12 <(sort -u "$hf") <(sort -u "$hosts") 2>/dev/null \
      | grep -vxF "$domain" | sed 's#^#https://#' \
      | awk -v s="$hs" 'NF{print $0"\t"s}' >> "$combined" || true
  done
  for hpair in "$raw/host_tlsxlive.txt:tlsx-live" "$raw/host_vhost.txt:vhost"; do
    hf="${hpair%%:*}"; hs="${hpair##*:}"
    [ -s "$hf" ] || continue
    grep -vxF "$domain" "$hf" 2>/dev/null | sed 's#^#https://#' \
      | awk -v s="$hs" 'NF{print $0"\t"s}' >> "$combined" || true
  done

  # A host the live probe proved up must be in the inventory even when no archive
  # or crawl URL came back for it. katana normally echoes its seed URL, which hid
  # this -- but with katana missing, failed or timed out (or passive sources
  # skipped), live hosts produced ZERO rows. Fallback only: a live URL is added
  # (source "live") just for hosts that have no row from any other source, so the
  # output is unchanged whenever the crawl did its job.
  if [ -s "$raw/live_hosts.txt" ]; then
    awk -F'\t' '
      function hostof(u,  h) { h=u; sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", h); sub(/[\/:?#].*$/, "", h); return tolower(h) }
      FILENAME == ARGV[1] { if (NF) have[hostof($1)]=1; next }   # (NR==FNR breaks when file 1 is empty)
      NF { h=hostof($1); if (h != "" && !(h in have)) { print $1"\tlive"; have[h]=1 } }
    ' "$combined" "$raw/live_hosts.txt" > "$raw/live_fallback.tsv" 2>/dev/null || : > "$raw/live_fallback.tsv"
    cat "$raw/live_fallback.tsv" >> "$combined" 2>/dev/null || true
  fi

  # aggregate: url -> ;-joined source set (preserve first-seen order)
  local mapurls="$raw/map_urls.tsv"
  awk -F'\t' '
    { u=$1
      if (!(u in seen)) { order[++n]=u; seen[u]=1 }
      if (index(";"srcs[u]";", ";"$2";")==0) srcs[u]=(srcs[u]==""?$2:srcs[u]";"$2)
    }
    END { for (i=1;i<=n;i++){ u=order[i]; print u"\t"srcs[u] } }
  ' "$combined" > "$mapurls"

  # emit seed<TAB>url<TAB>sources for the aggregator
  awk -v d="$domain" -F'\t' '{print d"\t"$1"\t"$2}' "$mapurls" > "$WORKDIR/parts/map.$safe.tsv"

  # --- per-URL validation/enrichment (skipped in passive-only / no-validate)
  if [ "$PASSIVE_ONLY" != "1" ] && [ "$NO_VALIDATE" != "1" ] && have "$HTTPX_BIN"; then
    local total capped
    total="$(wc -l < "$mapurls" | tr -d ' ')"
    capped="$total"
    if [ "$total" -gt "$MAX_URLS" ]; then
      capped="$MAX_URLS"
      warn "[$domain] $total URLs found; validating first $MAX_URLS (raise with --max-urls)"
    fi
    stage "$domain" "per-URL enrichment (httpx -json, $capped URLs)"
    local _hxout="$WORKDIR/parts/httpx.$safe.jsonl"; : > "$_hxout"
    local _enrkeys="$raw/enrich_keys.txt" _enrhit="$raw/enrich_hit.jsonl" _enrmiss="$raw/enrich_miss.txt"
    cut -f1 "$mapurls" | head -n "$capped" > "$_enrkeys"
    cache_split httpx_json "$_enrkeys" "$_enrhit" "$_enrmiss"   # reuse cached per-URL JSON
    cat "$_enrhit" >> "$_hxout" 2>/dev/null || true
    if [ -s "$_enrmiss" ]; then
      local _enrfresh="$raw/enrich_fresh.jsonl" _enrrc=0
      # -retries: one attempt per URL meant a single transient connection drop
      # ("use of closed network connection") silently blanked that row; measured
      # in the lab at 10/100 requests under concurrency without retries, 0/100
      # with 2. Retries only fire on failure, so healthy targets see no extra load.
      # -nfs (-no-fallback-scheme): probe each URL with ITS OWN scheme. Without it
      # httpx tries HTTPS first even for an http:// input, so http:// rows were
      # silently enriched with the HTTPS response (wrong status/title for plain-HTTP
      # services, redirects, or hosts that serve different content per scheme).
      cat "$_enrmiss" \
        | _to "$STAGE_TIMEOUT" "$HTTPX_BIN" -silent -json -status-code -content-length -title -tech-detect -web-server \
                -nfs -timeout 10 -retries "$HTTP_RETRIES" -rl "$RATE" "${rr[@]}" 2>>"$raw/httpx.err" > "$_enrfresh" || _enrrc=$?
      # late retry: httpx's own retries fire back to back, so a URL that failed
      # during a load spike usually fails all of them (the farm at -t 20 on 2 vCPU
      # blanked 1-3 hosts per run). URLs with no record get one more pass after a
      # pause, at a gentler pace. Healthy runs have no such URLs, so it costs nothing.
      if [ "$LATE_RETRY" = "1" ] && [ "$_enrrc" -eq 0 ]; then
        local _enrlate="$raw/enrich_late.txt"
        missing_keys httpxjson "$_enrmiss" "$_enrfresh" > "$_enrlate"
        if [ -s "$_enrlate" ]; then
          log "[$domain] enrichment: $(wc -l < "$_enrlate" | tr -d ' ') URL(s) got no response; retrying once after a pause"
          late_pause
          cat "$_enrlate" \
            | _to "$STAGE_TIMEOUT" "$HTTPX_BIN" -silent -json -status-code -content-length -title -tech-detect -web-server \
                    -nfs -timeout 10 -retries "$HTTP_RETRIES" -t 5 -rl "$RATE" "${rr[@]}" 2>>"$raw/httpx.err" >> "$_enrfresh" || true
        fi
      fi
      cat "$_enrfresh" >> "$_hxout" 2>/dev/null || true
      # cache each fresh record by its input URL. No negative entries: these URLs
      # belong to hosts the live probe just confirmed, so a missing record is a
      # failed request, not an absent page (see cache_store).
      [ "$_enrrc" -eq 0 ] && cache_store httpx_json "$_enrmiss" "$_enrfresh" httpxjson noneg
    fi
    # surface a clear hint if nothing (cached or fresh) came back at all
    if [ ! -s "$_hxout" ] && [ -s "$mapurls" ]; then
      warn "[$domain] httpx returned 0 records; enrichment columns will be empty."
      warn "[$domain] check $raw/httpx.err (use --keep-work) and verify 'httpx' is ProjectDiscovery's."
    fi
  fi

  local _wend _wel; _wend=$(date +%s 2>/dev/null || echo 0); _wel=$(( _wend - ${WORKER_START:-_wend} ))
  mkdir -p "$WORKDIR/done" 2>/dev/null; : > "$WORKDIR/done/$safe" 2>/dev/null || true
  ok "[$domain] done ($(wc -l < "$mapurls" | tr -d ' ') urls, $(fmt_hms $_wel))"
}

# ===========================================================================
# Optional DB library: source recon-db.sh (if present) BEFORE the worker
# dispatch so both the parent and each re-invoked worker have db_* functions.
# Sourcing is unconditional (functions are inert unless USE_DB=1); --db gates
# the actual calls. Workers inherit USE_DB and the PG* connection env.
# ===========================================================================
RECON_DB_LIB_LOADED=0
_dblib="$RECON_DIR/recon-db.sh"
[ -f "$_dblib" ] || _dblib="$(command -v recon-db.sh 2>/dev/null || true)"
if [ -n "$_dblib" ] && [ -f "$_dblib" ]; then
  # shellcheck disable=SC1090
  . "$_dblib" 2>/dev/null && RECON_DB_LIB_LOADED=1 || RECON_DB_LIB_LOADED=0
fi

# ===========================================================================
# Worker dispatch: re-invocation of self for a single domain (used by xargs).
# Must appear AFTER function definitions; relies on env vars exported by parent.
# ===========================================================================
if [ "${1:-}" = "--__worker" ]; then
  process_one "$2"
  exit $?
fi

# ===========================================================================
# Main
# ===========================================================================
usage() {
  cat >&2 <<EOF
run-recon.sh v$VERSION  --  map seed domains to discovered URLs (CSV)

USAGE:
  ./run-recon.sh -i domains.txt [-o results.csv] [options]

REQUIRED:
  -i, --input FILE        Text file with one domain per line (# comments ok)

OUTPUT:
  -o, --output FILE       CSV output path (default: <out-dir>/recon-<timestamp>.csv)
  -D, --out-dir DIR       Working/output directory (default: ./recon-output)

TUNING:
  -t, --threads N         Parallel seed domains            (default: $THREADS)
      --crawl-depth N     katana crawl depth               (default: $DEPTH)
      --rate N            Requests/sec where supported      (default: $RATE)
      --max-urls N        Max URLs validated per domain     (default: $MAX_URLS)

MODES:
      --passive-only      No katana, no httpx. Zero traffic to targets; may be stale.
      --no-validate       Crawl but skip final per-URL httpx enrichment.
      --subs              Enumerate subdomains (subfinder) before URL collection.
      --deep              Also run waymore (slower, broader passive coverage).

DISCOVERY (host expansion; active techniques -- assets you are authorized to assess):
      --resolve           DNS validation gate: keep only hosts that resolve (dnsx),
                          and route dnsx/tlsx/httpx via dedicated resolvers.
      --certs             Harvest sibling hostnames from TLS certs (tlsx SAN/CN),
                          two-phase: candidate hosts pre-probe + live hosts post-probe.
      --permute           Permute discovered subdomains (alterx); implies --resolve.
      --permute-max N     Skip permutations above N candidate hosts   (default: $PERMUTE_MAX).
      --brute             DNS dictionary bruteforce (shuffledns/puredns + massdns).
      --brute-wordlist F  Subdomain wordlist for --brute/--vhost (default: SecLists top-110k).
      --ports             Port discovery (naabu) before httpx -> catch non-standard web ports.
      --port-spec SPEC    naabu ports (default: web-ports preset; e.g. top-1000 or 80,443,8080).
  -p  SPEC                Alias for --port-spec.
      --rounds N          Recursive host-discovery rounds; re-enumerate new subs (default: $ROUNDS).
      --favicon           Favicon / internet-scan pivot (uncover; needs Shodan/Censys API keys).
      --resolvers FILE    Custom resolver list (else a built-in dedicated set is used;
                          both bypass a local Pi-hole and its rate limits). Resolvers are
                          health-checked at startup; a dead set is warned about, not silently
                          stalled on.
      --refresh-resolvers Regenerate the resolver list with dnsvalidator before running
                          (validates public resolvers; improves --brute/--resolve completeness).

SOURCES+ (extra URL discovery):
      --crawlers-all      Also run gospider + hakrawler (wider crawl than katana alone).
      --js                Mine JS for endpoints (subjs/getJS -> xnLinkFinder). urlfinder auto-runs.
      --github            Mine GitHub for subdomains + endpoints (needs a token). Passive re: target.
      --github-token F    File with GitHub token(s), one per line (else env GITHUB_TOKEN is used).

ANALYSIS / TRIAGE (side artifacts written next to the CSV; not URL rows):
      --zone-exposure     For each seed's DNS zone: try a zone transfer (AXFR) on every
                          authoritative name server and walk the DNSSEC NSEC chain; flag NSEC3.
                          Names found feed the seeds they fall under   -> <out>.zone.txt,
                          <out>.zone-names.txt. Queries only the zones' own name servers.
      --takeover          Subdomain-takeover check: CNAMEs of EVERY candidate name (live or not,
                          dnsx), dangling targets (NXDOMAIN), takeover-prone services; subzy and
                          nuclei -tags takeover fingerprint them -> <out>.takeover.txt, <out>.cname.tsv
      --screenshots       Screenshot live hosts (httpx -ss/gowitness). The browser is routed like httpx
                          (--proxy, NO_PROXY) and every capture is checked (ok/blank/failed/suspect)
                          -> screenshots-<ts>/, <out>.screenshots.tsv
      --origin            Detect the edge (CDN/WAF/reverse proxy) in front of each site and look for
                          its origin: candidates from origin-style names, SPF/MX and --zone-exposure
                          names, each verified by asking it for the site directly (same body hash or
                          title) -> <out>.origin.txt (findings), <out>.edge.tsv (per-host edge, origin
                          software, JARM, CDN, favicon mmh3)
      --tls               TLS posture (tlsx) -> CSV cols: tls_version, tls_cipher, cert_not_after,
                          cert_issuer, tls_flags (CertExpired/CertExpiring/SelfSigned/CertNameMismatch/
                          CertUntrusted/Wildcard). Joined to https rows. CertExpiring: within
                          CERT_WARN_DAYS (30). CertUntrusted: the chain does not verify against the
                          system trust store (TLS_CHAIN_CHECK=0 skips that check).
      --tls-full          ...also enumerate TLS versions + ciphers (adds WeakTLS/WeakCipher; noisier).
      --ipv6              Resolve AAAA records (dnsx) -> ipv6 CSV column.
      --enrich            Per-IP cloud provider (AWS/Azure/GCP/Cloudflare/Oracle/DO IP-range feeds) +
                          RDAP network org -> cloud, rdap_org CSV columns.
      --geodb FILE        MaxMind GeoLite2 .mmdb -> geo column (country ISO). Implies --enrich; needs
                          mmdblookup (libmaxminddb). You supply the DB (MaxMind account/EULA).
      --cpe-map FILE      Extend/override the built-in product->CPE table (TSV: name<TAB>cpe:2.3:a:vendor:product).
                          The cpe column (CPE 2.3, always emitted from tech + Server) feeds the offline vuln join.
      --vhost             Virtual-host bruteforce (ffuf Host header) -> new host rows
      --nuclei            Templated vuln/misconfig scan (nuclei)    -> <out>.nuclei.txt  [off]
      --nuclei-sev LIST   Severities for --nuclei (default: $NUCLEI_SEV).
      --interactsh-server URL
                          Send nuclei's out-of-band callbacks to YOUR interactsh-server
                          (NUCLEI_OAST=self; token via NUCLEI_ITOKEN env). Default: callbacks
                          off (-ni), so nothing goes to ProjectDiscovery's public oast.* servers.
                          NUCLEI_OAST=public opts in to those servers explicitly.
      --params            Parameter discovery (arjun)               -> <out>.params.txt  [off]
      --secrets           Secret scan discovered JS (secretfinder/trufflehog) -> <out>.secrets.txt [off]
      --active            Active CMS/app scan on live hosts (wpscan/droopescan/joomscan/cmseek/
                          whatweb + nuclei tech,cms; native curl/ffuf fallback) -> <out>.cms.txt
      --activescan        Thorough active scan: feroxbuster/ffuf over several SecLists lists + a broad
                          nuclei run -> <out>.activescan.txt  (heavier/louder than --fuzz; in --all)
      --cms-wordlist F    Plugin/theme slug wordlist for the native WP brute (default: SecLists CMS list).
      --buckets           Cloud bucket enum (cloud_enum: S3/Azure/GCP) -> <out>.buckets.txt

    OSINT enrichment (passive third-party lookups on domains/IPs; run even with --passive-only):
      --osint             RDAP registration + Shodan InternetDB (ports/hostnames) + Team Cymru
                          IP-to-ASN (org reveals cloud) -> <out>.osint.txt   [free, no key; in --all]
      --virustotal        VirusTotal domain report: reputation, passive DNS, subdomains
                          -> <out>.virustotal.txt   (needs env VT_API_KEY)
      --urlscan           urlscan.io search: historical page URLs + IPs -> <out>.urlscan.txt
                          (optional env URLSCAN_API_KEY raises rate limits)
      --social            Social-media account discovery for the org brand (tookie-osint)
                          -> <out>.social.txt   (brand from seed domain; override with --social-user)
      --social-user NAME  Username to search with --social (instead of the domain-derived brand).

MONITORING:
      --monitor           Diff discovered URLs against a prior CSV  -> <out>.new-assets.txt
      --monitor-prev F    Prior CSV to diff against (default: newest recon-*.csv in out-dir).
      --notify            Pipe the new-asset list through 'notify' (if configured).

REPORT & CACHE:
      --no-report         Skip the end-of-run HTML report (default: build <out>.report.html,
                          tying hosts, findings, screenshots and references together).
      --db                Use a PostgreSQL cache/store (reuses Kali's Metasploit postgres) to
                          cache passive-crawl URL sets, subdomain-enum results, OSINT/GitHub/
                          wpscan/cloud_enum/cert lookups and per-IP ASN, and to persist each run's
                          host inventory. Falls back to a normal run if unavailable.
                          One-time setup:  sudo ./recon-db.sh init
                          (PostgreSQL is health-checked at startup; if it's down, the run
                          continues uncached rather than stalling.)
      --proxy URL         Route GET-heavy stages through an HTTP(S) proxy (e.g. a caching squid/
                          mitmproxy); sets HTTP(S)_PROXY and httpx -proxy.
      CACHE_TTL=SECONDS   Cache freshness for --db (env; default 604800 = 7 days).
      NEG_TTL=SECONDS     Negative-cache TTL for confirmed-empty lookups (env; default 86400).
      CB_THRESHOLD=N      Circuit breaker: skip a source after N timeouts in a run (env; default 3).
      BRUTE_MAX=N         Cap the --brute wordlist to N entries (env; 0 = no cap).
      HTTP_RETRIES=N      httpx retries per URL on a transient failure, live probe + enrichment
                          (env; default 2; 0 = a single attempt, the pre-1.16 behaviour).
      LATE_RETRY=0        Turn off the one delayed extra pass for URLs/hosts that returned
                          nothing in enrichment or TLS posture (env; default 1).
      RANGE_TLS_PORTS=L   Ports for the ASN/CIDR certificate scan (env; default 443, or the
                          --ports list when --ports is on). ASN seeds need PDCP_API_KEY (asnmap).
      SKIP_SPECIAL_USE=0  Query passive internet sources even for RFC 6761 special-use names
                          (.test/.internal/.local/...). Default 1 skips them: they cannot exist
                          on the internet, so the queries only cost time.

UMBRELLA:
      --all               Enable the full discovery + defensive set: --subs --resolve --certs
                          --permute --brute --ports --js --crawlers-all --takeover
                          --screenshots --origin. (Scanning stages nuclei/params/secrets and
                          favicon/vhost/monitor stay opt-in.)

INPUT MODES:
      Seeds may be domains, or ASN ("AS13335") / CIDR ("192.0.2.0/24") lines. Ranges are
      expanded (asnmap/mapcidr) and cert-scanned (tlsx) into hostnames added to the run.

      --fuzz              Content-discovery brute force on live hosts (feroxbuster, else ffuf).
                          Hits are merged into the CSV with source=feroxbuster (or ffuf).
      --wordlist FILE     Wordlist for --fuzz (default: SecLists raft-medium-directories.txt).
      --fuzz-threads N    Fuzzer concurrency               (default: $FUZZ_THREADS).
      --fuzz-ext LIST     Extra extensions to probe, e.g. php,bak,json (default: none).
      --no-filter-static  Keep image/font/css URLs (default: filtered out).
      --keep-work         Do not delete the intermediate _work tree.
      --no-progress       Suppress stage timers and the progress heartbeat.
      --no-asn            Skip host IP + ASN resolution (leave ip/asn/asn_org columns blank).
      --limits FILE       Load per-source OSINT timeouts/delays from FILE (generate with
                          probe-datasource-limits.sh --recon-osint --emit-config FILE).

    OSINT rate/timeout env vars (per source; seconds). Defaults: timeout=STAGE_TIMEOUT, delay=0.
    Override individually or via --limits:  RDAP_TIMEOUT/RDAP_DELAY, INTERNETDB_TIMEOUT/INTERNETDB_DELAY,
    VT_TIMEOUT/VT_DELAY, URLSCAN_TIMEOUT/URLSCAN_DELAY.

    Wall-clock guards (env vars; per-request -timeout flags don't bound total runtime).
    Set to 0 to disable a cap. Defaults shown:
      STAGE_TIMEOUT=$STAGE_TIMEOUT   probe/crawl/ports/analysis tools
      PASSIVE_TIMEOUT=$PASSIVE_TIMEOUT  each passive source (subfinder/amass/gau/waymore/...)
      BRUTE_TIMEOUT=$BRUTE_TIMEOUT  DNS bruteforce (shuffledns/puredns)
      FUZZ_TIMEOUT=$FUZZ_TIMEOUT  content discovery (feroxbuster/ffuf) per invocation
      SCAN_TIMEOUT=$SCAN_TIMEOUT  nuclei / --activescan template runs
      HEARTBEAT=$HEARTBEAT     seconds between progress heartbeats

  -h, --help              Show this help
      --version           Show version

CSV columns:
  seed_domain, url, host, sources, status_code, content_length, webserver, title, technologies, ip, asn,
  asn_org, tls_version, tls_cipher, cert_not_after, cert_issuer, tls_flags, ipv6, cloud, rdap_org, geo, cpe

Side-artifact files (when the matching flag is set): <out>.takeover.txt, <out>.cname.tsv, <out>.zone.txt,
<out>.zone-names.txt, <out>.origin.txt, <out>.edge.tsv, <out>.screenshots.tsv, screenshots-<ts>/,
<out>.nuclei.txt, <out>.params.txt, <out>.secrets.txt, <out>.buckets.txt, <out>.cms.txt,
<out>.activescan.txt, <out>.osint.txt, <out>.virustotal.txt, <out>.urlscan.txt, <out>.social.txt,
<out>.new-assets.txt. Always: <out>.run.json (version, command line, tool versions, per-seed counts,
warnings, exit status) and <out>.report.html (unless --no-report).

Exit status: 0 finished with results; 2 bad arguments or input; 3 finished with NO results (0 URL rows).
EOF
}

INPUT=""
OUT_DIR="./recon-output"
KEEP_WORK=0
RESOLVERS_FILE=""
RUN_ARGS=("$@"); RUN_T0="$(date +%s 2>/dev/null || echo 0)"; RUN_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
RUN_DNS_CHECK="not run"; RUN_EXIT=0

while [ $# -gt 0 ]; do
  case "$1" in
    -i|--input)        INPUT="${2:?}"; shift 2;;
    -o|--output)       OUTPUT="${2:?}"; shift 2;;
    -D|--out-dir)      OUT_DIR="${2:?}"; shift 2;;
    -t|--threads)      THREADS="${2:?}"; shift 2;;
    --crawl-depth)     DEPTH="${2:?}"; shift 2;;
    --rate)            RATE="${2:?}"; shift 2;;
    --max-urls)        MAX_URLS="${2:?}"; shift 2;;
    --passive-only)    PASSIVE_ONLY=1; shift;;
    --no-validate)     NO_VALIDATE=1; shift;;
    --subs)            DO_SUBS=1; shift;;
    --deep)            DEEP=1; shift;;
    --resolve)         RESOLVE=1; shift;;
    --certs)           CERTS=1; shift;;
    --tls)             TLS_POSTURE=1; shift;;
    --tls-full)        TLS_POSTURE=1; TLS_ENUM=1; shift;;
    --ipv6)            IPV6=1; shift;;
    --enrich)          ENRICH=1; shift;;
    --geodb)           GEO_DB="${2:?}"; ENRICH=1; shift 2;;
    --cpe-map)         CPE_MAP_FILE="${2:?}"; shift 2;;
    --permute)         PERMUTE=1; shift;;
    --permute-max)     PERMUTE_MAX="${2:?}"; shift 2;;
    --resolvers)       RESOLVERS_FILE="${2:?}"; shift 2;;
    --brute)           BRUTE=1; shift;;
    --brute-wordlist)  BRUTE_WORDLIST="${2:?}"; shift 2;;
    --ports)           PORTS=1; shift;;
    --port-spec|-p)    PORT_SPEC="${2:?}"; shift 2;;
    --crawlers-all)    CRAWLERS_ALL=1; shift;;
    --js)              JS=1; shift;;
    --takeover)        TAKEOVER=1; shift;;
    --screenshots)     SCREENSHOTS=1; shift;;
    --origin)          ORIGIN=1; shift;;
    --zone-exposure)   ZONE_EXPOSURE=1; shift;;
    --favicon)         FAVICON=1; shift;;
    --rounds)          ROUNDS="${2:?}"; shift 2;;
    --vhost)           VHOST=1; shift;;
    --nuclei)          NUCLEI=1; shift;;
    --nuclei-sev)      NUCLEI_SEV="${2:?}"; shift 2;;
    --interactsh-server) NUCLEI_ISERVER="${2:?}"; NUCLEI_OAST=self; shift 2;;
    --params)          PARAMS=1; shift;;
    --secrets)         SECRETS=1; shift;;
    --monitor)         MONITOR=1; shift;;
    --monitor-prev)    MONITOR_PREV="${2:?}"; shift 2;;
    --notify)          NOTIFY=1; shift;;
    --github)          GITHUB=1; shift;;
    --github-token)    GITHUB_TOKEN_FILE="${2:?}"; shift 2;;
    --buckets)         BUCKETS=1; shift;;
    --refresh-resolvers) REFRESH_RESOLVERS=1; shift;;
    --active)          ACTIVE=1; shift;;
    --cms-wordlist)    CMS_WORDLIST="${2:?}"; shift 2;;
    --activescan)      ACTIVESCAN=1; shift;;
    --osint)           OSINT=1; shift;;
    --virustotal)      VIRUSTOTAL=1; shift;;
    --urlscan)         URLSCAN=1; shift;;
    --social)          SOCIAL=1; shift;;
    --social-user)     SOCIAL_USER="${2:?}"; SOCIAL=1; shift 2;;
    --all)             DO_SUBS=1; RESOLVE=1; CERTS=1; PERMUTE=1; BRUTE=1; PORTS=1; \
                       JS=1; CRAWLERS_ALL=1; TAKEOVER=1; SCREENSHOTS=1; ORIGIN=1; ACTIVE=1; \
                       ACTIVESCAN=1; OSINT=1; TLS_POSTURE=1; IPV6=1; ENRICH=1; ZONE_EXPOSURE=1; shift;;
    --fuzz)            FUZZ=1; shift;;
    --wordlist)        WORDLIST="${2:?}"; shift 2;;
    --fuzz-threads)    FUZZ_THREADS="${2:?}"; shift 2;;
    --fuzz-ext)        FUZZ_EXT="${2:?}"; shift 2;;
    --no-filter-static) FILTER_STATIC=0; shift;;
    --keep-work)       KEEP_WORK=1; shift;;
    --no-progress)     PROGRESS=0; shift;;
    --no-asn)          ASN=0; shift;;
    --db)              USE_DB=1; shift;;
    --proxy)           PROXY="${2:?}"; shift 2;;
    --no-report)       REPORT=0; shift;;
    --limits)          LIMITS_FILE="${2:?}"; shift 2;;
    -h|--help)         usage; exit 0;;
    --version)         echo "run-recon.sh v$VERSION"; exit 0;;
    *) err "Unknown argument: $1"; usage; exit 2;;
  esac
done

# --- load empirically-derived rate/timeout limits (from probe-datasource-limits.sh) ---
# The file sets *_TIMEOUT/*_DELAY (e.g. VT_TIMEOUT/VT_DELAY) with unconditional
# assignments, so sourcing here overrides the config defaults above.
if [ -n "$LIMITS_FILE" ]; then
  if [ -f "$LIMITS_FILE" ]; then
    # shellcheck disable=SC1090
    . "$LIMITS_FILE" && ok "loaded rate/timeout limits from $LIMITS_FILE"
  else
    warn "--limits file not found: $LIMITS_FILE (using defaults)"
  fi
fi

# --- validate input --------------------------------------------------------
if [ -z "$INPUT" ]; then err "Missing required --input FILE"; usage; exit 2; fi
# run-recon never reads stdin, but several ProjectDiscovery tools do even when given
# -l FILE (tlsx, and mapcidr -aggregate): with stdin an open pipe (CI, ssh without a
# terminal, some schedulers) they wait for input that never comes. Close it once here,
# so every tool started below inherits a closed stdin.
exec < /dev/null
if [ ! -f "$INPUT" ]; then err "Input file not found: $INPUT"; exit 2; fi

# --- dependency check ------------------------------------------------------
if ! have python3; then err "python3 is required (run the PowerShell setup first)"; exit 1; fi
if ! have gau && ! have waybackurls; then
  err "Need at least one passive collector (gau or waybackurls). Run Setup-ReconEnv.ps1."
  exit 1
fi
log "Tool availability:"
for t in gau waybackurls waymore subfinder httpx katana uro anew; do
  case "$t" in
    httpx)
      if have "$HTTPX_BIN"; then ok "  httpx ($HTTPX_BIN)"
      else warn "  httpx ('$HTTPX_BIN' missing - degraded)"; fi ;;
    *)
      if have "$t"; then ok "  $t"; else warn "  $t (missing - degraded)"; fi ;;
  esac
done
# Versions of the four tools whose output run-recon parses, for the run log: the same
# site can parse differently across releases (httpx 1.6 moved the IP to host_ip; dnsx
# 1.3 dropped NXDOMAIN rows from -rcode filters). LAB_VERIFIED lists the versions the
# benchmark lab checked field by field; anything else gets a warning, not a refusal.
LAB_VERIFIED="httpx=1.12.0 katana=1.8.0 tlsx=1.4.0 dnsx=1.3.1"
_tvd="$(mktemp -d 2>/dev/null || echo "/tmp/recon-tv.$$")"; mkdir -p "$_tvd"
_tvtools="httpx katana tlsx dnsx"; [ "$PASSIVE_ONLY" = "1" ] && _tvtools=""   # passive-only runs none of them
for t in $_tvtools; do
  b="$t"; [ "$t" = httpx ] && b="$HTTPX_BIN"
  have "$b" && have timeout || continue
  ( timeout 10 "$b" -version < /dev/null 2>&1 | sed -E 's/\x1B\[[0-9;]*m//g' | grep -i 'version' \
      | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 > "$_tvd/$t" ) &
done
wait
_tvline=""
for t in $_tvtools; do
  [ -s "$_tvd/$t" ] || continue
  v="$(cat "$_tvd/$t")"; _tvline="$_tvline $t $v,"
  want="$(printf '%s\n' $LAB_VERIFIED | sed -n "s/^$t=//p")"
  if [ -n "$want" ] && [ "$v" != "$want" ]; then
    warn "$t $v is not the lab-verified $want: its output format may differ. Re-run bench-run-recon.sh before trusting it."
  fi
done
rm -rf "$_tvd"
[ -n "$_tvline" ] && log "Tool versions:${_tvline%,} (lab-verified: $LAB_VERIFIED)"
if [ "$PASSIVE_ONLY" != "1" ] && ! have "$HTTPX_BIN"; then
  warn "httpx ('$HTTPX_BIN') not found: cannot validate; enrichment columns will be empty."
  warn "Install ProjectDiscovery httpx (Kali: sudo apt install httpx-toolkit), or set HTTPX_BIN=/path/to/httpx."
fi

# --- fuzz preflight --------------------------------------------------------
if [ "$FUZZ" = "1" ]; then
  if [ "$PASSIVE_ONLY" = "1" ]; then
    warn "--fuzz ignored under --passive-only (fuzzing is an active technique)."
    FUZZ=0
  elif ! have feroxbuster && ! have ffuf; then
    warn "--fuzz requested but neither feroxbuster nor ffuf is installed; skipping fuzzing."
    warn "Install them with:  setup-recon-env.sh --include-heavy"
    FUZZ=0
  elif [ ! -f "$WORDLIST" ]; then
    warn "--fuzz wordlist not found: $WORDLIST"
    warn "Install SecLists (setup-recon-env.sh --include-heavy) or pass --wordlist FILE; skipping fuzzing."
    FUZZ=0
  else
    if have feroxbuster; then FUZZER=feroxbuster; else FUZZER=ffuf; fi
    ok "Fuzzing enabled via $FUZZER  (wordlist: $WORDLIST)"
    warn "Content brute-forcing is loud and slow; ensure you are authorized for these hosts."
  fi
fi

# --- host-discovery preflight (dnsx resolve gate / tlsx certs / alterx) -----
if [ "$PASSIVE_ONLY" = "1" ]; then
  [ "$RESOLVE" = "1" ] && warn "--resolve ignored under --passive-only (needs active DNS)."
  [ "$CERTS"   = "1" ] && warn "--certs ignored under --passive-only (tlsx makes live TLS connections)."
  [ "$PERMUTE" = "1" ] && warn "--permute ignored under --passive-only (needs active DNS validation)."
  RESOLVE=0; CERTS=0; PERMUTE=0
fi
if [ "$CERTS" = "1" ] && ! have tlsx; then
  warn "--certs requested but tlsx not found; skipping cert harvesting."
  warn "Install:  go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest   (or: pdtm -i tlsx)"
  CERTS=0
fi
if [ "$PERMUTE" = "1" ] && ! have alterx; then
  warn "--permute requested but alterx not found; skipping permutations."
  warn "Install:  go install github.com/projectdiscovery/alterx/cmd/alterx@latest"
  PERMUTE=0
fi
if [ "$PERMUTE" = "1" ] && ! have dnsx; then
  warn "--permute needs dnsx to validate guesses (else false-positive explosion); skipping permutations."
  PERMUTE=0
fi
if [ "$RESOLVE" = "1" ] && ! have dnsx; then
  warn "--resolve requested but dnsx not found; skipping DNS validation gate."
  warn "Install:  sudo apt install dnsx   (Kali)   or   go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  RESOLVE=0
fi
# permutations are meaningless without resolution -> ensure the gate is on
if [ "$PERMUTE" = "1" ]; then RESOLVE=1; fi
[ "$CERTS"   = "1" ] && ok "Cert harvesting enabled (tlsx SAN/CN + live-host feedback loop)."
[ "$PERMUTE" = "1" ] && ok "Permutations enabled (alterx; skipped above $PERMUTE_MAX candidate hosts)."
[ "$RESOLVE" = "1" ] && ok "DNS validation gate enabled (dnsx)."

# --- v1.4.0 stage preflight (graceful degradation + passive-only gating) ----
if [ "$PASSIVE_ONLY" = "1" ]; then
  for pair in "BRUTE:--brute" "PORTS:--ports" "CRAWLERS_ALL:--crawlers-all" "JS:--js" \
              "TAKEOVER:--takeover" "SCREENSHOTS:--screenshots" "ORIGIN:--origin" \
              "FAVICON:--favicon" "VHOST:--vhost" "NUCLEI:--nuclei" "PARAMS:--params" \
              "SECRETS:--secrets" "ACTIVE:--active" "ACTIVESCAN:--activescan"; do
    v="${pair%%:*}"; flag="${pair##*:}"
    if [ "${!v}" = "1" ]; then warn "$flag ignored under --passive-only (active technique)."; printf -v "$v" '%s' 0; fi
  done
fi
if [ "$BRUTE" = "1" ]; then
  if ! { { have shuffledns && have massdns; } || have puredns; }; then
    warn "--brute needs shuffledns+massdns or puredns; none found; skipping."; BRUTE=0
  elif [ ! -f "$BRUTE_WORDLIST" ]; then
    warn "--brute wordlist not found ($BRUTE_WORDLIST); pass --brute-wordlist FILE; skipping."; BRUTE=0
  else ok "DNS bruteforce enabled ($(basename "$BRUTE_WORDLIST"))."; fi
fi
if [ "$PORTS" = "1" ]; then
  if ! have naabu; then
    warn "--ports needs naabu; skipping port discovery."; warn "Install (Kali): sudo apt install naabu"; PORTS=0
  else ok "Port discovery enabled (naabu${PORT_SPEC:+ -p $PORT_SPEC})."; fi
fi
if [ "$CRAWLERS_ALL" = "1" ] && ! have gospider && ! have hakrawler; then
  warn "--crawlers-all needs gospider or hakrawler; skipping extra crawlers."; CRAWLERS_ALL=0
fi
if [ "$JS" = "1" ] && ! have subjs && ! have getJS; then
  warn "--js needs subjs or getJS; skipping JS mining."; JS=0
fi
if [ "$SECRETS" = "1" ]; then
  if ! have secretfinder && ! have trufflehog; then
    warn "--secrets needs secretfinder or trufflehog; skipping secret scan."; SECRETS=0
  else JS=1; fi   # secret scanning consumes the JS discovered by the --js stage
fi
if [ "$TAKEOVER" = "1" ] && ! have dnsx && ! have subzy; then
  warn "--takeover needs dnsx (CNAME/dangling check) or subzy; skipping takeover detection."; TAKEOVER=0
elif [ "$TAKEOVER" = "1" ] && ! have subzy && ! have nuclei; then
  warn "--takeover: no subzy or nuclei, so only the DNS check runs (dangling CNAMEs); services that"
  warn "  still resolve at the provider are not fingerprinted. Install: go install github.com/PentestPad/subzy@latest"
fi
if [ "$SCREENSHOTS" = "1" ] && ! have "$HTTPX_BIN" && ! have gowitness; then
  warn "--screenshots needs httpx ($HTTPX_BIN) or gowitness; skipping screenshots."; SCREENSHOTS=0
fi
if [ "$ORIGIN" = "1" ] && ! have curl; then
  warn "--origin: curl not found, so candidate origins cannot be verified directly (install curl)."
fi
if [ "$ORIGIN" = "1" ] && ! have tlsx && ! have cdncheck; then
  warn "--origin: no tlsx or cdncheck, so JARM and CDN tags are skipped (edge detection and the origin search still run)."
fi
if [ "$FAVICON" = "1" ] && ! have uncover; then
  warn "--favicon needs uncover; skipping favicon/internet-scan pivot."; FAVICON=0
fi
[ "$FAVICON" = "1" ] && warn "--favicon uses uncover engines (Shodan/Censys/Fofa/etc.); results require API keys."
if [ "$VHOST" = "1" ]; then
  if ! have ffuf; then warn "--vhost needs ffuf; skipping vhost bruteforce."; VHOST=0
  elif [ ! -f "$BRUTE_WORDLIST" ]; then warn "--vhost wordlist not found ($BRUTE_WORDLIST); skipping vhost bruteforce."; VHOST=0
  else ok "Vhost bruteforce enabled (ffuf Host header)."; fi
fi
if [ "$NUCLEI" = "1" ]; then
  if ! have nuclei; then warn "--nuclei needs nuclei; skipping vuln scan."; NUCLEI=0
  else warn "--nuclei enabled: this widens scope from discovery to active vulnerability scanning."; fi
fi
case "$NUCLEI_OAST" in
  off|public) ;;
  self) [ -n "$NUCLEI_ISERVER" ] || { err "NUCLEI_OAST=self needs NUCLEI_ISERVER (or --interactsh-server URL)."; exit 2; }
        case "$NUCLEI_ISERVER" in *[[:space:]]*|-*) err "Invalid --interactsh-server value."; exit 2;; esac ;;
  *) err "NUCLEI_OAST must be off, self or public (got: $NUCLEI_OAST)"; exit 2;;
esac
if [ "$PARAMS" = "1" ] && ! have arjun; then
  warn "--params needs arjun; skipping parameter discovery."; PARAMS=0
fi
case "$ROUNDS" in ''|*[!0-9]*) ROUNDS=1;; esac
[ "$ROUNDS" -lt 1 ] && ROUNDS=1
if [ "$ROUNDS" -gt 1 ] && [ "$DO_SUBS" != "1" ]; then
  warn "--rounds $ROUNDS has no effect without --subs; forcing 1 round."; ROUNDS=1
fi
[ "$ROUNDS" -gt 1 ] && ok "Recursive host discovery: $ROUNDS rounds."
[ "$TAKEOVER"    = "1" ] && ok "Subdomain-takeover check enabled (CNAMEs of all candidates$(have dnsx && echo ' via dnsx')$(have subzy && echo ', subzy')$(have nuclei && echo ', nuclei -tags takeover'))."
[ "$SCREENSHOTS" = "1" ] && ok "Screenshots enabled."
[ "$ORIGIN"      = "1" ] && ok "Edge detection + origin search enabled (verified directly with curl --resolve)."
[ "$JS"          = "1" ] && ok "JS endpoint mining enabled."
[ "$CRAWLERS_ALL" = "1" ] && ok "Extra crawlers enabled (gospider/hakrawler)."
[ "$PARAMS"      = "1" ] && ok "Parameter discovery enabled (arjun)."
[ "$SECRETS"     = "1" ] && ok "Secret scanning enabled (on discovered JS)."

# GitHub mining preflight (passive w.r.t. target; needs a tool + a token)
if [ "$GITHUB" = "1" ]; then
  if ! have github-subdomains && ! have github-endpoints; then
    warn "--github needs github-subdomains/github-endpoints; skipping GitHub mining."
    warn "Install: go install github.com/gwen001/github-subdomains@latest (and github-endpoints)"
    GITHUB=0
  elif [ -n "$GITHUB_TOKEN_FILE" ] && [ ! -f "$GITHUB_TOKEN_FILE" ]; then
    warn "--github-token file not found ($GITHUB_TOKEN_FILE); skipping GitHub mining."; GITHUB=0
  elif [ -z "$GITHUB_TOKEN_FILE" ] && [ -z "${GITHUB_TOKEN:-}" ]; then
    warn "--github needs a token: pass --github-token FILE or export GITHUB_TOKEN; skipping."; GITHUB=0
  else
    ok "GitHub mining enabled (subdomains + endpoints)."
  fi
fi
# Cloud bucket enumeration preflight (queries cloud providers, not the target)
if [ "$BUCKETS" = "1" ]; then
  if ! have cloud_enum; then
    warn "--buckets needs cloud_enum; skipping cloud bucket enumeration."
    warn "Install via setup-recon-env.sh (git-venv: initstring/cloud_enum)."
    BUCKETS=0
  else
    ok "Cloud bucket enumeration enabled (cloud_enum: S3/Azure/GCP)."
  fi
fi
# Active CMS/app-layer scanning preflight (noisy; runs on the native tier regardless)
if [ "$ACTIVE" = "1" ]; then
  cms_tools=""
  for t in whatweb wpscan droopescan joomscan cmseek nuclei; do have "$t" && cms_tools="$cms_tools $t"; done
  if [ -z "$cms_tools" ]; then
    warn "--active: no CMS tools found (whatweb/wpscan/droopescan/joomscan/cmseek/nuclei);"
    warn "          falling back to native curl/ffuf probes only (limited coverage)."
  else
    ok "Active CMS scanning enabled (using:$cms_tools)."
  fi
  ! have whatweb && ! have nuclei && warn "--active: no whatweb/nuclei for fingerprinting; CMS detection will rely on native curl."
  have wpscan && [ -z "$WPSCAN_API_TOKEN" ] && warn "--active: WPScan present but no WPSCAN_API_TOKEN; plugin/version enum works, vuln data is skipped."
  ! have wpscan && [ ! -f "$CMS_WORDLIST" ] && warn "--active: no wpscan and CMS wordlist missing ($CMS_WORDLIST); WP plugin/theme brute will be skipped."
fi
# Thorough active scan preflight (feroxbuster/ffuf over SecLists + nuclei)
if [ "$ACTIVESCAN" = "1" ]; then
  as_have=""; for t in feroxbuster ffuf nuclei; do have "$t" && as_have="$as_have $t"; done
  if [ -z "$as_have" ]; then
    warn "--activescan needs feroxbuster/ffuf and/or nuclei; none found; skipping."
    warn "Install feroxbuster + nuclei via setup-recon-env.sh --include-heavy."
    ACTIVESCAN=0
  else
    as_lists=0; for _w in "${ACTIVESCAN_LISTS[@]}"; do [ -f "$_w" ] && as_lists=$((as_lists+1)); done
    if [ "$as_lists" -eq 0 ] && { have feroxbuster || have ffuf; }; then
      warn "--activescan: no SecLists lists found under $SECLISTS (content discovery will be skipped; nuclei still runs)."
      warn "Install SecLists via setup-recon-env.sh --include-heavy, or set SECLISTS=<path>."
    fi
    ok "Active scan enabled (using:$as_have; $as_lists SecLists list(s))."
  fi
fi
# Passive OSINT preflight (third-party lookups; NOT gated by --passive-only)
if [ "$VIRUSTOTAL" = "1" ] && [ -z "$VT_API_KEY" ]; then
  warn "--virustotal needs VT_API_KEY (export it); skipping VirusTotal enrichment."; VIRUSTOTAL=0
fi
if [ "$OSINT$VIRUSTOTAL$URLSCAN" != "000" ]; then
  ! have curl && warn "OSINT enrichment needs curl; results will be empty."
  ! have jq   && warn "OSINT enrichment needs jq to parse responses; results will be limited."
  [ "$OSINT" = "1" ]      && ok "OSINT enabled (RDAP + Shodan InternetDB + Team Cymru ASN; passive, no key)."
  [ "$VIRUSTOTAL" = "1" ] && ok "VirusTotal enrichment enabled."
  [ "$URLSCAN" = "1" ]    && ok "urlscan.io enrichment enabled$([ -z "$URLSCAN_API_KEY" ] && echo " (unauthenticated; lower rate limits)")."
fi
if [ "$SOCIAL" = "1" ]; then
  if ! have tookie-osint; then
    warn "--social needs tookie-osint; skipping social-media discovery."
    warn "Install via setup-recon-env.sh (git-venv: Alfredredbird/tookie-osint)."
    SOCIAL=0
  else
    ok "Social-media discovery enabled (tookie-osint, user='${SOCIAL_USER:-<brand from domain>}')."
  fi
fi

# --- prepare working dirs --------------------------------------------------
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
WORKDIR="$(cd "$OUT_DIR" && pwd)/_work-$TS"
mkdir -p "$WORKDIR/raw" "$WORKDIR/parts"
if [ -z "$OUTPUT" ]; then
  OUTPUT="$(cd "$OUT_DIR" && pwd)/recon-$TS.csv"
else
  case "$OUTPUT" in /*) :;; *) OUTPUT="$(pwd)/$OUTPUT";; esac
  mkdir -p "$(dirname "$OUTPUT")"
fi

# --- detect ASN / CIDR seeds (expanded to hostnames after resolvers are set) --
HAS_RANGES=0
if sed 's/\r$//' "$INPUT" | sed 's/#.*$//' | tr -d ' ' \
     | grep -qE '^(AS[0-9]+|([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})$'; then
  HAS_RANGES=1
fi
if [ "$HAS_RANGES" = "1" ] && [ "$PASSIVE_ONLY" = "1" ]; then
  warn "ASN/CIDR seeds present but --passive-only set; range expansion (tlsx) is active and will be skipped."
  HAS_RANGES=0
fi

# --- resolver selection (dedicated resolvers bypass a local Pi-hole) --------
# Populated when any DNS-heavy stage is active (or --resolvers given); then
# passed to dnsx, tlsx, AND httpx so DNS bursts don't trip a local resolver's
# rate limits. Left empty otherwise (system DNS -> unchanged default behavior).
if [ "$RESOLVE" = "1" ] || [ "$CERTS" = "1" ] || [ "$PERMUTE" = "1" ] \
   || [ "$BRUTE" = "1" ] || [ "$HAS_RANGES" = "1" ] || [ -n "$RESOLVERS_FILE" ] \
   || [ "$REFRESH_RESOLVERS" = "1" ]; then
  if [ -n "$RESOLVERS_FILE" ] && [ -f "$RESOLVERS_FILE" ]; then
    RESOLVERS="$RESOLVERS_FILE"
  else
    [ -n "$RESOLVERS_FILE" ] && warn "--resolvers file not found ($RESOLVERS_FILE); using built-in dedicated resolvers."
    RESOLVERS="$WORKDIR/resolvers.txt"
    printf '%s\n' "${RESOLVERS_LIST[@]}" > "$RESOLVERS"
    # optionally replace the built-in set with a freshly-validated public list
    if [ "$REFRESH_RESOLVERS" = "1" ]; then
      if have dnsvalidator; then
        log "Refreshing resolvers with dnsvalidator (validates public resolvers; can take a few minutes)..."
        if dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o "$WORKDIR/resolvers.txt" 2>/dev/null \
           && [ -s "$WORKDIR/resolvers.txt" ]; then
          ok "dnsvalidator: $(wc -l < "$WORKDIR/resolvers.txt" | tr -d ' ') validated resolvers."
        else
          warn "dnsvalidator produced no resolvers; restoring the built-in set."
          printf '%s\n' "${RESOLVERS_LIST[@]}" > "$RESOLVERS"
        fi
      else
        warn "--refresh-resolvers needs dnsvalidator; keeping the built-in resolver set."
      fi
    fi
  fi
  ok "DNS: routing dnsx/tlsx/httpx through $(wc -l < "$RESOLVERS" | tr -d ' ') dedicated resolvers (bypasses local DNS/Pi-hole)."
else
  RESOLVERS=""
fi

# --- normalize input (strip CRLF from Windows-edited files, comments, blanks)
DOMAINS_FILE="$WORKDIR/domains.txt"
sed 's/\r$//' "$INPUT" \
  | sed 's/#.*$//' \
  | tr 'A-Z' 'a-z' \
  | sed -E 's#^\s*(https?://)?##; s#/.*$##; s/^\s+//; s/\s+$//' \
  | grep -E '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$' \
  | sort -u > "$DOMAINS_FILE" || true

# --- ASN/CIDR seed mode: expand owned ranges, cert-scan them for hostnames ---
# For an asset owner this surfaces forgotten hosts no passive source will show.
# ASN -> CIDRs (asnmap); CIDRs are cert-scanned (tlsx reads CIDRs directly) and
# any in-scope-looking hostnames recovered are added to the seed list.
if [ "$HAS_RANGES" = "1" ]; then
  ASN_CIDR_FILE="$WORKDIR/asn_cidr.txt"
  sed 's/\r$//' "$INPUT" | sed 's/#.*$//' | tr -d ' ' \
    | grep -E '^(AS[0-9]+|([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})$' | sort -u > "$ASN_CIDR_FILE" || true
  CIDRS="$WORKDIR/cidrs.txt"; : > "$CIDRS"
  if grep -qE '^AS[0-9]+$' "$ASN_CIDR_FILE" && have asnmap; then
    # asnmap queries ProjectDiscovery's ASN API, which needs a (free) PDCP API key:
    # PDCP_API_KEY, or `asnmap -auth` (stored in ~/.pdcp/credentials.yaml). Without
    # it asnmap prints an error and nothing else, which used to look like "no ranges".
    if [ -z "${PDCP_API_KEY:-}" ] && [ ! -s "$HOME/.pdcp/credentials.yaml" ]; then
      warn "ASN seeds need a ProjectDiscovery Cloud API key for asnmap: export PDCP_API_KEY=... or run 'asnmap -auth'"
      warn "  (free key: https://cloud.projectdiscovery.io). Only literal CIDR seeds will be expanded."
    else
      ASNMAP_ERR="$WORKDIR/asnmap.err"; : > "$ASNMAP_ERR"
      while IFS= read -r asn; do [ -z "$asn" ] && continue
        _n0="$(wc -l < "$CIDRS")"
        # A rejected key makes asnmap ask for a new one on /dev/tty, which would block a
        # terminal run until the stage timeout. Without a controlling terminal (setsid)
        # the prompt fails at once instead.
        # asnmap prints its key prompt on stdout, so only CIDR lines are kept
        _amout="$WORKDIR/asnmap.out"; : > "$_amout"
        if have setsid; then
          _to "$STAGE_TIMEOUT" setsid -w asnmap -a "$asn" -silent < /dev/null 2>>"$ASNMAP_ERR" > "$_amout" || true
        else
          _to "$STAGE_TIMEOUT" asnmap -a "$asn" -silent < /dev/null 2>>"$ASNMAP_ERR" > "$_amout" || true
        fi
        grep -E '^[0-9a-fA-F:.]+/[0-9]{1,3}$' "$_amout" >> "$CIDRS" || true
        if [ "$(wc -l < "$CIDRS")" -eq "$_n0" ]; then
          if grep -qiE 'Enter PDCP API Key|unauthori[sz]ed' "$_amout" "$ASNMAP_ERR"; then
            warn "asnmap: the PDCP API key was rejected (unauthorized); check PDCP_API_KEY or rerun 'asnmap -auth'. $asn not expanded."
          else
            _amerr="$(sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' "$ASNMAP_ERR" | grep -v '^[[:space:]]*$' | tail -n 1 | cut -c1-200)"
            warn "asnmap returned no ranges for $asn: ${_amerr:-no error message (check the ASN)}"
          fi
        fi
      done < <(grep -E '^AS[0-9]+$' "$ASN_CIDR_FILE")
    fi
  elif grep -qE '^AS[0-9]+$' "$ASN_CIDR_FILE"; then
    warn "ASN seeds present but asnmap not installed; only literal CIDR seeds will be expanded."
  fi
  grep -E '/[0-9]+$' "$ASN_CIDR_FILE" >> "$CIDRS" 2>/dev/null || true
  # IPv6 prefixes (asnmap returns them too) cannot be swept: a /32 is 2^96 addresses
  if grep -q ':' "$CIDRS" 2>/dev/null; then
    log "ASN/CIDR expansion: skipping $(grep -c ':' "$CIDRS") IPv6 prefix(es); only IPv4 ranges are cert-scanned."
    grep -v ':' "$CIDRS" > "$CIDRS.v4" || true; mv "$CIDRS.v4" "$CIDRS"
  fi
  # mapcidr -aggregate merges overlapping/adjacent ranges. (Without -aggregate, mapcidr
  # -cl prints every IP of every range: an ASN with a /12 became a million lines.)
  # -aggregate also reads stdin while it is open, so stdin is closed explicitly.
  have mapcidr && [ -s "$CIDRS" ] && { mapcidr -cl "$CIDRS" -aggregate -silent < /dev/null 2>/dev/null | sort -u > "$CIDRS.agg" && [ -s "$CIDRS.agg" ] && mv "$CIDRS.agg" "$CIDRS"; } || true
  rm -f "$CIDRS.agg"
  sort -u "$CIDRS" -o "$CIDRS" 2>/dev/null || true
  EXPANDED="$WORKDIR/expanded_from_ranges.txt"; : > "$EXPANDED"
  # certificate-scan ports: 443 by default; with --ports, the same port list naabu uses
  if [ -z "$RANGE_TLS_PORTS" ]; then
    if [ "$PORTS" = "1" ]; then
      if printf '%s' "$PORT_SPEC" | grep -qE '^[0-9]+(,[0-9]+)*$'; then RANGE_TLS_PORTS="$PORT_SPEC"
      else RANGE_TLS_PORTS="80,443,3000,5000,7001,8000,8008,8080,8081,8181,8443,8888,9000,9200,9443"; fi
    else
      RANGE_TLS_PORTS=443
    fi
  fi
  printf '%s' "$RANGE_TLS_PORTS" | grep -qE '^[0-9]+(,[0-9]+)*$' || { err "RANGE_TLS_PORTS must be a comma-separated port list (got: $RANGE_TLS_PORTS)"; exit 2; }
  if [ -s "$CIDRS" ] && have tlsx; then
    tlsxr=(-l "$CIDRS" -p "$RANGE_TLS_PORTS" -san -cn -resp-only -silent -timeout 10)
    { [ -n "$RESOLVERS" ] && [ -s "$RESOLVERS" ]; } && tlsxr+=(-r "$RESOLVERS")
    tlsx "${tlsxr[@]}" 2>/dev/null | tr 'A-Z' 'a-z' \
      | grep -E '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$' | sort -u > "$EXPANDED" || : > "$EXPANDED"
  fi
  if [ -s "$EXPANDED" ]; then
    cat "$EXPANDED" >> "$DOMAINS_FILE"; sort -u "$DOMAINS_FILE" -o "$DOMAINS_FILE"
    ok "ASN/CIDR expansion: added $(wc -l < "$EXPANDED" | tr -d ' ') hostname(s) from cert scan of $(wc -l < "$CIDRS" | tr -d ' ') CIDR(s)."
  elif [ ! -s "$CIDRS" ]; then
    warn "ASN/CIDR seeds present but no ranges to scan (see the asnmap warnings above)."
  elif ! have tlsx; then
    warn "ASN/CIDR seeds present but tlsx is not installed; ranges were not cert-scanned."
  else
    warn "Cert scan of $(wc -l < "$CIDRS" | tr -d ' ') range(s) on port(s) $RANGE_TLS_PORTS found no hostnames."
  fi
fi

NDOM="$(wc -l < "$DOMAINS_FILE" | tr -d ' ')"
if [ "$NDOM" -eq 0 ]; then err "No valid domains parsed from $INPUT"; exit 1; fi

echo >&2
log "=============================================================="
log " EASM URL enumeration  |  v$VERSION"
log " Authorization reminder: only assess assets you are permitted to."
log "--------------------------------------------------------------"
log " Input domains : $NDOM"
log " Threads       : $THREADS"
log " Mode          : $([ "$PASSIVE_ONLY" = 1 ] && echo passive-only || { [ "$NO_VALIDATE" = 1 ] && echo 'crawl, no-validate' || echo 'passive + crawl + validate'; })"
log " Subdomains    : $(onoff $DO_SUBS)    Deep(waymore): $(onoff $DEEP)    Rounds: $ROUNDS"
log " Discovery     : resolve=$(onoff $RESOLVE)  certs=$(onoff $CERTS)  permute=$(onoff $PERMUTE)  brute=$(onoff $BRUTE)  ports=$(onoff $PORTS)  favicon=$(onoff $FAVICON)$([ -n "$RESOLVERS" ] && echo "  (dedicated resolvers)" || echo "")"
log " Sources+      : crawlers-all=$(onoff $CRAWLERS_ALL)  js=$(onoff $JS)"
log " DNS zones     : zone-exposure=$(onoff $ZONE_EXPOSURE)"
log " Analysis      : takeover=$(onoff $TAKEOVER)  screenshots=$(onoff $SCREENSHOTS)  origin=$(onoff $ORIGIN)  vhost=$(onoff $VHOST)  nuclei=$(onoff $NUCLEI)  params=$(onoff $PARAMS)  secrets=$(onoff $SECRETS)  active-cms=$(onoff $ACTIVE)  activescan=$(onoff $ACTIVESCAN)"
if [ "$NUCLEI$ACTIVE$ACTIVESCAN" != "000" ] && have nuclei; then
  case "$NUCLEI_OAST" in
    off)    log " nuclei OAST   : off (-ni; no callbacks to public interactsh servers)";;
    self)   log " nuclei OAST   : self-hosted ($NUCLEI_ISERVER)";;
    public) log " nuclei OAST   : PUBLIC interactsh servers (oast.*), by explicit opt-in";;
  esac
fi
log " Code+cloud    : github=$(onoff $GITHUB)  buckets=$(onoff $BUCKETS)$([ "$REFRESH_RESOLVERS" = 1 ] && echo "  (resolvers: dnsvalidator)" || echo "")"
log " OSINT         : osint=$(onoff $OSINT)  virustotal=$(onoff $VIRUSTOTAL)  urlscan=$(onoff $URLSCAN)  social=$(onoff $SOCIAL)  ip+asn=$(onoff $ASN)"
log " Monitoring    : $([ "$MONITOR" = 1 ] && echo "on (notify=$(onoff $NOTIFY))" || echo off)"
log " DB cache      : $([ "$USE_DB" = 1 ] && echo "on (db=$RECON_DB_NAME, ttl=${CACHE_TTL}s)" || echo off)"
log " HTTP proxy    : $([ -n "$PROXY" ] && echo "$PROXY" || echo off)"
log " HTML report   : $(onoff "$REPORT")"
log " Static filter : $(onoff $FILTER_STATIC)"
log " Fuzzing       : $([ "$FUZZ" = 1 ] && echo "on ($(basename "$WORDLIST"))" || echo off)"
log " Output CSV    : $OUTPUT"
log "=============================================================="
echo >&2

# ===========================================================================
# Service health checks -- when --db or --resolvers is in play, verify those
# services are actually operational up front and fail fast / degrade with clear
# guidance, instead of stalling on timeouts later. (Main process only.)
# ===========================================================================
# _svc_resolver_check FILE [NAME] : look NAME (the first seed) up on the first few
# resolvers in FILE. Any reply used to pass, so a lab DNS answering SERVFAIL for every
# name passed and the run "completed" with 0 rows. Now:
#   0  a resolver answered NOERROR or NXDOMAIN (RESOLVER_SEED_STATUS says which)
#   3  resolvers answer, but the lookup fails (SERVFAIL, REFUSED...): names will not resolve
#   1  no reply at all          2  cannot be tested (no dig)
# Sets RESOLVER_OK_ADDR to the resolver that answered.
_svc_resolver_check() {
  local f="$1" name="${2:-one.one.one.one}" tested=0 r out st bad=""
  RESOLVER_OK_ADDR=""; RESOLVER_SEED_STATUS=""
  have dig || return 2
  while IFS= read -r r || [ -n "$r" ]; do
    [ "$tested" -lt 3 ] || break
    r="${r%%#*}"; r="$(printf '%s' "$r" | tr -d '[:space:]')"; [ -z "$r" ] && continue
    tested=$((tested+1))
    out="$(dig @"$r" +time=2 +tries=1 +noall +comments "$name" A 2>/dev/null)" || continue
    st="$(printf '%s\n' "$out" | sed -nE 's/.*status: ([A-Z]+).*/\1/p' | head -n 1)"
    case "$st" in
      ""|NOERROR|NXDOMAIN) RESOLVER_OK_ADDR="$r"; RESOLVER_SEED_STATUS="${st:-NOERROR}"; return 0;;
      *) [ -n "$bad" ] || bad="$r $st";;
    esac
  done < "$f"
  if [ -n "$bad" ]; then RESOLVER_OK_ADDR="${bad%% *}"; RESOLVER_SEED_STATUS="${bad#* }"; return 3; fi
  [ "$tested" -gt 0 ] && return 1 || return 2
}

if [ "$USE_DB" = "1" ] || { [ -n "$RESOLVERS" ] && [ -s "$RESOLVERS" ]; }; then
  log "Preflight: verifying required services are operational..."
fi

# PostgreSQL service + recon DB (for --db). Workers inherit USE_DB + PG env and
# call the fail-soft cache functions; any problem here downgrades to an uncached run.
if [ "$USE_DB" = "1" ]; then
  if [ "$RECON_DB_LIB_LOADED" != "1" ]; then
    warn "  DB: recon-db.sh not found next to run-recon; running without the DB cache."
    USE_DB=0
  elif db_available && db_schema; then
    ok "  DB: PostgreSQL reachable; database '$RECON_DB_NAME' ready - caching on (TTL ${CACHE_TTL}s)."
  else
    # not usable: probe the service to explain why
    _pgargs=(); [ -n "${PGHOST:-}" ] && _pgargs+=(-h "$PGHOST"); [ -n "${PGPORT:-}" ] && _pgargs+=(-p "$PGPORT")
    _pgsrv="not responding"
    if have pg_isready && pg_isready "${_pgargs[@]}" -t 5 >/dev/null 2>&1; then
      _pgsrv="server up, but our database/credentials are not"
    elif have systemctl && systemctl is-active --quiet postgresql 2>/dev/null; then
      _pgsrv="service active, but not accepting our connection"
    elif have pg_lsclusters && pg_lsclusters 2>/dev/null | grep -qi online; then
      _pgsrv="cluster online, but not accepting our connection"
    fi
    warn "  DB: the '$RECON_DB_NAME' database is not reachable ($_pgsrv) - running without the DB cache."
    warn "      fix:  sudo systemctl start postgresql  &&  sudo $RECON_DIR/recon-db.sh init"
    USE_DB=0
  fi
fi

# DNS resolvers (for --resolvers / any active dedicated-resolver set)
if [ -n "$RESOLVERS" ] && [ -s "$RESOLVERS" ]; then
  _rseed="$(grep -m 1 . "$DOMAINS_FILE" 2>/dev/null || true)"
  _rescheck=0; _svc_resolver_check "$RESOLVERS" "${_rseed:-one.one.one.one}" || _rescheck=$?
  if [ "$_rescheck" = "0" ]; then
    if [ "$RESOLVER_SEED_STATUS" = "NXDOMAIN" ]; then
      ok "  DNS: resolver check passed (${RESOLVER_OK_ADDR:-a resolver} responding)."
      warn "  DNS: the first seed $_rseed does not exist (NXDOMAIN at $RESOLVER_OK_ADDR): check the seed list."
      RUN_DNS_CHECK="passed (first seed NXDOMAIN)"
    else
      ok "  DNS: resolver check passed (${RESOLVER_OK_ADDR:-a resolver} resolves ${_rseed:-one.one.one.one})."
      RUN_DNS_CHECK="passed"
    fi
  elif [ "$_rescheck" = "2" ]; then
    log "  DNS: 'dig' unavailable; skipping the resolver health check."
    RUN_DNS_CHECK="not tested (no dig)"
  elif [ "$_rescheck" = "3" ]; then
    warn "  DNS: $RESOLVER_OK_ADDR answers, but looking up the first seed $_rseed returns $RESOLVER_SEED_STATUS: names under it will not resolve."
    warn "      the zone may be broken or unreachable (lame delegation, DNSSEC failure, a lab zone that did not load), or the resolver cannot reach its name servers."
    RUN_DNS_CHECK="failed ($_rseed: $RESOLVER_SEED_STATUS at $RESOLVER_OK_ADDR)"
  else
    RUN_DNS_CHECK="failed (no reply)"
    warn "  DNS: no resolver in $(basename "$RESOLVERS") answered a test query - DNS-heavy stages (resolve/brute/certs) will stall."
    if [ -n "${RESOLVERS_FILE:-}" ] && [ "$RESOLVERS" = "$RESOLVERS_FILE" ]; then
      warn "      is the resolver up? (a local unbound at that address must be running) - or drop --resolvers / try --refresh-resolvers."
    else
      warn "      check network/DNS egress from this host, or pass --refresh-resolvers to rebuild the list."
    fi
  fi
fi

# --- export config for workers, then run domains in parallel ---------------

export WORKDIR PASSIVE_ONLY NO_VALIDATE DO_SUBS DEPTH RATE FILTER_STATIC MAX_URLS DEEP STATIC_EXT
export FUZZ WORDLIST FUZZ_THREADS FUZZ_EXT SECLISTS HTTPX_BIN
export RESOLVE CERTS PERMUTE PERMUTE_MAX RESOLVERS
export BRUTE BRUTE_WORDLIST BRUTE_MAX PORTS PORT_SPEC CRAWLERS_ALL JS TAKEOVER SCREENSHOTS ORIGIN FAVICON
export TLS_POSTURE TLS_ENUM IPV6
export ROUNDS VHOST NUCLEI NUCLEI_SEV PARAMS SECRETS
export GITHUB GITHUB_TOKEN_FILE BUCKETS
export ACTIVE CMS_WORDLIST CMS_MAX WPSCAN_API_TOKEN
export ACTIVESCAN SECLISTS
export OSINT VIRUSTOTAL VT_API_KEY URLSCAN URLSCAN_API_KEY OSINT_MAX
export SOCIAL SOCIAL_USER
export RDAP_TIMEOUT RDAP_DELAY INTERNETDB_TIMEOUT INTERNETDB_DELAY VT_TIMEOUT VT_DELAY URLSCAN_TIMEOUT URLSCAN_DELAY
export USE_DB CACHE_TTL RECON_DB_NAME RECON_DB_DSN PGDATABASE PGUSER PGHOST PGPORT PGPASSWORD
export NEG_TTL CB_THRESHOLD CB_SERIALIZE PROXY HTTP_RETRIES LATE_RETRY SKIP_SPECIAL_USE NUCLEI_OAST NUCLEI_ISERVER ZONE_EXPOSURE
export CERT_WARN_DAYS TLS_CHAIN_CHECK
# route GET-heavy stages (curl/whatweb/gau/wget/python) through the proxy if set;
# ProjectDiscovery tools additionally get an explicit -proxy flag at their call sites.
if [ -n "$PROXY" ]; then
  export HTTP_PROXY="$PROXY" HTTPS_PROXY="$PROXY" http_proxy="$PROXY" https_proxy="$PROXY"
fi
# Screenshot browser routing (httpx -ss starts Chrome, which takes the environment proxy
# but not NO_PROXY or httpx's own -proxy/-r). SS_CHROME: use an installed Chrome/Chromium
# instead of a downloaded one. SS_PROXY_SERVER: --proxy (credentials stripped: Chrome
# cannot take them on the command line). SS_PROXY_BYPASS: NO_PROXY in Chrome's syntax
# (';'-separated, "x" and "*.x" for each domain), so internal names never reach the proxy.
SS_CHROME=0; SS_PROXY_SERVER=""; SS_PROXY_BYPASS=""
if [ "$SCREENSHOTS" = "1" ]; then
  for _b in google-chrome google-chrome-stable chromium chromium-browser; do have "$_b" && { SS_CHROME=1; break; }; done
  if [ -n "$PROXY" ]; then
    SS_PROXY_SERVER="$(printf '%s' "$PROXY" | sed -E 's#^([A-Za-z][A-Za-z0-9+.-]*://)[^@/]*@#\1#')"
    [ "$SS_PROXY_SERVER" != "$PROXY" ] && warn "--screenshots: the browser cannot use the proxy's credentials; captures through it may fail."
  fi
  _np="${NO_PROXY:-${no_proxy:-}}"
  if [ -n "$_np" ] && [ -n "$SS_PROXY_SERVER${HTTPS_PROXY:-}${https_proxy:-}${HTTP_PROXY:-}${http_proxy:-}" ]; then
    SS_PROXY_BYPASS="$(printf '%s' "$_np" | tr ',' '\n' | awk '
      { gsub(/^[ \t]+|[ \t]+$/, ""); if ($0 == "") next; e = $0; sub(/^\*?\./, "", e); if (e == "") next
        if (e ~ /^[0-9.\/]+$/ || e ~ /:/ || e == "localhost" || e == "*") print e; else { print e; print "*." e } }' \
      | awk '!seen[$0]++' | paste -sd';' -)"
  fi
fi
export SS_CHROME SS_PROXY_SERVER SS_PROXY_BYPASS
export PROGRESS STAGE_TIMEOUT PASSIVE_TIMEOUT BRUTE_TIMEOUT FUZZ_TIMEOUT SCAN_TIMEOUT
# --- DNS zone exposure (main process: once per zone, before the workers) ------------
# For each seed: the zone apex (SOA owner) and its authoritative name servers. Then:
#   AXFR on every name server                -> zone-transfer-open [high]
#   DNSKEY present, NSEC chain answers        -> nsec-zone-walkable [medium] (walked)
#   NSEC3PARAM present                        -> nsec3-hashes-exposed [low] (not cracked)
#   otherwise                                 -> zone-checked [info] (evidence of the check)
# Names harvested go to $WORKDIR/zone_names.txt; each worker adds the ones at or under
# its seed to its candidates. Names outside every seed are listed, never scanned.
if [ "$ZONE_EXPOSURE" = "1" ]; then
  if ! have dig; then
    warn "--zone-exposure needs dig (dnsutils/bind-utils); skipping."
  else
    mkdir -p "$WORKDIR/parts"
    ZONE_RES=""; [ -n "$RESOLVERS" ] && [ -s "$RESOLVERS" ] && ZONE_RES="$(grep -vE '^\s*(#|$)' "$RESOLVERS" | head -n 1 | sed -E 's/:[0-9]+$//')"
    log "DNS zone exposure: checking the zones of $(grep -c . "$DOMAINS_FILE") seed(s)${ZONE_RES:+ (resolver $ZONE_RES)}"
    python3 - "$DOMAINS_FILE" "$WORKDIR/parts/zone.all.txt" "$WORKDIR/zone_names.txt" "$ZONE_RES" "$ZONE_WALK_MAX" <<'PYZONE' 2>>"$WORKDIR/zone.err" || warn "zone exposure check failed (see $WORKDIR/zone.err)"
import subprocess, sys, re
seeds_f, out_f, names_f, resolver, walk_max = sys.argv[1:6]
walk_max = int(walk_max or 5000)
res = ["@" + resolver] if resolver else []
NAME = re.compile(r"^[A-Za-z0-9_*]([A-Za-z0-9_.-]*[A-Za-z0-9])?\.?$")
def dig(*args, t=3):
    try:
        return subprocess.run(["dig", "+time=%d" % t, "+tries=1"] + list(args), capture_output=True,
                              text=True, timeout=t * 4 + 5).stdout
    except Exception:
        return ""
def rrs(text):
    for line in text.splitlines():
        if not line or line.startswith(";"):
            continue
        f = line.split()
        if len(f) >= 4 and f[2] == "IN":
            yield f[0].rstrip(".").lower(), f[3].upper(), f[4:]
def clean(n):
    n = n.rstrip(".").lower()
    return n if n and "\\" not in n and NAME.match(n) and not n.startswith("*") else ""
zones = {}
for seed in (l.strip() for l in open(seeds_f) if l.strip()):
    apex = ""
    for owner, typ, _ in rrs(dig(*res, "+noall", "+answer", "+authority", "SOA", seed)):
        if typ == "SOA":
            apex = owner; break
    if apex:
        zones.setdefault(apex, []).append(seed)
out, names = [], set()
for apex, zseeds in sorted(zones.items()):
    ns = sorted(set(clean(r[0]) for o, t, r in rrs(dig(*res, "+noall", "+answer", "NS", apex)) if t == "NS" and r))
    targets = []
    for n in ns:
        for o, t, r in rrs(dig(*res, "+noall", "+answer", "A", n)):
            if t == "A" and r:
                targets.append((n, r[0]))
    signed = any(t == "DNSKEY" for o, t, r in rrs(dig(*res, "+noall", "+answer", "DNSKEY", apex)))
    axfr_open, refused = [], 0
    for n, ip in targets:
        text = dig("+noall", "+answer", "AXFR", apex, "@" + ip, t=5)
        recs = [(o, t) for o, t, r in rrs(text)]
        if sum(1 for o, t in recs if t == "SOA") >= 1 and len(recs) > 2:
            got = set(c for c in (clean(o) for o, t in recs if t not in ("RRSIG", "NSEC", "NSEC3")) if c)
            names |= {(apex, x, "axfr") for x in got}
            axfr_open.append("%s(%s) records=%d names=%d" % (n, ip, len(recs), len(got)))
        else:
            refused += 1
    for a in axfr_open:
        n_ip, rest = a.split(" ", 1)
        out.append("[%s] zone-transfer-open [high] host=%s zone=%s ns=%s %s note=any client can download "
                   "the whole zone with AXFR; allow transfers only to your secondaries" % (apex, apex, apex, n_ip, rest))
    walked, nsec3 = set(), ""
    if signed and targets:
        ip = targets[0][1]
        p3 = [r for o, t, r in rrs(dig("+noall", "+answer", "+dnssec", "+norec", "NSEC3PARAM", apex, "@" + ip)) if t == "NSEC3PARAM"]
        if p3:
            nsec3 = " ".join(p3[0][:4])
        else:
            cur, seen = apex, {apex}
            while len(walked) < walk_max:
                nxt = ""
                for o, t, r in rrs(dig("+noall", "+answer", "+dnssec", "+norec", "NSEC", cur, "@" + ip)):
                    if t == "NSEC" and o == cur and r:
                        nxt = clean(r[0]); break
                if not nxt or nxt in seen or not (nxt == apex or nxt.endswith("." + apex)):
                    break
                seen.add(nxt); walked.add(nxt); cur = nxt
            names |= {(apex, x, "nsec") for x in walked}
    if walked:
        out.append("[%s] nsec-zone-walkable [medium] host=%s zone=%s names=%d%s note=the DNSSEC NSEC chain lists "
                   "every name in the zone; use NSEC3 (or online signing with minimal NSEC) to stop enumeration"
                   % (apex, apex, apex, len(walked), " capped=%d" % walk_max if len(walked) >= walk_max else ""))
    if nsec3:
        f = nsec3.split()
        iters, salt = (f[2], f[3]) if len(f) >= 4 else ("?", "?")
        optout = len(f) >= 2 and f[1] == "1"
        out.append("[%s] nsec3-hashes-exposed [low] host=%s zone=%s params=\"%s\" iterations=%s salt=%s%s note=NSEC3 "
                   "hashes can be collected and cracked offline with a wordlist; names are not exposed directly"
                   % (apex, apex, apex, nsec3, iters, salt, " opt-out=yes" if optout else ""))
    if not axfr_open and not walked and not nsec3:
        out.append("[%s] zone-checked [info] host=%s zone=%s signed=%s axfr=refused(%d/%d) nsec=%s"
                   % (apex, apex, apex, "yes" if signed else "no", refused, len(targets),
                      "not-walkable" if signed else "n/a"))
open(out_f, "a").write("".join(x + "\n" for x in out))
with open(names_f, "a") as f:
    for z, n, src in sorted(names):
        f.write("%s\t%s\t%s\n" % (z, n, src))
PYZONE
    if [ -s "$WORKDIR/zone_names.txt" ]; then
      log "DNS zone exposure: $(cut -f2 "$WORKDIR/zone_names.txt" | sort -u | wc -l | tr -d ' ') name(s) harvested; those under a seed join its candidates"
    fi
  fi
fi

export -f _ss_norm 2>/dev/null || true
export -f process_one special_use_domain nuclei_oast_args takeover_check origin_check missing_keys late_pause prep_file scope_filter resolve_hosts brute_subs analyze_hosts cms_scan activescan osint_scan uro_filter \
          _to _delay fmt_hms stage log ok warn err have _c \
          cache_or_run cb_fail cb_open _cbdir _cbkey _serialized seen_once url_junk_filter 2>/dev/null || true

SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"

# Overall-progress heartbeat: a background ticker prints total elapsed and how
# many domains have finished (each worker touches $WORKDIR/done/<safe>), so a
# long-running stage never looks like a hang. Disabled if PROGRESS=0 / HEARTBEAT=0.
RUN_START=$(date +%s 2>/dev/null || echo 0)
NDOMAINS="$(grep -cvE '^\s*$' "$DOMAINS_FILE" 2>/dev/null || true)"; NDOMAINS="${NDOMAINS:-0}"
mkdir -p "$WORKDIR/done"
HEARTBEAT_PID=""
if [ "${PROGRESS:-1}" = "1" ] && [ "${HEARTBEAT:-0}" -gt 0 ] 2>/dev/null; then
  (
    while :; do
      sleep "$HEARTBEAT"
      _now=$(date +%s 2>/dev/null || echo 0); _el=$(( _now - RUN_START ))
      _done=$(find "$WORKDIR/done" -type f 2>/dev/null | wc -l | tr -d ' ')
      printf '%s   ...%s running %s  %s(%s/%s domains complete)%s\n' \
        "$(_c $'\033[1;35m')" "$(_c $'\033[0m')" "$(fmt_hms $_el)" \
        "$(_c $'\033[2m')" "$_done" "$NDOMAINS" "$(_c $'\033[0m')" >&2
    done
  ) &
  HEARTBEAT_PID=$!
fi
# make sure the ticker never outlives the run (WORKDIR cleanup stays with the
# keep-work-aware logic at the end of the script)
trap '[ -n "${HEARTBEAT_PID:-}" ] && kill "$HEARTBEAT_PID" 2>/dev/null || true' EXIT INT TERM

# xargs runs the per-domain worker N at a time. Invoke via 'bash' explicitly so
# this does not depend on the script's execute bit (survives Windows round-trips).
# shellcheck disable=SC2016
cat "$DOMAINS_FILE" | xargs -P "$THREADS" -I{} bash "$SELF" --__worker {} || true

if [ -n "$HEARTBEAT_PID" ]; then kill "$HEARTBEAT_PID" 2>/dev/null || true; HEARTBEAT_PID=""; fi
if [ "${PROGRESS:-1}" = "1" ]; then
  _rel=$(( $(date +%s 2>/dev/null || echo 0) - RUN_START ))
  ok "all domains processed in $(fmt_hms $_rel)"
fi

# --- aggregate per-domain parts -------------------------------------------
log "Aggregating results..."
cat "$WORKDIR"/parts/map.*.tsv   2>/dev/null > "$WORKDIR/map.tsv"     || : > "$WORKDIR/map.tsv"
cat "$WORKDIR"/parts/httpx.*.jsonl 2>/dev/null > "$WORKDIR/httpx.jsonl" || : > "$WORKDIR/httpx.jsonl"
cat "$WORKDIR"/parts/tlsx.*.jsonl  2>/dev/null > "$WORKDIR/tlsx.jsonl"  || : > "$WORKDIR/tlsx.jsonl"
cat "$WORKDIR"/parts/aaaa.*.txt    2>/dev/null > "$WORKDIR/aaaa.tsv"    || : > "$WORKDIR/aaaa.tsv"

# fetch_cloud_ranges : emit "cidr<TAB>provider" for the public cloud IP-range feeds.
fetch_cloud_ranges() {
  python3 - <<'PYCLOUD'
import subprocess, json, sys, re
def curl(url):
    try:
        return subprocess.run(["curl", "-s", "--max-time", "30", url],
                              capture_output=True, text=True, timeout=40).stdout
    except Exception:
        return ""
o = sys.stdout
def emit(cidr, prov):
    if cidr:
        o.write(cidr + "\t" + prov + "\n")
try:
    j = json.loads(curl("https://ip-ranges.amazonaws.com/ip-ranges.json"))
    for p in j.get("prefixes", []):      emit(p.get("ip_prefix"), "AWS")
    for p in j.get("ipv6_prefixes", []): emit(p.get("ipv6_prefix"), "AWS")
except Exception: pass
try:
    j = json.loads(curl("https://www.gstatic.com/ipranges/cloud.json"))
    for p in j.get("prefixes", []):      emit(p.get("ipv4Prefix") or p.get("ipv6Prefix"), "GCP")
except Exception: pass
for u in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
    for line in curl(u).splitlines():
        line = line.strip()
        if line and "/" in line: emit(line, "Cloudflare")
try:
    j = json.loads(curl("https://docs.oracle.com/iaas/tools/public_ip_ranges.json"))
    for reg in j.get("regions", []):
        for c in reg.get("cidrs", []):   emit(c.get("cidr"), "OracleCloud")
except Exception: pass
for line in curl("https://www.digitalocean.com/geo/google.csv").splitlines():
    line = line.strip()
    if line and "/" in line: emit(line.split(",")[0], "DigitalOcean")
try:   # Azure publishes a dated download URL behind a details page -- best effort
    page = curl("https://www.microsoft.com/en-us/download/details.aspx?id=56519")
    m = re.search(r'https://download\.microsoft\.com/download/[^"]*ServiceTags_Public_\d+\.json', page)
    if m:
        j = json.loads(curl(m.group(0)))
        for v in j.get("values", []):
            for c in ((v.get("properties") or {}).get("addressPrefixes") or []):
                emit(c, "Azure")
except Exception: pass
PYCLOUD
}

AAAA_FILE="$WORKDIR/aaaa.tsv"; export AAAA_FILE ENRICH GEO_DB

# cloud IP-range feeds: refresh the on-disk cache if missing/stale, then hand its
# path to the aggregator for longest-prefix matching (blank column if unavailable).
CLOUD_RANGES_FILE=""
if [ "$ENRICH" = "1" ]; then
  CLOUD_RANGES_FILE="$RECON_CLOUD_CACHE"
  _cloud_fresh=0
  if [ -s "$CLOUD_RANGES_FILE" ]; then
    _cage=$(( $(date +%s) - $(date -r "$CLOUD_RANGES_FILE" +%s 2>/dev/null || echo 0) ))
    [ "$_cage" -lt "$CLOUD_TTL" ] && _cloud_fresh=1
  fi
  if [ "$_cloud_fresh" = "0" ] && have curl; then
    mkdir -p "$(dirname "$CLOUD_RANGES_FILE")" 2>/dev/null || true
    log "Refreshing cloud IP-range feeds (AWS/GCP/Cloudflare/Oracle/DO/Azure)..."
    if fetch_cloud_ranges > "$CLOUD_RANGES_FILE.tmp" 2>/dev/null && [ -s "$CLOUD_RANGES_FILE.tmp" ]; then
      mv -f "$CLOUD_RANGES_FILE.tmp" "$CLOUD_RANGES_FILE"
    else
      rm -f "$CLOUD_RANGES_FILE.tmp" 2>/dev/null || true
      [ -s "$CLOUD_RANGES_FILE" ] || warn "cloud IP-range fetch failed; 'cloud' column blank (check network)."
    fi
  fi
fi
export CLOUD_RANGES_FILE

# RDAP org cache handoff (like ASN): warm from DB, sync newly-resolved orgs back after.
RDAP_CACHE_FILE="$WORKDIR/rdap_cache.tsv"; : > "$RDAP_CACHE_FILE"
if [ "$USE_DB" = "1" ] && [ "$ENRICH" = "1" ]; then
  _psql -c "SELECT key || E'\t' || value FROM recon_cache WHERE source='rdap_ip'" > "$RDAP_CACHE_FILE" 2>/dev/null || : > "$RDAP_CACHE_FILE"
fi
export RDAP_CACHE_FILE

# --- build the final CSV with python (robust quoting/escaping) -------------
# ASN cache handoff: when --db is on, warm the aggregator's Team Cymru cache from
# the DB (IP -> "AS# org") so repeat runs don't re-dig the same IPs; sync back after.
ASN_CACHE_FILE="$WORKDIR/asn_cache.tsv"; : > "$ASN_CACHE_FILE"
if [ "$USE_DB" = "1" ] && [ "$ASN" = "1" ]; then
  _psql -c "SELECT key || E'\t' || value FROM recon_cache WHERE source='asn'" > "$ASN_CACHE_FILE" 2>/dev/null || : > "$ASN_CACHE_FILE"
fi
export ASN_CACHE_FILE CPE_MAP_FILE
python3 - "$WORKDIR/map.tsv" "$WORKDIR/httpx.jsonl" "$OUTPUT" "$ASN" "$ASN_MAX" "$WORKDIR/tlsx.jsonl" <<'PY'
import sys, os, csv, json, subprocess, datetime, ipaddress, re
from urllib.parse import urlparse

map_path, httpx_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
ASN_ENABLED = (len(sys.argv) > 4 and sys.argv[4] == "1")
ASN_MAX     = int(sys.argv[5]) if len(sys.argv) > 5 else 2000
tlsx_path   = sys.argv[6] if len(sys.argv) > 6 else ""

def is_ipv4(s):
    p = s.split(".")
    return len(p) == 4 and all(x.isdigit() and 0 <= int(x) <= 255 for x in p)

def is_public_ip(s):
    # Only globally-routable addresses are worth (or safe) sending to third-party
    # lookups. Loopback, RFC 1918, link-local, CGNAT and documentation ranges
    # have no ASN / RDAP owner / cloud range / geo, and asking Team Cymru or
    # rdap.org about an internal address leaks internal topology for nothing.
    try:
        return ipaddress.ip_address(s).is_global
    except Exception:
        return False

def first(d, *keys, default=""):
    for k in keys:
        v = d.get(k)
        if v not in (None, "", []):
            return v
    return default

def _host_of(u):
    try:
        return (urlparse(u if "://" in u else "http://" + u).hostname or "").lower()
    except Exception:
        return ""

def urlkey(u):
    # normalize a URL for joining: lowercase scheme+host, drop the default port,
    # strip a trailing slash -- so :80/:443, case and trailing-slash differences
    # between the crawled URL and httpx's url/input still match. The QUERY is kept:
    # /?cat=1, /?author=1 and / are different pages. (Dropping it used to collapse
    # every query variant onto the root's key, so a site's root row could carry
    # e.g. its RSS feed's title/length -- and which one depended on httpx's
    # non-deterministic output order.)
    try:
        pr = urlparse(u if "://" in u else "http://" + u)
        scheme = (pr.scheme or "").lower()
        host = (pr.hostname or "").lower()
        port = pr.port
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None
        netloc = host + (":%d" % port if port else "")
        path = (pr.path or "").rstrip("/")
        return "%s://%s%s%s" % (scheme, netloc, path, ("?" + pr.query) if pr.query else "")
    except Exception:
        return (u or "").rstrip("/")

def is_root_url(u):
    # the site root: empty or "/" path and no query
    try:
        pr = urlparse(u if "://" in u else "http://" + u)
        return (pr.path or "") in ("", "/") and not pr.query
    except Exception:
        return False

# --- IP + ASN attribution helpers -----------------------------------------
# IP comes from httpx's A records (the address it actually connected to). The
# origin ASN is resolved via the free Team Cymru DNS service (no key), cached
# per IP and bounded by ASN_MAX so large runs stay fast.
_asn_cache = {}    # IP -> (asn, org)
_asn_budget = [ASN_MAX]
# warm the cache from the handoff file (populated from the DB by run-recon), so
# IPs resolved on a prior run are not re-queried against Team Cymru.
_asn_cache_file = os.environ.get("ASN_CACHE_FILE", "")
if _asn_cache_file and os.path.exists(_asn_cache_file):
    try:
        with open(_asn_cache_file, encoding="utf-8", errors="replace") as _f:
            for _ln in _f:
                _p = _ln.rstrip("\n").split("\t", 1)
                if _p and _p[0]:
                    _vp = (_p[1] if len(_p) > 1 else "").split(None, 1)
                    _asn_cache[_p[0]] = (_vp[0] if _vp else "", _vp[1] if len(_vp) > 1 else "")
    except Exception:
        pass
_asn_loaded = set(_asn_cache.keys())   # already in the DB; only sync back NEW lookups

def _dig(args):
    try:
        return subprocess.run(["dig", "+short", *args], capture_output=True,
                              text=True, timeout=8).stdout
    except Exception:
        return ""

def lookup_asn(ip):
    if not ip or not ASN_ENABLED or not is_ipv4(ip) or not is_public_ip(ip):
        return ("", "")
    if ip in _asn_cache:
        return _asn_cache[ip]
    if _asn_budget[0] <= 0:
        return ("", "")
    _asn_budget[0] -= 1
    asn = org = ""
    rev = ".".join(reversed(ip.split(".")))
    txt = _dig([f"{rev}.origin.asn.cymru.com", "TXT"]).strip().strip('"')
    if txt and txt.split("|")[0].strip():
        num = txt.split("|")[0].strip().split()[0]
        if num:
            asn = "AS" + num
            nm = _dig([f"AS{num}.asn.cymru.com", "TXT"]).strip().strip('"')
            if "|" in nm:
                org = nm.split("|")[-1].strip()
    _asn_cache[ip] = (asn, org)
    return _asn_cache[ip]

# --- extra per-row enrichment: IPv6 (AAAA), cloud provider, RDAP org, geo -------
ENRICH = os.environ.get("ENRICH", "0") == "1"
GEO_DB = os.environ.get("GEO_DB", "")

# AAAA records per host (from the dnsx stage): host -> "v6;v6"
_aaaa = {}
_af = os.environ.get("AAAA_FILE", "")
if _af and os.path.exists(_af):
    try:
        with open(_af, encoding="utf-8", errors="replace") as _f:
            for _ln in _f:
                _p = _ln.rstrip("\n").split("\t", 1)
                if _p and _p[0]:
                    _aaaa[_p[0].lower()] = _p[1] if len(_p) > 1 else ""
    except Exception:
        pass

# cloud provider by longest-prefix match against the fetched IP-range feeds
_cloud_nets = []
_cf = os.environ.get("CLOUD_RANGES_FILE", "")
if ENRICH and _cf and os.path.exists(_cf):
    try:
        with open(_cf, encoding="utf-8", errors="replace") as _f:
            for _ln in _f:
                _c, _, _prov = _ln.rstrip("\n").partition("\t")
                if _c and _prov:
                    try:
                        _cloud_nets.append((ipaddress.ip_network(_c, strict=False), _prov))
                    except Exception:
                        pass
    except Exception:
        pass
_cloud_nets.sort(key=lambda t: t[0].prefixlen, reverse=True)  # longest prefix first
_cloud_cache = {}
def lookup_cloud(ip):
    if not (ENRICH and ip and _cloud_nets) or not is_public_ip(ip):
        return ""
    if ip in _cloud_cache:
        return _cloud_cache[ip]
    res = ""
    try:
        addr = ipaddress.ip_address(ip)
        for net, prov in _cloud_nets:
            if addr.version == net.version and addr in net:
                res = prov
                break
    except Exception:
        res = ""
    _cloud_cache[ip] = res
    return res

# geolocation (country ISO code) via a local MaxMind DB, read with mmdblookup
_geo_cache = {}
def lookup_geo(ip):
    if not (ENRICH and GEO_DB and ip) or not is_public_ip(ip):
        return ""
    if ip in _geo_cache:
        return _geo_cache[ip]
    res = ""
    try:
        out = subprocess.run(["mmdblookup", "--file", GEO_DB, "--ip", ip, "country", "iso_code"],
                             capture_output=True, text=True, timeout=5).stdout
        m = re.search(r'"([A-Za-z]{2})"', out)
        if m:
            res = m.group(1).upper()
    except Exception:
        res = ""
    _geo_cache[ip] = res
    return res

# RDAP network org (curl to rdap.org), cached like ASN (warm from DB, sync new back)
_rdap_cache = {}
_rf = os.environ.get("RDAP_CACHE_FILE", "")
if _rf and os.path.exists(_rf):
    try:
        with open(_rf, encoding="utf-8", errors="replace") as _f:
            for _ln in _f:
                _p = _ln.rstrip("\n").split("\t", 1)
                if _p and _p[0]:
                    _rdap_cache[_p[0]] = _p[1] if len(_p) > 1 else ""
    except Exception:
        pass
_rdap_loaded = set(_rdap_cache.keys())
_rdap_budget = [ASN_MAX]
def _rdap_name(j):
    if not isinstance(j, dict):
        return ""
    nm = j.get("name") or ""
    if nm:
        return nm
    for ent in (j.get("entities") or []):
        if not isinstance(ent, dict):
            continue
        if any(r in (ent.get("roles") or []) for r in ("registrant", "administrative", "owner")):
            vc = ent.get("vcardArray")
            if isinstance(vc, list) and len(vc) > 1 and isinstance(vc[1], list):
                for item in vc[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        return str(item[3])
    return ""
def lookup_rdap(ip):
    if not (ENRICH and ip and is_ipv4(ip)) or not is_public_ip(ip):
        return ""
    if ip in _rdap_cache:
        return _rdap_cache[ip]
    if _rdap_budget[0] <= 0:
        return ""
    _rdap_budget[0] -= 1
    org = ""
    try:
        out = subprocess.run(["curl", "-s", "--max-time", "8", "-H", "Accept: application/rdap+json",
                              "https://rdap.org/ip/" + ip], capture_output=True, text=True, timeout=12).stdout
        org = _rdap_name(json.loads(out))
    except Exception:
        org = ""
    _rdap_cache[ip] = org
    return org

# --- CPE 2.3 emission (FPV-06) ------------------------------------------------
# Rule-based, ported from WebInventory's approach: a curated product -> CPE 2.3
# vendor:product table, with the detected version substituted into the version
# field. Products come from httpx's tech detection (Wappalyzer, "Name:version")
# and the Server header ("token/version"). Always on (pure offline transform of
# data already collected); the resulting `cpe` column feeds the offline NVD/KEV/
# EPSS join. A few products are split across vendor strings in NVD (e.g. nginx):
# those map to a LIST so a CVE under either vendor still correlates. Extend or
# correct without editing this script via CPE_MAP_FILE (see below).
_CPE_RULES = {
    # --- web servers / proxies ---
    "nginx":            ["cpe:2.3:a:f5:nginx", "cpe:2.3:a:nginx:nginx"],
    "apache":           "cpe:2.3:a:apache:http_server",
    "apachehttpserver": "cpe:2.3:a:apache:http_server",
    "httpd":            "cpe:2.3:a:apache:http_server",
    "microsoftiis":     "cpe:2.3:a:microsoft:internet_information_services",
    "iis":              "cpe:2.3:a:microsoft:internet_information_services",
    "openresty":        "cpe:2.3:a:openresty:openresty",
    "lighttpd":         "cpe:2.3:a:lighttpd:lighttpd",
    "litespeed":        "cpe:2.3:a:litespeedtech:litespeed_web_server",
    "jetty":            "cpe:2.3:a:eclipse:jetty",
    "tomcat":           "cpe:2.3:a:apache:tomcat",
    "apachetomcat":     "cpe:2.3:a:apache:tomcat",
    "caddy":            "cpe:2.3:a:caddyserver:caddy",
    "haproxy":          "cpe:2.3:a:haproxy:haproxy",
    "varnish":          "cpe:2.3:a:varnish_cache_project:varnish_cache",
    "squid":            "cpe:2.3:a:squid-cache:squid",
    "traefik":          "cpe:2.3:a:traefik:traefik",
    # --- languages / runtimes / libs that report versions ---
    "php":              "cpe:2.3:a:php:php",
    "nodejs":           "cpe:2.3:a:nodejs:node.js",
    "python":           "cpe:2.3:a:python:python",
    "openssl":          "cpe:2.3:a:openssl:openssl",
    "perl":             "cpe:2.3:a:perl:perl",
    "ruby":             "cpe:2.3:a:ruby-lang:ruby",
    "openssh":          "cpe:2.3:a:openbsd:openssh",
    # --- app frameworks ---
    "microsoftaspnet":  "cpe:2.3:a:microsoft:asp.net",
    "aspnet":           "cpe:2.3:a:microsoft:asp.net",
    "express":          "cpe:2.3:a:openjsf:express",
    "django":           "cpe:2.3:a:djangoproject:django",
    "laravel":          "cpe:2.3:a:laravel:laravel",
    "rubyonrails":      "cpe:2.3:a:rubyonrails:rails",
    "symfony":          "cpe:2.3:a:sensiolabs:symfony",
    "spring":           "cpe:2.3:a:vmware:spring_framework",
    "springframework":  "cpe:2.3:a:vmware:spring_framework",
    # --- CMS / web apps ---
    "wordpress":        "cpe:2.3:a:wordpress:wordpress",
    "drupal":           "cpe:2.3:a:drupal:drupal",
    "joomla":           "cpe:2.3:a:joomla:joomla\\!",   # NVD product is joomla!
    "magento":          "cpe:2.3:a:magento:magento",
    "typo3":            "cpe:2.3:a:typo3:typo3",
    "phpmyadmin":       "cpe:2.3:a:phpmyadmin:phpmyadmin",
    # --- JS libraries ---
    "jquery":           "cpe:2.3:a:jquery:jquery",
    "bootstrap":        "cpe:2.3:a:getbootstrap:bootstrap",
    "angularjs":        "cpe:2.3:a:angularjs:angular.js",
    "angular":          "cpe:2.3:a:angular:angular",
    "vuejs":            "cpe:2.3:a:vuejs:vue",
    "lodash":           "cpe:2.3:a:lodash:lodash",
    # --- devops / infra UIs ---
    "jenkins":          "cpe:2.3:a:jenkins:jenkins",
    "gitlab":           "cpe:2.3:a:gitlab:gitlab",
    "grafana":          "cpe:2.3:a:grafana:grafana",
    "kibana":           "cpe:2.3:a:elastic:kibana",
    "elasticsearch":    "cpe:2.3:a:elastic:elasticsearch",
    "confluence":       "cpe:2.3:a:atlassian:confluence",
    "jira":             "cpe:2.3:a:atlassian:jira",
    # --- mail / ftp (when surfaced as a web-adjacent banner) ---
    "exim":             "cpe:2.3:a:exim:exim",
    "postfix":          "cpe:2.3:a:postfix:postfix",
    "proftpd":          "cpe:2.3:a:proftpd:proftpd",
}

def _cpe_norm(s):
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())

# optional external extension/override: TSV "normalized_name<TAB>cpe:2.3:a:vendor:product"
# (blank lines and '#' comments ignored). Merged over the built-ins so a site can add a
# product or fix a vendor string without touching the script (like WebInventory -RulesFile).
_cpe_map_file = os.environ.get("CPE_MAP_FILE", "")
if _cpe_map_file and os.path.exists(_cpe_map_file):
    try:
        with open(_cpe_map_file, encoding="utf-8", errors="replace") as _f:
            for _ln in _f:
                _ln = _ln.strip()
                if not _ln or _ln.startswith("#"):
                    continue
                _k, _, _v = _ln.partition("\t")
                _k = _cpe_norm(_k); _v = _v.strip()
                if _k and _v.startswith("cpe:2.3:"):
                    _CPE_RULES[_k] = _v
    except Exception:
        pass

def _cpe_ver(v):
    # keep a leading numeric version token; drop trailing junk like "(Ubuntu)" or "-1.el7"
    m = re.match(r"[0-9][0-9A-Za-z._+-]*", (v or "").strip())
    return m.group(0) if m else ""

def _cpe_for(name, version):
    pfx = _CPE_RULES.get(_cpe_norm(name))
    if not pfx:
        return []
    ver = _cpe_ver(version) or "*"
    prefixes = pfx if isinstance(pfx, list) else [pfx]
    return [p + ":" + ver + ":*:*:*:*:*:*:*" for p in prefixes]

def build_cpes(tech_str, webserver):
    # (product, version) candidates: httpx tech ('Name:version') + Server header tokens.
    cands = []
    for t in (tech_str or "").split(";"):
        t = t.strip()
        if not t:
            continue
        nm, sep, vr = t.partition(":")
        cands.append((nm.strip(), vr.strip() if sep else ""))
    for mm in re.finditer(r"([A-Za-z][A-Za-z0-9._+-]*?)/([0-9][0-9A-Za-z._-]*)", webserver or ""):
        cands.append((mm.group(1), mm.group(2)))
    ws = (webserver or "").strip()
    if ws and "/" not in ws and " " not in ws:        # bare token, e.g. "cloudflare"
        cands.append((ws, ""))
    out = []
    for nm, vr in cands:
        for c in _cpe_for(nm, vr):
            if c not in out:
                out.append(c)
    return ";".join(out)

# Index httpx enrichment for the join, in TIERS that never preempt each other:
#   meta      exact URL -- httpx 'input' first (it is exactly the URL we fed), then 'url'
#   meta_norm normalized URL (urlkey: case/default-port/trailing-slash folded, query kept)
#   host_root a host's ROOT record -- only to bridge a root URL across scheme/port
#             (http://host/ crawled, https://host returned); never lends a page's
#             status/title to a different deep URL.
# Records are indexed in a sorted order, so ties resolve identically every run no
# matter what order httpx (concurrent) wrote them in. n_httpx counts parsed records
# so we can diagnose join failures.
meta = {}
meta_norm = {}
host_root = {}
_hx_recs = []
n_httpx = 0
try:
    with open(httpx_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except Exception:
                continue
            if not isinstance(j, dict):
                continue   # httpx emits objects; ignore a stray array/scalar line
            n_httpx += 1
            tech = first(j, "tech", "technologies", default=[])
            if isinstance(tech, str):
                tech = [tech]
            # IP: the address httpx actually connected to. httpx >= 1.6 reports it
            # as 'host_ip' (and 'host' became the HOSTNAME); older builds put the
            # IP in 'host'/'ip'. 'a' (the resolved A set) is the fallback -- with
            # several A records its first entry need not be the one connected to.
            hx_ip = ""
            hv = j.get("host_ip", "")
            if isinstance(hv, str) and is_ipv4(hv):
                hx_ip = hv
            if not hx_ip:
                a_recs = first(j, "a", default=[])
                if isinstance(a_recs, str):
                    a_recs = [a_recs]
                hx_ip = next((x for x in a_recs if isinstance(x, str) and is_ipv4(x)), "")
            if not hx_ip:
                for k in ("ip", "host"):
                    hv = j.get(k, "")
                    if isinstance(hv, str) and is_ipv4(hv):
                        hx_ip = hv
                        break
            rec = {
                "ip":             hx_ip,
                "status_code":    first(j, "status_code", "status-code"),
                "content_length": first(j, "content_length", "content-length"),
                "webserver":      first(j, "webserver", "web-server", "server"),
                "title":          first(j, "title"),
                "technologies":   ";".join(str(t) for t in tech) if tech else "",
            }
            _in = j.get("input") or ""
            _ur = j.get("url") or ""
            _hx_recs.append((str(_in), str(_ur), rec))
except FileNotFoundError:
    pass
_hx_recs.sort(key=lambda t: (t[0], t[1], str(t[2].get("status_code", "")),
                             str(t[2].get("content_length", ""))))
for _in, _ur, rec in _hx_recs:          # tier 1a: exact input
    if _in:
        meta.setdefault(_in, rec)
for _in, _ur, rec in _hx_recs:          # tier 1b: exact url (never overrides an input)
    if _ur:
        meta.setdefault(_ur, rec)
for _in, _ur, rec in _hx_recs:          # tier 2: normalized, input before url
    for v in (_in, _ur):
        if v:
            meta_norm.setdefault(urlkey(v), rec)
for _in, _ur, rec in _hx_recs:          # tier 3: root record per host
    for v in (_in, _ur):
        if v and is_root_url(v):
            hj = _host_of(v)
            if hj:
                host_root.setdefault(hj, rec)

# --- TLS posture (tlsx): index by host:port and host; compute hygiene flags ----
def _truthy(v):
    if isinstance(v, bool): return v
    return str(v).strip().lower() in ("true", "1", "yes")

def _tls_label(v):
    k = (v or "").lower().replace("_", "").replace(" ", "").replace(".", "").replace("v", "")
    return {"ssl20": "SSL 2.0", "ssl2": "SSL 2.0", "ssl30": "SSL 3.0", "ssl3": "SSL 3.0",
            "tls10": "TLS 1.0", "tls11": "TLS 1.1", "tls12": "TLS 1.2", "tls13": "TLS 1.3"}.get(k, v or "")

def _weak_version(v):
    k = (v or "").lower().replace("_", "").replace(" ", "").replace(".", "").replace("v", "")
    return k in ("ssl20", "ssl2", "ssl30", "ssl3", "tls10", "tls11")

def _weak_cipher(c):
    c = (c or "").upper()
    return any(w in c for w in ("RC4", "3DES", "DES", "NULL", "EXPORT", "ANON", "ADH", "AECDH", "MD5"))

def _days_until(s):
    s = (s or "").strip()
    if not s: return None
    now = datetime.datetime.now(datetime.timezone.utc)   # tz-aware; avoids deprecated utcnow()
    try:
        dt = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return (dt - now).days
    except Exception:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.datetime.strptime(s[:len(fmt) + 2], fmt).replace(tzinfo=datetime.timezone.utc)
            return (dt - now).days
        except Exception:
            continue
    return None

def _posture(rec):
    neg_ver = first(rec, "tls_version", "version")
    cipher  = first(rec, "cipher", "cipher_suite")
    not_after = first(rec, "not_after", "notafter")
    issuer = first(rec, "issuer_org", "issuer_cn", "issuer_dn")
    if isinstance(issuer, list): issuer = issuer[0] if issuer else ""
    flags = []
    venum = first(rec, "version_enum", "versions_enum", "tls_version_enum", default=[])
    if isinstance(venum, str): venum = [venum]
    if any(_weak_version(v) for v in ([neg_ver] + list(venum))):
        flags.append("WeakTLS")
    ciphers = []
    cenum = first(rec, "cipher_enum", "ciphers_enum", default=[])
    if isinstance(cenum, list):
        for e in cenum:
            if isinstance(e, dict):
                cs = e.get("ciphers") or e.get("cipher_list") or []
                ciphers += cs if isinstance(cs, list) else [cs]
            elif isinstance(e, str):
                ciphers.append(e)
    if cipher: ciphers.append(cipher)
    weak_ciphers = sorted({c for c in ciphers if c and _weak_cipher(c)})
    if weak_ciphers: flags.append("WeakCipher")
    if _truthy(rec.get("expired")):
        flags.append("CertExpired")
    elif not_after:
        d = _days_until(not_after)
        if d is not None and 0 <= d <= int(os.environ.get("CERT_WARN_DAYS") or 30): flags.append("CertExpiring")
    if _truthy(rec.get("self_signed")):   flags.append("SelfSigned")
    if _truthy(rec.get("mismatched")):    flags.append("CertNameMismatch")
    if _truthy(rec.get("untrusted")):     flags.append("CertUntrusted")
    if _truthy(rec.get("revoked")):       flags.append("CertRevoked")
    if _truthy(rec.get("wildcard_certificate")) or _truthy(rec.get("wildcard_cert")):
        flags.append("Wildcard")
    return {"tls_version": _tls_label(neg_ver),
            "tls_cipher": cipher or (";".join(weak_ciphers) if weak_ciphers else ""),
            "cert_not_after": not_after or "", "cert_issuer": issuer or "",
            "tls_flags": ";".join(flags)}

tls_by_hp, tls_by_host = {}, {}
if tlsx_path:
    try:
        with open(tlsx_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line: continue
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                if not isinstance(j, dict): continue
                h = (j.get("host") or "").lower()
                p = str(j.get("port") or "")
                pv = _posture(j)
                if h and p: tls_by_hp.setdefault(h + ":" + p, pv)
                if h:       tls_by_host.setdefault(h, pv)
    except FileNotFoundError:
        pass

rows, seen = [], set()
n_enriched = 0
try:
    with open(map_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            seed, url = parts[0], parts[1]
            sources = parts[2] if len(parts) > 2 else ""
            key = (seed, url)
            if key in seen:
                continue
            seen.add(key)
            try:
                host = urlparse(url).hostname or ""
            except Exception:
                host = ""
            # exact -> normalized -> (root URLs only) the host's root record. A deep
            # URL httpx returned nothing for stays unenriched rather than wearing
            # another page's status/title.
            m = (meta.get(url) or meta_norm.get(urlkey(url))
                 or (host_root.get(host.lower()) if is_root_url(url) else None) or {})
            if m:
                n_enriched += 1
            httpx_ip = m.get("ip", "")
            ip = httpx_ip if is_ipv4(httpx_ip) else ""
            asn, asn_org = lookup_asn(ip)
            # TLS posture for https URLs (match host:port, default 443, then host)
            tls = {}
            try:
                pr = urlparse(url)
                if (pr.scheme or "").lower() == "https":
                    hh = (pr.hostname or "").lower()
                    tls = tls_by_hp.get(hh + ":" + str(pr.port or 443)) or tls_by_host.get(hh) or {}
            except Exception:
                tls = {}
            rows.append([
                seed, url, host, sources,
                m.get("status_code", ""),
                m.get("content_length", ""),
                m.get("webserver", ""),
                m.get("title", ""),
                m.get("technologies", ""),
                ip, asn, asn_org,
                tls.get("tls_version", ""), tls.get("tls_cipher", ""),
                tls.get("cert_not_after", ""), tls.get("cert_issuer", ""),
                tls.get("tls_flags", ""),
                _aaaa.get(host.lower(), ""),   # ipv6 (AAAA)
                lookup_cloud(ip),              # cloud provider
                lookup_rdap(ip),               # RDAP network org
                lookup_geo(ip),                # geo (country ISO)
                build_cpes(m.get("technologies", ""), m.get("webserver", "")),  # cpe (FPV-06)
            ])
except FileNotFoundError:
    pass

rows.sort(key=lambda r: (r[0], r[1]))
# FPV-01: titles, headers, org names and certificate issuers come from the scanned site
# or third parties; a cell starting with = + - @ (or tab/CR) is a live formula in Excel.
# Those text cells get a leading apostrophe; generate-report.sh and recon-db.sh import
# strip it again. Numeric and fixed-format columns are left alone.
_GUARD_COLS = {0, 1, 2, 3, 6, 7, 8, 11, 13, 15, 18, 19, 20, 21}
def _csv_safe(v):
    v = "" if v is None else str(v)
    return ("'" + v) if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v
rows = [[(_csv_safe(c) if i in _GUARD_COLS else c) for i, c in enumerate(r)] for r in rows]
with open(out_path, "w", newline="", encoding="utf-8") as fo:
    w = csv.writer(fo)
    w.writerow(["seed_domain", "url", "host", "sources",
                "status_code", "content_length", "webserver", "title", "technologies",
                "ip", "asn", "asn_org",
                "tls_version", "tls_cipher", "cert_not_after", "cert_issuer", "tls_flags",
                "ipv6", "cloud", "rdap_org", "geo", "cpe"])
    w.writerows(rows)

live = sum(1 for r in rows if str(r[4]).startswith(("2", "3", "401", "403")))
# persist the (warm + newly-resolved) ASN cache back to the handoff file so
# run-recon can sync it into the DB for the next run.
if _asn_cache_file:
    try:
        with open(_asn_cache_file, "w", encoding="utf-8") as _f:
            for _ip, (_a, _o) in _asn_cache.items():
                if _ip in _asn_loaded:
                    continue   # unchanged warm entry -- already in the DB
                _f.write((f"{_ip}\t{_a} {_o}").rstrip() + "\n")
    except Exception:
        pass
# same handoff for newly-resolved RDAP orgs
if _rf:
    try:
        with open(_rf, "w", encoding="utf-8") as _f:
            for _ip, _o in _rdap_cache.items():
                if _ip in _rdap_loaded or not _o:
                    continue
                _f.write(f"{_ip}\t{_o}\n")
    except Exception:
        pass
print(f"ROWS={len(rows)}")
print(f"LIVE={live}")
print(f"HTTPX_RECS={n_httpx}")
print(f"ENRICHED={n_enriched}")
# Diagnose an empty-enrichment situation so it isn't silent.
if rows and n_enriched == 0:
    if n_httpx == 0:
        sys.stderr.write(
            "[!] enrichment: httpx produced 0 JSON records, so columns E-L are empty. "
            "Check $WORKDIR/httpx.jsonl and that 'httpx' is ProjectDiscovery's httpx-toolkit "
            "(not python3-httpx at /usr/bin/httpx).\n")
    else:
        _sample_meta = next(iter(meta), "")
        _sample_map = rows[0][1] if rows else ""
        sys.stderr.write(
            "[!] enrichment: parsed %d httpx record(s) but NONE matched the %d crawled URL(s) -- "
            "the URL join failed. Example httpx key=%r vs crawled url=%r.\n"
            % (n_httpx, len(rows), _sample_meta, _sample_map))
elif rows and n_enriched < len(rows):
    sys.stderr.write("[*] enrichment: %d/%d URL rows enriched from httpx (%d had no match).\n"
                     % (n_enriched, len(rows), len(rows) - n_enriched))
PY

# sync the aggregator's (refreshed) ASN cache back into the DB for next time
if [ "$USE_DB" = "1" ] && [ "$ASN" = "1" ] && [ -s "$ASN_CACHE_FILE" ]; then
  db_bulk_cache asn "$ASN_CACHE_FILE" || true   # one statement for all newly-resolved IPs
fi

# sync the aggregator's (refreshed) RDAP-org cache back into the DB for next time
if [ "$USE_DB" = "1" ] && [ "$ENRICH" = "1" ] && [ -s "$RDAP_CACHE_FILE" ]; then
  db_bulk_cache rdap_ip "$RDAP_CACHE_FILE" || true
fi

# --- summary ---------------------------------------------------------------
RES_ROWS="$(grep -c '^' "$OUTPUT" 2>/dev/null || true)"; RES_ROWS="${RES_ROWS:-1}"
RES_ROWS=$((RES_ROWS>0 ? RES_ROWS-1 : 0))   # minus header
echo >&2
ok "=============================================================="
if [ "$RES_ROWS" -gt 0 ]; then
  ok " Complete."
else
  # nothing came back: say so, and exit 3 so a scheduled run or a script notices
  warn " Finished with NO results: 0 URL rows. See the warnings above (DNS, resolve gate, live probe)."
  RUN_EXIT=3
fi
ok " Domains processed : $NDOM"
ok " URL rows written  : $RES_ROWS"
ok " CSV               : $OUTPUT"
ok "=============================================================="

# --- aggregate opt-in side artifacts (takeover/origin/nuclei/params/secrets) -
for kind in takeover origin nuclei params secrets buckets cms activescan osint virustotal urlscan social; do
  if ls "$WORKDIR"/parts/"$kind".*.txt >/dev/null 2>&1; then
    cat "$WORKDIR"/parts/"$kind".*.txt 2>/dev/null | sort -u > "$OUTPUT.$kind.txt" || : > "$OUTPUT.$kind.txt"
    if [ -s "$OUTPUT.$kind.txt" ]; then
      ok " ${kind} findings : $OUTPUT.$kind.txt ($(wc -l < "$OUTPUT.$kind.txt" | tr -d ' ') line(s))"
    else
      rm -f "$OUTPUT.$kind.txt"
    fi
  fi
done
# edge / origin attributes from --origin (one row per live host)
if ls "$WORKDIR"/parts/edge.*.tsv >/dev/null 2>&1; then
  { printf 'seed_domain\thost\tedge\torigin_software\tedge_evidence\tjarm\tcdn\tfavicon_mmh3\ttitle\tedge_ip\n'
    cat "$WORKDIR"/parts/edge.*.tsv | sort -u; } > "$OUTPUT.edge.tsv"
  ok " edge / origin   : $OUTPUT.edge.tsv ($(( $(wc -l < "$OUTPUT.edge.tsv") - 1 )) host(s))"
fi
# zone exposure: findings and the harvested names
if [ "$ZONE_EXPOSURE" = "1" ]; then
  [ -s "$WORKDIR/parts/zone.all.txt" ] && cp "$WORKDIR/parts/zone.all.txt" "$OUTPUT.zone.txt" \
    && ok " zone exposure   : $OUTPUT.zone.txt ($(grep -c . "$OUTPUT.zone.txt") line(s))"
  if [ -s "$WORKDIR/zone_names.txt" ]; then
    { printf 'zone\tname\tsource\n'; cat "$WORKDIR/zone_names.txt"; } > "$OUTPUT.zone-names.txt"
    ok " zone names      : $OUTPUT.zone-names.txt ($(grep -c . "$WORKDIR/zone_names.txt") name(s))"
  fi
fi
# CNAME inventory from --takeover (every candidate with a CNAME, dangling or not)
if ls "$WORKDIR"/parts/cname.*.tsv >/dev/null 2>&1; then
  { printf 'seed_domain\thost\tcname_chain\tdns\tprovider\n'; cat "$WORKDIR"/parts/cname.*.tsv | sort -u; } > "$OUTPUT.cname.tsv"
  if [ "$(wc -l < "$OUTPUT.cname.tsv")" -gt 1 ]; then
    ok " cname inventory : $OUTPUT.cname.tsv ($(( $(wc -l < "$OUTPUT.cname.tsv") - 1 )) name(s) with a CNAME)"
  else
    rm -f "$OUTPUT.cname.tsv"
  fi
fi
SHOTDIR="$(dirname "$OUTPUT")/screenshots-$TS"
if [ -d "$WORKDIR/screenshots" ] && [ -n "$(ls -A "$WORKDIR/screenshots" 2>/dev/null)" ]; then
  mv "$WORKDIR/screenshots" "$SHOTDIR" 2>/dev/null && ok " screenshots     : $SHOTDIR/"
fi
# screenshot manifest: one row per host the stage was asked for, so the report never
# shows an empty image or someone else's page as the site.
#   ok       an image of the page that was probed
#   blank    the page itself is empty (0-byte body), so the image is too
#   failed   no image, or an empty image of a page that has content
#   suspect  the browser rendered a different title than the probe saw, or the image is
#            identical to the one of a host with a different title (e.g. a proxy error page)
if [ "$SCREENSHOTS" = "1" ] && ls "$WORKDIR"/parts/ss.*.tsv >/dev/null 2>&1; then
  cat "$WORKDIR"/parts/ss.*.tsv > "$WORKDIR/ss_all.tsv" 2>/dev/null || : > "$WORKDIR/ss_all.tsv"
  python3 - "$WORKDIR/ss_all.tsv" "$SHOTDIR" "$OUTPUT.screenshots.tsv" <<'PYSSM' 2>/dev/null || warn " screenshot manifest could not be written"
import sys, os, re, hashlib, glob
src, shotdir, out = sys.argv[1:4]
def norm(x):
    return re.sub(r"[^a-z0-9]+", "", (x or "").lower())
rows = {}
for line in open(src, encoding="utf-8", errors="replace"):
    f = (line.rstrip("\n").split("\t") + [""] * 6)[:6]
    if f[0] and (f[0] not in rows or (not rows[f[0]][0] and f[1])):
        rows[f[0]] = f[1:]
imgs = glob.glob(os.path.join(shotdir, "**", "*.png"), recursive=True) if os.path.isdir(shotdir) else []
res = {}
for h, (rel, pt, bt, flag, blen) in sorted(rows.items()):
    path = os.path.join(shotdir, rel) if rel else ""
    if not rel or not os.path.isfile(path):
        # gowitness, or a layout we did not record: match the file by host name
        nh = norm(h)
        cand = [p for p in imgs if nh and nh in norm(os.path.relpath(p, shotdir))]
        if cand:
            path = min(cand, key=len); rel = os.path.relpath(path, shotdir)
        else:
            path = ""
    size = os.path.getsize(path) if path and os.path.isfile(path) else 0
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest() if size else ""
    if not path:
        st, why = "failed", "no image"
    elif size == 0 and blen == "0":
        st, why = "blank", "the page is empty (0-byte body): nothing to capture"
    elif size == 0:
        st, why = "failed", "empty image (0 bytes)"
    elif flag == "cached":
        st, why = "ok", "from the cache"
    elif pt and bt and pt.lower() != bt.lower():
        st, why = "suspect", "browser rendered '%s', the probe saw '%s'" % (bt[:80], pt[:80])
    else:
        st, why = "ok", ""
    res[h] = [rel, st, why, size, digest, pt]
by = {}
for h, r in res.items():
    if r[4]:
        by.setdefault(r[4], []).append(h)
for d, hs in by.items():
    if len(hs) > 1 and len(set(t for t in (res[h][5].lower() for h in hs) if t)) > 1:
        for h in hs:
            if res[h][1] == "ok":
                res[h][1] = "suspect"
                res[h][2] = "same image as %s, whose page differs" % ", ".join(x for x in sorted(hs) if x != h)[:200]
with open(out, "w", encoding="utf-8") as o:
    o.write("host\tfile\tstatus\treason\tbytes\n")
    for h in sorted(res):
        r = res[h]
        o.write("%s\t%s\t%s\t%s\t%d\n" % (h, r[0], r[1], r[2], r[3]))
PYSSM
  if [ -s "$OUTPUT.screenshots.tsv" ]; then
    _ssok="$(awk -F'\t' 'NR>1 && $3=="ok"' "$OUTPUT.screenshots.tsv" | wc -l | tr -d ' ')"
    _ssblank="$(awk -F'\t' 'NR>1 && $3=="blank"' "$OUTPUT.screenshots.tsv" | wc -l | tr -d ' ')"
    _ssbad="$(awk -F'\t' 'NR>1 && ($3=="failed" || $3=="suspect")' "$OUTPUT.screenshots.tsv" | wc -l | tr -d ' ')"
    ok " screenshot list : $OUTPUT.screenshots.tsv ($_ssok ok, $_ssblank blank page(s), $_ssbad failed or suspect)"
    [ "$_ssbad" -gt 0 ] && warn " $_ssbad screenshot(s) failed or do not show the probed page (see the status column)."
  fi
fi

# --- monitoring: diff discovered URLs against a prior CSV -------------------
if [ "$MONITOR" = "1" ]; then
  PREV="$MONITOR_PREV"
  if [ -z "$PREV" ]; then
    # newest recon-*.csv in the output dir, excluding the current run (no ls parsing)
    _pv_newest=""; _pv_dir="$(dirname "$OUTPUT")"
    for _pv_f in "$_pv_dir"/recon-*.csv; do
      [ -f "$_pv_f" ] && [ "$_pv_f" != "$OUTPUT" ] || continue
      if [ -z "$_pv_newest" ] || [ "$_pv_f" -nt "$_pv_newest" ]; then _pv_newest="$_pv_f"; fi
    done
    PREV="$_pv_newest"
  fi
  if [ -n "$PREV" ] && [ -f "$PREV" ]; then
    NEWASSETS="$OUTPUT.new-assets.txt"
    comm -13 <(tail -n +2 "$PREV" 2>/dev/null | cut -d, -f2 | sort -u) \
             <(tail -n +2 "$OUTPUT" 2>/dev/null | cut -d, -f2 | sort -u) > "$NEWASSETS" 2>/dev/null || : > "$NEWASSETS"
    NN="$(wc -l < "$NEWASSETS" | tr -d ' ')"
    if [ "$NN" -gt 0 ]; then
      ok " Monitoring      : $NN new asset(s) vs $(basename "$PREV") -> $NEWASSETS"
      if [ "$NOTIFY" = "1" ] && have notify; then notify -silent < "$NEWASSETS" 2>/dev/null || true; fi
    else
      rm -f "$NEWASSETS"; ok " Monitoring      : no new assets vs $(basename "$PREV")."
    fi
  else
    warn " --monitor: no prior CSV to diff against (pass --monitor-prev FILE)."
  fi
fi

# --- persist this run's host inventory into the DB (for later reference) ----
if [ "$USE_DB" = "1" ]; then
  if db_load_csv "$OUTPUT" "$TS"; then
    ok " DB store        : loaded $RES_ROWS host row(s) into recon_hosts (run_ts=$TS)."
  else
    warn " DB store: could not load the CSV into recon_hosts (continuing)."
  fi
fi

# --- run record: what produced this output (the report's run header) ------------
# <out>.run.json: version, command line (proxy credentials redacted), seeds, tool
# versions, resolvers and their check, counts per seed and per artifact, warnings,
# duration and exit status.
RUN_T1="$(date +%s 2>/dev/null || echo 0)"
cat "$WORKDIR"/parts/seedstat.*.tsv 2>/dev/null > "$WORKDIR/seedstat.tsv" || : > "$WORKDIR/seedstat.tsv"
RUN_RESOLVERS_N=0; [ -n "$RESOLVERS" ] && [ -s "$RESOLVERS" ] && RUN_RESOLVERS_N="$(grep -cvE '^\s*(#|$)' "$RESOLVERS" || true)"
if [ "${#RUN_ARGS[@]}" -gt 0 ]; then printf '%s\0' "${RUN_ARGS[@]}" > "$WORKDIR/run_args.bin"; else : > "$WORKDIR/run_args.bin"; fi
RR_VERSION="$VERSION" RR_STARTED="$RUN_STARTED" RR_DURATION="$(( RUN_T1 - RUN_T0 ))" RR_INPUT="$INPUT" \
RR_NDOM="${NDOM:-0}" RR_TOOLVERS="${_tvline:-}" RR_LABVER="${LAB_VERIFIED:-}" RR_RESOLVERS="$RESOLVERS" \
RR_RESOLVERS_N="$RUN_RESOLVERS_N" RR_DNS_CHECK="$RUN_DNS_CHECK" RR_PROXY="$PROXY" RR_SS_CHROME="$SS_CHROME" \
RR_SS_PROXY="$SS_PROXY_SERVER" RR_SS_BYPASS="$SS_PROXY_BYPASS" RR_ROWS="$RES_ROWS" RR_EXIT="$RUN_EXIT" \
python3 - "$OUTPUT" "$WORKDIR" <<'PYRUN' 2>/dev/null || warn " could not write $OUTPUT.run.json"
import sys, json, os, re
out, wd = sys.argv[1:3]
E = os.environ.get
def red(x):
    return re.sub(r"(://)[^/@\s]*@", r"\1***@", x or "")
def num(v):
    return int(v) if (v or "").isdigit() else None
raw = open(os.path.join(wd, "run_args.bin"), "rb").read().decode("utf-8", "replace")
args = [red(a) for a in raw.split("\0")[:-1]] if raw else []
seeds = []
for line in open(os.path.join(wd, "seedstat.tsv"), encoding="utf-8", errors="replace"):
    f = line.rstrip("\n").split("\t")
    if len(f) >= 4:
        seeds.append({"seed": f[0], "candidates": num(f[1]), "resolved": num(f[2]), "live_hosts": num(f[3])})
arts = {}
for k in ("takeover", "origin", "zone", "nuclei", "params", "secrets", "buckets", "cms", "activescan",
          "osint", "virustotal", "urlscan", "social"):
    p = "%s.%s.txt" % (out, k)
    if os.path.isfile(p):
        arts[k] = sum(1 for l in open(p, encoding="utf-8", errors="replace") if l.strip())
for k, p in (("edge_hosts", out + ".edge.tsv"), ("cname_names", out + ".cname.tsv"),
             ("zone_names", out + ".zone-names.txt"), ("screenshots", out + ".screenshots.tsv")):
    if os.path.isfile(p):
        arts[k] = max(0, sum(1 for l in open(p, encoding="utf-8", errors="replace") if l.strip()) - 1)
warns = []
wf = os.path.join(wd, "warnings.txt")
if os.path.isfile(wf):
    for l in open(wf, encoding="utf-8", errors="replace"):
        l = red(re.sub(r"\x1b\[[0-9;]*m", "", l).strip())
        if l and l not in warns:
            warns.append(l)
tv = {}
for part in (E("RR_TOOLVERS") or "").split(","):
    f = part.split()
    if len(f) == 2:
        tv[f[0]] = f[1]
rec = {
    "tool": "run-recon", "version": E("RR_VERSION", ""),
    "args": args,
    "started": E("RR_STARTED", ""), "duration_s": max(0, num(E("RR_DURATION")) or 0),
    "input": E("RR_INPUT", ""), "seeds": len(seeds) or (num(E("RR_NDOM")) or 0), "per_seed": seeds,
    "tool_versions": tv, "lab_verified": E("RR_LABVER", ""),
    "resolvers": {"file": E("RR_RESOLVERS", ""), "count": num(E("RR_RESOLVERS_N")) or 0, "check": E("RR_DNS_CHECK", "")},
    "proxy": red(E("RR_PROXY")),
    "screenshot_browser": {"system_chrome": E("RR_SS_CHROME") == "1", "proxy_server": red(E("RR_SS_PROXY")),
                           "bypass_list": bool(E("RR_SS_BYPASS"))},
    "url_rows": num(E("RR_ROWS")) or 0, "artifacts": arts,
    "warnings": warns[:200], "warnings_total": len(warns),
    "exit_status": num(E("RR_EXIT")) or 0,
}
with open(out + ".run.json", "w", encoding="utf-8") as f:
    json.dump(rec, f, indent=2)
    f.write("\n")
PYRUN
[ -s "$OUTPUT.run.json" ] && ok " run record      : $OUTPUT.run.json"

# --- HTML report: tie hosts + findings + screenshots together --------------
if [ "$REPORT" = "1" ]; then
  RPT="$RECON_DIR/generate-report.sh"
  [ -f "$RPT" ] || RPT="$(command -v generate-report.sh 2>/dev/null || true)"
  if [ -n "$RPT" ] && [ -f "$RPT" ]; then
    # generate-report.sh auto-detects the screenshots-$TS/ dir next to the CSV
    if bash "$RPT" -o "$OUTPUT.report.html" "$OUTPUT" >/dev/null 2>&1; then
      ok " HTML report     : $OUTPUT.report.html"
    else
      warn " HTML report generation failed (run '$RPT $OUTPUT' manually to see why)."
    fi
  else
    warn " generate-report.sh not found next to run-recon; skipping the HTML report (--no-report to silence)."
  fi
fi

if [ "$KEEP_WORK" = "1" ]; then
  log "Intermediate artifacts kept in: $WORKDIR"
else
  rm -rf "$WORKDIR" 2>/dev/null || true
fi
exit "$RUN_EXIT"
