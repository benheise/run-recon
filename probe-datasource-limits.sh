#!/usr/bin/env bash
# =============================================================================
# probe-datasource-limits.sh  --  rate-limit & timeout discovery for OSINT/EASM
#                                 data sources (companion to DATA-SOURCES.md).
#
# Many external-recon data sources start to time out or return 429/403 after
# only a few requests. This script empirically derives, per source:
#   * a safe per-request TIMEOUT   (from measured latency: p95 x margin)
#   * a safe inter-request DELAY   (from declared rate-limit headers and/or a
#                                   gentle rate ramp that stops at the first
#                                   throttle and backs off)
# and can emit those as sourceable NAME_TIMEOUT / NAME_DELAY variables for your
# fetchers.
#
# SAFE BY DESIGN: small sample counts, slow->fast ramp that STOPS at the first
# throttle (never probes faster than a failing rate), honors Retry-After, and
# supports --polite (headers + latency only, no ramp). Probing still consumes
# quota -- point it at endpoints you're allowed to hit.
#
# Usage:
#   ./probe-datasource-limits.sh                       # probe built-in key-free endpoints
#   ./probe-datasource-limits.sh --recon-osint         # probe the exact Outcrop OSINT endpoints
#   ./probe-datasource-limits.sh --url URL             # probe one URL
#   ./probe-datasource-limits.sh --file sources.tsv    # 'name<TAB>url' per line ('#' comments ok)
#   ./probe-datasource-limits.sh --file s.tsv -H "x-apikey: $VT_KEY" --emit-config limits.env
#   ./probe-datasource-limits.sh --url URL --polite    # no ramp (headers + latency only)
#
# Wire into Outcrop (drives --osint/--virustotal/--urlscan timeouts+delays):
#   export VT_API_KEY=... URLSCAN_API_KEY=...           # optional; enables authed presets
#   ./probe-datasource-limits.sh --recon-osint --emit-config limits.env
#   outcrop -i domains.txt --osint --virustotal --urlscan --limits limits.env
#
# Options:
#   --recon-osint          probe the endpoints Outcrop's OSINT stages hit (rdap, shodan
#                          internetdb, virustotal, urlscan) and emit Outcrop's var names.
#                          Authed presets auto-attach headers when VT_API_KEY / URLSCAN_API_KEY set.
#   --sample-domain DOM    domain to probe RDAP/VirusTotal/urlscan with (default example.com)
#   --sample-ip IP         IP to probe Shodan InternetDB with (default 1.1.1.1)
#   --url URL              probe a single URL (repeatable)
#   --file FILE            TSV/space file of 'name  url' lines
#   -H, --header "H: V"    header applied to every request (repeatable; e.g. API keys)
#   --samples N            latency samples (default 6)
#   --ceiling SECS         hard per-request cap / max timeout to recommend (default 20)
#   --safe-delay SECS      spacing during the latency probe (default 1.5)
#   --burst N              requests per ramp step (default 5)
#   --polite               skip the rate ramp (headers + latency only)
#   --emit-config FILE     also write NAME_TIMEOUT/NAME_DELAY lines here ('-' = stdout)
#   --json                 emit machine-readable JSON to stdout
#   -h, --help             this help
#
# Exit: 0 always (diagnostic). Requires: curl, awk, sort, sleep (GNU).
# =============================================================================
set -uo pipefail

C() { [ -t 2 ] && printf '%s' "$1" || printf ''; }
B=$(C $'\033[1m'); DIM=$(C $'\033[2m'); R=$(C $'\033[0m')
GRN=$(C $'\033[1;32m'); YEL=$(C $'\033[1;33m'); CYN=$(C $'\033[1;36m')
log()  { printf '%s[*]%s %s\n' "$CYN" "$R" "$*" >&2; }
warn() { printf '%s[!]%s %s\n' "$YEL" "$R" "$*" >&2; }

UA="probe-datasource-limits/1.0 (+recon rate discovery)"
SAMPLES=6; CEIL=20; SAFE_DELAY=1.5; BURST=5; POLITE=0; EMIT=""; JSON=0; COOLDOWN=2
RECON=0; SAMPLE_DOMAIN="example.com"; SAMPLE_IP="1.1.1.1"
declare -a HDRARGS=() URLS=() NAMES=() FILES=() SHDRS=() VPREFIX=() CUR_HDRS=()

# ramp spacing, SLOW -> FAST (seconds). The ramp stops at the first throttle,
# so it never sends faster than a rate that already failed.
RAMP_DELAYS=(2.0 1.0 0.5 0.25 0.1)

usage() { sed -n '2,51p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --recon-osint)   RECON=1; shift;;
    --sample-domain) SAMPLE_DOMAIN="$2"; shift 2;;
    --sample-ip)     SAMPLE_IP="$2"; shift 2;;
    --url)         URLS+=("$2"); NAMES+=(""); SHDRS+=(""); VPREFIX+=(""); shift 2;;
    --file)        FILES+=("$2"); shift 2;;
    -H|--header)   HDRARGS+=(-H "$2"); shift 2;;
    --samples)     SAMPLES="$2"; shift 2;;
    --ceiling)     CEIL="$2"; shift 2;;
    --safe-delay)  SAFE_DELAY="$2"; shift 2;;
    --burst)       BURST="$2"; shift 2;;
    --polite)      POLITE=1; shift;;
    --emit-config) EMIT="$2"; shift 2;;
    --json)        JSON=1; shift;;
    -h|--help)     usage;;
    *) warn "unknown option: $1"; shift;;
  esac
done

command -v curl >/dev/null 2>&1 || { warn "curl is required"; exit 0; }

# ---- --recon-osint: the exact endpoints Outcrop's OSINT stages hit ----------
# Emits Outcrop's variable names (RDAP_/INTERNETDB_/VT_/URLSCAN_) so the output
# feeds `outcrop --limits`. Authed presets attach the right header automatically
# when the matching API key is exported (VT_API_KEY -> x-apikey, URLSCAN_API_KEY -> API-Key).
if [ "$RECON" -eq 1 ]; then
  NAMES+=("rdap");       URLS+=("https://rdap.org/domain/$SAMPLE_DOMAIN");                 SHDRS+=("");                        VPREFIX+=("RDAP")
  NAMES+=("internetdb"); URLS+=("https://internetdb.shodan.io/$SAMPLE_IP");                SHDRS+=("");                        VPREFIX+=("INTERNETDB")
  if [ -n "${VT_API_KEY:-}" ]; then
    NAMES+=("virustotal"); URLS+=("https://www.virustotal.com/api/v3/domains/$SAMPLE_DOMAIN"); SHDRS+=("x-apikey: ${VT_API_KEY}"); VPREFIX+=("VT")
  else
    warn "--recon-osint: VT_API_KEY unset -> skipping VirusTotal (Outcrop keeps VT_TIMEOUT=STAGE_TIMEOUT)."
  fi
  # urlscan works unauthenticated (lower limits); attach API-Key if provided.
  if [ -n "${URLSCAN_API_KEY:-}" ]; then
    NAMES+=("urlscan"); URLS+=("https://urlscan.io/api/v1/search/?q=domain:$SAMPLE_DOMAIN"); SHDRS+=("API-Key: ${URLSCAN_API_KEY}"); VPREFIX+=("URLSCAN")
  else
    NAMES+=("urlscan"); URLS+=("https://urlscan.io/api/v1/search/?q=domain:$SAMPLE_DOMAIN"); SHDRS+=("");                            VPREFIX+=("URLSCAN")
  fi
  warn "--recon-osint: Team Cymru (ASN) is DNS-based and tookie-osint (--social) queries many sites; neither is HTTP-rate-probed here."
  [ -z "$EMIT" ] && log "tip: re-run with --emit-config limits.env, then: outcrop --limits limits.env ..."
fi

# ---- built-in key-free endpoints (illustrative; override with --url/--file) --
if [ "${#URLS[@]}" -eq 0 ] && [ "${#FILES[@]}" -eq 0 ]; then
  NAMES=(crt_sh google_dns rdap_org urlscan_search hackertarget bgpview)
  URLS=(
    "https://crt.sh/?q=example.com&output=json"
    "https://dns.google/resolve?name=example.com&type=A"
    "https://rdap.org/domain/example.com"
    "https://urlscan.io/api/v1/search/?q=domain:example.com"
    "https://api.hackertarget.com/hostsearch/?q=example.com"
    "https://api.bgpview.io/asn/13335"
  )
  warn "No --url/--file given; probing built-in key-free endpoints (demo)."
fi

# ---- load --file entries: 'name<whitespace>url' ----------------------------
for f in ${FILES[@]+"${FILES[@]}"}; do
  [ -n "$f" ] && [ -f "$f" ] || { warn "file not found: $f"; continue; }
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%$'\r'}"
    case "$line" in ''|\#*) continue;; esac
    local_name="${line%%[[:space:]]*}"; local_url="${line#*[[:space:]]}"
    local_url="$(printf '%s' "$local_url" | sed 's/^[[:space:]]*//')"
    [ -n "$local_url" ] || continue
    NAMES+=("$local_name"); URLS+=("$local_url")
  done < "$f"
done

# derive a safe env var name from a source name/url
varname() {
  local s="$1"
  [ -n "$s" ] || s="$2"
  printf '%s' "$s" | sed -E 's#^[a-z]+://##; s#/.*$##; s#[^A-Za-z0-9]+#_#g' \
    | tr 'a-z' 'A-Z' | sed -E 's/^_+//; s/_+$//' | cut -c1-40
}

# min median p95 max n  <- numbers on stdin (nearest-rank percentiles)
_stats() {
  sort -n | awk '
    {v[NR]=$1}
    END{
      n=NR; if(n==0){print "0 0 0 0 0"; exit}
      mi=int((0.50*n)+0.999999); if(mi<1)mi=1; if(mi>n)mi=n
      pi=int((0.95*n)+0.999999); if(pi<1)pi=1; if(pi>n)pi=n
      printf "%.3f %.3f %.3f %.3f %d\n", v[1], v[mi], v[pi], v[n], n
    }'
}

# one request -> echoes "CODE TIME_TOTAL RC"; writes response headers to $1.
# Uses CUR_HDRS (global headers + the current source's authed-preset header).
probe_once() {
  local hdr="$1" url="$2" out rc=0
  out=$(curl -sS -A "$UA" ${CUR_HDRS[@]+"${CUR_HDRS[@]}"} -o /dev/null -D "$hdr" \
        --max-time "$CEIL" -w '%{http_code} %{time_total}' "$url" 2>>"$ERRLOG") || rc=$?
  if [ "$rc" -ne 0 ]; then
    # 28=timeout, 7=conn refused, 35=TLS, 6=DNS ...
    printf '%s %s %s\n' "ERR$rc" "$CEIL" "$rc"
  else
    printf '%s %s\n' "$out" 0
  fi
}

# summarize rate-limit-ish headers from a header dump into one compact string
rl_headers() {
  local hdr="$1" out=""
  local h v
  for h in retry-after x-ratelimit-limit x-ratelimit-remaining x-ratelimit-reset \
           ratelimit-limit ratelimit-remaining ratelimit-reset \
           x-rate-limit-limit x-rate-limit-remaining x-rate-limit-reset; do
    v=$(grep -i "^${h}:" "$hdr" 2>/dev/null | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^[[:space:]]*//')
    [ -n "$v" ] && out="${out}${out:+ }${h}=${v}"
  done
  printf '%s' "$out"
}
retry_after() { grep -i '^retry-after:' "$1" 2>/dev/null | head -1 | cut -d: -f2- | tr -d '\r ' ; }

is_throttle() { case "$1" in 429|403|503|509|529|ERR28|ERR7|ERR35) return 0;; *) return 1;; esac; }

WORK=$(mktemp -d 2>/dev/null || echo /tmp/probe.$$); mkdir -p "$WORK"
ERRLOG="$WORK/curl.err"; : > "$ERRLOG"
trap 'rm -rf "$WORK" 2>/dev/null' EXIT

printf '\n%s== data-source rate/timeout discovery ==%s  %ssamples=%s ceiling=%ss ramp=%s%s\n\n' \
  "$B" "$R" "$DIM" "$SAMPLES" "$CEIL" "$([ "$POLITE" = 1 ] && echo off || echo on)" "$R" >&2

CFG=""; JROWS=""
EXPORT_PREFIX=""; [ "$RECON" -eq 1 ] && EXPORT_PREFIX="export "
for i in "${!URLS[@]}"; do
  url="${URLS[$i]}"; name="${NAMES[$i]:-}"; shdr="${SHDRS[$i]:-}"; vpre="${VPREFIX[$i]:-}"
  vn="${vpre:-$(varname "$name" "$url")}"
  disp="${name:-$vn}"
  # per-source header set = global -H headers + this source's authed-preset header
  CUR_HDRS=(${HDRARGS[@]+"${HDRARGS[@]}"}); [ -n "$shdr" ] && CUR_HDRS+=(-H "$shdr")
  authed=""; [ -n "$shdr" ] && authed=" ${GRN}[authed]${R}"
  printf '%s%s%s%s  %s%s%s\n' "$B" "$disp" "$R" "$authed" "$DIM" "$url" "$R" >&2

  # --- phase 1: latency + header probe (gentle, spaced) ---
  times="$WORK/t.$i"; : > "$times"; hdr="$WORK/h.$i"; codes=""
  timeouts=0; n=0
  while [ "$n" -lt "$SAMPLES" ]; do
    read -r code t _rc < <(probe_once "$hdr" "$url")
    codes="${codes}${codes:+,}${code}"
    case "$code" in ERR28) timeouts=$((timeouts+1));; esac
    case "$code" in ERR*) : ;; *) printf '%s\n' "$t" >> "$times";; esac
    n=$((n+1)); [ "$n" -lt "$SAMPLES" ] && sleep "$SAFE_DELAY"
  done
  read -r mn med p95 mx cnt < <(_stats < "$times")
  rlh="$(rl_headers "$hdr")"

  # --- phase 2: gentle rate ramp (slow -> fast; stop at first throttle) ---
  rec_delay=""; ramp_note=""
  if [ "$POLITE" -eq 0 ]; then
    # let the source's rate window clear after the latency probe so the ramp
    # measures the ramp's own rate, not leftover load (honor any Retry-After seen)
    cool="$(retry_after "$hdr")"
    if printf '%s' "$cool" | grep -qE '^[0-9]+$' && [ "$cool" -gt 0 ]; then
      sleep "$(( cool > 15 ? 15 : cool ))"
    else
      sleep "${COOLDOWN}"
    fi
    last_good=""
    for d in "${RAMP_DELAYS[@]}"; do
      bad=0; b=0
      while [ "$b" -lt "$BURST" ]; do
        read -r code _t _rc < <(probe_once "$hdr" "$url")
        if is_throttle "$code"; then bad=1
          ra="$(retry_after "$hdr")"
          if printf '%s' "$ra" | grep -qE '^[0-9]+$'; then
            [ "$ra" -gt 0 ] && { sleep "$(( ra > 30 ? 30 : ra ))"; }
          fi
          break
        fi
        b=$((b+1)); sleep "$d"
      done
      if [ "$bad" -eq 1 ]; then
        ramp_note="throttled at ${d}s spacing (code $code)"
        break
      fi
      last_good="$d"
      sleep "$COOLDOWN"   # let the window clear before trying a faster rate
    done
    if [ -n "$last_good" ]; then
      rec_delay="$last_good"
      [ -z "$ramp_note" ] && ramp_note="no throttle down to ${last_good}s"
    else
      # even the slowest step failed -> be conservative
      ra="$(retry_after "$hdr")"
      if printf '%s' "$ra" | grep -qE '^[0-9]+$' && [ "$ra" -gt 0 ]; then rec_delay="$ra"
      else rec_delay="5"; fi
    fi
  fi

  # --- recommendations ---
  # timeout = ceil(p95 * 2), floored at 5, capped at ceiling; bumped if timeouts seen
  rec_to=$(awk -v p="$p95" -v c="$CEIL" 'BEGIN{
    v=(p*2); if(v<5)v=5; if(v>c)v=c; printf "%d", (v==int(v)?v:int(v)+1)}')
  [ "$timeouts" -gt 0 ] && rec_to="$CEIL"
  # delay: from ramp; else from headers window/limit if derivable; else default
  if [ -z "$rec_delay" ]; then
    lim=$(printf '%s' "$rlh" | grep -oiE '(x-)?ratelimit-limit=[0-9]+' | head -1 | grep -oE '[0-9]+' || true)
    rst=$(printf '%s' "$rlh" | grep -oiE '(x-)?ratelimit-reset=[0-9]+' | head -1 | grep -oE '[0-9]+' || true)
    if [ -n "${lim:-}" ] && [ -n "${rst:-}" ] && [ "$lim" -gt 0 ] && [ "$rst" -gt 0 ] && [ "$rst" -le 3600 ]; then
      rec_delay=$(awk -v r="$rst" -v l="$lim" 'BEGIN{d=(r/l)*1.3; if(d<0.2)d=0.2; printf "%.2f", d}')
    else rec_delay="1.0"; fi
  fi

  # --- report ---
  st_color="$GRN"; case "$codes" in *429*|*403*|*503*|*ERR*) st_color="$YEL";; esac
  printf '   latency  min=%ss med=%ss p95=%ss max=%ss (n=%s%s)\n' \
    "$mn" "$med" "$p95" "$mx" "$cnt" "$([ "$timeouts" -gt 0 ] && echo ", ${timeouts} timeouts")" >&2
  printf '   codes    %s%s%s\n' "$st_color" "$codes" "$R" >&2
  [ -n "$rlh" ]       && printf '   rate-hdr %s%s%s\n' "$DIM" "$rlh" "$R" >&2
  [ -n "$ramp_note" ] && printf '   ramp     %s\n' "$ramp_note" >&2
  printf '   %s=> timeout=%ss  delay=%ss%s\n\n' "$B" "$rec_to" "$rec_delay" "$R" >&2

  CFG="${CFG}${EXPORT_PREFIX}${vn}_TIMEOUT=${rec_to}"$'\n'"${EXPORT_PREFIX}${vn}_DELAY=${rec_delay}"$'\n'
  JROWS="${JROWS}${JROWS:+,}$(printf '{"name":"%s","var":"%s","url":"%s","min":%s,"median":%s,"p95":%s,"max":%s,"samples":%s,"timeouts":%s,"codes":"%s","rate_headers":"%s","rec_timeout":%s,"rec_delay":%s}' \
    "$disp" "$vn" "$url" "${mn:-0}" "${med:-0}" "${p95:-0}" "${mx:-0}" "${cnt:-0}" "$timeouts" "$codes" "$(printf '%s' "$rlh" | sed 's/"/\\"/g')" "$rec_to" "$rec_delay")"
done

# ---- emit ----
if [ "$JSON" -eq 1 ]; then printf '[%s]\n' "$JROWS"; fi

if [ -n "$EMIT" ]; then
  { printf '# generated by probe-datasource-limits.sh on %s\n' "$(date -u +%FT%TZ 2>/dev/null || date)"
    printf '# per-source recommended per-request timeout (s) and inter-request delay (s)\n'
    [ "$RECON" -eq 1 ] && printf '# load into Outcrop:  outcrop -i domains.txt --osint --virustotal --urlscan --limits %s\n' "$EMIT"
    printf '%s' "$CFG"
  } > "$([ "$EMIT" = "-" ] && echo /dev/stdout || echo "$EMIT")"
  [ "$EMIT" != "-" ] && log "wrote config -> $EMIT"
  [ "$EMIT" != "-" ] && [ "$RECON" -eq 1 ] && log "wire it in:  outcrop -i domains.txt --osint --virustotal --urlscan --limits $EMIT"
fi

log "done. Recommendations are conservative starting points -- widen delay if you still see 429/403 in production."
