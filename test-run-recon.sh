#!/usr/bin/env bash
#
# test-run-recon.sh -- mock-based test suite for run-recon.sh
#
# Installs a fake implementation of every external tool run-recon.sh calls
# (subfinder, gau, waybackurls, waymore, httpx, katana, feroxbuster, ffuf,
# uro, anew). Each mock:
#   * logs the exact arguments it received  -> assert the right FLAGS are passed
#   * emits representative output           -> assert the pipeline INGESTS it right
#
# No real recon tools or network are needed; the mocks are the tools under test's
# dependencies, so this runs anywhere (incl. this repo's CI).
#
# Usage:
#   ./test-run-recon.sh [path/to/run-recon.sh]   (defaults to ./run-recon.sh next to this file)
#
# Exit code: 0 if all assertions pass, 1 otherwise.
#
set -uo pipefail

RUN_RECON="${1:-$(cd "$(dirname "$0")" && pwd)/run-recon.sh}"
if [ ! -f "$RUN_RECON" ]; then echo "run-recon.sh not found at: $RUN_RECON" >&2; exit 2; fi

# Keep the suite independent of the ambient environment: a GITHUB_TOKEN/GH_TOKEN
# injected by the host (CI, a gh-configured shell) would otherwise make the
# "--github without a token" case see a token. Tests that need one pass a token file.
unset GITHUB_TOKEN GH_TOKEN

TMP="$(mktemp -d)"
MOCKBIN="$TMP/bin"; MOCKLOG="$TMP/log"
mkdir -p "$MOCKBIN" "$MOCKLOG"
DOMAINS="$TMP/domains.txt"; printf 'example.com\n' > "$DOMAINS"
WL="$TMP/wordlist.txt"; printf 'admin\nlogin\n' > "$WL"

# minimal SecLists tree so --activescan content discovery has lists to iterate
SECLISTS_TEST="$TMP/seclists"
mkdir -p "$SECLISTS_TEST/Discovery/Web-Content/api"
printf 'admin\napi\nbackup\n'   > "$SECLISTS_TEST/Discovery/Web-Content/raft-large-directories.txt"
printf 'index.php\n.env\n'      > "$SECLISTS_TEST/Discovery/Web-Content/raft-large-files.txt"
printf 'server-status\n'        > "$SECLISTS_TEST/Discovery/Web-Content/quickhits.txt"
printf 'v1\ngraphql\n'          > "$SECLISTS_TEST/Discovery/Web-Content/api/api-endpoints.txt"
printf 'robots.txt\n'           > "$SECLISTS_TEST/Discovery/Web-Content/common.txt"
export MOCKLOG

trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------------------
# Assertion framework
# ---------------------------------------------------------------------------
TESTS=0; PASSN=0; FAILN=0; FAILED=()
C_G=$'\033[0;32m'; C_R=$'\033[0;31m'; C_Y=$'\033[1;33m'; C_0=$'\033[0m'
_pass(){ TESTS=$((TESTS+1)); PASSN=$((PASSN+1)); printf '   %sPASS%s %s\n' "$C_G" "$C_0" "$1"; }
_fail(){ TESTS=$((TESTS+1)); FAILN=$((FAILN+1)); FAILED+=("$1"); printf '   %sFAIL%s %s\n' "$C_R" "$C_0" "$1"; }
section(){ printf '\n%s== %s ==%s\n' "$C_Y" "$1" "$C_0"; }

assert_grep(){  # <file> [--] <ERE> <msg>
  local file="$1"; shift; [ "${1:-}" = "--" ] && shift
  local pat="$1" msg="$2"
  if [ -f "$file" ] && grep -Eq -e "$pat" -- "$file"; then _pass "$msg"; else _fail "$msg  [want /$pat/ in $(basename "$file")]"; fi
}
assert_fgrep(){ # <file> [--] <fixed-string> <msg>
  local file="$1"; shift; [ "${1:-}" = "--" ] && shift
  local pat="$1" msg="$2"
  if [ -f "$file" ] && grep -Fq -e "$pat" -- "$file"; then _pass "$msg"; else _fail "$msg  [want '$pat']"; fi
}
refute_grep(){  # <file> [--] <ERE> <msg>
  local file="$1"; shift; [ "${1:-}" = "--" ] && shift
  local pat="$1" msg="$2"
  if [ -f "$file" ] && grep -Eq -e "$pat" -- "$file"; then _fail "$msg  [unexpected /$pat/]"; else _pass "$msg"; fi
}
assert_absent(){ # <file> <msg>   (file should not exist / be empty)
  if [ ! -s "$1" ]; then _pass "$2"; else _fail "$2  [$(basename "$1") unexpectedly present]"; fi
}
assert_exists(){ # <file> <msg>   (file should exist and be non-empty)
  if [ -s "$1" ]; then _pass "$2"; else _fail "$2  [$(basename "$1") missing/empty]"; fi
}

# ---------------------------------------------------------------------------
# Install mocks (each logs "$@" to $MOCKLOG/<tool>.args and emits output)
# ---------------------------------------------------------------------------
mk(){ cat > "$MOCKBIN/$1"; chmod +x "$MOCKBIN/$1"; }

mk subfinder <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/subfinder.args"; echo >> "$MOCKLOG/subfinder.args"
printf 'api.example.com\nwww.example.com\ndead.example.com\n'
EOF

mk anew <<'EOF'
#!/usr/bin/env bash
f="${1:-}"; [ -n "$f" ] && touch "$f"
while IFS= read -r l; do
  [ -z "$l" ] && continue
  if [ -n "$f" ]; then
    grep -qxF -- "$l" "$f" 2>/dev/null || { printf '%s\n' "$l" >>"$f"; printf '%s\n' "$l"; }
  else printf '%s\n' "$l"; fi
done
EOF

mk gau <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/gau.args"; echo >> "$MOCKLOG/gau.args"
while IFS= read -r h; do [ -z "$h" ] && continue; printf 'https://%s/gau-path\n' "$h"; done
printf 'https://evil-example.com/OFFSCOPE\n'   # off-scope: must be dropped by scope_filter
EOF

mk waybackurls <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/waybackurls.args"; echo >> "$MOCKLOG/waybackurls.args"
cat >/dev/null
printf 'https://example.com/wb-path\n'
EOF

mk waymore <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/waymore.args"; echo >> "$MOCKLOG/waymore.args"
out=""; while [ $# -gt 0 ]; do case "$1" in -oU) out="$2"; shift 2;; *) shift;; esac; done
[ -n "$out" ] && printf 'https://example.com/waymore-path\n' > "$out"
EOF

# httpx: modes -> -h (identity), -json (enrichment), -ss (screenshot), else (live probe)
mk httpx <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/httpx.args"; echo >> "$MOCKLOG/httpx.args"
# Reject unknown flags the way ProjectDiscovery httpx (goflags) does -- this is
# what catches an invalid flag like -a that silently blanks all enrichment.
__vf=" -timeout -rl -rate-limit -r -resolvers -l -list -o -output -srd -store-response-dir -mc -match-code -t -threads -retries -H -header -p -ports -delay -proxy -http-proxy -ho -headless-options -hash -st -screenshot-timeout -path -er -extract-regex "
__bf=" -silent -json -sc -status-code -cl -content-length -ct -content-type -title -td -tech-detect -server -web-server -ip -cname -asn -cdn -probe -ss -screenshot -system-chrome -nc -no-color -version -h -help -fr -follow-redirects -favicon -location -jarm -method -websocket -nfs -no-fallback-scheme -nf -no-fallback -esb -exclude-screenshot-bytes -ehb -exclude-headless-body -irh -include-response-header -irr -include-response -irrb -include-response-base64 "
__A=("$@"); __i=0
while [ $__i -lt ${#__A[@]} ]; do
  case "${__A[$__i]}" in
    -*) case "$__vf" in *" ${__A[$__i]} "*) __i=$((__i+1));;
          *) case "$__bf" in *" ${__A[$__i]} "*) : ;;
               *) echo "flag provided but not defined: ${__A[$__i]}" >&2; exit 1;; esac;; esac;;
  esac
  __i=$((__i+1))
done
for a in "$@"; do [ "$a" = "-h" ] && { echo "  -td, -tech-detect  display technology in use based on wappalyzer dataset"; exit 0; }; done
ss=0; for a in "$@"; do case "$a" in -ss|-screenshot) ss=1;; esac; done
if [ "$ss" = 1 ]; then
  # httpx 1.12 layout: <srd>/screenshot/<host>/<hash>.png, and with -json -o FILE one
  # record per host (screenshot_path, the probe's title, the browser's headless_body).
  # MOCK_SS_PROXYPAGE=1: the browser rendered a proxy error page (title mismatch);
  # MOCK_SS_BLANK=1: the page body is empty (0-byte image, content_length 0).
  srd=""; out=""; sl=""; sa=("$@"); si=0
  while [ $si -lt ${#sa[@]} ]; do case "${sa[$si]}" in
    -srd|-store-response-dir) si=$((si+1)); srd="${sa[$si]:-}";;
    -o|-output) si=$((si+1)); out="${sa[$si]:-}";;
    -l|-list) si=$((si+1)); sl="${sa[$si]:-}";; esac; si=$((si+1)); done
  d="${srd:-.}"; mkdir -p "$d/screenshot" 2>/dev/null
  [ -n "$sl" ] && [ -f "$sl" ] && exec < "$sl"
  while IFS= read -r h; do
    [ -z "$h" ] && continue
    mkdir -p "$d/screenshot/$h"; f="$(cd "$d/screenshot/$h" && pwd)/abc123.png"; bt="Home"; cl=100
    if [ -n "${MOCK_SS_BLANK:-}" ]; then : > "$f"; cl=0; else printf 'PNG-%s' "$h" > "$f"; fi
    [ -n "${MOCK_SS_PROXYPAGE:-}" ] && bt="Proxy Error"
    [ -n "$out" ] && printf '{"input":"%s","url":"https://%s","title":"Home","content_length":%s,"screenshot_path":"%s","screenshot_path_rel":"%s/abc123.png","headless_body":"<html><head><title>%s</title></head></html>"}\n' \
      "$h" "$h" "$cl" "$f" "$h" "$bt" >> "$out"
  done
  exit 0
fi
mode=probe; for a in "$@"; do [ "$a" = "-json" ] && mode=json; done
# when -l FILE is given, read from it; else read stdin
list=""; args=("$@"); i=0
while [ $i -lt ${#args[@]} ]; do case "${args[$i]}" in -l|-list) i=$((i+1)); list="${args[$i]:-}";; esac; i=$((i+1)); done
if [ -n "$list" ] && [ -f "$list" ]; then exec < "$list"; fi
# MOCK_HTTPX_NOLIVE=1: nothing answers the live probe
if [ "$mode" = probe ] && [ -n "${MOCK_HTTPX_NOLIVE:-}" ]; then cat >/dev/null; exit 0; fi
# --origin reference fetch (-irh): a Cloudflare edge in front of nginx; the body hash is
# that of "ORIGIN-BODY", which the curl mock returns for the leaked origin address
irh=0; fav=0; b64=0; paths=""; pa=("$@"); pi=0
while [ $pi -lt ${#pa[@]} ]; do case "${pa[$pi]}" in
  -irh|-include-response-header) irh=1;; -favicon) fav=1;; -irrb) b64=1;;
  -path) pi=$((pi+1)); paths="${pa[$pi]:-}";; esac; pi=$((pi+1)); done
# body BODY CT: a response body for -irr (JSON string) or -irrb (base64 of the raw bytes;
# BODY's escapes such as \n and \000 are expanded first)
body(){ if [ "$b64" = 1 ]; then printf '%b' "$1" | base64 -w0; else printf '%s' "$1"; fi; }
rec(){ # URL PATH STATUS CONTENT-TYPE BODY [extra JSON fields]
  printf '{"input":"%s","url":"%s%s","path":"%s","status_code":%s,"content_type":"%s",%s"body":"%s"}\n' \
    "$u" "$u" "$2" "$2" "$3" "$4" "${6:-}" "$(body "$5")"; }
# --extras: robots.txt (a hidden path + a wildcard rule + a sitemap), an EXPIRED security.txt,
# and a catch-all 200 for the random 404-probe path. MOCK_EXTRAS_NOSEC=1: no security.txt.
# The root page (/) and /favicon.ico (--extras 1.20, -irrb): MOCK_EXTRAS_ICON=link declares
# <link rel=icon href=/static/app.ico> (fetched in a follow-up pass), =data an inline data:
# URI icon, =html serves an HTML soft-404 as /favicon.ico (not an icon: no hash).
if [ "$mode" = json ] && [ -n "$paths" ]; then
  while IFS= read -r u; do [ -z "$u" ] && continue; u="${u%/}"
    IFS=',' read -ra PL <<< "$paths"
    for pth in "${PL[@]}"; do
      case "$pth" in
        /) case "${MOCK_EXTRAS_ICON:-}" in
             link) rec "$u" / 200 text/html '<html><head><title>Home</title><link rel="shortcut icon" href="/static/app.ico"></head></html>';;
             data) rec "$u" / 200 text/html '<html><head><link rel=icon href="data:image/png;base64,iVBOR01PQ0stREFUQS1JQ09O"></head></html>';;
             *)    rec "$u" / 200 text/html '<html><head><title>Home</title></head></html>';;
           esac;;
        /favicon.ico) if [ "${MOCK_EXTRAS_ICON:-}" = html ]; then rec "$u" "$pth" 200 text/html '<!doctype html><html>soft 404</html>'
          else rec "$u" "$pth" 200 image/x-icon '\000\000\001\000MOCK-ICON'; fi;;
        /robots.txt) rec "$u" "$pth" 200 text/plain 'User-agent: *\nDisallow: /hidden-admin/\nDisallow: /*.bak$\nSitemap: https://example.com/sitemap.xml\n';;
        /.well-known/security.txt) if [ -z "${MOCK_EXTRAS_NOSEC:-}" ]; then
            rec "$u" "$pth" 200 text/plain 'Contact: mailto:security@example.com\nExpires: 2021-01-01T00:00:00Z\n'
          else rec "$u" "$pth" 404 text/html '<html>nf</html>'; fi;;
        /security.txt) rec "$u" "$pth" 404 text/html '<html>nf</html>';;
        *) rec "$u" "$pth" 200 text/html '<html><address>Apache/2.4.41 (Ubuntu) Server</address></html>' '"webserver":"nginx","title":"Home","content_length":5,';;
      esac
    done
  done
  exit 0
fi
# follow-up icon fetch (-irrb, full URLs, no -path): the icon a root page declared
if [ "$mode" = json ] && [ "$b64" = 1 ]; then
  while IFS= read -r u; do [ -z "$u" ] && continue
    printf '{"input":"%s","url":"%s","status_code":200,"content_type":"image/png","body":"%s"}\n' "$u" "$u" "$(printf '\211PNGMOCK-LINKED-ICON' | base64 -w0)"
  done
  exit 0
fi
# favicon pass (-favicon without -irh): one favicon for every host
if [ "$mode" = json ] && [ "$fav" = 1 ] && [ "$irh" = 0 ]; then
  while IFS= read -r u; do [ -z "$u" ] && continue
    printf '{"input":"%s","url":"%s","status_code":200,"favicon":"-123456","favicon_md5":"0123456789abcdef0123456789abcdef","favicon_path":"/favicon.ico"}\n' "$u" "$u"
  done
  exit 0
fi
if [ "$mode" = json ] && [ "$irh" = 1 ] && [ "$fav" = 1 ]; then
  sha="$(printf '%s' 'ORIGIN-BODY' | sha256sum | cut -d' ' -f1)"
  while IFS= read -r u; do [ -z "$u" ] && continue
    # MOCK_REF_SERVER: a lone Server header (no CDN headers) instead of Cloudflare -> nginx
    if [ -n "${MOCK_REF_SERVER:-}" ]; then _hdr="{\"server\":\"$MOCK_REF_SERVER\"}"; else _hdr='{"server":"cloudflare, nginx/1.25.3","cf_ray":"8a1b2c3d"}'; fi
    printf '{"input":"%s","url":"%s","status_code":200,"content_length":11,"title":"Origin Test","host_ip":"104.16.1.1","favicon":"-123","hash":{"body_sha256":"%s"},"header":%s}\n' "$u" "$u" "$sha" "$_hdr"
  done
  exit 0
fi
if [ "$mode" = json ]; then
  esc='\"'    # two bytes: backslash, quote -> valid JSON escaped quote
  while IFS= read -r u; do
    [ -z "$u" ] && continue
    # MOCK_HTTPX_FLAKY=URL: no record for that URL on the first -json call only
    # (a request that failed during a load spike); MOCK_HTTPX_DEAD=URL: never.
    if [ -n "${MOCK_HTTPX_FLAKY:-}" ] && [ "$u" = "$MOCK_HTTPX_FLAKY" ] && [ ! -e "$MOCKLOG/httpx.flaky" ]; then
      : > "$MOCKLOG/httpx.flaky"; continue
    fi
    [ -n "${MOCK_HTTPX_DEAD:-}" ] && [ "$u" = "$MOCK_HTTPX_DEAD" ] && continue
    # MOCK_HTTPX_REDIRECT="URL>LOCATION": that URL answers 302 (1.20 redirect hops);
    # MOCK_HTTPX_LOGIN=URL: that URL is a login page whose form posts over http:// (-er matches)
    if [ -n "${MOCK_HTTPX_REDIRECT:-}" ] && [ "$u" = "${MOCK_HTTPX_REDIRECT%%>*}" ]; then
      printf '{"input":"%s","url":"%s","status_code":302,"location":"%s","content_length":0,"webserver":"nginx","title":"","host":"93.184.216.34","header":{"location":"%s"}}\n' "$u" "$u" "${MOCK_HTTPX_REDIRECT#*>}" "${MOCK_HTTPX_REDIRECT#*>}"
      continue
    fi
    if [ -n "${MOCK_HTTPX_LOGIN:-}" ] && [ "$u" = "$MOCK_HTTPX_LOGIN" ]; then
      printf '{"input":"%s","url":"%s","status_code":200,"content_length":50,"webserver":"nginx","title":"Login","host":"93.184.216.34","content_type":"text/html","header":{"content_type":"text/html"},"extracts":{"re":["<form method=\\"post\\" action=\\"http://example.com/session\\">","<input type=\\"password"]}}\n' "$u" "$u"
      continue
    fi
    if [ "$irh" = 1 ]; then   # 1.19 enrichment: the same request's headers, body hash and time
      printf '{"input":"%s","url":"%s","status_code":200,"content_length":100,"webserver":"nginx","title":"Home, %sMain%s","tech":["nginx","PHP"],"host":"93.184.216.34","time":"12.5ms","content_type":"text/html","hash":{"body_sha256":"%064d"},"header":{"server":"nginx","content_type":"text/html; charset=utf-8","x_frame_options":"DENY","set_cookie":"sessionid=abc; Path=/; HttpOnly, theme=dark; Expires=Thu, 01 Jan 2030 00:00:00 GMT; Secure; HttpOnly","alt_svc":"h3=\\\":443\\\"; ma=86400","x_powered_by":"PHP/8.1.2"}}\n' "$u" "$u" "$esc" "$esc" 7
    else
      printf '{"input":"%s","url":"%s","status_code":200,"content_length":100,"webserver":"nginx","title":"Home, %sMain%s","tech":["nginx","PHP"],"host":"93.184.216.34"}\n' "$u" "$u" "$esc" "$esc"
    fi
  done
else
  while IFS= read -r h; do [ -z "$h" ] && continue; printf '%s\n' "$h" >> "$MOCKLOG/httpx.stdin"; printf 'https://%s\n' "$h"; done
fi
EOF

mk katana <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/katana.args"; echo >> "$MOCKLOG/katana.args"
readlink "/proc/$$/fd/0" >> "$MOCKLOG/katana.stdin" 2>/dev/null || true
printf 'https://example.com/katana-path\n'
# MOCK_KATANA_JUNK=1: what -jc makes of JSON-escaped paths in inline scripts
if [ -n "${MOCK_KATANA_JUNK:-}" ]; then
  printf '%s\n' 'https://example.com/%5C/example.com%5C/index.php' 'https://example.com/wp\/emoji.js'
fi
EOF

mk feroxbuster <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/feroxbuster.args"; echo >> "$MOCKLOG/feroxbuster.args"
while IFS= read -r u; do [ -z "$u" ] && continue; printf '%s/ferox-admin\n' "${u%/}"; done
EOF

mk ffuf <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/ffuf.args"; echo >> "$MOCKLOG/ffuf.args"
printf 'ffuf-hit\n'          # -s prints the matched payload; run-recon rebuilds base/payload
EOF

mk uro <<'EOF'
#!/usr/bin/env bash
awk '!seen[$0]++'
EOF

# dnsx: resolve gate. Plaintext mode echoes resolving hosts (drops dead.*);
# -wd JSON mode additionally strips wildcard.* and emits {"host":...} lines.
# dig mock: answers Team Cymru IP-to-ASN (used by --osint and the CSV ip/asn columns)
# and A-record lookups; anything else is silent.
mk dig <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/dig.args"; echo >> "$MOCKLOG/dig.args"
q=""; typ=""; comments=0; srv=""
for a in "$@"; do
  case "$a" in
    +comments) comments=1;;
    @*) srv="${a#@}";;
    +*) ;;
    *.cymru.com) q="$a";;
    TXT|A|AAAA|MX|NS|CNAME|SOA|DNSKEY|DS|AXFR|NSEC|NSEC3PARAM) typ="$a";;
    *.origin.asn.cymru.com|AS*.asn.cymru.com) q="$a";;
    *) [ -z "$q" ] && case "$a" in *.*) q="$a";; esac;;
  esac
done
# reverse DNS (-x IP): public addresses and the 10.0.0.0/8 test address have a PTR
_px=0; for a in "$@"; do if [ "$_px" = 1 ]; then case "$a" in 93.184.216.34) echo "edge-93-184-216-34.example.net.";; 10.0.0.9) echo "db01.corp.example.";; esac; exit 0; fi; [ "$a" = "-x" ] && _px=1; done
# --dns-posture fixtures for example.com (MOCK_POSTURE=bad|lookups|multi), answered in dig's
# full format with a status header:
#   NS ns1 (authoritative), ns-gone.gone-dns.net (domain gone: dangling), ns-lame (REFUSED)
#   MX mx1 (exists), mx-old.gone-mail.net (domain gone); SPF include: an existing record and a
#   domain that does not exist, ending ?all; DMARC quarantine pct=50 without rua; MTA-STS
#   enforce listing mx1 only (curl mock); no TLS-RPT; no CAA
if [ -n "${MOCK_POSTURE:-}" ] && [ "$comments" = 1 ]; then
  st=NOERROR; aa=""; out=()
  a(){ out+=("$1. 60 IN $2 $3"); }
  case "$typ:$q" in
    SOA:example.com) if [ "$srv" = 192.0.2.54 ]; then st=REFUSED; else aa=" aa"; a example.com SOA "ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 60"; fi;;
    SOA:gone-dns.net|SOA:gone-mail.net|SOA:gone-spf.net) st=NXDOMAIN;;
    NS:example.com) a example.com NS ns1.example.com.; a example.com NS ns-gone.gone-dns.net.; a example.com NS ns-lame.example.com.;;
    A:ns1.example.com) a "$q" A 192.0.2.53;;    A:ns-lame.example.com) a "$q" A 192.0.2.54;;
    A:mx1.example.com) a "$q" A 192.0.2.25;;    A:mta-sts.example.com) a "$q" A 192.0.2.80;;
    A:ns-gone.gone-dns.net|AAAA:ns-gone.gone-dns.net|A:mx-old.gone-mail.net|AAAA:mx-old.gone-mail.net) st=NXDOMAIN;;
    MX:example.com) a example.com MX "10 mx1.example.com."; a example.com MX "20 mx-old.gone-mail.net.";;
    TXT:example.com)
      case "$MOCK_POSTURE" in
        lookups) a example.com TXT '"v=spf1 include:i1.example.com include:i2.example.com include:i3.example.com include:i4.example.com include:i5.example.com include:i6.example.com" " include:i7.example.com include:i8.example.com include:i9.example.com include:i10.example.com include:i11.example.com -all"';;
        multi)   a example.com TXT '"v=spf1 -all"'; a example.com TXT '"v=spf1 mx -all"';;
        *)       a example.com TXT '"v=spf1 include:_spf.example.com include:gone-spf.net ?all"';;
      esac;;
    TXT:_spf.example.com) a "$q" TXT '"v=spf1 ip4:192.0.2.0/24 -all"';;
    TXT:i*.example.com) a "$q" TXT '"v=spf1 -all"';;
    TXT:gone-spf.net) st=NXDOMAIN;;
    TXT:_dmarc.example.com) a "$q" TXT '"v=DMARC1; p=quarantine; pct=50"';;
    TXT:_mta-sts.example.com) a "$q" TXT '"v=STSv1; id=20261101"';;
  esac
  echo ";; ->>HEADER<<- opcode: QUERY, status: $st, id: 4242"
  echo ";; flags: qr rd$aa; QUERY: 1, ANSWER: ${#out[@]}, AUTHORITY: 0, ADDITIONAL: 1"
  [ "${#out[@]}" -gt 0 ] && printf '%s\n' "${out[@]}"
  exit 0
fi
# resolver preflight (+noall +comments): MOCK_DIG_STATUS sets the reply status
[ "$comments" = 1 ] && echo ";; ->>HEADER<<- opcode: QUERY, status: ${MOCK_DIG_STATUS:-NOERROR}, id: 4242"
# a seed that is a CNAME to a name that does not exist (the resolve-gate warning)
if [ "$typ" = CNAME ]; then case "$q" in dead.example.com) echo "deleted.herokuapp.com.";; esac; exit 0; fi
# --zone-exposure fixtures for example.com (MOCK_ZONE=axfr|nsec|nsec3|signed|none).
# MOCK_ZONE_DS=1: the parent publishes a DS. MOCK_ZONE_V6=1: ns1 also has an IPv6 address,
# which never answers. MOCK_ZONE_NS2=1: a second name server, ns0 (tried first), that
# refuses the transfer and answers no NSEC queries.
if [ -n "${MOCK_ZONE:-}" ]; then
  SOA="example.com. 60 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 60"
  [ "$srv" = 2001:db8::53 ] && exit 9                       # unreachable: no reply at all
  case "$typ" in
    SOA) case "$q" in example.com|*.example.com) echo "$SOA";; esac; exit 0;;
    NS)  if [ "$q" = example.com ]; then echo "example.com. 60 IN NS ns1.example.com."
           [ -n "${MOCK_ZONE_NS2:-}" ] && echo "example.com. 60 IN NS ns0.example.com."; fi; exit 0;;
    A)   if [ "$q" = ns1.example.com ]; then echo "ns1.example.com. 60 IN A 192.0.2.53"; exit 0; fi
         if [ "$q" = ns0.example.com ]; then echo "ns0.example.com. 60 IN A 192.0.2.52"; exit 0; fi;;
    AAAA) [ "$q" = ns1.example.com ] && [ -n "${MOCK_ZONE_V6:-}" ] && echo "ns1.example.com. 60 IN AAAA 2001:db8::53"; exit 0;;
    DS)  [ "$q" = example.com ] && [ -n "${MOCK_ZONE_DS:-}" ] && echo "example.com. 60 IN DS 2371 13 2 1F987CC6583E92DF0890718C42A0A6C0A5D6D9F1B6E5D1C3A4E1C0B7A5D6E4F1"; exit 0;;
    DNSKEY) case "$MOCK_ZONE" in nsec|nsec3|signed) echo "example.com. 60 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==";; esac; exit 0;;
    NSEC3PARAM) [ "$MOCK_ZONE" = nsec3 ] && echo "example.com. 0 IN NSEC3PARAM 1 0 5 ABCDEF"; exit 0;;
    AXFR) if [ "$srv" = 192.0.2.52 ]; then echo "; Transfer failed."
          elif [ "$MOCK_ZONE" = axfr ]; then
            printf '%s\n' "$SOA" "example.com. 60 IN NS ns1.example.com." "ns1.example.com. 60 IN A 192.0.2.53" \
              "www.example.com. 60 IN A 192.0.2.10" "hidden-zone.example.com. 60 IN A 192.0.2.11" "$SOA"
          else echo "; Transfer failed."; fi; exit 0;;
    NSEC) if [ "$MOCK_ZONE" = nsec ] && [ "$srv" != 192.0.2.52 ]; then
            case "$q" in example.com) n=a-secret.example.com;; a-secret.example.com) n=ns1.example.com;;
              ns1.example.com) n=www.example.com;; www.example.com) n=example.com;; *) exit 0;; esac
            echo "$q. 60 IN NSEC $n. A RRSIG NSEC"
          fi; exit 0;;
  esac
fi
case "$q" in
  *.origin.asn.cymru.com) echo '"15133 | 93.184.216.0/24 | US | arin | 2008-06-02"';;
  AS15133.asn.cymru.com)  echo '"15133 | US | arin | 2008-06-02 | EDGECAST, US"';;
  example.com) if [ "$typ" = TXT ]; then
                 # MOCK_SPF=include: an include: chain, ip6:, a small range and a /24 (too wide)
                 if [ "${MOCK_SPF:-}" = include ]; then echo '"v=spf1 include:_spf.example.com ip6:2001:db8:5::7 ip4:198.51.100.16/30 ip4:203.0.113.0/24 -all"'
                 else echo '"v=spf1 ip4:198.51.100.7 -all"'; fi
               elif [ "$typ" = A ]; then echo "93.184.216.34"; fi;;
  _spf.example.com) [ "$typ" = TXT ] && echo '"v=spf1 ip4:198.51.100.8 -all"';;
  *) [ "$typ" = "A" ] && echo "93.184.216.34" || true;;
esac
EOF

mk dnsx <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/dnsx.args"; echo >> "$MOCKLOG/dnsx.args"
args=("$@"); i=0; list=""; wd=""; json=0; a4=0; aaaa=0; cname=0; rcode=""
while [ $i -lt ${#args[@]} ]; do
  case "${args[$i]}" in
    -l|-list)              i=$((i+1)); list="${args[$i]:-}";;
    -a)                    a4=1;;
    -wd|-wildcard-domain)  i=$((i+1)); wd="${args[$i]:-}";;
    -r|-resolver|-resolvers) i=$((i+1));;
    -j|-json)              json=1;;
    -aaaa)                 aaaa=1;;
    -cname)                cname=1;;
    -rc|-rcode)            i=$((i+1)); rcode="${args[$i]:-}";;
  esac
  i=$((i+1))
done
if [ -n "$list" ] && [ -f "$list" ]; then exec < "$list"; fi
# CNAME fixtures (only names that have a CNAME are printed, as in dnsx 1.3):
#   orphan.* -> gone-app.azurewebsites.net (does not exist: dangling, takeover-prone service)
#   stale.*  -> old.vendor-example.net     (does not exist: dangling, unknown service)
#   alias.*  -> www.example.com            (healthy)
#   dead.*   -> deleted.herokuapp.com      (dangling; the A lookup of dead.* is NXDOMAIN too)
if [ "$cname" = 1 ]; then
  while IFS= read -r h; do
    case "$h" in
      orphan.*) t=gone-app.azurewebsites.net;; stale.*) t=old.vendor-example.net;;
      alias.*)  t=www.example.com;;            dead.*)  t=deleted.herokuapp.com;;
      *) continue;;
    esac
    printf '{"host":"%s","resolver":["1.1.1.1:53"],"cname":["%s"],"status_code":"NOERROR"}\n' "$h" "$t"
  done
  exit 0
fi
if [ -n "$rcode" ]; then   # text form: "<name> [NXDOMAIN]"
  while IFS= read -r h; do
    case "$h" in gone-app.azurewebsites.net|old.vendor-example.net|deleted.herokuapp.com) printf '%s [NXDOMAIN]\n' "$h";; esac
  done
  exit 0
fi
while IFS= read -r h; do
  [ -z "$h" ] && continue
  case "$h" in dead.*) continue;; esac                 # simulate NXDOMAIN
  if [ -n "$wd" ]; then case "$h" in wildcard.*) continue;; esac; fi   # -wd strips wildcard
  if [ "$aaaa" = 1 ] && [ "$a4" = 1 ]; then              # both families (--origin candidates)
    [ "$json" = 1 ] && printf '{"host":"%s","a":["10.0.0.1"],"aaaa":["2001:db8::1"]}\n' "$h"
  elif [ "$aaaa" = 1 ]; then                           # AAAA stage (--ipv6): emit IPv6
    [ "$json" = 1 ] && printf '{"host":"%s","aaaa":["2001:db8::1"]}\n' "$h"
  elif [ "$json" = 1 ]; then printf '{"host":"%s","a":["10.0.0.1"]}\n' "$h"
  else printf '%s\n' "$h"; fi
done
EOF

# tlsx: active cert grab. SAN/CN mode emits sibling hostnames (incl. one off-scope
# name scope_filter must drop). With -jarm emits a fingerprint line (origin mode).
# When the -l list is the live-hosts file (live_bare.txt), emits an extra sibling
# to exercise the post-probe cert feedback loop (source=tlsx-live).
mk tlsx <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/tlsx.args"; echo >> "$MOCKLOG/tlsx.args"
args=("$@"); i=0; list=""; jarm=0; tlsver=0; json=0
while [ $i -lt ${#args[@]} ]; do
  case "${args[$i]}" in -l|-list) i=$((i+1)); list="${args[$i]:-}";; -jarm) jarm=1;; -tls-version) tlsver=1;; -json) json=1;; esac; i=$((i+1))
done
if [ "$tlsver" = 1 ]; then   # TLS posture mode: emit a JSON record per host:port
  while IFS= read -r a || [ -n "$a" ]; do
    [ -n "$a" ] || continue
    if [ -n "${MOCK_TLSX_FLAKY:-}" ] && [ "$a" = "$MOCK_TLSX_FLAKY" ] && [ ! -e "$MOCKLOG/tlsx.flaky" ]; then
      : > "$MOCKLOG/tlsx.flaky"; continue
    fi
    h="${a%%:*}"; p="${a##*:}"; [ "$p" = "$a" ] && p=443
    printf '{"host":"%s","port":"%s","tls_version":"tls13","cipher":"TLS_AES_256_GCM_SHA384","not_after":"2030-01-01T00:00:00Z","issuer_org":"Lets Encrypt"}\n' "$h" "$p"
  done < "$list"
  exit 0
fi
if [ "$jarm" = 1 ]; then   # tlsx 1.4 prints colours even into a pipe unless -nc
  while IFS= read -r a || [ -n "$a" ]; do
    [ -n "$a" ] && printf '%s [\033[35m%s\033[0m]\n' "$a" 28d3ed0032d3ed0032d3ed0032d3edc8a0c9d8e0b7f4f6abcdef0123456789
  done < "${list:-/dev/null}"
  exit 0
fi
# range cert scan (-json, 1.20): the names with the address that presented them
if [ "$json" = 1 ]; then
  printf '{"host":"192.0.2.10","ip":"192.0.2.10","port":"443","subject_cn":"cert-sibling.example.com","subject_an":["cert-sibling.example.com","assets.example.com","sneaky.otherdomain.com"]}\n'
  exit 0
fi
printf 'cert-sibling.example.com\nassets.example.com\nsneaky.otherdomain.com\n'
case "$(basename "${list:-}")" in
  live_bare.txt)    printf 'feedback-host.example.com\n';;
  favicon_ips.txt)  printf 'favicon-host.example.com\n';;
  favicon_hits_hp.txt) printf 'favicon-pivot.example.com\n';;
esac
EOF

# curl: network-safe default so the suite never makes real egress (OSINT RDAP/
# InternetDB, CMS generator probes, cloud IP-range feeds, per-IP RDAP all route
# through curl). Logs args, emits nothing, exits 0. Tests needing a specific HTTP/
# RDAP/cloud-feed body override this with `mk curl` and restore this default after.
mk curl <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/curl.args"; echo >> "$MOCKLOG/curl.args"
exit 0
EOF

# --- passive subdomain sources -------------------------------------------
mk amass <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/amass.args"; echo >> "$MOCKLOG/amass.args"
printf 'amass-host.example.com\n'
EOF

mk assetfinder <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/assetfinder.args"; echo >> "$MOCKLOG/assetfinder.args"
printf 'asset-host.example.com\n'
EOF

# --- DNS bruteforce (shuffledns/puredns + massdns) -----------------------
mk shuffledns <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/shuffledns.args"; echo >> "$MOCKLOG/shuffledns.args"
printf 'brute-host.example.com\n'
EOF
mk puredns <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/puredns.args"; echo >> "$MOCKLOG/puredns.args"
printf 'brute-host.example.com\n'
EOF
mk massdns <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/massdns.args"; echo >> "$MOCKLOG/massdns.args"
EOF

# --- port discovery (naabu) ----------------------------------------------
mk naabu <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/naabu.args"; echo >> "$MOCKLOG/naabu.args"
printf 'example.com:8080\n'
EOF

# --- ASN/CIDR (asnmap + mapcidr) -----------------------------------------
mk asnmap <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/asnmap.args"; echo >> "$MOCKLOG/asnmap.args"
if [ "${ASNMAP_MOCK:-}" = "reject" ]; then
  # asnmap 1.2: an unauthorized key triggers an interactive prompt on STDOUT
  printf '[*] Enter PDCP API Key (exit to abort): '
  printf '[FTL] Could not read input from terminal: open /dev/tty: no such device or address\n' >&2
  exit 1
fi
printf '192.0.2.0/25\n192.0.2.128/25\n2001:db8::/32\n'
EOF
mk mapcidr <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/mapcidr.args"; echo >> "$MOCKLOG/mapcidr.args"
args=("$@"); i=0; f=""
while [ $i -lt ${#args[@]} ]; do case "${args[$i]}" in -cl|-cidr-list|-l) i=$((i+1)); f="${args[$i]:-}";; esac; i=$((i+1)); done
if [ -n "$f" ] && [ -f "$f" ]; then
  case " $* " in
    *" -aggregate "*|*" -a "*) sed -e 's#^192\.0\.2\.0/25$#192.0.2.0/24#' -e '/^192\.0\.2\.128\/25$/d' "$f";;
    *) for c in $(cat "$f"); do printf '%s-ip-1\n%s-ip-2\n' "$c" "$c"; done;;   # -cl alone expands to IPs
  esac
else printf '192.0.2.0/24\n'; fi
EOF

# --- extra URL sources ----------------------------------------------------
mk urlfinder <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/urlfinder.args"; echo >> "$MOCKLOG/urlfinder.args"
printf 'https://example.com/urlfinder-path\n'
EOF
mk gospider <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/gospider.args"; echo >> "$MOCKLOG/gospider.args"
printf '[url] - https://example.com/gospider-path\n'   # verbose style; run-recon greps the URL
EOF
mk hakrawler <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/hakrawler.args"; echo >> "$MOCKLOG/hakrawler.args"
cat >/dev/null
printf 'https://example.com/hakrawler-path\n'
EOF

# --- JS mining (subjs/getJS -> xnLinkFinder) -----------------------------
mk subjs <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/subjs.args"; echo >> "$MOCKLOG/subjs.args"
cat >/dev/null
printf 'https://example.com/app.js\n'
EOF
mk getJS <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/getJS.args"; echo >> "$MOCKLOG/getJS.args"
printf 'https://example.com/main.js\n'
EOF
mk xnLinkFinder <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/xnLinkFinder.args"; echo >> "$MOCKLOG/xnLinkFinder.args"
printf 'https://example.com/js-endpoint\n'
EOF

# --- defensive / triage ---------------------------------------------------
mk subzy <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/subzy.args"; echo >> "$MOCKLOG/subzy.args"
# subzy 1.2: settings banner, then one block per VULNERABLE name (ANSI-coloured)
printf '[ * ] Loaded 76 fingerprints\n[ Yes ] Show only potentially vulnerable subdomains (--hide_fails)\n'
args=("$@"); i=0; tf=""
while [ $i -lt ${#args[@]} ]; do case "${args[$i]}" in --targets) i=$((i+1)); tf="${args[$i]:-}";; esac; i=$((i+1)); done
if [ -n "$tf" ] && grep -q '^alias\.' "$tf" 2>/dev/null; then
  h="$(grep '^alias\.' "$tf" | head -1)"
  printf -- '-----------------\n[ \033[32mVULNERABLE\033[0m ]  -  %s  [ GitHub Pages ]\n[ DISCUSSION ]  -  https://example.invalid/1\n-----------------\n' "$h"
fi
EOF
mk gowitness <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/gowitness.args"; echo >> "$MOCKLOG/gowitness.args"
sp=""; sa=("$@"); si=0
while [ $si -lt ${#sa[@]} ]; do case "${sa[$si]}" in --screenshot-path) si=$((si+1)); sp="${sa[$si]:-}";; esac; si=$((si+1)); done
d="${sp:-.}"; mkdir -p "$d" 2>/dev/null; : > "$d/host.jpeg"
EOF
mk cdncheck <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/cdncheck.args"; echo >> "$MOCKLOG/cdncheck.args"
cat >/dev/null
printf 'example.com [cloudflare]\n'
EOF
mk uncover <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/uncover.args"; echo >> "$MOCKLOG/uncover.args"
case " $* " in *http.favicon.hash:*) printf '198.51.100.20:8443\n';; *) printf '192.0.2.77:443\n';; esac
EOF
mk nuclei <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/nuclei.args"; echo >> "$MOCKLOG/nuclei.args"
case " $* " in
  *" -tags takeover "*) printf '[azure-takeover-detection] [dns] [high] orphan.example.com\n';;
  *) printf '[cve-2021-44228] [high] https://example.com/vuln\n';;
esac
EOF
mk arjun <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/arjun.args"; echo >> "$MOCKLOG/arjun.args"
out=""; a=("$@"); i=0
while [ $i -lt ${#a[@]} ]; do case "${a[$i]}" in -oT) i=$((i+1)); out="${a[$i]:-}";; esac; i=$((i+1)); done
line='https://example.com/search?q=FUZZ'
if [ -n "$out" ]; then printf '%s\n' "$line" > "$out"; else printf '%s\n' "$line"; fi
EOF
mk secretfinder <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/secretfinder.args"; echo >> "$MOCKLOG/secretfinder.args"
printf 'aws_key AKIAEXAMPLE1234\n'
EOF
mk trufflehog <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/trufflehog.args"; echo >> "$MOCKLOG/trufflehog.args"
printf 'trufflehog: found credential\n'
EOF

# --- monitoring -----------------------------------------------------------
mk notify <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/notify.args"; echo >> "$MOCKLOG/notify.args"
cat > "$MOCKLOG/notify.stdin"
EOF

# --- passive subs (findomain) + GitHub mining + cloud buckets + resolvers ---
mk findomain <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/findomain.args"; echo >> "$MOCKLOG/findomain.args"
printf 'findomain-host.example.com\n'
EOF
mk github-subdomains <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/github-subdomains.args"; echo >> "$MOCKLOG/github-subdomains.args"
printf 'github-host.example.com\n'
EOF
mk github-endpoints <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/github-endpoints.args"; echo >> "$MOCKLOG/github-endpoints.args"
out=""; a=("$@"); i=0
while [ $i -lt ${#a[@]} ]; do case "${a[$i]}" in -o) i=$((i+1)); out="${a[$i]:-}";; esac; i=$((i+1)); done
line='https://example.com/github-endpoint'
if [ -n "$out" ]; then printf '%s\n' "$line" > "$out"; else printf '%s\n' "$line"; fi
EOF
mk cloud_enum <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/cloud_enum.args"; echo >> "$MOCKLOG/cloud_enum.args"
echo "[+] Checking for S3 buckets"                                  # progress line (must be filtered out)
echo "OPEN S3 BUCKET: http://example.com.s3.amazonaws.com/"         # a real finding
EOF
mk dnsvalidator <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/dnsvalidator.args"; echo >> "$MOCKLOG/dnsvalidator.args"
out=""; a=("$@"); i=0
while [ $i -lt ${#a[@]} ]; do case "${a[$i]}" in -o) i=$((i+1)); out="${a[$i]:-}";; esac; i=$((i+1)); done
{ printf '1.1.1.1\n9.9.9.9\n8.8.8.8\n'; } > "${out:-/dev/stdout}"
EOF

# --- active CMS/app-layer scanning -----------------------------------------
# whatweb fingerprint mock names WordPress+Drupal+Joomla so the full dispatch
# (wpscan/droopescan/joomscan) is exercised from a single fixture host.
mk whatweb <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/whatweb.args"; echo >> "$MOCKLOG/whatweb.args"
echo "http://example.com [200 OK] WordPress[6.4.2], Drupal, Joomla, MetaGenerator[WordPress 6.4.2]"
EOF
mk wpscan <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/wpscan.args"; echo >> "$MOCKLOG/wpscan.args"
echo "[+] WordPress version 6.4.2 identified"
echo "[+] WordPress theme in use: twentytwentyfour"
echo "[i] User(s) Identified: admin"
echo "[!] 3 vulnerabilities identified in plugin contact-form-7"
EOF
mk droopescan <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/droopescan.args"; echo >> "$MOCKLOG/droopescan.args"
echo "[+] Possible version(s): 9.5.0"
echo "[+] Found: http://example.com/core/misc/drupal.js"
EOF
mk joomscan <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/joomscan.args"; echo >> "$MOCKLOG/joomscan.args"
echo "[++] Joomla version : 3.9.1"
echo "[++] Core Joomla Vulnerability : CVE-2019-10945"
EOF
mk cmseek <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/cmseek.args"; echo >> "$MOCKLOG/cmseek.args"
cat >/dev/null 2>&1 || true
echo "CMS Detected: WordPress"
echo "Version: 6.4.2"
EOF

# uro: URL dedupe/filter. Reads -i FILE or stdin, emits unique lines (stands in
# for uro's semantic dedup). Used by resolve_hosts and the activescan nuclei feed.
mk uro <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/uro.args"; echo >> "$MOCKLOG/uro.args"
f=""; A=("$@"); i=0
while [ $i -lt ${#A[@]} ]; do case "${A[$i]}" in -i) i=$((i+1)); f="${A[$i]:-}";; esac; i=$((i+1)); done
if [ -n "$f" ] && [ -f "$f" ]; then sort -u "$f"; else sort -u; fi
EOF

# tookie-osint: social-media account discovery. Emits a couple of "found" account
# URLs for the queried username (Sherlock-style [+] lines).
mk tookie-osint <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/tookie-osint.args"; echo >> "$MOCKLOG/tookie-osint.args"
u="example"; A=("$@"); i=0
while [ $i -lt ${#A[@]} ]; do case "${A[$i]}" in -u|--username|--user) i=$((i+1)); u="${A[$i]:-example}";; esac; i=$((i+1)); done
cat >/dev/null 2>&1 || true
echo "[+] GitHub: https://github.com/$u"
echo "[+] Twitter: https://twitter.com/$u"
echo "[-] Foobar: not found"
EOF

# alterx: permutation generator. Consumes candidate hosts on stdin, emits a few
# permutations (incl. a wildcard.* that the -wd dnsx pass should later strip).
mk httpx-toolkit <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/httpx-toolkit.args"; echo >> "$MOCKLOG/httpx-toolkit.args"
__vf=" -timeout -rl -rate-limit -r -resolvers -l -list -o -output -srd -store-response-dir -mc -match-code -t -threads -retries -H -header -p -ports -delay -proxy -http-proxy -ho -headless-options -hash -st -screenshot-timeout -path -er -extract-regex "
__bf=" -silent -json -sc -status-code -cl -content-length -ct -content-type -title -td -tech-detect -server -web-server -ip -cname -asn -cdn -probe -ss -screenshot -system-chrome -nc -no-color -version -h -help -fr -follow-redirects -favicon -location -jarm -method -websocket -nfs -no-fallback-scheme -nf -no-fallback -esb -exclude-screenshot-bytes -ehb -exclude-headless-body -irh -include-response-header -irr -include-response -irrb -include-response-base64 "
__A=("$@"); __i=0
while [ $__i -lt ${#__A[@]} ]; do
  case "${__A[$__i]}" in
    -*) case "$__vf" in *" ${__A[$__i]} "*) __i=$((__i+1));;
          *) case "$__bf" in *" ${__A[$__i]} "*) : ;;
               *) echo "flag provided but not defined: ${__A[$__i]}" >&2; exit 1;; esac;; esac;;
  esac
  __i=$((__i+1))
done
for a in "$@"; do [ "$a" = "-h" ] && { echo "  -td, -tech-detect  display technology in use based on wappalyzer dataset"; exit 0; }; done
mode=probe; for a in "$@"; do [ "$a" = "-json" ] && mode=json; done
list=""; args=("$@"); i=0
while [ $i -lt ${#args[@]} ]; do case "${args[$i]}" in -l|-list) i=$((i+1)); list="${args[$i]:-}";; esac; i=$((i+1)); done
if [ -n "$list" ] && [ -f "$list" ]; then exec < "$list"; fi
if [ "$mode" = json ]; then
  esc='\"'
  while IFS= read -r u; do [ -z "$u" ] && continue
    printf '{"input":"%s","url":"%s","status_code":200,"content_length":100,"webserver":"nginx","title":"Home, %sMain%s","tech":["nginx","PHP"],"host":"93.184.216.34"}\n' "$u" "$u" "$esc" "$esc"
  done
else
  while IFS= read -r h; do [ -z "$h" ] && continue; printf 'https://%s\n' "$h"; done
fi
EOF

mk alterx <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/alterx.args"; echo >> "$MOCKLOG/alterx.args"
cat >/dev/null
printf 'admin-dev.example.com\napi-staging.example.com\nwildcard.example.com\n'
EOF

# ---------------------------------------------------------------------------
# Masked system PATH.
#
# The mocks in $MOCKBIN shadow real tools only while they exist there. Fallback
# scenarios move a mock OUT of $MOCKBIN to force run-recon down its fallback path
# (e.g. hide feroxbuster -> exercise ffuf; hide shuffledns -> exercise puredns).
# If we ran with PATH="$MOCKBIN:$PATH", the *real* tool (feroxbuster/shuffledns/
# etc., installed on a Kali box) would then be found via the inherited PATH and
# run instead of the intended fallback -- so those tests fail on real installs
# but pass on a bare box. Fix: run against $MOCKBIN + a $SYSBIN that symlinks
# every PATH executable EXCEPT the ones we mock. Coreutils stay available;
# real recon tools are masked, so hiding a mock truly removes the tool.
# ---------------------------------------------------------------------------
SYSBIN="$TMP/sysbin"; mkdir -p "$SYSBIN"
{
  IFS=: read -ra _pdirs <<< "$PATH"
  for _d in "${_pdirs[@]}"; do
    [ -d "$_d" ] || continue
    for _f in "$_d"/*; do
      [ -f "$_f" ] && [ -x "$_f" ] || continue
      _b="$(basename "$_f")"
      [ -e "$MOCKBIN/$_b" ] && continue      # we mock this tool -> mask the real one
      [ -e "$SYSBIN/$_b" ] && continue        # earlier PATH entry wins
      ln -s "$_f" "$SYSBIN/$_b" 2>/dev/null || true
    done
  done
} 2>/dev/null
TESTPATH="$MOCKBIN:$SYSBIN"

# ---------------------------------------------------------------------------
# run_case <name> [extra run-recon args...]  -> sets CSV / ERRLOG / OUTDIR
# ---------------------------------------------------------------------------
run_case(){
  local name="$1"; shift
  printf '   %s...%s running: %s\n' "$C_Y" "$C_0" "$name" >&2
  OUTDIR="$TMP/out_$name"; rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"
  rm -f "$MOCKLOG"/*.args
  CSV="$OUTDIR/r.csv"; ERRLOG="$OUTDIR/stderr.log"
  # isolate the cloud IP-range cache per case (never touch the real ~/.cache);
  # a caller may override it via a RECON_CLOUD_CACHE= prefix (enrichment tests).
  local _cloud="${RECON_CLOUD_CACHE:-$OUTDIR/cloud_ranges.tsv}"
  # TLS_CHAIN_CHECK=0: the chain check opens real TLS connections; the mock hosts are
  # not ours to connect to (its own test runs against a local TLS server)
  timeout 25 env PATH="$TESTPATH" HTTPX_BIN=httpx SECLISTS="$SECLISTS_TEST" RECON_CLOUD_CACHE="$_cloud" \
    TLS_CHAIN_CHECK="${TLS_CHAIN_CHECK:-0}" \
    bash "$RUN_RECON" -i "$DOMAINS" -D "$OUTDIR" -o "$CSV" --keep-work "$@" \
    >/dev/null 2>"$ERRLOG" || true
}

# ===========================================================================
# TEST CASES
# ===========================================================================
printf '%sTesting:%s %s\n' "$C_Y" "$C_0" "$RUN_RECON"

# --- 1) passive-only: gau+wayback only, no active tools, no enrichment -----
section "passive-only mode (gau + waybackurls)"
run_case passive --passive-only
assert_grep  "$CSV" 'https://example.com/gau-path,example\.com,gau'      "gau URL present, source=gau"
assert_grep  "$CSV" 'https://example.com/wb-path,example\.com,wayback'   "waybackurls URL present, source=wayback"
assert_grep  "$CSV" 'gau-path,example\.com,gau,,,,,'                     "enrichment columns empty in passive-only"
refute_grep  "$CSV" 'evil-example\.com'                                  "off-scope URL dropped by scope_filter"
assert_absent "$MOCKLOG/httpx.args"                                      "httpx NOT invoked in passive-only"
assert_absent "$MOCKLOG/katana.args"                                     "katana NOT invoked in passive-only"
assert_grep  "$MOCKLOG/gau.args" -- '--threads 5'                        "gau received --threads 5"

# --- 2) default: passive + live-probe + crawl + enrichment -----------------
section "default mode (probe + katana + httpx enrichment)"
run_case default
assert_grep  "$CSV" 'https://example.com/katana-path,example\.com,katana' "katana URL present (proves probe fed live hosts)"
assert_grep  "$CSV" '/gau-path.*,200,100,nginx,'                          "enrichment populated: status/length/webserver"
assert_grep  "$CSV" '/gau-path.*nginx;PHP'                                "technologies column populated (nginx;PHP)"
assert_fgrep "$CSV" '"Home, ""Main"""'                                    "CSV escaping: comma+quote title correctly quoted"
assert_grep  "$MOCKLOG/httpx.args" -- '-json'                             "httpx enrichment call used -json"
assert_grep  "$MOCKLOG/httpx.args" -- '-tech-detect'                      "httpx enrichment call used -tech-detect"
assert_grep  "$MOCKLOG/katana.args" -- '-fs rdn'                          "katana scoped with -fs rdn"
assert_grep  "$MOCKLOG/katana.args" -- '-jc'                              "katana JS-crawl -jc passed"
assert_grep  "$MOCKLOG/katana.args" -- '-kf all'                          "katana known-files -kf all passed"
assert_grep  "$MOCKLOG/katana.args" -- '-ef '                             "katana static-extension filter -ef passed"

# --- 3) --subs: subfinder (+amass/assetfinder) feed host list into gau ------
section "--subs (subfinder -dL frontier -> host list -> gau)"
run_case subs --subs
assert_grep  "$MOCKLOG/subfinder.args" -- '-dL '                        "subfinder received -dL frontier list"
assert_grep  "$MOCKLOG/subfinder.args" -- '-all'                        "subfinder received -all (all sources)"
assert_grep  "$MOCKLOG/subfinder.args" -- '-silent'                     "subfinder received -silent"
assert_grep  "$CSV" 'https://api\.example\.com/gau-path,api\.example\.com,gau' "subdomain URL attributed to seed example.com"
assert_grep  "$CSV" 'https://amass-host\.example\.com,amass-host\.example\.com,amass' "amass subdomain emitted (source=amass)"
assert_grep  "$CSV" 'https://asset-host\.example\.com,asset-host\.example\.com,assetfinder' "assetfinder subdomain emitted (source=assetfinder)"
assert_grep  "$CSV" 'https://findomain-host\.example\.com,findomain-host\.example\.com,findomain' "findomain subdomain emitted (source=findomain)"
refute_grep  "$MOCKLOG/gau.args" -- '--subs'                            "gau called WITHOUT --subs when subs pre-enumerated"

# --- 4) --deep: waymore contributes, honoring -oU --------------------------
section "--deep (waymore)"
run_case deep --deep
assert_grep  "$MOCKLOG/waymore.args" -- '-mode U'                        "waymore received -mode U"
assert_grep  "$MOCKLOG/waymore.args" -- '-oU'                            "waymore received -oU output path"
assert_grep  "$CSV" 'https://example.com/waymore-path,example\.com,waymore' "waymore URL present, source=waymore"

# --- 5) --fuzz with feroxbuster --------------------------------------------
section "--fuzz (feroxbuster)"
run_case fuzz_ferox --fuzz --wordlist "$WL"
assert_grep  "$MOCKLOG/feroxbuster.args" -- '--stdin'                    "feroxbuster received --stdin"
assert_grep  "$MOCKLOG/feroxbuster.args" -- '--silent'                   "feroxbuster received --silent"
assert_grep  "$MOCKLOG/feroxbuster.args" -- '-C 404'                     "feroxbuster received -C 404 filter"
assert_grep  "$MOCKLOG/feroxbuster.args" -- "-w $WL"                     "feroxbuster received the RAFT wordlist"
assert_grep  "$CSV" 'https://example.com/ferox-admin,example\.com,feroxbuster' "fuzz hit merged with source=feroxbuster"
assert_grep  "$CSV" '/ferox-admin.*,200,'                               "fuzz hit also enriched by httpx"

# --- 6) --fuzz fallback to ffuf (feroxbuster absent) -----------------------
section "--fuzz fallback (ffuf)"
mv "$MOCKBIN/feroxbuster" "$TMP/feroxbuster.hidden"
run_case fuzz_ffuf --fuzz --wordlist "$WL"
mv "$TMP/feroxbuster.hidden" "$MOCKBIN/feroxbuster"
assert_grep  "$MOCKLOG/ffuf.args" -- '-mc 200'                          "ffuf received -mc status match list"
assert_grep  "$MOCKLOG/ffuf.args" -- '-s'                               "ffuf received -s (silent)"
assert_grep  "$CSV" 'https://example.com/ffuf-hit,example\.com,ffuf'    "ffuf payload reconstructed to full URL, source=ffuf"

# --- 7) --no-validate: crawl runs, enrichment skipped ----------------------
section "--no-validate (crawl yes, enrichment no)"
run_case noval --no-validate
assert_grep  "$CSV" 'https://example.com/katana-path,example\.com,katana' "katana crawl still runs under --no-validate"
assert_grep  "$CSV" 'katana-path,example\.com,katana,,,,,'               "enrichment columns empty under --no-validate"
refute_grep  "$MOCKLOG/httpx.args" -- '-json'                            "no -json enrichment call under --no-validate"

# --- 9) --max-urls cap warning ---------------------------------------------
section "--max-urls cap"
run_case maxurls --max-urls 1
assert_grep "$ERRLOG" 'validating first 1'                               "warns and caps validation at --max-urls"

# --- 10) unknown flag is rejected ------------------------------------------
section "argument validation"
OUTDIR="$TMP/out_badflag"; mkdir -p "$OUTDIR"
timeout 25 env PATH="$TESTPATH" bash "$RUN_RECON" -i "$DOMAINS" --bogus-flag >/dev/null 2>"$OUTDIR/e.log"; rc=$?
if [ "$rc" -eq 2 ]; then _pass "unknown flag exits with code 2"; else _fail "unknown flag exit code ($rc != 2)"; fi
assert_grep "$OUTDIR/e.log" 'Unknown argument'                           "unknown flag prints a clear error"

# --- 11) --resolve gate: dnsx drops non-resolving hosts, resolvers threaded ---
section "--resolve (dnsx validation gate + dedicated resolvers)"
run_case resolve --subs --resolve
assert_grep  "$MOCKLOG/dnsx.args" -- '-silent'                          "dnsx invoked for resolution"
assert_grep  "$MOCKLOG/dnsx.args" -- '-r '                              "dnsx received -r (dedicated resolvers)"
refute_grep  "$CSV" 'dead\.example\.com'                                "non-resolving host dropped by dnsx gate"
assert_grep  "$CSV" 'https://api\.example\.com,api\.example\.com,subfinder' "resolving subdomain emitted as host row (source=subfinder)"
assert_grep  "$MOCKLOG/httpx.args" -- '-r '                             "httpx also routed through dedicated resolvers (Pi-hole bypass)"
assert_grep  "$ERRLOG" 'dedicated resolvers'                            "startup notes dedicated-resolver routing"

# --- 12) --certs: tlsx SAN/CN harvest -> host rows, off-scope dropped -------
section "--certs (tlsx cert SAN/CN harvesting)"
run_case certs --certs
assert_grep  "$MOCKLOG/tlsx.args" -- '-san'                             "tlsx received -san"
assert_grep  "$MOCKLOG/tlsx.args" -- '-cn'                              "tlsx received -cn"
assert_grep  "$MOCKLOG/tlsx.args" -- '-resp-only'                       "tlsx received -resp-only"
assert_grep  "$MOCKLOG/tlsx.args" -- '-r '                              "tlsx routed through dedicated resolvers"
assert_grep  "$CSV" 'https://cert-sibling\.example\.com,cert-sibling\.example\.com,tlsx' "cert-discovered host emitted (source=tlsx)"
refute_grep  "$CSV" 'otherdomain'                                       "off-scope SAN dropped by scope_filter"

# --- 13) --permute: alterx permutations, dnsx -wd strips wildcard ----------
section "--permute (alterx permutations + wildcard strip)"
run_case permute --permute
assert_grep  "$MOCKLOG/alterx.args" -- '-silent'                        "alterx invoked for permutations"
assert_grep  "$MOCKLOG/dnsx.args" -- '-wd example.com'                  "dnsx -wd wildcard filtering engaged for permutations"
assert_grep  "$CSV" 'https://admin-dev\.example\.com,admin-dev\.example\.com,alterx' "resolving permutation emitted (source=alterx)"
refute_grep  "$CSV" 'wildcard\.example\.com'                            "wildcard permutation stripped by dnsx -wd"

# --- 14) --permute-max guard: skip permutations above the cap --------------
section "--permute-max guard"
run_case permute_cap --permute --permute-max 0
assert_absent "$MOCKLOG/alterx.args"                                    "alterx NOT invoked when candidates exceed --permute-max"
assert_grep  "$ERRLOG" 'skipping permutations'                          "warns that permutations were skipped (cap exceeded)"

# --- 15) passive-only gates off all active discovery -----------------------
section "--passive-only disables resolve/certs/permute"
run_case passive_gate --passive-only --resolve --certs --permute
assert_grep   "$ERRLOG" 'ignored under --passive-only'                  "active discovery flags warned + disabled under --passive-only"
assert_absent "$MOCKLOG/dnsx.args"                                      "dnsx NOT invoked under --passive-only"
assert_absent "$MOCKLOG/tlsx.args"                                      "tlsx NOT invoked under --passive-only"
assert_absent "$MOCKLOG/alterx.args"                                    "alterx NOT invoked under --passive-only"

# --- 16) --resolvers FILE: custom resolver list is threaded through --------
section "--resolvers FILE (custom resolver list)"
CUSTOM_RES="$TMP/my-resolvers.txt"; printf '203.0.113.53\n198.51.100.53\n' > "$CUSTOM_RES"
run_case resolvers_file --resolve --resolvers "$CUSTOM_RES"
assert_fgrep "$MOCKLOG/dnsx.args" "$CUSTOM_RES"                         "dnsx received the custom --resolvers file path"
assert_grep  "$ERRLOG" 'Preflight: verifying required services'        "--resolvers triggers the service preflight"
assert_grep  "$ERRLOG" 'resolver check passed'                         "resolver health check passes when resolvers reply"
assert_fgrep "$MOCKLOG/katana.args" "-r $CUSTOM_RES"                     "katana crawls with the same --resolvers (v1.16: system resolver)"

# --- 17) --brute: shuffledns+massdns dictionary bruteforce -> host rows -----
section "--brute (shuffledns + massdns)"
run_case brute --brute --brute-wordlist "$WL"
assert_grep  "$MOCKLOG/shuffledns.args" -- '-mode bruteforce'           "shuffledns invoked in bruteforce mode"
assert_grep  "$MOCKLOG/shuffledns.args" -- '-m '                        "shuffledns pointed at massdns (-m)"
assert_grep  "$MOCKLOG/shuffledns.args" -- '-r '                        "shuffledns routed through dedicated resolvers"
assert_grep  "$CSV" 'https://brute-host\.example\.com,brute-host\.example\.com,bruteforce' "bruteforced host emitted (source=bruteforce)"

# --- 18) --brute fallback to puredns (shuffledns absent) --------------------
section "--brute fallback (puredns)"
mv "$MOCKBIN/shuffledns" "$TMP/shuffledns.hidden"
run_case brute_puredns --brute --brute-wordlist "$WL"
mv "$TMP/shuffledns.hidden" "$MOCKBIN/shuffledns"
assert_grep  "$MOCKLOG/puredns.args" -- 'bruteforce'                    "puredns invoked for bruteforce when shuffledns absent"
assert_grep  "$CSV" 'https://brute-host\.example\.com,brute-host\.example\.com,bruteforce' "puredns host emitted (source=bruteforce)"

# --- 19) --ports: naabu discovers ports, feeds them to httpx ----------------
section "--ports (naabu -> httpx probe input)"
run_case ports --ports
assert_grep  "$MOCKLOG/naabu.args" -- '-list '                         "naabu received -list of hosts"
assert_grep  "$MOCKLOG/naabu.args" -- '-p '                            "naabu received a -p port spec"
assert_fgrep "$MOCKLOG/httpx.stdin" 'example.com:8080'                  "naabu host:port was fed to the httpx live probe"

# --- 20) --crawlers-all: gospider + hakrawler contribute URLs ---------------
section "--crawlers-all (gospider + hakrawler)"
run_case crawlers --crawlers-all
assert_grep  "$MOCKLOG/gospider.args" -- '-S '                         "gospider received -S live-host list"
assert_grep  "$CSV" 'https://example\.com/gospider-path,example\.com,gospider'   "gospider URL merged (source=gospider)"
assert_grep  "$CSV" 'https://example\.com/hakrawler-path,example\.com,hakrawler' "hakrawler URL merged (source=hakrawler)"

# --- 21) --js: subjs/getJS -> xnLinkFinder endpoint mining ------------------
section "--js (JS endpoint mining)"
run_case js --js
assert_grep  "$MOCKLOG/xnLinkFinder.args" -- '-sf example.com'          "xnLinkFinder scoped to the seed (-sf)"
assert_grep  "$CSV" 'https://example\.com/js-endpoint,example\.com,js'  "mined JS endpoint merged (source=js)"
assert_grep  "$CSV" 'https://example\.com/app\.js,example\.com,js'      "discovered JS file itself recorded (source=js)"

# --- 22) urlfinder auto-runs as a passive source ---------------------------
section "urlfinder (auto passive source)"
run_case urlfinder_auto
assert_grep  "$MOCKLOG/urlfinder.args" -- '-d example.com'              "urlfinder auto-invoked for the seed"
assert_grep  "$CSV" 'https://example\.com/urlfinder-path,example\.com,urlfinder' "urlfinder URL merged (source=urlfinder)"

# --- 23) --takeover: subzy -> side artifact --------------------------------
section "stdin closed for every tool (tlsx/katana/mapcidr read an open stdin even with -l FILE)"
OUTDIR="$TMP/out_stdin"; rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"; rm -f "$MOCKLOG"/*.args "$MOCKLOG/katana.stdin"
timeout 25 env PATH="$TESTPATH" HTTPX_BIN=httpx bash "$RUN_RECON" -i "$DOMAINS" -D "$OUTDIR" -o "$OUTDIR/r.csv" --keep-work \
  < <(sleep 30) >/dev/null 2>"$OUTDIR/stderr.log"; _rc=$?
pkill -f 'sleep 30' 2>/dev/null || true
[ "$_rc" -ne 124 ] && _pass "run completes with stdin held open by another process" || _fail "run completes with stdin held open by another process"
assert_grep  "$MOCKLOG/katana.stdin" '^/dev/null$'                       "tools inherit a closed stdin (/dev/null), not the caller's pipe"

section "--takeover (CNAMEs of every candidate + subzy/nuclei fingerprints)"
TKD="$TMP/takeover_seeds.txt"; printf 'example.com\n' > "$TKD"
# candidates come from subfinder; add the CNAME fixtures to its output for this case
cp "$MOCKBIN/subfinder" "$MOCKBIN/subfinder.orig"
mk subfinder <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/subfinder.args"; echo >> "$MOCKLOG/subfinder.args"
printf 'api.example.com\nwww.example.com\ndead.example.com\norphan.example.com\nstale.example.com\nalias.example.com\n'
EOF
DOMAINS="$TKD" run_case takeover --takeover --subs --resolve
assert_grep   "$MOCKLOG/dnsx.args" -- '-cname -json'                   "takeover: dnsx CNAME lookup"
assert_grep   "$MOCKLOG/dnsx.args" -- '-rcode nxdomain'                 "takeover: CNAME targets checked for NXDOMAIN"
assert_grep   "$CSV.takeover.txt" 'dangling-cname \[high\] host=orphan\.example\.com cname=gone-app\.azurewebsites\.net dns=NXDOMAIN provider=azure-app-service' "dangling CNAME into a takeover-prone service is [high]"
assert_grep   "$CSV.takeover.txt" 'dangling-cname \[medium\] host=stale\.example\.com cname=old\.vendor-example\.net' "dangling CNAME to an unknown domain is [medium]"
assert_grep   "$CSV.takeover.txt" 'host=dead\.example\.com cname=deleted\.herokuapp\.com' "a name dropped by the resolve gate (NXDOMAIN) is still checked"
refute_grep   "$CSV.takeover.txt" 'dangling-cname.*host=alias\.'      "healthy CNAME (target resolves) is not flagged"
assert_grep   "$CSV.cname.tsv" '^example\.com	alias\.example\.com	www\.example\.com	resolves'  "every CNAME goes to <out>.cname.tsv"
assert_grep   "$MOCKLOG/subzy.args" -- '--targets .*cname_hosts\.txt'  "subzy fingerprints the names that have a CNAME (not only live hosts)"
assert_grep   "$CSV.takeover.txt" 'subzy-vulnerable \[high\] host=alias\.example\.com service=GitHub Pages' "subzy VULNERABLE line parsed (ANSI stripped)"
refute_grep   "$CSV.takeover.txt" 'Show only potentially'               "subzy's settings banner is not a finding (v1.16 false positive)"
assert_grep   "$MOCKLOG/nuclei.args" -- '-tags takeover -silent -ni'     "nuclei -tags takeover runs with callbacks off"
assert_grep   "$CSV.takeover.txt" 'nuclei-takeover \[azure-takeover-detection\]' "nuclei takeover hits recorded"
mv "$MOCKBIN/subfinder.orig" "$MOCKBIN/subfinder"
# the report reads the severity tag and attributes host= findings to that host
bash "$(dirname "$RUN_RECON")/generate-report.sh" "$CSV" -o "$OUTDIR/tk.html" >/dev/null 2>&1 || true
if python3 -c 'import sys,re; s=open(sys.argv[1],encoding="utf-8").read(); t=re.sub(r"<[^>]+>"," ",s); sys.exit(0 if re.search(r"MEDIUM\s+Subdomain takeover\s+stale\.example\.com", t) else 1)' "$OUTDIR/tk.html" 2>/dev/null
then _pass "report: dangling CNAME shown as MEDIUM on the affected host"; else _fail "report: dangling CNAME shown as MEDIUM on the affected host"; fi

# --- 24) --origin: tlsx JARM + cdncheck -> side artifact -------------------
section "--origin (edge detection, candidate origins, direct verification)"
# curl stands in for the direct request: the leaked address 10.0.0.1 (direct./origin./
# backend.example.com all resolve to it in the dnsx mock) serves the edge's body;
# 198.51.100.7 (the seed's SPF ip4:) serves nothing. MOCK_ORIGIN_BODY overrides the body.
mk curl <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/curl.args"; echo >> "$MOCKLOG/curl.args"
out=""; res=""; a=("$@"); i=0
while [ $i -lt ${#a[@]} ]; do case "${a[$i]}" in -o) i=$((i+1)); out="${a[$i]}";; --resolve) i=$((i+1)); res="${a[$i]}";; esac; i=$((i+1)); done
[ -n "$out" ] || exit 0
# -w %{http_code}: the status on stdout; an address with nothing listening is refused
# (000, exit 7) as curl reports it
case "$res" in
  example.com:443:10.0.0.1) printf '%s' "${MOCK_ORIGIN_BODY:-ORIGIN-BODY}" > "$out"; printf '200';;
  *) : > "$out"; printf '000'; exit 7;;
esac
exit 0
EOF
run_case origin --origin
assert_grep  "$MOCKLOG/tlsx.args" -- '-jarm -silent -nc'               "tlsx -jarm runs with -nc (no colour codes)"
assert_grep  "$MOCKLOG/httpx.args" -- '-irh -title -hash sha256 -favicon' "reference fetch records headers, title, body hash, favicon"
assert_grep  "$CSV.edge.tsv" '^example\.com	example\.com	cloudflare	nginx/1\.25\.3	server-chain,cf-ray	28d3ed0032' "edge.tsv: edge, origin software, evidence and JARM per host"
assert_grep  "$CSV.edge.tsv" '	cloudflare	-123	Origin Test	104\.16\.1\.1$'  "edge.tsv: cdncheck tag, favicon, title, edge address"
refute_grep  "$CSV.edge.tsv" $'\033'                                    "no terminal colour codes in edge.tsv (v1.17 report showed them)"
assert_grep  "$MOCKLOG/dig.args" 'TXT example\.com'                     "the seed's SPF record is read for candidate addresses"
assert_fgrep "$MOCKLOG/curl.args" '--resolve example.com:443:10.0.0.1'   "candidate verified with curl --resolve (Host and SNI = the site's name)"
assert_fgrep "$MOCKLOG/curl.args" '--resolve example.com:443:198.51.100.7' "SPF ip4: address is a candidate too"
assert_fgrep "$MOCKLOG/curl.args" "--noproxy *"                          "the direct request bypasses any proxy"
refute_grep  "$MOCKLOG/curl.args" '104\.16\.1\.1'                       "the edge's own address is never a candidate"
assert_grep  "$CSV.origin.txt" '^\[example\.com\] origin-exposed \[high\] host=example\.com origin=10\.0\.0\.1 port=443 via=backend\.example\.com,direct\.example\.com,origin\.example\.com match=body-sha256 edge=cloudflare' "verified origin behind an edge -> origin-exposed [high]"
refute_grep  "$CSV.origin.txt" 'jarm|cdn '                               "JARM/CDN hints are attributes (edge.tsv), not findings (v1.17 false positives)"
assert_fgrep "$MOCKLOG/curl.args" '--resolve example.com:443:[2001:db8::1] https://example.com:443/' "AAAA of an origin name is a candidate too (IPv6 bracketed)"
assert_fgrep "$MOCKLOG/curl.args" '--resolve example.com:80:198.51.100.7 http://example.com:80/' "ORIGIN_PORTS: port 80 is tried over plain HTTP"
refute_grep  "$CSV.origin.txt" 'origin-protected'                       "no origin-protected for a site whose origin another address exposes"
bash "$(dirname "$RUN_RECON")/generate-report.sh" "$CSV" -o "$OUTDIR/o.html" >/dev/null 2>&1 || true
if python3 -c 'import sys,re; s=open(sys.argv[1],encoding="utf-8").read(); t=re.sub(r"<[^>]+>"," ",s); sys.exit(0 if re.search(r"HIGH\s+Exposed origin\s+example\.com", t) and "cloudflare &rarr; nginx/1.25.3 &rarr; origin" in s else 1)' "$OUTDIR/o.html" 2>/dev/null
then _pass "report: exposed origin is a HIGH finding; the host card shows edge -> origin software -> origin"; else _fail "report: exposed origin is a HIGH finding; the host card shows edge -> origin software -> origin"; fi
MOCK_ORIGIN_BODY='something else' run_case origin_nomatch --origin
refute_grep  "$CSV.origin.txt" 'origin-(exposed|alternate|candidate)'   "a candidate serving a different page is not reported as an origin"
assert_grep  "$CSV.origin.txt" '^\[example\.com\] origin-protected \[info\] host=example\.com origin=10\.0\.0\.1 via=backend\.example\.com,direct\.example\.com,origin\.example\.com reason=443:status-200-other-content,80:refused ' "an origin name's address that does not serve the site -> origin-protected [info], with the reason per port"
assert_grep  "$CSV.origin.txt" 'origin-protected \[info\] host=example\.com origin=2001:db8::1 .*reason=443:refused,80:refused' "refused on every port -> origin-protected [info]"
bash "$(dirname "$RUN_RECON")/generate-report.sh" "$CSV" -o "$OUTDIR/p.html" >/dev/null 2>&1 || true
if python3 -c 'import sys,re; s=open(sys.argv[1],encoding="utf-8").read(); t=re.sub(r"<[^>]+>"," ",s); sys.exit(0 if "Protected origin" in s and not re.search(r"(HIGH|MEDIUM|LOW)\s+(Exposed origin|Protected origin)", t) else 1)' "$OUTDIR/p.html" 2>/dev/null
then _pass "report: a protected origin is shown as evidence, not as a finding"; else _fail "report: a protected origin is shown as evidence, not as a finding"; fi
ORIGIN_PORTS=443 run_case origin_ports --origin
refute_grep  "$MOCKLOG/curl.args" ':80:'                                 "ORIGIN_PORTS=443: only 443 is tried"
MOCK_ORIGIN_BODY='<html><title>Origin Test</title>changed</html>' run_case origin_title --origin
assert_grep  "$CSV.origin.txt" 'origin-candidate \[low\] host=example\.com origin=10\.0\.0\.1 port=443 .*match=title' "same title, different body -> origin-candidate [low] (verify by hand)"
mk curl <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/curl.args"; echo >> "$MOCKLOG/curl.args"
exit 0
EOF

# --- 25) --screenshots: httpx -ss populates the screenshots dir -------------
section "--screenshots (httpx -ss, browser routing, capture validation)"
mk chromium <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
HTTPS_PROXY=http://proxy.invalid:3128 NO_PROXY=.corp.example,10.0.0.0/8,localhost run_case shots --screenshots
assert_grep  "$MOCKLOG/httpx.args" -- '-ss'                            "httpx invoked with -ss (screenshot)"
assert_grep  "$MOCKLOG/httpx.args" -- '-srd '                         "httpx screenshots directed to our -srd dir"
if find "$OUTDIR"/screenshots-* -name '*.png' 2>/dev/null | grep -q .; then _pass "screenshots dir relocated next to the CSV with images"; else _fail "screenshots dir relocated next to the CSV with images"; fi
assert_grep  "$MOCKLOG/httpx.args" -- '-system-chrome'                  "an installed Chrome/Chromium is used (no download)"
assert_grep  "$MOCKLOG/httpx.args" -- '-ho --proxy-bypass-list=corp\.example;\*\.corp\.example;10\.0\.0\.0/8;localhost' "NO_PROXY handed to the browser in Chrome's syntax (it ignored NO_PROXY)"
assert_grep  "$MOCKLOG/httpx.args" -- '-json -esb -o '                  "screenshot run records what the browser rendered (-json, no image bytes)"
assert_grep  "$CSV.screenshots.tsv" '^example\.com	screenshot/example\.com/abc123\.png	ok	'  "screenshot manifest: host, file, status ok"
HTTPS_PROXY='' https_proxy='' HTTP_PROXY='' http_proxy='' NO_PROXY='' no_proxy='' run_case shots_noproxy --screenshots
refute_grep  "$MOCKLOG/httpx.args" 'proxy-bypass-list|proxy-server'      "no proxy configured: the browser gets no proxy options"
run_case shots_proxy --screenshots --proxy http://user:pw@127.0.0.1:8080
assert_grep  "$MOCKLOG/httpx.args" -- '-ho --proxy-server=http://127\.0\.0\.1:8080' "--proxy reaches the browser (credentials stripped)"
assert_grep  "$ERRLOG" 'cannot use the proxy.s credentials'             "warns that the browser cannot authenticate to the proxy"
MOCK_SS_PROXYPAGE=1 run_case shots_suspect --screenshots
assert_grep  "$CSV.screenshots.tsv" '	suspect	browser rendered .Proxy Error., the probe saw .Home.' "browser title differs from the probe -> suspect (the v1.17 proxy error page)"
assert_grep  "$ERRLOG" 'do not show the probed page'                     "suspect captures are reported at the end of the run"
MOCK_SS_BLANK=1 run_case shots_blank --screenshots
assert_grep  "$CSV.screenshots.tsv" '	blank	the page is empty'           "empty page -> blank (not a failed capture)"
rm -f "$MOCKBIN/chromium"

# --- 26) --vhost: ffuf Host-header bruteforce -> new host rows --------------
section "--vhost (ffuf Host header)"
run_case vhost --vhost --brute-wordlist "$WL"
assert_grep  "$MOCKLOG/ffuf.args" -- 'Host: FUZZ'                      "ffuf received a Host: FUZZ header"
assert_grep  "$CSV" 'ffuf-hit\.example\.com,ffuf-hit\.example\.com,vhost' "vhost hit emitted as host row (source=vhost)"

# --- 27) --nuclei: opt-in scan -> side artifact + scope warning -------------
section "--nuclei (opt-in vuln scan)"
run_case nuclei --nuclei
assert_grep  "$MOCKLOG/nuclei.args" -- '-severity '                    "nuclei received -severity list"
assert_grep  "$CSV.nuclei.txt" 'cve-2021-44228'                        "nuclei finding written to <out>.nuclei.txt"
assert_grep  "$ERRLOG" 'widens scope'                                  "warns that --nuclei widens scope to scanning"
assert_grep  "$MOCKLOG/nuclei.args" -- '-severity [^ ]+ -silent -ni'   "nuclei callbacks off by default (-ni: nothing to public oast.* servers)"
assert_grep  "$ERRLOG" 'nuclei OAST   : off'                           "banner shows the OAST mode"
run_case nuclei_self --nuclei --interactsh-server https://oast.lab.internal
assert_grep  "$MOCKLOG/nuclei.args" -- '-iserver https://oast\.lab\.internal' "--interactsh-server sends callbacks to your own server"
refute_grep  "$MOCKLOG/nuclei.args" -- ' -ni '                         "self-hosted OAST: -ni not passed"
NUCLEI_OAST=self NUCLEI_ISERVER=https://oast.lab.internal NUCLEI_ITOKEN=s3cr3t-token run_case nuclei_tok --nuclei
assert_grep  "$MOCKLOG/nuclei.args" -- '-itoken s3cr3t-token'          "NUCLEI_ITOKEN passed to nuclei"
refute_grep  "$ERRLOG" 's3cr3t-token'                                  "interactsh token never logged"
NUCLEI_OAST=public run_case nuclei_pub --nuclei
refute_grep  "$MOCKLOG/nuclei.args" -- ' -ni | -iserver '              "NUCLEI_OAST=public: nuclei defaults (explicit opt-in)"
assert_grep  "$ERRLOG" 'PUBLIC interactsh servers'                      "public OAST is called out in the banner"
NUCLEI_OAST=self run_case nuclei_noserver --nuclei
assert_grep  "$ERRLOG" 'NUCLEI_OAST=self needs NUCLEI_ISERVER'          "self-hosted OAST without a server is refused"
NUCLEI_OAST=bogus run_case nuclei_bad --nuclei
assert_grep  "$ERRLOG" 'NUCLEI_OAST must be off, self or public'        "invalid NUCLEI_OAST is refused"

# --- 28) --params: arjun -> side artifact ----------------------------------
section "--params (arjun)"
run_case params --params
assert_grep  "$MOCKLOG/arjun.args" -- '-i '                            "arjun received -i input list"
assert_grep  "$MOCKLOG/arjun.args" -- '-oT '                           "arjun writes text output via -oT"
assert_fgrep "$CSV.params.txt" 'search?q='                            "arjun parameter finding written to <out>.params.txt"

# --- 28b) --favicon: uncover -> IPs -> tlsx cert scan -> in-scope hostnames -
section "--favicon (uncover IPs -> tlsx cert scan)"
run_case favicon --favicon
assert_grep  "$MOCKLOG/uncover.args" -- '-q '                          "uncover queried with -q"
assert_grep  "$CSV" 'https://favicon-host\.example\.com,favicon-host\.example\.com,favicon' "hostname recovered from uncover IPs via cert scan (source=favicon)"

# --- 29) --secrets: implies --js, secretfinder scans JS -> side artifact ----
section "--secrets (secretfinder on JS; implies --js)"
run_case secrets --secrets
assert_grep  "$MOCKLOG/subjs.args" -- ''                              "--secrets pulled JS (implies --js: subjs ran)"
assert_grep  "$MOCKLOG/secretfinder.args" -- '-i '                     "secretfinder scanned a JS URL (-i)"
assert_grep  "$CSV.secrets.txt" 'AKIAEXAMPLE'                          "secret finding written to <out>.secrets.txt"

# --- 30) ASN/CIDR seed mode: asnmap -> tlsx cert scan -> seeds --------------
section "ASN/CIDR seed mode (asnmap + tlsx range cert scan)"
ASN_INPUT="$TMP/asn.txt"; printf 'AS13335\n' > "$ASN_INPUT"
OUTDIR="$TMP/out_asn"; rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"; rm -f "$MOCKLOG"/*.args
CSV="$OUTDIR/r.csv"; ERRLOG="$OUTDIR/stderr.log"
printf '   %s...%s running: asn_mode\n' "$C_Y" "$C_0" >&2
mkdir -p "$TMP/asnhome"
timeout 25 env PATH="$TESTPATH" HTTPX_BIN=httpx HOME="$TMP/asnhome" PDCP_API_KEY=test-key \
  bash "$RUN_RECON" -i "$ASN_INPUT" -D "$OUTDIR" -o "$CSV" --keep-work >/dev/null 2>"$ERRLOG" || true
assert_grep  "$MOCKLOG/asnmap.args" -- '-a AS13335'                    "asnmap expands the ASN seed to CIDRs"
assert_grep  "$MOCKLOG/mapcidr.args" -- '-aggregate'                   "mapcidr aggregates ranges (-cl alone would expand every IP)"
assert_fgrep "$OUTDIR"/_work-*/cidrs.txt '192.0.2.0/24'                 "the two /25 halves were merged into one /24"
refute_grep  "$OUTDIR"/_work-*/cidrs.txt -- '-ip-'                      "no per-IP expansion in the range list"
assert_grep  "$ERRLOG" 'skipping 1 IPv6 prefix'                         "IPv6 prefixes are not swept (a /32 is 2^96 addresses)"
refute_grep  "$OUTDIR"/_work-*/cidrs.txt ':'                            "no IPv6 prefix handed to the cert scan"
assert_grep  "$MOCKLOG/tlsx.args" -- '-p 443 '                          "range cert scan on 443 by default"
assert_fgrep "$MOCKLOG/tlsx.args" 'cidrs.txt'                          "tlsx cert-scans the expanded CIDR list"
assert_grep  "$ERRLOG" 'ASN/CIDR expansion'                           "startup reports ASN/CIDR expansion"
assert_grep  "$CSV" '^cert-sibling\.example\.com,https://cert-sibling\.example\.com/gau-path' "cert-derived hostname enrolled as a seed and crawled"
assert_grep  "$MOCKLOG/tlsx.args" -- '-san -cn -json'                   "range cert scan records which address presented each name (-json)"
assert_fgrep "$OUTDIR"/_work-*/range_certs.tsv $'192.0.2.10\tcert-sibling.example.com' "address/name pairs kept for --origin"
# --origin: an address in your ranges that presents the site's certificate is a candidate
OUTDIR="$TMP/out_asn_origin"; rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"; rm -f "$MOCKLOG"/*.args; ERRLOG="$OUTDIR/stderr.log"
timeout 40 env PATH="$TESTPATH" HTTPX_BIN=httpx HOME="$TMP/asnhome" PDCP_API_KEY=test-key TLS_CHAIN_CHECK=0 \
  bash "$RUN_RECON" -i "$ASN_INPUT" -D "$OUTDIR" -o "$OUTDIR/r.csv" --keep-work --origin >/dev/null 2>"$ERRLOG" || true
assert_fgrep "$MOCKLOG/curl.args" '--resolve cert-sibling.example.com:443:192.0.2.10' "--origin tries the range address whose certificate names the site (range-cert)"
# no key: say so up front and do not call asnmap
OUTDIR="$TMP/out_asn_nokey"; rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"; rm -f "$MOCKLOG"/*.args; ERRLOG="$OUTDIR/stderr.log"
timeout 25 env -u PDCP_API_KEY PATH="$TESTPATH" HTTPX_BIN=httpx HOME="$TMP/asnhome" \
  bash "$RUN_RECON" -i "$ASN_INPUT" -D "$OUTDIR" -o "$OUTDIR/r.csv" --keep-work >/dev/null 2>"$ERRLOG" || true
assert_grep  "$ERRLOG" 'need a ProjectDiscovery Cloud API key for asnmap' "no PDCP key: clear warning (was: silent 'no hostnames')"
assert_absent "$MOCKLOG/asnmap.args"                                    "no PDCP key: asnmap is not called"
# rejected key: asnmap's stdout prompt is not mistaken for a range
OUTDIR="$TMP/out_asn_reject"; rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"; rm -f "$MOCKLOG"/*.args; ERRLOG="$OUTDIR/stderr.log"
timeout 25 env PATH="$TESTPATH" HTTPX_BIN=httpx HOME="$TMP/asnhome" PDCP_API_KEY=bad-key ASNMAP_MOCK=reject \
  bash "$RUN_RECON" -i "$ASN_INPUT" -D "$OUTDIR" -o "$OUTDIR/r.csv" --keep-work >/dev/null 2>"$ERRLOG" || true
assert_grep  "$ERRLOG" 'PDCP API key was rejected'                       "rejected key reported as such"
refute_grep  "$OUTDIR"/_work-*/cidrs.txt 'Enter PDCP'                    "asnmap's key prompt (stdout) never reaches the range list"
# with --ports, the range cert scan follows the port list
OUTDIR="$TMP/out_asn_ports"; rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"; rm -f "$MOCKLOG"/*.args; ERRLOG="$OUTDIR/stderr.log"
timeout 25 env PATH="$TESTPATH" HTTPX_BIN=httpx HOME="$TMP/asnhome" PDCP_API_KEY=test-key \
  bash "$RUN_RECON" -i "$ASN_INPUT" -D "$OUTDIR" -o "$OUTDIR/r.csv" --keep-work --ports --port-spec 443,8443 >/dev/null 2>"$ERRLOG" || true
assert_fgrep "$MOCKLOG/tlsx.args" '-p 443,8443 '                         "with --ports, the range cert scan uses the same port list"

# --- 31) --monitor: diff vs prior CSV -> new-assets + notify ----------------
section "--monitor (diff vs prior CSV + notify)"
PREVCSV="$TMP/prev.csv"
printf 'seed_domain,url,host,sources,status_code,content_length,webserver,title,technologies\n' > "$PREVCSV"
printf 'example.com,https://example.com/OLD-ONLY,example.com,gau,,,,,\n' >> "$PREVCSV"
run_case monitor --monitor --monitor-prev "$PREVCSV" --notify
assert_grep  "$CSV.new-assets.txt" 'gau-path'                         "new URL flagged as a new asset vs prior CSV"
refute_grep  "$CSV.new-assets.txt" 'OLD-ONLY'                         "prior-only URL not reported as new"
assert_grep  "$ERRLOG" 'new asset'                                    "monitoring summary reports new assets"
assert_grep  "$MOCKLOG/notify.args" -- '^-silent -bulk $'               "notify sends one message per run (-bulk)"
assert_grep  "$MOCKLOG/notify.stdin" '^run-recon: [0-9]+ new asset\(s\) vs prev\.csv$' "the message opens with a summary line"
assert_grep  "$MOCKLOG/notify.stdin" 'gau-path'                       "...and lists the new assets"
NOTIFY_CONFIG="$TMP/notify.yaml" run_case monitor_cfg --monitor --monitor-prev "$PREVCSV" --notify
assert_grep  "$MOCKLOG/notify.args" -- "-pc $TMP/notify\.yaml"          "NOTIFY_CONFIG picks the providers (-pc)"

# --- 32) --all: umbrella enables the full discovery + defensive set ---------
section "--all (umbrella flag)"
run_case all_flag --all --brute-wordlist "$WL"
assert_grep  "$MOCKLOG/naabu.args"      -- ''                         "--all enabled port discovery (naabu ran)"
assert_grep  "$MOCKLOG/shuffledns.args" -- ''                         "--all enabled DNS bruteforce (shuffledns ran)"
assert_grep  "$MOCKLOG/subzy.args"      -- ''                         "--all enabled takeover detection (subzy ran)"
assert_grep  "$MOCKLOG/tlsx.args"       -- '-jarm'                    "--all enabled origin fingerprinting (tlsx -jarm ran)"
assert_grep  "$ERRLOG" 'zone-exposure=on'                              "--all enabled the DNS zone exposure check"
assert_grep  "$MOCKLOG/gospider.args"   -- ''                         "--all enabled extra crawlers (gospider ran)"
assert_grep  "$MOCKLOG/whatweb.args"    -- ''                         "--all enabled active CMS scanning (whatweb fingerprint ran)"
assert_grep  "$MOCKLOG/feroxbuster.args" -- 'Discovery/Web-Content'   "--all enabled the thorough active scan (feroxbuster over SecLists ran)"

# --- 33) passive-only gates off ALL new active stages ----------------------
section "--passive-only disables ports/brute/js/takeover/nuclei/origin/secrets/active/activescan"
run_case passive_gate2 --passive-only --ports --brute --brute-wordlist "$WL" \
         --js --takeover --nuclei --origin --secrets --crawlers-all --active --activescan
assert_grep   "$ERRLOG" 'ignored under --passive-only'                "new active flags warned + disabled under --passive-only"
assert_absent "$MOCKLOG/naabu.args"                                   "naabu NOT invoked under --passive-only"
assert_absent "$MOCKLOG/shuffledns.args"                              "shuffledns NOT invoked under --passive-only"
assert_absent "$MOCKLOG/subzy.args"                                   "subzy NOT invoked under --passive-only"
assert_absent "$MOCKLOG/nuclei.args"                                  "nuclei NOT invoked under --passive-only"
assert_absent "$MOCKLOG/gospider.args"                               "gospider NOT invoked under --passive-only"
assert_absent "$MOCKLOG/whatweb.args"                                "whatweb (active CMS) NOT invoked under --passive-only"
assert_absent "$MOCKLOG/wpscan.args"                                 "wpscan NOT invoked under --passive-only"
assert_absent "$MOCKLOG/feroxbuster.args"                            "feroxbuster (activescan) NOT invoked under --passive-only"

# --- 34) --github: github-subdomains (host rows) + github-endpoints (URLs) --
section "--github (github-subdomains + github-endpoints)"
GHTOKFILE="$TMP/ghtoken.txt"; printf 'ghp_dummytoken\n' > "$GHTOKFILE"
run_case github --github --github-token "$GHTOKFILE"
assert_grep  "$MOCKLOG/github-subdomains.args" -- '-d example.com'     "github-subdomains queried the seed"
assert_grep  "$MOCKLOG/github-subdomains.args" -- '-t '               "github-subdomains received the token file"
assert_grep  "$CSV" 'https://github-host\.example\.com,github-host\.example\.com,github' "github-mined subdomain emitted (source=github)"
assert_grep  "$MOCKLOG/github-endpoints.args" -- '-o '               "github-endpoints wrote to an -o file"
assert_grep  "$CSV" 'https://example\.com/github-endpoint,example\.com,github' "github-mined endpoint merged (source=github)"

# --- 35) --github without a token is disabled ------------------------------
section "--github without token (disabled)"
run_case github_notok --github
assert_grep   "$ERRLOG" 'needs a token'                              "warns --github needs a token"
assert_absent "$MOCKLOG/github-subdomains.args"                      "github-subdomains NOT invoked without a token"

# --- 36) --buckets: cloud_enum -> side artifact (findings only) -------------
section "--buckets (cloud_enum S3/Azure/GCP)"
run_case buckets --buckets
assert_grep  "$MOCKLOG/cloud_enum.args" -- '-k example.com'          "cloud_enum keyed on the seed domain"
assert_grep  "$MOCKLOG/cloud_enum.args" -- '-k example'             "cloud_enum also keyed on the base label"
assert_grep  "$CSV.buckets.txt" 'OPEN S3 BUCKET'                     "open bucket finding written to <out>.buckets.txt"
refute_grep  "$CSV.buckets.txt" 'Checking for S3'                    "cloud_enum progress lines filtered out of the artifact"

# --- 37) --refresh-resolvers: dnsvalidator regenerates the resolver list ----
section "--refresh-resolvers (dnsvalidator)"
run_case refresh --resolve --refresh-resolvers
assert_grep  "$MOCKLOG/dnsvalidator.args" -- '-tL '                  "dnsvalidator invoked with a baseline list (-tL)"
assert_grep  "$MOCKLOG/dnsvalidator.args" -- '-o '                   "dnsvalidator wrote the validated list (-o)"
assert_grep  "$ERRLOG" 'validated resolvers'                         "startup reports the freshly validated resolver count"
assert_grep  "$MOCKLOG/dnsx.args" -- '-r '                          "dnsx uses the refreshed resolver list"

# --- 38) --active: CMS fingerprint -> per-CMS deep enum + nuclei vuln map ----
section "--active (whatweb -> wpscan/droopescan/joomscan + nuclei tech,cms)"
run_case active --active
assert_grep  "$MOCKLOG/whatweb.args"    -- 'example.com'              "whatweb fingerprinted the live host"
assert_grep  "$MOCKLOG/wpscan.args"     -- '--enumerate '            "wpscan enumerated the WordPress host"
assert_grep  "$MOCKLOG/droopescan.args" -- 'scan drupal'             "droopescan scanned the Drupal host"
assert_grep  "$MOCKLOG/joomscan.args"   -- '--url '                  "joomscan scanned the Joomla host"
assert_grep  "$MOCKLOG/nuclei.args"     -- '-tags tech,cms'          "nuclei ran tech,cms templates for vuln mapping"
assert_grep  "$CSV.cms.txt" 'wpscan'                                 "wpscan findings written to <out>.cms.txt"
assert_grep  "$CSV.cms.txt" 'nuclei-cms'                             "nuclei CMS findings written to <out>.cms.txt"

# --- 39) --active native fallback: ffuf plugin/theme brute (wpscan absent) ---
section "--active native WP brute (ffuf) when wpscan absent"
mv "$MOCKBIN/wpscan" "$TMP/wpscan.hidden"
run_case active_native --active --cms-wordlist "$WL"
mv "$TMP/wpscan.hidden" "$MOCKBIN/wpscan"
assert_grep  "$MOCKLOG/ffuf.args" -- 'wp-content/plugins/FUZZ'        "native WP plugin brute via ffuf when wpscan absent"
assert_grep  "$CSV.cms.txt" 'wp-plugin'                              "ffuf plugin hit recorded in <out>.cms.txt"

# --- 40) --active generic path: cmseek when fingerprint is unknown ----------
section "--active generic CMS (cmseek) when fingerprint unknown"
mv "$MOCKBIN/whatweb" "$TMP/whatweb.hidden"
run_case active_generic --active
mv "$TMP/whatweb.hidden" "$MOCKBIN/whatweb"
assert_grep  "$MOCKLOG/cmseek.args" -- '-u '                         "cmseek scanned the unfingerprinted host"
assert_grep  "$CSV.cms.txt" 'cmseek'                                 "cmseek findings written to <out>.cms.txt"

# --- 41) --activescan: SecLists content discovery (feroxbuster) + nuclei -----
section "--activescan (feroxbuster over SecLists + nuclei)"
run_case activescan --activescan
assert_grep  "$MOCKLOG/feroxbuster.args" -- 'raft-large-directories' "feroxbuster ran a SecLists content list"
assert_grep  "$MOCKLOG/feroxbuster.args" -- 'api-endpoints'          "feroxbuster iterated multiple SecLists lists (api)"
assert_grep  "$MOCKLOG/nuclei.args"      -- '-severity'              "activescan ran a broad nuclei scan"
assert_grep  "$MOCKLOG/uro.args"         -- 'activescan_urls'        "uro deduped feroxbuster output before nuclei"
assert_grep  "$CSV.activescan.txt" 'uro filtered content'           "uro filter summary recorded in <out>.activescan.txt"
assert_grep  "$MOCKLOG/nuclei.args"      -- 'activescan_targets'     "nuclei scanned the uro-cleaned discovered URLs (+ live hosts)"
assert_fgrep "$CSV.activescan.txt" 'content('                       "content-discovery hits written to <out>.activescan.txt"
assert_grep  "$CSV.activescan.txt" 'nuclei'                         "nuclei findings written to <out>.activescan.txt"

# --- 42) --activescan ffuf fallback (feroxbuster absent) -------------------
section "--activescan ffuf fallback (feroxbuster absent)"
mv "$MOCKBIN/feroxbuster" "$TMP/feroxbuster.hidden2"
run_case activescan_ffuf --activescan
mv "$TMP/feroxbuster.hidden2" "$MOCKBIN/feroxbuster"
assert_grep  "$MOCKLOG/ffuf.args" -- 'Discovery/Web-Content'         "ffuf used SecLists lists when feroxbuster absent"
assert_fgrep "$CSV.activescan.txt" 'content('                       "ffuf activescan hits written to <out>.activescan.txt"

# --- 43) default httpx binary is httpx-toolkit (no HTTPX_BIN override) -------
section "default httpx is httpx-toolkit (no HTTPX_BIN set)"
OUTDIR="$TMP/out_httpxdefault"; rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"; rm -f "$MOCKLOG"/*.args
ERRLOG="$OUTDIR/stderr.log"
printf '   %s...%s running: httpx_default\n' "$C_Y" "$C_0" >&2
timeout 25 env -u HTTPX_BIN PATH="$TESTPATH" \
  bash "$RUN_RECON" -i "$DOMAINS" -D "$OUTDIR" -o "$OUTDIR/r.csv" >/dev/null 2>"$ERRLOG" || true
assert_grep   "$MOCKLOG/httpx-toolkit.args" -- ''                    "run-recon calls httpx-toolkit by default (no HTTPX_BIN)"
assert_absent "$MOCKLOG/httpx.args"                                  "the python-named 'httpx' is NOT used by default"
assert_grep   "$OUTDIR/r.csv" ',example\.com,gau,200,100,nginx,'     "enrichment columns populated via the default httpx-toolkit"
assert_fgrep  "$OUTDIR/r.csv" 'technologies,ip,asn,asn_org'          "CSV header carries the ip/asn/asn_org attribution columns"
assert_grep   "$OUTDIR/r.csv" ',93\.184\.216\.34,AS15133,"EDGECAST, US"' "ip + ASN + org resolved (httpx A-record + Team Cymru)"

# --- 44) --osint: passive (no key), and NOT gated by --passive-only ---------
section "--osint (passive OSINT; runs even under --passive-only)"
run_case osint --osint
assert_grep   "$ERRLOG" 'OSINT enabled'                             "--osint enabled (RDAP + InternetDB + Team Cymru, no key)"
run_case osint_passive --passive-only --osint
assert_grep   "$ERRLOG" 'OSINT enabled'                             "--osint still enabled under --passive-only (third-party lookups)"
refute_grep   "$ERRLOG" '\-\-osint ignored under --passive-only'    "--osint not disabled by --passive-only"

# --- 45) --virustotal gates on VT_API_KEY -----------------------------------
section "--virustotal (needs VT_API_KEY)"
run_case vt_nokey --virustotal
assert_grep   "$ERRLOG" 'needs VT_API_KEY'                          "--virustotal disabled without a key"
OUTDIR="$TMP/out_vtkey"; rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"; rm -f "$MOCKLOG"/*.args; ERRLOG="$OUTDIR/stderr.log"
printf '   %s...%s running: vt_key\n' "$C_Y" "$C_0" >&2
timeout 25 env PATH="$TESTPATH" HTTPX_BIN=httpx VT_API_KEY=dummy \
  bash "$RUN_RECON" -i "$DOMAINS" -D "$OUTDIR" -o "$OUTDIR/r.csv" --virustotal >/dev/null 2>"$ERRLOG" || true
assert_grep   "$ERRLOG" 'VirusTotal enrichment enabled'            "--virustotal enabled when VT_API_KEY is set"

# --- 46) --urlscan enables (optional key) -----------------------------------
section "--urlscan"
run_case urlscan --urlscan
assert_grep   "$ERRLOG" 'urlscan.io enrichment enabled'            "--urlscan enabled (optional key)"

# --- 47) --social: tookie-osint account discovery (brand from domain) -------
section "--social (tookie-osint social-media discovery)"
run_case social --social
assert_grep   "$ERRLOG" 'Social-media discovery enabled'           "--social enabled when tookie-osint present"
assert_grep   "$MOCKLOG/tookie-osint.args" -- '-u example'         "tookie-osint queried the brand username from example.com"
assert_grep   "$CSV.social.txt" 'github\.com/example'              "found social accounts written to <out>.social.txt"
refute_grep   "$CSV.social.txt" 'not found'                        "non-hits (\\[-\\]) excluded from social results"
# custom username override
run_case social_user --social-user acmecorp
assert_grep   "$MOCKLOG/tookie-osint.args" -- '-u acmecorp'        "--social-user overrides the domain-derived brand"
# gating: hidden tookie-osint -> disabled with guidance
mv "$MOCKBIN/tookie-osint" "$TMP/tookie.hidden"
run_case social_missing --social
mv "$TMP/tookie.hidden" "$MOCKBIN/tookie-osint"
assert_grep   "$ERRLOG" 'needs tookie-osint'                       "--social disabled (with guidance) when tookie-osint absent"

# --- 48) --limits: load per-source OSINT timeouts/delays (probe -> run-recon) -
section "--limits (probe output wired into run-recon)"
LIMF="$TMP/limits.env"; printf 'export VT_TIMEOUT=11\nexport VT_DELAY=2\nexport INTERNETDB_DELAY=0.5\n' > "$LIMF"
run_case limits --osint --limits "$LIMF"
assert_grep   "$ERRLOG" 'loaded rate/timeout limits'               "--limits sourced the probe's config file"
run_case limits_missing --osint --limits "$TMP/nope.env"
assert_grep   "$ERRLOG" 'limits file not found'                    "--limits warns and continues when the file is absent"

# --- 49) HTML report generation (generate-report.sh + run-recon wiring) -----
section "HTML report (generate-report.sh, findings + screenshots + hosts)"
REPORT_SH="$(dirname "$RUN_RECON")/generate-report.sh"
RPTDIR="$TMP/rptfix"; rm -rf "$RPTDIR"; mkdir -p "$RPTDIR/screenshots-t/screenshot"
cat > "$RPTDIR/r.csv" <<CSVEOF
seed_domain,url,host,sources,status_code,content_length,webserver,title,technologies,ip,asn,asn_org
example.com,https://example.com/,example.com,gau,200,10,nginx,Home,nginx,93.184.216.34,AS15133,"EDGECAST, US"
example.com,https://admin.example.com/,admin.example.com,subfinder,200,10,nginx,Admin,nginx,93.184.216.34,AS15133,"EDGECAST, US"
CSVEOF
printf '[example.com] nuclei [CVE-2023-9999] [http] [high] https://admin.example.com/x\n' > "$RPTDIR/r.csv.nuclei.txt"
printf '[example.com] takeover admin.example.com dangling CNAME to unclaimed s3 bucket\n' > "$RPTDIR/r.csv.takeover.txt"
printf '[example.com] shodan-internetdb 93.184.216.34 ports=[443] hostnames=[] tags=[cdn]\n' > "$RPTDIR/r.csv.osint.txt"
printf 'PNG' > "$RPTDIR/screenshots-t/screenshot/https_admin.example.com.png"
# host-in-subdirectory layout (generic filename) -- regression guard: the report
# must match the host from a dir component, not only the basename.
mkdir -p "$RPTDIR/screenshots-t/screenshot/example.com"
printf 'PNG' > "$RPTDIR/screenshots-t/screenshot/example.com/screenshot.png"
env PATH="$TESTPATH" bash "$REPORT_SH" -o "$RPTDIR/out.html" "$RPTDIR/r.csv" >/dev/null 2>"$RPTDIR/e.log"
assert_exists "$RPTDIR/out.html"                                   "report HTML file created"
assert_grep   "$RPTDIR/out.html" 'CVE-2023-9999'                  "nuclei vulnerability rendered in report"
assert_grep   "$RPTDIR/out.html" 'HIGH'                           "severity badge rendered"
assert_grep   "$RPTDIR/out.html" 'Subdomain takeover'            "takeover weakness highlighted in findings"
assert_grep   "$RPTDIR/out.html" 'https_admin.example.com.png'   "screenshot linked into the host card"
assert_grep   "$RPTDIR/out.html" 'example\.com/screenshot\.png'  "screenshot matched from a host subdirectory (not just basename)"
assert_grep   "$RPTDIR/out.html" 'shodan-internetdb'            "OSINT sub-source preserved (not stripped)"
assert_grep   "$RPTDIR/out.html" 'EDGECAST'                     "ASN/network attribution shown per host"
assert_grep   "$RPTDIR/out.html" 'id="h-adminexamplecom"'       "per-host anchor emitted for cross-linking"
# an empty image file is a failed capture, not a screenshot (v1.17 showed broken images)
: > "$RPTDIR/screenshots-t/screenshot/https_admin.example.com.png"
env PATH="$TESTPATH" bash "$REPORT_SH" -o "$RPTDIR/out0.html" "$RPTDIR/r.csv" >/dev/null 2>&1
refute_grep   "$RPTDIR/out0.html" 'src="[^"]*https_admin\.example\.com\.png'  "a 0-byte image is not shown as the host's screenshot"
assert_grep   "$RPTDIR/out0.html" 'screenshot failed'                "a 0-byte image is shown as a failed capture"
assert_grep   "$RPTDIR/out.html" 'Known vulnerabilities: not checked' "no vuln join -> the report says vulnerabilities were not checked"
# versioned and versionless CPEs are counted apart: only a version can be matched to CVEs
{ printf 'seed_domain,url,host,sources,status_code,content_length,webserver,title,technologies,ip,asn,asn_org,tls_version,tls_cipher,cert_not_after,cert_issuer,tls_flags,ipv6,cloud,rdap_org,geo,cpe\n'
  printf 'example.com,https://example.com/,example.com,gau,200,10,nginx,Home,Nginx,93.184.216.34,,,,,,,,,,,,cpe:2.3:a:f5:nginx:1.21.6:*:*:*:*:*:*:*\n'
  printf 'example.com,https://ci.example.com/,ci.example.com,gau,200,10,Jetty,CI,Jenkins,93.184.216.35,,,,,,,,,,,,cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*\n'
} > "$RPTDIR/cpe.csv"
env PATH="$TESTPATH" bash "$REPORT_SH" -o "$RPTDIR/cpe.html" "$RPTDIR/cpe.csv" >/dev/null 2>&1
assert_grep   "$RPTDIR/cpe.html" '1 versioned CPE\(s\) on 1 host\(s\) would be checked' "versioned CPEs: the ones a CVE join can use"
assert_grep   "$RPTDIR/cpe.html" '1 CPE\(s\) on 1 host\(s\) carry no version'           "versionless CPEs counted apart (the product, not its version)"
# wiring: a normal run auto-builds the report; --no-report suppresses it
run_case report_auto
assert_exists "$CSV.report.html"                                  "run-recon auto-generates <out>.report.html at end of run"
run_case report_off --no-report
assert_absent "$CSV.report.html"                                  "--no-report suppresses the HTML report"

# --- 50) PostgreSQL cache/store (recon-db.sh) integration -------------------
section "--db graceful degradation (Postgres unavailable)"
run_case db_off --db --passive-only
assert_grep   "$ERRLOG" 'not reachable'                            "--db warns when the recon Postgres DB is unreachable"
assert_grep   "$ERRLOG" 'without the DB cache'                     "--db downgrades to a normal uncached run"
assert_grep   "$CSV" 'example\.com'                               "run still completes + CSV produced without the DB"
assert_absent "$MOCKLOG/psql.args"                                "no psql calls attempted once the DB is ruled unavailable"

section "--db wiring: cache consulted + inventory persisted (mock psql)"
mk psql <<'PSQLEOF'
#!/usr/bin/env bash
printf 'ARGS: %s\n' "$*" >> "$MOCKLOG/psql.args"
sql=""; A=("$@"); i=0
while [ $i -lt ${#A[@]} ]; do case "${A[$i]}" in -c) i=$((i+1)); sql="${A[$i]}";; esac; i=$((i+1)); done
[ -z "$sql" ] && sql="$(cat 2>/dev/null)"
printf 'SQL: %s\n' "$sql" >> "$MOCKLOG/psql.args"
case "$sql" in "SELECT 1") echo 1;; *) : ;; esac   # reachable; cache gets miss -> live fetch + put
exit 0
PSQLEOF
run_case db_wire --db --osint
assert_grep   "$ERRLOG" 'PostgreSQL reachable'                    "--db health check passes when psql + DB are reachable"
assert_grep   "$ERRLOG" 'caching on'                              "--db reports caching enabled after the health check"
assert_grep   "$MOCKLOG/psql.args" 'recon_cache'                  "lookups consult the recon_cache table"
assert_grep   "$MOCKLOG/psql.args" "source='urls'"              "passive-crawl URLs keyed/cached by domain (skips re-crawl)"
assert_grep   "$MOCKLOG/psql.args" 'recon_hosts'                  "run inventory persisted into recon_hosts"
assert_grep   "$CSV" 'example\.com'                               "run completes with a populated CSV under --db"
assert_grep   "$MOCKLOG/psql.args" 'httpx_json'                   "httpx per-URL enrichment keyed/cached (skips re-probing URLs)"
assert_grep   "$MOCKLOG/psql.args" 'live_probe'                   "httpx live-host probe cached per host"
assert_grep   "$MOCKLOG/psql.args" "'katana'"                     "katana crawl output cached per live host"
# A1: subdomain-enum results cached per seed; A2: ASN synced; negative cache namespace used
run_case subs_db --db --subs
assert_grep   "$MOCKLOG/psql.args" "source='subs'"             "A1: passive subdomain-enum results keyed/cached per seed"
run_case asn_db --db
assert_grep   "$MOCKLOG/psql.args" "source='asn'"              "A2: per-IP ASN persisted to the DB cache"
# port / origin / screenshot caches (need their flags to run)
run_case db_wire2 --db --ports --origin --screenshots
assert_grep   "$MOCKLOG/psql.args" 'naabu_ports'                  "naabu port results cached per host"
assert_grep   "$MOCKLOG/psql.args" 'tlsx_jarm'                    "tlsx JARM fingerprints cached per host"
assert_grep   "$MOCKLOG/psql.args" "source='screenshot'"        "screenshots byte-cached per host (skip re-render)"
rm -f "$MOCKBIN/psql"

# --- import historic run CSVs into recon_hosts (oldest first, newest wins) --------
section "import: historic CSVs load oldest-first, newest run authoritative, schema-drift tolerant"
IMPDIR="$TMP/import"; rm -rf "$IMPDIR"; mkdir -p "$IMPDIR/data"
# a stateful psql mock modelling db_load_csv (\copy _stage + INSERT..SELECT ON CONFLICT)
# and the 'latest' DISTINCT ON view, backed by a JSON file
cat > "$MOCKBIN/psql" <<'PSQLEOF'
#!/usr/bin/env python3
import sys, os, re, csv, json
DB=os.environ["HOSTS_DB"]
load=lambda: (json.load(open(DB)) if os.path.exists(DB) else {})
save=lambda d: json.dump(d, open(DB,"w"))
a=sys.argv[1:]; sql=a[a.index("-c")+1] if "-c" in a else sys.stdin.read()
if sql.strip()=="SELECT 1": print(1); sys.exit(0)
if "\\copy _stage FROM" in sql and "INSERT INTO recon_hosts" in sql:
    path=re.search(r"\\copy _stage FROM '([^']+)'", sql).group(1)
    ts=re.search(r"SELECT '([^']*)',", sql).group(1); db=load()
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            url=row.get("url","")
            if not url: continue
            k=ts+"\x1f"+url
            if k in db: continue
            db[k]={"run_ts":ts,"url":url,"host":row.get("host",""),"ip":row.get("ip",""),
                   "asn_org":row.get("asn_org",""),"status_code":row.get("status_code",""),"title":row.get("title","")}
    save(db); sys.exit(0)
m=re.search(r"DISTINCT ON \(url\).*WHERE host LIKE '%([^']*)%'", sql, re.S)
if m:
    pat=m.group(1); db=load(); best={}
    for r in db.values():
        if pat not in r["host"]: continue
        if r["url"] not in best or r["run_ts"]>best[r["url"]]["run_ts"]: best[r["url"]]=r
    for u in sorted(best):
        r=best[u]; print("|".join([r["run_ts"],r["host"],r["url"],r["ip"],r["asn_org"],r["status_code"],r["title"]]))
    sys.exit(0)
m=re.search(r"SELECT run_ts,host,ip,asn_org,status_code FROM recon_hosts WHERE host LIKE '%([^']*)%'", sql)
if m:
    pat=m.group(1)
    for r in sorted(load().values(), key=lambda x:(x["host"],x["run_ts"])):
        if pat in r["host"]: print("|".join([r["run_ts"],r["host"],r["ip"],r["asn_org"],r["status_code"]]))
    sys.exit(0)
sys.exit(0)
PSQLEOF
chmod +x "$MOCKBIN/psql"
# old NARROW schema (no enrichment): a.example.com status 200
printf 'seed_domain,url,host,sources,status_code,content_length\nex.com,https://a.example.com/,a.example.com,gau,200,100\n' > "$IMPDIR/data/recon-20260101-120000.csv"
# newer FULL schema: a.example.com now 500 (changed) + b.example.com
printf 'seed_domain,url,host,sources,status_code,content_length,webserver,title,technologies,ip,asn,asn_org\nex.com,https://a.example.com/,a.example.com,gau,500,0,nginx,Down,nginx,1.1.1.1,AS1,OrgA\nex.com,https://b.example.com/,b.example.com,katana,200,50,apache,Bee,apache,2.2.2.2,AS2,OrgB\n' > "$IMPDIR/data/recon-20260301-120000.csv"
env PATH="$TESTPATH" HOSTS_DB="$IMPDIR/hosts.json" bash "$(dirname "$RUN_RECON")/recon-db.sh" import "$IMPDIR/data" > "$IMPDIR/imp.log" 2>&1 || true
env PATH="$TESTPATH" HOSTS_DB="$IMPDIR/hosts.json" bash "$(dirname "$RUN_RECON")/recon-db.sh" latest > "$IMPDIR/latest.log" 2>&1 || true
env PATH="$TESTPATH" HOSTS_DB="$IMPDIR/hosts.json" bash "$(dirname "$RUN_RECON")/recon-db.sh" hosts a.example.com > "$IMPDIR/hist.log" 2>&1 || true
assert_fgrep "$IMPDIR/imp.log"    'recon-20260101-120000.csv -> run_ts=20260101-120000'  "old narrow-schema CSV imported (columns matched by name)"
assert_fgrep "$IMPDIR/imp.log"    'imported 2 file(s), 3 row(s)'                          "both files imported, row counts summed"
assert_fgrep "$IMPDIR/latest.log" '20260301-120000|a.example.com|https://a.example.com/|1.1.1.1|OrgA|500' "latest view: newest run wins per URL (500, not 200)"
assert_fgrep "$IMPDIR/hist.log"   '20260101-120000|a.example.com|||200'                   "history preserved: the old run's 200 row is still queryable"
refute_grep  "$IMPDIR/latest.log" '20260101.*a\.example\.com'                             "stale run not shown as current for a.example.com"

# db_load_csv must load a FULL-WIDTH live-run CSV (tls_* + ipv6/cloud/rdap_org/geo),
# normalizing to the fixed 12-col _stage. Real psql would reject the raw wide CSV with
# "extra data after last expected column" (the bash mock won't enforce width, so this
# exercises the normalize path directly against a 21-column header).
printf 'seed_domain,url,host,sources,status_code,content_length,webserver,title,technologies,ip,asn,asn_org,tls_version,tls_cipher,cert_not_after,cert_issuer,tls_flags,ipv6,cloud,rdap_org,geo\nex.com,https://c.example.com/,c.example.com,gau,200,10,nginx,Cee,nginx,3.3.3.3,AS3,OrgC,TLS1.3,TLS_AES_128_GCM_SHA256,2030-01-01T00:00:00Z,"CA Inc",,2001:db8::1,AWS,Amazon,US\n' > "$IMPDIR/data/full-width.csv"
env PATH="$TESTPATH" HOSTS_DB="$IMPDIR/full.json" bash -c '. "'"$(dirname "$RUN_RECON")"'/recon-db.sh" 2>/dev/null; db_load_csv "'"$IMPDIR"'/data/full-width.csv" "20260401-000000"' > "$IMPDIR/full.log" 2>&1 || true
env PATH="$TESTPATH" HOSTS_DB="$IMPDIR/full.json" bash "$(dirname "$RUN_RECON")/recon-db.sh" hosts c.example.com > "$IMPDIR/fullq.log" 2>&1 || true
assert_fgrep "$IMPDIR/fullq.log" '20260401-000000|c.example.com|3.3.3.3|OrgC|200' "db_load_csv normalizes a 21-col run CSV (url/host/ip/asn_org/status preserved)"

# --- fix-collation: detect a glibc collation mismatch, REINDEX + REFRESH, verify -
section "fix-collation: init detects a collation mismatch and fix-collation clears it"
COLLDIR="$TMP/collation"; rm -rf "$COLLDIR"; mkdir -p "$COLLDIR/state"
touch "$COLLDIR/state/mismatch"   # start with the mismatch present
# stateful psql mock: the catalog check reports the mismatch; REFRESH clears it
cat > "$MOCKBIN/psql" <<'PSQLEOF'
#!/usr/bin/env python3
import sys, os
mm=os.path.join(os.environ["COLL_STATE"],"mismatch")
a=sys.argv[1:]; sql=a[a.index("-c")+1] if "-c" in a else (sys.stdin.read() if not sys.stdin.isatty() else "")
if sql.strip()=="SELECT 1": print("1"); sys.exit(0)
if "pg_database_collation_actual_version" in sql:
    sys.stdout.write("t\n" if os.path.exists(mm) else "f\n"); sys.exit(0)
if sql.startswith("REINDEX DATABASE"): sys.exit(0)
if "REFRESH COLLATION VERSION" in sql:
    try: os.remove(mm)
    except FileNotFoundError: pass
    sys.exit(0)
sys.exit(0)
PSQLEOF
chmod +x "$MOCKBIN/psql"
RDB="$(dirname "$RUN_RECON")/recon-db.sh"
collrun(){ env PATH="$TESTPATH" COLL_STATE="$COLLDIR/state" PGDATABASE=recon RECON_DB_NAME=recon RECON_DB_ENV="$COLLDIR/db.env" bash "$RDB" "$@"; }
collrun init          > "$COLLDIR/init1.log" 2>&1 || true
assert_grep   "$COLLDIR/init1.log" 'collation version mismatch'   "init detects the collation mismatch up front"
assert_grep   "$COLLDIR/init1.log" 'fix-collation'               "init points to the one-command fix"
collrun fix-collation > "$COLLDIR/fix.log" 2>&1 || true
assert_grep   "$COLLDIR/fix.log"   'as the database owner'        "fix-collation runs as the DB owner (no sudo in the common case)"
assert_grep   "$COLLDIR/fix.log"   'collation version is current' "fix-collation reindexes, refreshes, and verifies"
assert_absent "$COLLDIR/state/mismatch"                           "REFRESH COLLATION VERSION actually ran (mismatch cleared)"
collrun init          > "$COLLDIR/init2.log" 2>&1 || true
refute_grep   "$COLLDIR/init2.log" 'collation version mismatch'   "after the fix, init no longer warns"
rm -f "$MOCKBIN/psql"

# --- TLS posture (tlsx) : flag logic + join + report surfacing -------------------
# A) standalone aggregator test with controlled tlsx JSON (covers date-based flags)
section "TLS posture: aggregator computes version/cipher/cert flags and joins by host"
TLSDIR="$TMP/tlsposture"; rm -rf "$TLSDIR"; mkdir -p "$TLSDIR"
awk "/python3 - .*map.tsv.*<<'PY'/{f=1;next} f&&/^PY\$/{f=0} f" "$RUN_RECON" > "$TLSDIR/agg.py"
printf 'ex.com\thttps://good.ex.com/\tgau\nex.com\thttps://weak.ex.com/\tgau\nex.com\thttps://exp.ex.com/\tgau\nex.com\thttps://ss.ex.com/\tgau\nex.com\thttp://plain.ex.com/\tgau\n' > "$TLSDIR/map.tsv"
: > "$TLSDIR/httpx.jsonl"
python3 - > "$TLSDIR/tlsx.jsonl" <<'PYGEN'
import json, datetime
now=datetime.datetime.now(datetime.timezone.utc)
far=(now+datetime.timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
past=(now-datetime.timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
for r in [
 {"host":"good.ex.com","port":"443","tls_version":"tls13","cipher":"TLS_AES_256_GCM_SHA384","not_after":far,"issuer_org":"Lets Encrypt"},
 {"host":"weak.ex.com","port":"443","tls_version":"tls12","cipher":"TLS_ECDHE_RSA_WITH_RC4_128_SHA","version_enum":["tls10","tls12"],"not_after":far,"issuer_org":"X"},
 {"host":"exp.ex.com","port":"443","tls_version":"tls12","cipher":"TLS_AES_128_GCM_SHA256","expired":True,"not_after":past,"issuer_org":"X"},
 {"host":"ss.ex.com","port":"443","tls_version":"tls12","cipher":"TLS_AES_128_GCM_SHA256","self_signed":True,"mismatched":True,"untrusted":True,"not_after":far},
]: print(json.dumps(r))
PYGEN
( cd "$TLSDIR" && env PATH="$TESTPATH" python3 agg.py map.tsv httpx.jsonl out.csv 0 2000 tlsx.jsonl >/dev/null 2>/dev/null )
assert_grep  "$TLSDIR/out.csv" 'good\.ex\.com,gau,.*,TLS 1\.3,TLS_AES_256_GCM_SHA384,'  "healthy host: TLS 1.3 + modern cipher"
refute_grep  "$TLSDIR/out.csv" 'good\.ex\.com.*(WeakTLS|CertExpired|SelfSigned|CertExpiring|CertNameMismatch)' "healthy host carries no TLS flags"
assert_grep  "$TLSDIR/out.csv" 'weak\.ex\.com.*WeakTLS;WeakCipher'            "weak host flagged WeakTLS (enum) + WeakCipher (RC4)"
assert_grep  "$TLSDIR/out.csv" 'exp\.ex\.com.*CertExpired'                    "expired cert -> CertExpired"
assert_grep  "$TLSDIR/out.csv" 'ss\.ex\.com.*SelfSigned;CertNameMismatch;CertUntrusted' "self-signed/mismatch/untrusted flags"
refute_grep  "$TLSDIR/out.csv" 'plain\.ex\.com.*TLS 1'                        "http row has empty TLS columns (not probed)"
printf 'ex.com\thttps://soon.ex.com/\tgau\n' > "$TLSDIR/map2.tsv"
python3 -c 'import json,datetime; d=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=25)).strftime("%Y-%m-%dT%H:%M:%SZ"); print(json.dumps({"host":"soon.ex.com","port":"443","tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256","not_after":d}))' > "$TLSDIR/tlsx2.jsonl"
( cd "$TLSDIR" && env PATH="$TESTPATH" python3 agg.py map2.tsv httpx.jsonl out2.csv 0 2000 tlsx2.jsonl >/dev/null 2>/dev/null )
( cd "$TLSDIR" && env PATH="$TESTPATH" CERT_WARN_DAYS=21 python3 agg.py map2.tsv httpx.jsonl out3.csv 0 2000 tlsx2.jsonl >/dev/null 2>/dev/null )
assert_grep  "$TLSDIR/out2.csv" 'soon\.ex\.com.*CertExpiring'                 "25 days left -> CertExpiring at the default 30 days (WebInventory's -CertWarnDays)"
refute_grep  "$TLSDIR/out3.csv" 'CertExpiring'                                 "CERT_WARN_DAYS=21 restores the v1.17 threshold"

# B) end-to-end: --tls wires the stage, posture JSON joins into the CSV
section "TLS posture: --tls runs tlsx posture and populates CSV columns end-to-end"
run_case tls --tls
assert_grep "$MOCKLOG/tlsx.args" -- '-tls-version'                "tlsx invoked with -tls-version (posture mode)"
assert_grep "$CSV" ',TLS 1.3,TLS_AES_256_GCM_SHA384,'             "posture joined into the CSV for live https hosts"
assert_grep "$CSV" 'tls_version,tls_cipher,cert_not_after,cert_issuer,tls_flags' "CSV header carries the 5 TLS columns"
assert_grep "$MOCKLOG/tlsx.args" -- '-wildcard-cert -cert -silent' "posture asks tlsx for the leaf certificate (-cert, 1.20)"
# --tls-full / --tls-enum: the version matrix is run-recon's own probe (tls_enum_probe), not
# tlsx -version-enum / -cipher-enum; it only contacts addresses tlsx reported (the mock reports none)
run_case tlsfull --tls-full
refute_grep "$MOCKLOG/tlsx.args" -- '-version-enum|-cipher-enum'  "--tls-full no longer runs tlsx's enumeration"
assert_grep "$ERRLOG" 'TLS version matrix \+ weak-cipher probe'     "--tls-full runs the version-matrix stage"

# C) report surfaces TLS flags as findings
section "TLS posture: report surfaces tls_flags as findings"
TRPT="$TMP/tlsreport"; rm -rf "$TRPT"; mkdir -p "$TRPT"
printf 'seed_domain,url,host,sources,status_code,content_length,webserver,title,technologies,ip,asn,asn_org,tls_version,tls_cipher,cert_not_after,cert_issuer,tls_flags\n' > "$TRPT/r.csv"
printf 'ex.com,https://ss.ex.com/,ss.ex.com,gau,200,10,nginx,Hi,nginx,1.2.3.4,AS1,Org,TLS 1.2,TLS_AES_128_GCM_SHA256,2030-01-01T00:00:00Z,X,SelfSigned;WeakCipher\n' >> "$TRPT/r.csv"
env PATH="$TESTPATH" bash "$REPORT_SH" -o "$TRPT/out.html" "$TRPT/r.csv" >/dev/null 2>"$TRPT/e.log"
assert_grep "$TRPT/out.html" 'self-signed certificate'           "report shows the SelfSigned finding"
assert_grep "$TRPT/out.html" 'weak cipher offered'               "report shows the WeakCipher finding"

# ===========================================================================
# Installment 2: IPv6 (AAAA) + cloud provider + RDAP org + geo enrichment
# ===========================================================================
# A) standalone aggregator: AAAA join, longest-prefix cloud match, RDAP (name +
#    vCard fn), geo via mmdblookup, and the RDAP warm-cache (no re-query) path.
section "enrichment: aggregator fills ipv6/cloud/rdap_org/geo and honors the RDAP warm cache"
ENRDIR="$TMP/enrich"; rm -rf "$ENRDIR"; mkdir -p "$ENRDIR"
awk "/python3 - .*map.tsv.*<<'PY'/{f=1;next} f&&/^PY\$/{f=0} f" "$RUN_RECON" > "$ENRDIR/agg.py"
# curl mock: RDAP responses by IP (top-level name AND registrant vCard fn); logs calls
mk curl <<'CURLEOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/curl.args"; echo >> "$MOCKLOG/curl.args"
url=""; for a in "$@"; do case "$a" in https://*|http://*) url="$a";; esac; done
case "$url" in
  *rdap.org/ip/52.1.2.3) echo '{"name":"AMAZON-AES"}';;
  *rdap.org/ip/8.8.8.8)  echo '{"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Google LLC"]]]}]}';;
  *rdap.org/ip/9.9.9.9)  echo '{"name":"SHOULD-NOT-BE-QUERIED"}';;
  *) echo '{}';;
esac
CURLEOF
# mmdblookup mock: country iso_code per IP, in libmaxminddb's output shape
mk mmdblookup <<'MMEOF'
#!/usr/bin/env bash
ip=""; A=("$@"); i=0
while [ $i -lt ${#A[@]} ]; do case "${A[$i]}" in --ip) i=$((i+1)); ip="${A[$i]:-}";; esac; i=$((i+1)); done
case "$ip" in
  52.1.2.3) printf '  "%s" <utf8_string>\n' "US";;
  8.8.8.8)  printf '  "%s" <utf8_string>\n' "US";;
  *)        printf '  "%s" <utf8_string>\n' "DE";;
esac
MMEOF
printf 'ex.com\thttps://aws.ex.com/\tgau\nex.com\thttps://goog.ex.com/\tgau\nex.com\thttps://warm.ex.com/\tgau\n' > "$ENRDIR/map.tsv"
# httpx gives each URL its connected IP
printf '%s\n' \
 '{"input":"https://aws.ex.com/","url":"https://aws.ex.com/","status_code":200,"a":["52.1.2.3"],"host":"52.1.2.3"}' \
 '{"input":"https://goog.ex.com/","url":"https://goog.ex.com/","status_code":200,"a":["8.8.8.8"],"host":"8.8.8.8"}' \
 '{"input":"https://warm.ex.com/","url":"https://warm.ex.com/","status_code":200,"a":["9.9.9.9"],"host":"9.9.9.9"}' \
 > "$ENRDIR/httpx.jsonl"
: > "$ENRDIR/tlsx.jsonl"
# AAAA only for aws.ex.com (goog/warm have none -> empty ipv6)
printf 'aws.ex.com\t2600:1f18::1;2600:1f18::2\n' > "$ENRDIR/aaaa.tsv"
# cloud feed with overlapping prefixes: 52.1.2.3 must match the /16 (longest), not /8
printf '52.0.0.0/8\tAWS\n52.1.0.0/16\tAWS-Specific\n' > "$ENRDIR/cloud.tsv"
# pre-warm RDAP for 9.9.9.9 so it is NOT re-queried over the network
printf '9.9.9.9\tPREWARMED-ORG\n' > "$ENRDIR/rdap.tsv"
rm -f "$MOCKLOG/curl.args"   # clean slate for the warm-cache refute below
( cd "$ENRDIR" && env PATH="$TESTPATH" ENRICH=1 GEO_DB="$ENRDIR/geo.mmdb" \
    AAAA_FILE="$ENRDIR/aaaa.tsv" CLOUD_RANGES_FILE="$ENRDIR/cloud.tsv" RDAP_CACHE_FILE="$ENRDIR/rdap.tsv" \
    python3 agg.py map.tsv httpx.jsonl out.csv 0 2000 tlsx.jsonl >/dev/null 2>/dev/null )
assert_grep  "$ENRDIR/out.csv" 'aws\.ex\.com.*,52\.1\.2\.3,.*2600:1f18::1;2600:1f18::2,AWS-Specific,AMAZON-AES,US' "aws row: AAAA join + longest-prefix cloud (/16) + RDAP name + geo"
assert_grep  "$ENRDIR/out.csv" 'goog\.ex\.com.*,8\.8\.8\.8,.*,Google LLC,US' "goog row: RDAP registrant vCard fn resolved; no AAAA -> empty ipv6"
assert_grep  "$ENRDIR/out.csv" 'warm\.ex\.com.*,9\.9\.9\.9,.*,PREWARMED-ORG,DE' "warm row: RDAP served from the warm cache"
refute_grep  "$MOCKLOG/curl.args" '9\.9\.9\.9'                    "warm-cached IP is never re-queried against rdap.org"
assert_grep  "$ENRDIR/out.csv" 'ipv6,cloud,rdap_org,geo'          "CSV header carries the 4 enrichment columns"
# newly-resolved RDAP orgs are synced back to the handoff file (for the DB)
assert_grep  "$ENRDIR/rdap.tsv" '52\.1\.2\.3.*AMAZON-AES'         "new RDAP org written back to the cache file"
refute_grep  "$ENRDIR/rdap.tsv" '9\.9\.9\.9.*AMAZON'              "warm entry not rewritten/duplicated"

# B) end-to-end: --ipv6 --enrich wires the AAAA stage, cloud-feed fetch, RDAP + geo
section "enrichment: --ipv6 --enrich populate ipv6/cloud/rdap_org/geo end-to-end"
# cloud-feed curl mock (AWS feed covering the httpx mock IP 93.184.216.34) + RDAP
mk curl <<'CURLEOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/curl.args"; echo >> "$MOCKLOG/curl.args"
url=""; for a in "$@"; do case "$a" in https://*|http://*) url="$a";; esac; done
case "$url" in
  *ip-ranges.amazonaws.com*) echo '{"prefixes":[{"ip_prefix":"93.184.216.0/24"}],"ipv6_prefixes":[]}';;
  *rdap.org/ip/93.184.216.34) echo '{"name":"EDGECAST-NETBLK"}';;
  *rdap.org/ip/*) echo '{}';;
  *) echo '';;
esac
CURLEOF
mk mmdblookup <<'MMEOF'
#!/usr/bin/env bash
printf '  "%s" <utf8_string>\n' "US"
MMEOF
rm -f "$ENRDIR/cloud_cache.tsv"
RECON_CLOUD_CACHE="$ENRDIR/cloud_cache.tsv" run_case enrich --ipv6 --enrich --geodb "$ENRDIR/geo.mmdb"
assert_grep "$MOCKLOG/dnsx.args" -- '-aaaa'                       "--ipv6 runs the dnsx AAAA stage"
assert_grep "$CSV" 'ipv6,cloud,rdap_org,geo'                      "CSV header carries the enrichment columns end-to-end"
assert_grep "$CSV" ',2001:db8::1,'                                "AAAA (ipv6) joined into the CSV"
assert_grep "$CSV" ',AWS,EDGECAST-NETBLK,US'                      "cloud (AWS feed) + RDAP + geo joined for the live IP"
assert_fgrep "$ENRDIR/cloud_cache.tsv" '93.184.216.0/24'          "cloud IP-range feed fetched + cached to disk"

# --all implies --ipv6 --enrich (+ TLS posture)
run_case allflags --all
assert_grep "$MOCKLOG/dnsx.args" -- '-aaaa'                       "--all turns on IPv6 AAAA resolution"

# restore the suite-default network-safe curl; drop the geo mock
mk curl <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/curl.args"; echo >> "$MOCKLOG/curl.args"
exit 0
EOF
rm -f "$MOCKBIN/mmdblookup"

# ===========================================================================
# Installment 3 (part 1): CPE 2.3 emission (FPV-06)
# ===========================================================================
# A) standalone aggregator: version-aware CPE from httpx tech ('Name:version') and
#    the Server header ('token/version', junk stripped), plus a CPE_MAP_FILE override.
section "CPE emission: CPE 2.3 from tech + Server header, with CPE_MAP_FILE override"
CPEDIR="$TMP/cpe"; rm -rf "$CPEDIR"; mkdir -p "$CPEDIR"
awk "/python3 - .*map.tsv.*<<'PY'/{f=1;next} f&&/^PY\$/{f=0} f" "$RUN_RECON" > "$CPEDIR/agg.py"
printf 'ex.com\thttps://a.ex.com/\tgau\nex.com\thttps://b.ex.com/\tgau\nex.com\thttps://c.ex.com/\tgau\n' > "$CPEDIR/map.tsv"
printf '%s\n' \
 '{"input":"https://a.ex.com/","url":"https://a.ex.com/","status_code":200,"webserver":"nginx/1.18.0 (Ubuntu)","tech":["PHP:7.4.3","WordPress:6.4"]}' \
 '{"input":"https://b.ex.com/","url":"https://b.ex.com/","status_code":200,"webserver":"Microsoft-IIS/10.0","tech":["Microsoft ASP.NET:4.0"]}' \
 '{"input":"https://c.ex.com/","url":"https://c.ex.com/","status_code":200,"webserver":"AcmeCustom/2.1","tech":[]}' \
 > "$CPEDIR/httpx.jsonl"
: > "$CPEDIR/tlsx.jsonl"
printf '# site extensions\nAcmeCustom\tcpe:2.3:a:acme:custom_server\n' > "$CPEDIR/cpemap.tsv"
( cd "$CPEDIR" && env PATH="$TESTPATH" CPE_MAP_FILE="$CPEDIR/cpemap.tsv" python3 agg.py map.tsv httpx.jsonl out.csv 0 2000 tlsx.jsonl >/dev/null 2>/dev/null )
assert_grep "$CPEDIR/out.csv" ',geo,cpe'                                       "CSV header carries the cpe column (appended after geo)"
assert_grep "$CPEDIR/out.csv" 'a\.ex\.com.*cpe:2.3:a:f5:nginx:1\.18\.0:'       "nginx version from Server header (trailing '(Ubuntu)' stripped)"
assert_grep "$CPEDIR/out.csv" 'a\.ex\.com.*cpe:2.3:a:nginx:nginx:1\.18\.0:'    "nginx dual-vendor CPE (NVD splits nginx across f5/nginx)"
assert_grep "$CPEDIR/out.csv" 'a\.ex\.com.*cpe:2.3:a:php:php:7\.4\.3:'         "PHP version from httpx tech (Name:version)"
assert_grep "$CPEDIR/out.csv" 'a\.ex\.com.*cpe:2.3:a:wordpress:wordpress:6\.4:' "WordPress tech -> CPE"
assert_grep "$CPEDIR/out.csv" 'b\.ex\.com.*cpe:2.3:a:microsoft:internet_information_services:10\.0:' "Microsoft-IIS Server token -> CPE"
assert_grep "$CPEDIR/out.csv" 'b\.ex\.com.*cpe:2.3:a:microsoft:asp\.net:4\.0:' "ASP.NET tech ('Microsoft ASP.NET' normalized) -> CPE"
assert_grep "$CPEDIR/out.csv" 'c\.ex\.com.*cpe:2.3:a:acme:custom_server:2\.1:' "CPE_MAP_FILE override maps an otherwise-unknown product"
refute_grep "$CPEDIR/out.csv" 'cpe:2.3:a:apache:tomcat'                        "Apache-Coyote-style tokens not mis-mapped (no bogus Tomcat CPE)"

# B) end-to-end: the default run emits CPEs (product-only when httpx gives no version)
section "CPE emission: default run populates the cpe column end-to-end"
run_case cpe
assert_grep "$CSV" ',geo,cpe'                        "cpe column present in the CSV header end-to-end"
assert_grep "$CSV" 'cpe:2.3:a:f5:nginx:\*:'          "nginx CPE emitted from httpx tech/Server (product-only, version '*')"
assert_grep "$CSV" 'cpe:2.3:a:php:php:\*:'           "PHP CPE emitted from httpx tech"

# ===========================================================================
# Installment 3 (part 2): offline NVD/KEV/EPSS vulnerability join (FPV-07)
# ===========================================================================
section "vulns: offline NVD/KEV/EPSS join (version/range/all-versions/update/product-only/platform/newest-wins)"
VJ="$TMP/vulns"; rm -rf "$VJ"; mkdir -p "$VJ/nvd"
RDB="$(dirname "$RUN_RECON")/recon-db.sh"
# inventory CSV with a cpe column (as run-recon now emits)
{
  printf 'seed_domain,url,host,ip,status_code,technologies,cpe\n'
  printf 'ex.com,https://a.ex.com/,a.ex.com,1.1.1.1,200,nginx;PHP,"%s"\n' \
    'cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*;cpe:2.3:a:php:php:7.4.3:*:*:*:*:*:*:*;cpe:2.3:a:wordpress:wordpress:6.4:*:*:*:*:*:*:*;cpe:2.3:a:openbsd:openssh:9.3p1:*:*:*:*:*:*:*'
  printf 'ex.com,https://b.ex.com/,b.ex.com,2.2.2.2,200,Apache,cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*\n'
} > "$VJ/run.csv"
# NVD CVE JSON 2.0 feeds (hand-made): yearly + modified (newest-wins on CVE-2024-0002)
python3 - "$VJ/nvd" <<'PYGEN'
import json, sys
d=sys.argv[1]
def cm(c,vuln=True,**k): x={"criteria":c,"vulnerable":vuln}; x.update(k); return x
def nd(*m,op="OR"): return {"operator":op,"cpeMatch":list(m)}
def cf(nodes,op=""):
    c={"nodes":nodes}
    if op: c["operator"]=op
    return c
def met(s,sv): return {"cvssMetricV31":[{"cvssData":{"baseScore":s,"baseSeverity":sv,"version":"3.1"}}]}
def cve(cid,cfgs,desc,lm="2024-01-01T00:00:00",st="Analyzed",s=7.5,sv="HIGH"):
    return {"cve":{"id":cid,"vulnStatus":st,"published":"2024-01-01T00:00:00","lastModified":lm,
        "descriptions":[{"lang":"en","value":desc}],"metrics":met(s,sv),"configurations":cfgs}}
main=[
 cve("CVE-2024-0001",[cf([nd(cm("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",versionEndExcluding="1.20.0"))])],"nginx range"),
 cve("CVE-2024-0002",[cf([nd(cm("cpe:2.3:a:php:php:7.4.3:*:*:*:*:*:*:*"))])],"OLD php",s=9.8,sv="CRITICAL"),
 cve("CVE-2024-0003",[cf([nd(cm("cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"))])],"wordpress all versions"),
 cve("CVE-2024-0004",[cf([nd(cm("cpe:2.3:a:openbsd:openssh:9.3:p1:*:*:*:*:*:*"))])],"openssh update field"),
 cve("CVE-2024-0005",[cf([nd(cm("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",versionEndExcluding="2.4.50"))])],"apache NOT kev"),
 cve("CVE-2024-0006",[cf([nd(cm("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",versionEndExcluding="2.4.50"))])],"apache KEV"),
 cve("CVE-2024-0007",[cf([nd(cm("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",versionEndExcluding="8.0.0")),
                          nd(cm("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"))],op="AND")],"php AND windows",s=8.1),
 cve("CVE-2024-0009",[cf([nd(cm("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",versionEndExcluding="2.0.0"))])],"nginx REJECTED",st="Rejected"),
]
json.dump({"vulnerabilities":main}, open(d+"/nvdcve-2.0-2024.json","w"))
json.dump({"vulnerabilities":[cve("CVE-2024-0002",[cf([nd(cm("cpe:2.3:a:php:php:7.4.3:*:*:*:*:*:*:*"))])],
    "NEW php",lm="2024-06-01T00:00:00",s=9.8,sv="CRITICAL")]}, open(d+"/nvdcve-2.0-modified.json","w"))
PYGEN
printf '{"catalogVersion":"2024.11.01","vulnerabilities":[{"cveID":"CVE-2024-0002","dateAdded":"2024-02-01","dueDate":"2024-02-21","knownRansomwareCampaignUse":"Known"},{"cveID":"CVE-2024-0006","dateAdded":"2024-03-01","dueDate":"2024-03-21","knownRansomwareCampaignUse":"Unknown"}]}\n' > "$VJ/kev.json"
printf '#model_version:v2024.test,score_date:2024-11-01T00:00:00+0000\ncve,epss,percentile\nCVE-2024-0001,0.500000,0.900000\nCVE-2024-0002,0.970000,0.990000\nCVE-2024-0006,0.300000,0.800000\nCVE-2024-0007,0.100000,0.500000\n' > "$VJ/epss.csv"
gzip -kf "$VJ/epss.csv"   # exercise the .gz branch
env PATH="$TESTPATH" bash "$RDB" vulns "$VJ/run.csv" --nvd-feed "$VJ/nvd" --kev-file "$VJ/kev.json" --epss-file "$VJ/epss.csv.gz" -o "$VJ/out.csv" > "$VJ/run.log" 2>&1 || true
VOUT="$VJ/out.csv"
head -2 "$VOUT" | tail -1 > "$VJ/firstrow.csv"
assert_grep  "$VOUT" 'seed_domain,host,ip,port,url,.*,cve,kev,.*,epss,.*,match,description' "vulns CSV has the full header"
assert_grep  "$VOUT" 'CVE-2024-0001,.*,range,'                        "range match (nginx 1.18.0 < 1.20.0)"
assert_grep  "$VOUT" 'CVE-2024-0002,Yes,.*,version,NEW php'           "version match + KEV + newest-record-wins (NEW, not OLD)"
refute_grep  "$VOUT" 'OLD php'                                        "superseded (older lastModified) NVD record dropped"
assert_grep  "$VOUT" 'CVE-2024-0003,.*,all-versions,'                 "all-versions match (NVD names product, no version limit)"
assert_grep  "$VOUT" 'CVE-2024-0004,.*,version,'                      "update-field match (NVD 9.3:p1 == service 9.3p1)"
assert_grep  "$VOUT" 'CVE-2024-0006,Yes,'                             "apache product-only listed because it is on KEV"
assert_fgrep "$VOUT" 'range (platform not verified)'                  "AND config w/ unverifiable OS platform flagged"
refute_grep  "$VOUT" 'CVE-2024-0005'                                  "product-only + NOT KEV is suppressed (noise control)"
refute_grep  "$VOUT" 'CVE-2024-0009'                                  "Rejected CVE skipped"
assert_grep  "$VJ/firstrow.csv" 'CVE-2024-0002'                       "sort: KEV-first then EPSS (highest-EPSS KEV row first)"
assert_exists "$VOUT.provenance.json"                                 "provenance sidecar written"
assert_fgrep "$VOUT.provenance.json" '2024.11.01'                     "provenance records the KEV catalogVersion"
assert_fgrep "$VOUT.provenance.json" 'v2024.test'                     "provenance records the EPSS model version"
# a bare CSV with no cpe column must be handled gracefully (0 rows, not a crash)
printf 'seed_domain,url,host,cpe\nex.com,https://x/,x,\n' > "$VJ/empty.csv"
env PATH="$TESTPATH" bash "$RDB" vulns "$VJ/empty.csv" --nvd-feed "$VJ/nvd" > "$VJ/empty.log" 2>&1 || true
assert_exists "$VJ/empty.vulns.csv"                                   "no-CPE inventory still produces a (header-only) output"
# missing --nvd-feed is a usage error
env PATH="$TESTPATH" bash "$RDB" vulns "$VJ/run.csv" > "$VJ/usage.log" 2>&1 || true
assert_grep  "$VJ/usage.log" 'nvd-feed'                               "missing --nvd-feed reported as a usage error"

# the HTML report surfaces vuln-join rows as KEV/CVSS/EPSS findings (auto-detecting <csv>.vulns.csv)
section "report: vuln-join CVEs surface as findings (KEV critical, CVSS/EPSS severity, summary cards)"
VRPT="$TMP/vulnreport"; rm -rf "$VRPT"; mkdir -p "$VRPT"
printf 'seed_domain,url,host,sources,status_code,content_length,webserver,title,technologies,ip,asn,asn_org,tls_version,tls_cipher,cert_not_after,cert_issuer,tls_flags,ipv6,cloud,rdap_org,geo,cpe\n' > "$VRPT/r.csv"
printf 'ex.com,https://a.ex.com/,a.ex.com,gau,200,10,nginx,Hi,PHP,1.1.1.1,AS1,Org,,,,,,,,,,cpe:2.3:a:php:php:7.4.3:*:*:*:*:*:*:*\n' >> "$VRPT/r.csv"
# vuln-join CSV named for auto-detection (<csv>.vulns.csv)
printf 'seed_domain,host,ip,port,url,status_code,products,cpe,cve,kev,kev_date_added,kev_due_date,kev_ransomware,epss,epss_percentile,cvss_score,cvss_severity,cvss_version,published,match,description\n' > "$VRPT/r.csv.vulns.csv"
printf 'ex.com,a.ex.com,1.1.1.1,443,https://a.ex.com/,200,PHP,cpe:2.3:a:php:php:7.4.3:*:*:*:*:*:*:*,CVE-2099-0001,Yes,2099-01-01,2099-01-21,Known,0.970000,0.990000,9.8,CRITICAL,3.1,2099-01-01,version,remote code execution in php\n' >> "$VRPT/r.csv.vulns.csv"
printf 'ex.com,a.ex.com,1.1.1.1,443,https://a.ex.com/,200,PHP,cpe:2.3:a:php:php:7.4.3:*:*:*:*:*:*:*,CVE-2099-0002,,,,,0.010000,0.100000,5.3,MEDIUM,3.1,2099-01-01,range,info disclosure\n' >> "$VRPT/r.csv.vulns.csv"
env PATH="$TESTPATH" bash "$REPORT_SH" -o "$VRPT/out.html" "$VRPT/r.csv" >/dev/null 2>"$VRPT/e.log"
assert_grep "$VRPT/out.html" 'Known CVE'                              "report renders the vuln (Known CVE) finding kind"
assert_grep "$VRPT/out.html" 'CVE-2099-0001'                          "KEV CVE present in the report"
assert_grep "$VRPT/out.html" 'CVE-2099-0002'                          "non-KEV CVE present in the report"
assert_fgrep "$VRPT/out.html" 'KEV/ransomware'                        "KEV ransomware flag shown in the finding detail"
assert_grep "$VRPT/out.html" '>KEV<'                                  "KEV summary card rendered"
assert_grep "$VRPT/out.html" 'CRITICAL</span>'                        "KEV CVE rated CRITICAL (severity badge)"
# explicit --vulns path also works (not just auto-detect)
env PATH="$TESTPATH" bash "$REPORT_SH" --vulns "$VRPT/r.csv.vulns.csv" -o "$VRPT/out2.html" "$VRPT/r.csv" >/dev/null 2>&1
assert_grep "$VRPT/out2.html" 'CVE-2099-0001'                         "--vulns explicit path surfaces CVEs"
# a report with no vulns CSV still works (no CVE section, no crash)
rm -f "$VRPT/r.csv.vulns.csv"
env PATH="$TESTPATH" bash "$REPORT_SH" -o "$VRPT/out3.html" "$VRPT/r.csv" >/dev/null 2>&1
assert_exists "$VRPT/out3.html"                                       "report builds fine when no vuln join is present"
refute_grep "$VRPT/out3.html" 'CVE-2099'                              "no CVE findings when there is no vulns CSV"

# ===========================================================================
# clean: data-retention sweep (prune blank files, keep everything the report uses)
# ===========================================================================
# existence-based checks: the files under test are intentionally zero-byte, so the
# size-based assert_exists/assert_absent ([ -s ]) would give false results here.
_exists(){ if [ -e "$1" ]; then _pass "$2"; else _fail "$2  [$1 missing]"; fi; }
_gone(){   if [ ! -e "$1" ]; then _pass "$2"; else _fail "$2  [$1 still present]"; fi; }
section "clean: prunes empty intermediate files + empty dirs, preserves report data"
CLN="$TMP/clean"; rm -rf "$CLN"; mkdir -p "$CLN/_work-X/raw/h" "$CLN/_work-X/done" "$CLN/_work-X/parts" "$CLN/screenshots-X/screenshot"
RDB="$(dirname "$RUN_RECON")/recon-db.sh"
: > "$CLN/_work-X/raw/h/host_amass.txt"              # blank -> remove
printf '  \n\n' > "$CLN/_work-X/raw/h/gau.txt"       # whitespace-only -> remove
: > "$CLN/_work-X/done/h"                            # empty marker -> remove (dir then empty)
: > "$CLN/_work-X/parts/aaaa.h.txt"                  # empty part -> remove
printf 'https://h/x\n' > "$CLN/_work-X/raw/h/katana.txt"          # data -> keep
printf '{"url":"x"}\n' > "$CLN/_work-X/parts/httpx.h.jsonl"       # data -> keep
printf 'seed,url,host\nex,https://h/,h\n' > "$CLN/recon-X.csv"    # .csv -> keep always
: > "$CLN/recon-X.csv.nuclei.txt"                    # stale empty artifact -> remove
printf '<html>x</html>' > "$CLN/recon-X.csv.report.html"         # .html -> keep always
: > "$CLN/keep-empty.png"                            # image ext -> keep even when empty
printf 'PNG' > "$CLN/screenshots-X/screenshot/h.png"             # image -> keep
# dry-run removes nothing
env PATH="$TESTPATH" bash "$RDB" clean "$CLN" --dry-run > "$CLN/dry.log" 2>&1 || true
assert_grep "$CLN/dry.log" 'dry-run'                             "clean --dry-run announces preview mode"
_exists "$CLN/_work-X/done/h"                                    "clean --dry-run deletes nothing (marker still present)"
# apply
env PATH="$TESTPATH" bash "$RDB" clean "$CLN" > "$CLN/apply.log" 2>&1 || true
_gone   "$CLN/_work-X/raw/h/host_amass.txt"                      "clean removes a zero-byte intermediate"
_gone   "$CLN/_work-X/raw/h/gau.txt"                             "clean removes a whitespace-only file"
_gone   "$CLN/_work-X/done/h"                                    "clean removes an empty done-marker"
_gone   "$CLN/_work-X/parts/aaaa.h.txt"                          "clean removes an empty parts file"
_gone   "$CLN/recon-X.csv.nuclei.txt"                            "clean removes a stale empty side-artifact"
_exists "$CLN/recon-X.csv"                                       "clean preserves the CSV (report data)"
_exists "$CLN/recon-X.csv.report.html"                           "clean preserves the HTML report"
_exists "$CLN/keep-empty.png"                                    "clean preserves image files even when empty"
_exists "$CLN/_work-X/raw/h/katana.txt"                          "clean preserves non-empty intermediates (--keep-work data)"
_exists "$CLN/screenshots-X/screenshot/h.png"                    "clean preserves screenshots"
_gone   "$CLN/_work-X/done"                                      "clean removes the emptied done/ directory"
# --rows: drop a blank (no host, no url) data row into a <csv>.cleaned.csv, original untouched
printf 'seed_domain,url,host\nex,https://a/,a\nex,,\n' > "$CLN/rows.csv"
env PATH="$TESTPATH" bash "$RDB" clean "$CLN/rows.csv" --rows > "$CLN/rows.log" 2>&1 || true
assert_exists "$CLN/rows.cleaned.csv"                            "clean --rows writes a de-blanked CSV copy"
assert_grep   "$CLN/rows.cleaned.csv" 'https://a/,a'             "clean --rows keeps real rows"
refute_grep   "$CLN/rows.cleaned.csv" '^ex,,'                    "clean --rows drops the blank (no host/url) row"
assert_grep   "$CLN/rows.csv" '^ex,,'                            "clean --rows never mutates the original CSV"

# ===========================================================================
# bench-run-recon.sh compare: the benchmark harness's accuracy + A/B comparator
# ===========================================================================
section "bench compare: accuracy vs expected + field-by-field A/B reproducibility"
BENCH="$(dirname "$RUN_RECON")/bench-run-recon.sh"
BD="$TMP/bench"; rm -rf "$BD"; mkdir -p "$BD"
_rc(){ if [ "$(cat "$1" 2>/dev/null)" = "$2" ]; then _pass "$3"; else _fail "$3  [rc=$(cat "$1" 2>/dev/null), want $2]"; fi; }
if [ ! -f "$BENCH" ]; then
  _fail "bench-run-recon.sh present next to run-recon.sh"
else
  _pass "bench-run-recon.sh present next to run-recon.sh"
  printf 'host,status,technologies,cpe,tls_flags\n' > "$BD/expected.csv"
  printf 'nginx.lab,200,Nginx,cpe:2.3:a:f5:nginx:1.21.6,CertUntrusted\n' >> "$BD/expected.csv"
  printf 'wp.lab,200,WordPress;PHP,cpe:2.3:a:wordpress:wordpress:6.4,CertUntrusted\n' >> "$BD/expected.csv"
  # a matching run (accuracy -> identical, exit 0)
  printf 'seed_domain,url,host,status_code,technologies,tls_flags,cpe\n' > "$BD/good.csv"
  printf 'l,https://nginx.lab/,nginx.lab,200,Nginx,CertUntrusted,cpe:2.3:a:f5:nginx:1.21.6:*:*:*:*:*:*:*\n' >> "$BD/good.csv"
  printf 'l,https://wp.lab/,wp.lab,200,WordPress;PHP;Apache,CertUntrusted,cpe:2.3:a:wordpress:wordpress:6.4:*:*:*:*:*:*:*\n' >> "$BD/good.csv"
  env PATH="$TESTPATH" bash "$BENCH" compare "$BD/expected.csv" "$BD/good.csv" > "$BD/good.log" 2>&1; echo $? > "$BD/good.rc"
  assert_grep "$BD/good.log" 'RESULT: identical'                 "compare: a matching run scores identical"
  _rc "$BD/good.rc" 0                                            "compare: identical run exits 0"
  # a run that under-detects the WordPress version (missing CPE prefix) -> DIFF, exit 1
  printf 'seed_domain,url,host,status_code,technologies,tls_flags,cpe\n' > "$BD/bad.csv"
  printf 'l,https://nginx.lab/,nginx.lab,200,Nginx,CertUntrusted,cpe:2.3:a:f5:nginx:1.21.6:*:*:*:*:*:*:*\n' >> "$BD/bad.csv"
  printf 'l,https://wp.lab/,wp.lab,200,WordPress;PHP,CertUntrusted,cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*\n' >> "$BD/bad.csv"
  env PATH="$TESTPATH" bash "$BENCH" compare "$BD/expected.csv" "$BD/bad.csv" > "$BD/bad.log" 2>&1; echo $? > "$BD/bad.rc"
  assert_grep "$BD/bad.log" 'missing cpe: cpe:2.3:a:wordpress:wordpress:6.4' "compare: flags an under-detected version (missing CPE)"
  _rc "$BD/bad.rc" 1                                             "compare: a run with differences exits 1"
  # a run that misses a host entirely -> MISS, exit 1
  printf 'seed_domain,url,host,status_code,technologies,tls_flags,cpe\n' > "$BD/miss.csv"
  printf 'l,https://nginx.lab/,nginx.lab,200,Nginx,CertUntrusted,cpe:2.3:a:f5:nginx:1.21.6:*:*:*:*:*:*:*\n' >> "$BD/miss.csv"
  env PATH="$TESTPATH" bash "$BENCH" compare "$BD/expected.csv" "$BD/miss.csv" > "$BD/miss.log" 2>&1; echo $? > "$BD/miss.rc"
  assert_grep "$BD/miss.log" 'MISS host not discovered: wp.lab'  "compare: flags an undiscovered expected host"
  # --exact A/B: identical runs -> identical/exit 0; a changed field -> DIFFERENT/exit 1
  env PATH="$TESTPATH" bash "$BENCH" compare "$BD/good.csv" "$BD/good.csv" --exact > "$BD/ex0.log" 2>&1; echo $? > "$BD/ex0.rc"
  assert_grep "$BD/ex0.log" 'RESULT: identical'                  "compare --exact: two identical runs are identical"
  _rc "$BD/ex0.rc" 0                                            "compare --exact: identical runs exit 0"
  sed 's#,200,WordPress;PHP;Apache,#,500,WordPress;PHP;Apache,#' "$BD/good.csv" > "$BD/good2.csv"
  env PATH="$TESTPATH" bash "$BENCH" compare "$BD/good.csv" "$BD/good2.csv" --exact > "$BD/ex1.log" 2>&1; echo $? > "$BD/ex1.rc"
  assert_grep "$BD/ex1.log" 'differ .*status_code'               "compare --exact: a changed field is reported"
  _rc "$BD/ex1.rc" 1                                            "compare --exact: differing runs exit 1"
  # accuracy: ipv6 column, "-" means "must be empty" (catches junk in the ipv6 column)
  printf 'host,ipv6\nnginx.lab,2001:db8:1::10\nspa.lab,-\n' > "$BD/e6.csv"
  printf 'seed_domain,url,host,ipv6\nl,https://nginx.lab/,nginx.lab,2001:db8:1::10\nl,https://spa.lab/,spa.lab,\n' > "$BD/a6ok.csv"
  printf 'seed_domain,url,host,ipv6\nl,https://nginx.lab/,nginx.lab,2001:db8:1::10\nl,https://spa.lab/,spa.lab,;; OPT PSEUDOSECTION:\n' > "$BD/a6bad.csv"
  env PATH="$TESTPATH" bash "$BENCH" compare "$BD/e6.csv" "$BD/a6ok.csv" > "$BD/e6ok.log" 2>&1
  assert_grep "$BD/e6ok.log" 'RESULT: identical'                 "compare: ipv6 expectations (value present / '-' empty) pass on clean output"
  env PATH="$TESTPATH" bash "$BENCH" compare "$BD/e6.csv" "$BD/a6bad.csv" > "$BD/e6bad.log" 2>&1
  assert_grep "$BD/e6bad.log" 'spa.lab ipv6: want none'          "compare: junk in an ipv6 column that must be empty is a difference"
fi

# ===========================================================================
# Real-tool shakedown regressions (found running the real PD toolchain in the lab)
# ===========================================================================
section "shakedown: AAAA parser rejects dnsx resolver chatter, parses RR-only answers"
SDIR="$TMP/shakedown"; rm -rf "$SDIR"; mkdir -p "$SDIR"
python3 - "$RUN_RECON" > "$SDIR/aaaa.py" <<'PYX'
import sys
s = open(sys.argv[1]).read()
i = s.index('-aaaa -json -silent')
j = s.index("python3 -c '\n", i) + len("python3 -c '\n")
k = s.index("\n' >> \"$P/aaaa.", j)
print(s[j:k])
PYX
# real dnsx 1.2.2 shapes: AAAA present / "aaaa": null + OPT chatter / RR-only in "all"
printf '%s\n' \
  '{"host":"nginx.test","aaaa":["2001:db8:1::10"],"all":["nginx.test.\t60\tIN\tAAAA\t2001:db8:1::10"]}' \
  '{"host":"spa.test","aaaa":null,"all":["\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096"],"status_code":"NOERROR"}' \
  '{"host":"rr.test","all":["rr.test.\t60\tIN\tAAAA\t2001:db8::7","\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 4096"]}' \
  | python3 "$SDIR/aaaa.py" > "$SDIR/aaaa.out" 2>&1
assert_grep "$SDIR/aaaa.out" '^nginx\.test	2001:db8:1::10'      "AAAA: a real answer is kept"
refute_grep "$SDIR/aaaa.out" 'spa\.test|PSEUDOSECTION|EDNS'         "AAAA: resolver chatter for a no-AAAA name produces no record"
assert_grep "$SDIR/aaaa.out" '^rr\.test	2001:db8::7'                "AAAA: RR-only answer parsed by record type"
[ "$(grep -c '' "$SDIR/aaaa.out")" = "2" ] && _pass "AAAA: exactly one clean line per name with an address" || _fail "AAAA: exactly one clean line per name with an address  [$(grep -c '' "$SDIR/aaaa.out") lines]"

section "shakedown: httpx>=1.6 IP field (host_ip) + no third-party lookups for non-public IPs"
awk "/python3 - .*map.tsv.*<<'PY'/{f=1;next} f&&/^PY\$/{f=0} f" "$RUN_RECON" > "$SDIR/agg.py"
printf 'ex.com\thttps://pub.ex.com/\tgau\nex.com\thttps://int.ex.com/\tgau\n' > "$SDIR/map.tsv"
# httpx 1.12 shape: 'host' is the HOSTNAME, the connected IP is 'host_ip', no 'a'
printf '%s\n' \
  '{"input":"https://pub.ex.com/","url":"https://pub.ex.com/","host":"pub.ex.com","host_ip":"93.184.216.34","status_code":200}' \
  '{"input":"https://int.ex.com/","url":"https://int.ex.com/","host":"int.ex.com","host_ip":"10.1.2.3","status_code":200}' \
  > "$SDIR/httpx.jsonl"
: > "$SDIR/tlsx.jsonl"; rm -f "$MOCKLOG/dig.args"
( cd "$SDIR" && env PATH="$TESTPATH" python3 agg.py map.tsv httpx.jsonl out.csv 1 2000 tlsx.jsonl >/dev/null 2>&1 )
assert_grep "$SDIR/out.csv" 'pub\.ex\.com.*,93\.184\.216\.34,AS15133,'  "host_ip read as the IP (httpx>=1.6), ASN resolved for a public IP"
assert_grep "$SDIR/out.csv" 'int\.ex\.com.*,10\.1\.2\.3,,'              "internal IP still reported in the inventory, with no ASN"
assert_grep "$MOCKLOG/dig.args" '34\.216\.184\.93\.origin\.asn\.cymru'  "public IP is sent to Team Cymru"
refute_grep "$MOCKLOG/dig.args" '3\.2\.1\.10\.origin'                   "RFC 1918 IP is never sent to Team Cymru"

section "shakedown: deterministic URL join (query kept, tiers never preempt, no borrowing)"
JD="$TMP/joindet"; rm -rf "$JD"; mkdir -p "$JD"
awk "/python3 - .*map.tsv.*<<'PY'/{f=1;next} f&&/^PY\$/{f=0} f" "$RUN_RECON" > "$JD/agg.py"
printf 'ex.com\thttp://wp.ex.com\tkatana\nex.com\thttp://wp.ex.com/?feed=rss2&author=1\tkatana\nex.com\thttp://wp.ex.com/deep/nope\tkatana\n' > "$JD/map.tsv"
# the FEED record comes first: the old join let its query-dropped key claim the root's slot
printf '%s\n' \
  '{"input":"http://wp.ex.com/?feed=rss2&author=1","url":"http://wp.ex.com/?feed=rss2&author=1","status_code":200,"content_length":1596,"title":"Author feed","host_ip":"93.184.216.34"}' \
  '{"input":"http://wp.ex.com","url":"http://wp.ex.com","status_code":200,"content_length":83711,"title":"Home","host_ip":"93.184.216.34"}' \
  > "$JD/hx1.jsonl"
tac "$JD/hx1.jsonl" > "$JD/hx2.jsonl"        # same records, opposite order
( cd "$JD" && env PATH="$TESTPATH" python3 agg.py map.tsv hx1.jsonl o1.csv 0 100 >/dev/null 2>&1 )
( cd "$JD" && env PATH="$TESTPATH" python3 agg.py map.tsv hx2.jsonl o2.csv 0 100 >/dev/null 2>&1 )
assert_grep "$JD/o1.csv" 'http://wp\.ex\.com,wp\.ex\.com,katana,200,83711,,Home'   "root row gets the ROOT record, not a query variant's (query kept in the join key)"
assert_grep "$JD/o1.csv" 'feed=rss2&author=1,wp\.ex\.com,katana,200,1596,,Author feed' "query-variant row keeps its own record"
assert_grep "$JD/o1.csv" 'deep/nope,wp\.ex\.com,katana,,,,,'                          "deep URL with no record of its own is NOT filled from another page"
if cmp -s "$JD/o1.csv" "$JD/o2.csv"; then _pass "join is deterministic: identical CSV for either httpx record order"; else _fail "join is deterministic: identical CSV for either httpx record order"; fi

section "shakedown: enrichment probes each URL with its own scheme (-nfs)"
run_case nfs
assert_grep "$MOCKLOG/httpx.args" -- '-json.*-nfs'                 "per-URL enrichment passes -nfs (no silent https upgrade of http:// rows)"
assert_grep "$MOCKLOG/httpx.args" -- '-json.*-retries 2'           "per-URL enrichment retries transient failures (no silently blank rows)"
assert_grep "$MOCKLOG/httpx.args" -- '^-silent -rl [0-9]+ -timeout 10 -retries 2' "live-host probe retries transient failures (no silently dropped hosts)"
refute_grep "$CSV" ',live'                                         "live fallback stays silent when the crawl returned URLs for the host (output unchanged)"

section "shakedown: RFC 6761 special-use names skip passive internet sources"
SPD="$TMP/special.txt"; printf 'app.test\n' > "$SPD"
DOMAINS="$SPD" run_case special
assert_absent "$MOCKLOG/gau.args"                                  "gau not run for a .test seed"
assert_absent "$MOCKLOG/waybackurls.args"                          "waybackurls not run for a .test seed"
assert_grep   "$ERRLOG" 'special-use name'                         "skip is logged"
assert_grep   "$CSV" 'https://app\.test,app\.test,live'          "live host with no crawl/archive URLs is still inventoried (source=live fallback)"
DOMAINS="$SPD" SKIP_SPECIAL_USE=0 run_case special_off
assert_grep   "$MOCKLOG/gau.args" -- '--threads'                   "SKIP_SPECIAL_USE=0 restores passive collection (leave-one-out switch)"

section "farm: late retry recovers load-induced blanks; failures are never negative-cached"
# missing_keys: which keys produced no record (httpx input/url; tlsx host:port)
MKD="$TMP/missing_keys"; rm -rf "$MKD"; mkdir -p "$MKD"
printf 'https://a.test\nhttp://a.test/x\nhttps://b.test/?q=1\n' > "$MKD/keys"
printf '%s\n' '{"input":"https://a.test","url":"https://a.test"}' '{"input":"https://b.test/?q=1"}' > "$MKD/res"
printf 'a.test:443\nb.test:443\nc.test:8443\n' > "$MKD/tk"
printf '%s\n' '{"host":"A.test","port":"443"}' '{"host":"c.test","port":"8443"}' > "$MKD/tr"
( eval "$(sed -n '/^missing_keys() {/,/^}/p' "$RUN_RECON")"
  missing_keys httpxjson "$MKD/keys" "$MKD/res" > "$MKD/h.out"
  missing_keys jsonauthority "$MKD/tk" "$MKD/tr" > "$MKD/t.out"
  missing_keys httpxjson "$MKD/keys" "$MKD/nope" > "$MKD/n.out" )
[ "$(cat "$MKD/h.out")" = "http://a.test/x" ] && _pass "missing_keys: httpx URLs without a record" || _fail "missing_keys: httpx URLs without a record  [$(tr '\n' ' ' < "$MKD/h.out")]"
[ "$(cat "$MKD/t.out")" = "b.test:443" ] && _pass "missing_keys: tlsx host:port without a record (host case-insensitive)" || _fail "missing_keys: tlsx host:port without a record  [$(tr '\n' ' ' < "$MKD/t.out")]"
[ "$(grep -c '' "$MKD/n.out")" = "3" ] && _pass "missing_keys: no result file -> every key is missing" || _fail "missing_keys: no result file -> every key is missing"
# enrichment: one URL fails its first pass, as under load
rm -f "$MOCKLOG/httpx.flaky" "$MOCKLOG/tlsx.flaky"
export MOCK_HTTPX_FLAKY="https://example.com/katana-path"
run_case late_on
assert_grep   "$ERRLOG" 'enrichment: 1 URL\(s\) got no response; retrying once' "late retry: a URL with no record is retried once (logged)"
assert_grep   "$MOCKLOG/httpx.args" -- '-json.* -t 5 '              "late retry runs at a gentler pace (-t 5)"
assert_grep   "$CSV" 'katana-path,example\.com,katana,200,100,'      "late retry: the row is enriched instead of left blank"
rm -f "$MOCKLOG/httpx.flaky"
LATE_RETRY=0 run_case late_off
refute_grep   "$ERRLOG" 'retrying once'                              "LATE_RETRY=0 restores the single pass (leave-one-out switch)"
assert_grep   "$CSV" 'katana-path,example\.com,katana,,,'            "LATE_RETRY=0: the load-induced blank row stays blank (the v1.15 behaviour)"
unset MOCK_HTTPX_FLAKY
run_case late_clean
refute_grep   "$ERRLOG" 'retrying once'                              "healthy run: no late retry, no pause"
# TLS posture: one host gives no handshake on the first pass
export MOCK_TLSX_FLAKY="example.com:443"
run_case late_tls --tls
assert_grep   "$ERRLOG" 'TLS posture: 1 host\(s\) gave no handshake; retrying once' "late retry: TLS posture retries a host with no handshake record"
if python3 -c 'import csv,sys; r=[x for x in csv.DictReader(open(sys.argv[1])) if x.get("host")=="example.com" and x["url"].startswith("https://")]; sys.exit(0 if r and all(x.get("tls_version") for x in r) else 1)' "$CSV" 2>/dev/null
then _pass "late retry: TLS columns filled for that host"; else _fail "late retry: TLS columns filled for that host"; fi
unset MOCK_TLSX_FLAKY
# --db: a URL that never answered must not be negative-cached, or a load-induced
# blank would be served from the cache for NEG_TTL (it is retried next run instead)
cat > "$MOCKBIN/psql" <<'PSQLEOF'
#!/usr/bin/env bash
sql=""; A=("$@"); i=0
while [ $i -lt ${#A[@]} ]; do case "${A[$i]}" in -c) i=$((i+1)); sql="${A[$i]}";; esac; i=$((i+1)); done
[ -z "$sql" ] && sql="$(cat 2>/dev/null)"
printf 'SQL: %s\n' "$sql" >> "$MOCKLOG/psql.args"
case "$sql" in "SELECT 1") echo 1;; esac
exit 0
PSQLEOF
chmod +x "$MOCKBIN/psql"
export MOCK_HTTPX_DEAD="https://example.com/katana-path"
run_case noneg_db --db
assert_grep   "$MOCKLOG/psql.args" "'httpx_json_v3','https://example\.com/" "--db: enrichment records that came back are cached (key httpx_json_v3: records cached before 1.20 have no login-form matches)"
assert_grep   "$MOCKLOG/psql.args" "'live_probe!neg'|'live_probe','"      "--db: the live probe keeps its cache entries (dead hosts may be negative-cached)"
refute_grep   "$MOCKLOG/psql.args" "\\('httpx_json_v3!neg','"                  "--db: a URL with no record is NOT negative-cached (retried next run, not blank for NEG_TTL)"
unset MOCK_HTTPX_DEAD


BIGWL="$TMP/big.txt"; seq 1 100 | sed 's/^/w/' > "$BIGWL"
BRUTE_MAX=5 run_case brutecap --brute --brute-wordlist "$BIGWL"
# shuffledns (or puredns) must be handed a capped *.wl file, not the 100-line original
if [ -f "$MOCKLOG/shuffledns.args" ]; then
  assert_grep "$MOCKLOG/shuffledns.args" -- '-w [^ ]*\.wl'        "brute wordlist passed as a capped .wl copy"
else
  assert_grep "$MOCKLOG/puredns.args" -- '\.wl'                   "brute wordlist passed as a capped .wl copy"
fi

# --- 52) D2: --proxy wires httpx -proxy ------------------------------------
section "--proxy routes stages through an HTTP(S) proxy (D2)"
run_case proxy --proxy http://127.0.0.1:8080
assert_grep   "$MOCKLOG/httpx.args" -- '-proxy http://127.0.0.1:8080'  "httpx receives the -proxy flag"
assert_grep   "$MOCKLOG/katana.args" -- '-proxy http://127.0.0.1:8080' "katana's crawl goes through the proxy too (v1.16 connected directly)"

# --- v1.19 (Batch 2): HTTP columns, --extras, favicon pivot, reverse DNS -------------
section "Batch 2: HTTP columns from the enrichment request (no extra traffic)"
run_case http_cols
assert_grep  "$MOCKLOG/httpx.args" -- '-tech-detect -web-server -irh -hash sha256 -nfs' "enrichment asks for headers and the body hash in the same request"
assert_grep  "$CSV" '^seed_domain,url,host,.*,cpe,redirect_location,response_ms,body_sha256,content_type,powered_by,auth,cookies,cookie_issues,missing_sec_headers,hsts_max_age,alt_svc,http_flags,favicon_mmh3,favicon_md5,ptr,robots,security_txt,final_url,redirect_chain,login_form,tls_supported,tls_ciphers,tls_weak_cipher,cert_key,cert_sig_alg,cert_not_before.?$' "17 HTTP columns appended after cpe, then the 9 of 1.20 (existing positions unchanged)"
assert_grep  "$CSV" ',https://example\.com/katana-path,.*,12,0{63}7,text/html,PHP/8\.1\.2,,sessionid;theme,sessionid:no-Secure,Content-Security-Policy;X-Content-Type-Options;Strict-Transport-Security,,"h3="":443""; ma=86400",,' "response time, body hash, content type, X-Powered-By, cookies and their flag gaps, missing headers, Alt-Svc"
refute_grep  "$MOCKLOG/httpx.args" -- '-path |-favicon' "default run sends no favicon or well-known requests"

section "Batch 2: aggregator derives the HTTP columns correctly (auth, cleartext, HSTS, redirects, PTR)"
HD="$TMP/httpcols"; rm -rf "$HD"; mkdir -p "$HD"
awk "/python3 - .*map.tsv.*<<'PY'/{f=1;next} f&&/^PY\$/{f=0} f" "$RUN_RECON" > "$HD/agg.py"
printf 'ex.com\thttp://vpn.ex.com/\tgau\nex.com\thttps://www.ex.com/\tgau\nex.com\thttps://www.ex.com/old\tgau\nex.com\thttp://www.ex.com/\tgau\nex.com\thttps://db.ex.com/\tgau\nex.com\thttps://www.ex.com/app.js\tgau\n' > "$HD/map.tsv"
python3 - > "$HD/httpx.jsonl" <<'PYGEN'
import json
recs = [
 {"url": "http://vpn.ex.com/", "status_code": 401, "content_type": "text/html", "time": "1.2s", "host_ip": "93.184.216.34",
  "header": {"www_authenticate": 'Basic realm="Legacy VPN", charset="UTF-8"'}},
 {"url": "https://www.ex.com/", "status_code": 200, "content_type": "text/html", "time": "850µs", "host_ip": "93.184.216.34",
  "header": {"strict_transport_security": "max-age=63072000; includeSubDomains; preload",
             "content_security_policy": "default-src 'self'; frame-ancestors 'none'", "x_content_type_options": "nosniff"}},
 {"url": "https://www.ex.com/old", "status_code": 301, "content_type": "text/html", "time": "3ms", "host_ip": "93.184.216.34",
  "header": {"location": "https://www.ex.com/new"}},
 {"url": "http://www.ex.com/", "status_code": 200, "content_type": "text/html", "time": "4ms", "host_ip": "93.184.216.34", "header": {}},
 {"url": "https://db.ex.com/", "status_code": 200, "content_type": "text/html", "time": "4ms", "host_ip": "10.0.0.9", "header": {}},
 {"url": "https://www.ex.com/app.js", "status_code": 200, "content_type": "application/javascript", "time": "2ms", "host_ip": "93.184.216.34", "header": {}},
]
for r in recs:
    r["input"] = r["url"]; print(json.dumps(r))
PYGEN
printf 'www.ex.com\t-1293291\taabbccddeeff00112233445566778899\t/favicon.ico\n' > "$HD/fav.tsv"
printf 'www.ex.com\t200 disallow=3 allow=0 sitemap=1\tpresent contact=mailto:s@ex.com expires=2030-01-01\n' > "$HD/hi.tsv"
: > "$HD/tlsx.jsonl"
( cd "$HD" && env PATH="$TESTPATH" ENRICH=1 FAVHASH_FILE="$HD/fav.tsv" HOSTINFO_FILE="$HD/hi.tsv" RECON_CLOUD_CACHE="$HD/c.tsv" python3 agg.py map.tsv httpx.jsonl out.csv 0 2000 tlsx.jsonl >/dev/null 2>/dev/null )
( cd "$HD" && env PATH="$TESTPATH" ENRICH=1 PTR_PRIVATE=1 PTR_RESOLVER=10.0.0.53 RECON_CLOUD_CACHE="$HD/c.tsv" python3 agg.py map.tsv httpx.jsonl out2.csv 0 2000 tlsx.jsonl >/dev/null 2>/dev/null )
assert_grep  "$HD/out.csv" ',http://vpn\.ex\.com/,.*,1200,,text/html,,"Basic realm=""Legacy VPN""",,,Content-Security-Policy;X-Frame-Options;X-Content-Type-Options,,,CleartextAuth,' "Basic auth over HTTP -> auth realm + CleartextAuth; 1.2s -> 1200 ms; HSTS not expected on http"
assert_grep  "$HD/out.csv" ',https://www\.ex\.com/,.*,1,,text/html,,,,,,63072000,,,-1293291,aabbccddeeff00112233445566778899,edge-93-184-216-34\.example\.net,200 disallow=3 allow=0 sitemap=1,present contact=' "all headers present (CSP frame-ancestors covers X-Frame-Options), HSTS max-age, favicon, PTR, robots, security.txt"
assert_grep  "$HD/out.csv" ',https://www\.ex\.com/old,.*,https://www\.ex\.com/new,3,' "redirect target recorded; no header verdict on a redirect"
assert_grep  "$HD/out.csv" ',http://www\.ex\.com/,.*,PlainHttp,' "HTML served on plain HTTP -> PlainHttp"
assert_grep  "$HD/out.csv" ',https://www\.ex\.com/app\.js,.*,application/javascript,,,,,,,' "no security-header verdict on non-HTML responses"
refute_grep  "$HD/out.csv" 'db01\.corp\.example'                       "PTR of a non-public address is not asked of public resolvers"
assert_grep  "$HD/out2.csv" ',https://db\.ex\.com/,.*,db01\.corp\.example,' "PTR of a non-public address via YOUR resolver (--resolvers)"
assert_grep  "$MOCKLOG/dig.args" '@10\.0\.0\.53 \+time=2 \+tries=1 -x 10\.0\.0\.9' "private PTR goes to the --resolvers address"

section "Batch 2: --extras (robots.txt, security.txt, 404 probe, favicon hashes)"
# the mock icon is the bytes 00 00 01 00 "MOCK-ICON": Shodan mmh3 -732438843, MD5 1e23ac45...
run_case extras --extras
assert_grep  "$MOCKLOG/httpx.args" -- '-path /,/favicon\.ico,/robots\.txt,/\.well-known/security\.txt,/security\.txt,/rr-[0-9a-f]+\.html -silent -json -irrb' "one httpx pass: root, favicon, well-known paths and a random 404 probe (bodies base64)"
refute_grep  "$MOCKLOG/httpx.args" -- '-favicon'                            "no separate favicon pass: the icon is hashed from the same responses"
assert_fgrep "$OUTDIR"/_work-*/parts/favhash.example.com.tsv $'example.com\t-732438843\t1e23ac45e53e0bd440ab397425229b87\t/favicon.ico' "favicon mmh3 and MD5 computed locally from /favicon.ico"
assert_grep  "$CSV" ',https://example\.com/hidden-admin/,example\.com,robots,' "robots.txt Disallow path becomes a URL row (source robots)"
refute_grep  "$CSV" 'bak\$|\*\.bak'                                         "wildcard robots rules are not turned into URLs"
assert_grep  "$CSV.extras.txt" '^\[example\.com\] security-txt-expired \[low\] host=example\.com path=/\.well-known/security\.txt expires=2021-01-01T00:00:00Z' "expired security.txt -> security-txt-expired [low]"
assert_grep  "$CSV.extras.txt" 'catch-all-200 \[info\] host=example\.com path=/rr-'  "random path answered 200 -> catch-all-200 [info]"
assert_grep  "$CSV.extras.txt" 'error-page \[info\] host=example\.com status=200 server="nginx" title="Home" reveals="Apache/2\.4\.41 \(Ubuntu\)"' "error page reveals a version the Server header does not"
assert_grep  "$CSV" ',-732438843,1e23ac45e53e0bd440ab397425229b87,,200 disallow=2 allow=0 sitemap=1,expired contact=mailto:security@example\.com expires=2021-01-01T00:00:00Z,{9}.?$' "favicon, robots and security.txt columns on the host's rows"
MOCK_EXTRAS_NOSEC=1 run_case extras_nosec --extras
assert_grep  "$CSV" ',missing,{9}.?$'                                       "no security.txt -> security_txt=missing"
refute_grep  "$CSV.extras.txt" 'security-txt'                             "a missing security.txt is a column value, not a finding"
MOCK_EXTRAS_ICON='link' run_case extras_iconlink --extras
assert_grep  "$MOCKLOG/httpx.args" -- '-l [^ ]*extras_icon_urls\.txt -silent -json -irrb' "an icon declared at another path is fetched in one follow-up pass"
assert_fgrep "$OUTDIR"/_work-*/raw/example.com/extras_icon_urls.txt 'https://example.com/static/app.ico' "<link rel=\"shortcut icon\"> href resolved against the root"
assert_fgrep "$OUTDIR"/_work-*/parts/favhash.example.com.tsv $'example.com\t997645422\t5efb3ec8359469339d84389e1257dc4a\t/static/app.ico' "the declared icon is hashed, not /favicon.ico (WebInventory's order)"
MOCK_EXTRAS_ICON='data' run_case extras_icondata --extras
assert_fgrep "$OUTDIR"/_work-*/parts/favhash.example.com.tsv $'example.com\t-634531059\t1af556a006bb28e4f735986a835366aa\tdata:' "an inline data: icon is decoded and hashed, with no request"
refute_grep  "$MOCKLOG/httpx.args" 'extras_icon_urls'                      "no follow-up pass for a data: icon"
MOCK_EXTRAS_ICON='html' run_case extras_iconhtml --extras
refute_grep  "$OUTDIR"/_work-*/parts/favhash.example.com.tsv 'example\.com'  "an HTML page served as /favicon.ico is not an icon: no hash"
run_case extras_favicon --extras --favicon
refute_grep  "$MOCKLOG/httpx.args" -- '-favicon'                            "--extras --favicon: the pivot reuses the hashes --extras computed"
assert_grep  "$MOCKLOG/uncover.args" -- 'http\.favicon\.hash:-732438843'     "the locally computed mmh3 drives the favicon pivot"

section "Batch 2: --favicon pivots on the favicon hash (uncover), hits feed --origin"
mv "$MOCKBIN/uncover" "$MOCKBIN/uncover.keys"
mk uncover <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/uncover.args"; echo >> "$MOCKLOG/uncover.args"
echo '[FTL] Could not run enumeration: [uncover:RUNTIME] agents [shodan] requires keys but no keys were found' >&2
exit 1
EOF
run_case favnokeys --favicon
assert_grep  "$ERRLOG" '--favicon: uncover has no API keys for its engines'  "uncover without keys: one clear warning (was silent)"
if [ "$(grep -c 'uncover has no API keys' "$ERRLOG")" = 1 ]; then _pass "...said once, not per call"; else _fail "...said once, not per call"; fi
mv "$MOCKBIN/uncover.keys" "$MOCKBIN/uncover"
run_case favpivot --favicon --origin
assert_grep  "$MOCKLOG/uncover.args" -- '-shodan http\.favicon\.hash:-123456 -fofa icon_hash="-123456" -censys services\.http\.response\.favicons\.md5_hash: "0123456789abcdef0123456789abcdef" -silent -duc -l 100' "favicon hash searched on Shodan/Fofa (mmh3) and Censys (MD5), no update check, capped"
assert_grep  "$MOCKLOG/uncover.args" -- '-q ssl:"example\.com" -silent -duc' "certificate-name search kept, without uncover's update check"
assert_grep  "$CSV.favicon.txt" '^\[example\.com\] favicon-pivot host=[^ ]*example\.com mmh3=-123456 md5=0123456789abcdef0123456789abcdef hits=1$' "favicon pivot recorded with its hit count"
assert_grep  "$CSV" ',https://favicon-pivot\.example\.com,favicon-pivot\.example\.com,favicon,' "in-scope name from a host sharing the favicon (cert scan of the hit)"
assert_fgrep "$MOCKLOG/curl.args" '--resolve example.com:443:198.51.100.20' "favicon hit tried as an origin candidate"
mk curl <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/curl.args"; echo >> "$MOCKLOG/curl.args"
exit 0
EOF

section "Batch 2: report surfaces HTTP posture and findings"
R9="$TMP/rpt19"; rm -rf "$R9"; mkdir -p "$R9"
{
  printf 'seed_domain,url,host,sources,status_code,content_length,webserver,title,technologies,ip,asn,asn_org,tls_version,tls_cipher,cert_not_after,cert_issuer,tls_flags,ipv6,cloud,rdap_org,geo,cpe,redirect_location,response_ms,body_sha256,content_type,powered_by,auth,cookies,cookie_issues,missing_sec_headers,hsts_max_age,alt_svc,http_flags,favicon_mmh3,favicon_md5,ptr,robots,security_txt\n'
  printf 'ex.com,https://www.ex.com/,www.ex.com,gau,200,10,nginx,Home,,93.184.216.34,,,,,,,,,,,,,,12,,text/html,PHP/8.1,,sid,sid:no-Secure,Content-Security-Policy;Strict-Transport-Security,,h3=":443",,-1293291,aabbccddeeff00112233445566778899,edge.example.net,200 disallow=3 allow=0 sitemap=1,expired contact=mailto:s@ex.com expires=2021-01-01\n'
  printf 'ex.com,http://www.ex.com/,www.ex.com,gau,200,10,nginx,Home,,93.184.216.34,,,,,,,,,,,,,,12,,text/html,,,,,Content-Security-Policy,,,PlainHttp,-1293291,,,,\n'
  printf 'ex.com,http://vpn.ex.com/,vpn.ex.com,gau,401,0,nginx,,,93.184.216.34,,,,,,,,,,,,,,9,,text/html,,"Basic realm=""Legacy VPN""",,,,,,CleartextAuth,,,,,missing\n'
} > "$R9/r.csv"
printf '[ex.com] security-txt-expired [low] host=www.ex.com path=/.well-known/security.txt expires=2021-01-01 note=x\n[ex.com] catch-all-200 [info] host=www.ex.com path=/rr-1.html length=5 note=x\n' > "$R9/r.csv.extras.txt"
env PATH="$TESTPATH" bash "$REPORT_SH" -o "$R9/out.html" "$R9/r.csv" >/dev/null 2>"$R9/e.log"
python3 - "$R9/out.html" > "$R9/text.txt" <<'PYTXT'
import sys, re, html
s = open(sys.argv[1], encoding="utf-8").read()
print(html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s))))
PYTXT
assert_grep  "$R9/text.txt" 'MEDIUM HTTP vpn\.ex\.com credentials sent in cleartext: Basic realm="Legacy VPN" on http://vpn\.ex\.com/' "CleartextAuth -> MEDIUM finding"
assert_grep  "$R9/text.txt" 'LOW HTTP www\.ex\.com served over plain HTTP without a redirect to HTTPS: http://www\.ex\.com/' "PlainHttp -> LOW finding, once per host"
assert_grep  "$R9/text.txt" 'LOW security\.txt www\.ex\.com security-txt-expired' "expired security.txt -> LOW finding"
refute_grep  "$R9/text.txt" 'INFO Web server note'                        "catch-all-200 is a note, not a finding"
assert_grep  "$R9/text.txt" 'Security headers missing CSP, HSTS'           "host card: missing headers of the root page (https preferred)"
assert_grep  "$R9/text.txt" 'Favicon mmh3 -1293291 md5 aabbccddeeff00112233445566778899' "host card: favicon hashes"
assert_grep  "$R9/text.txt" 'PTR edge\.example\.net'                       "host card: reverse DNS"
assert_grep  "$R9/text.txt" 'robots\.txt 200 disallow=3'                   "host card: robots.txt"
assert_grep  "$R9/text.txt" 'security\.txt expired contact=mailto:s@ex\.com' "host card: security.txt"
assert_grep  "$R9/text.txt" 'Cookie flags sid:no-Secure'                   "host card: cookie flag gaps"
assert_grep  "$R9/text.txt" 'X-Powered-By PHP/8\.1'                        "host card: X-Powered-By"

# --- v1.18: DNS zone exposure (AXFR, NSEC walk, NSEC3) ------------------------------
section "--zone-exposure: open AXFR, walkable NSEC chain, NSEC3, and the negative case"
run_case zone_off
refute_grep  "$MOCKLOG/dig.args" 'AXFR|NSEC'                            "default run sends no AXFR/NSEC queries"
MOCK_ZONE=axfr run_case zone_axfr --zone-exposure
assert_grep  "$MOCKLOG/dig.args" 'AXFR example\.com @192\.0\.2\.53'      "AXFR tried on the zone's own name server (from NS -> A)"
assert_grep  "$CSV.zone.txt" '^\[example\.com\] zone-transfer-open \[high\] host=example\.com zone=example\.com ns=ns1\.example\.com\(192\.0\.2\.53\) records=6 names=4' "open zone transfer -> zone-transfer-open [high]"
assert_grep  "$CSV.zone-names.txt" '^example\.com	hidden-zone\.example\.com	axfr$' "transferred names listed in <out>.zone-names.txt"
assert_grep  "$CSV" ',https://hidden-zone\.example\.com,'                "a name only the zone transfer revealed is probed and inventoried"
assert_grep  "$ERRLOG" 'name\(s\) from AXFR/NSEC added to the candidates'  "worker reports the zone names it added"
MOCK_ZONE=nsec run_case zone_nsec --zone-exposure
assert_grep  "$MOCKLOG/dig.args" '\+dnssec \+norec NSEC a-secret\.example\.com @192\.0\.2\.53' "NSEC chain followed name by name"
assert_grep  "$CSV.zone.txt" 'nsec-zone-walkable \[medium\] host=example\.com zone=example\.com names=3' "walkable NSEC chain -> nsec-zone-walkable [medium]"
assert_grep  "$CSV.zone-names.txt" '^example\.com	a-secret\.example\.com	nsec$' "walked names listed with source nsec"
refute_grep  "$CSV.zone.txt" 'zone-transfer-open'                       "a refused transfer is not reported as open"
MOCK_ZONE=nsec3 run_case zone_nsec3 --zone-exposure
assert_grep  "$CSV.zone.txt" 'nsec3-hashes-exposed \[low\] host=example\.com .*iterations=5 salt=ABCDEF' "NSEC3 zone -> nsec3-hashes-exposed [low] with its parameters"
refute_grep  "$MOCKLOG/dig.args" ' NSEC a-secret'                       "an NSEC3 zone is not walked"
MOCK_ZONE=none run_case zone_none --zone-exposure
assert_grep  "$CSV.zone.txt" 'zone-checked \[info\] host=example\.com zone=example\.com signed=no axfr=refused\(1/1\) nsec=n/a' "nothing exposed -> zone-checked [info] (evidence the check ran)"
assert_absent "$CSV.zone-names.txt"                                    "no names harvested from a closed zone"
MOCK_ZONE=nsec MOCK_ZONE_NS2=1 MOCK_ZONE_V6=1 run_case zone_multi --zone-exposure
assert_grep  "$MOCKLOG/dig.args" 'AAAA ns1\.example\.com'                "the name servers' IPv6 addresses are looked up too"
assert_grep  "$MOCKLOG/dig.args" 'AXFR example\.com @2001:db8::53'        "AXFR tried on the IPv6 address of a name server"
assert_grep  "$MOCKLOG/dig.args" 'NSEC example\.com @192\.0\.2\.52'      "the walk starts on the first name server..."
assert_grep  "$CSV.zone.txt" 'nsec-zone-walkable \[medium\] host=example\.com zone=example\.com names=3' "...and moves on to the next when it gives no chain (v1.19 asked only the first)"
refute_grep  "$MOCKLOG/dig.args" 'NSEC [a-z0-9.]+ @2001:db8::53'         "an address that never answered is not walked"
assert_grep  "$CSV.zone.txt" '^\[example\.com\] dnssec-unanchored \[low\] host=example\.com zone=example\.com ds=no' "signed without a DS in the parent -> dnssec-unanchored [low]"
MOCK_ZONE=none MOCK_ZONE_V6=1 run_case zone_v6dead --zone-exposure
assert_grep  "$CSV.zone.txt" 'zone-checked \[info\] .*axfr=refused\(1/1\) nsec=n/a unreachable=1$' "an address with no reply is counted apart, not as a refusal"
MOCK_ZONE=signed MOCK_ZONE_DS=1 run_case zone_ds --zone-exposure
assert_grep  "$CSV.zone.txt" 'zone-checked \[info\] host=example\.com zone=example\.com signed=yes axfr=refused\(1/1\) nsec=not-walkable ds=yes$' "signed, anchored, not walkable -> zone-checked with ds=yes"
refute_grep  "$CSV.zone.txt" 'dnssec-unanchored'                       "a DS in the parent: no dnssec-unanchored"
bash "$(dirname "$RUN_RECON")/generate-report.sh" "$TMP/out_zone_axfr/r.csv" -o "$OUTDIR/z.html" >/dev/null 2>&1 || true
if python3 -c 'import sys,re; s=open(sys.argv[1],encoding="utf-8").read(); t=re.sub(r"<[^>]+>"," ",s); sys.exit(0 if re.search(r"HIGH\s+DNS zone exposure\s+example\.com", t) and "DNS zones checked" in s else 1)' "$OUTDIR/z.html" 2>/dev/null
then _pass "report: zone transfer is a HIGH finding and the zones table lists it"; else _fail "report: zone transfer is a HIGH finding and the zones table lists it"; fi

# --- v1.18: run integrity -------------------------------------------------------------
section "run integrity: resolver preflight resolves a seed; per-seed warnings; 0 rows -> exit 3; run.json"
INTRES="$TMP/int-resolvers.txt"; printf '9.9.9.9\n' > "$INTRES"
run_case res_ok --resolve --resolvers "$INTRES"
assert_grep  "$ERRLOG" 'resolver check passed \(9\.9\.9\.9 resolves example\.com\)' "preflight looks up the first seed, not any name"
MOCK_DIG_STATUS=SERVFAIL run_case res_servfail --resolve --resolvers "$INTRES"
assert_grep  "$ERRLOG" '9\.9\.9\.9 answers, but looking up the first seed example\.com returns SERVFAIL' "SERVFAIL for the seed is not a passed check (v1.17 said passed)"
MOCK_DIG_STATUS=NXDOMAIN run_case res_nx --resolve --resolvers "$INTRES"
assert_grep  "$ERRLOG" 'the first seed example\.com does not exist \(NXDOMAIN'  "an NXDOMAIN seed is called out"
_DOMS="$DOMAINS"; DOMAINS="$TMP/deadseed.txt"; printf 'dead.example.com\n' > "$DOMAINS"
run_case deadseed --resolve
assert_grep  "$ERRLOG" '\[dead\.example\.com\] none of 1 candidate name\(s\) resolved' "per-seed warning when nothing resolves"
assert_grep  "$ERRLOG" 'the seed is a CNAME to deleted\.herokuapp\.com, which does not resolve \(dangling; --takeover checks it\)' "a seed that is a dangling CNAME is called out as one"
printf 'dead.other.org\n' > "$DOMAINS"
run_case deadseed2 --resolve
assert_grep  "$ERRLOG" '\[dead\.other\.org\] none of 1 candidate name\(s\) resolved, not even the seed' "no CNAME: the plain warning"
DOMAINS="$_DOMS"
MOCK_HTTPX_NOLIVE=1 run_case nolive
assert_grep  "$ERRLOG" '\[example\.com\] no live web host: [0-9]+ name\(s\) probed' "per-seed warning when nothing answers the probe"
ZR="$TMP/zerorows"; rm -rf "$ZR"; mkdir -p "$ZR"; printf 'nothing.test\n' > "$ZR/d.txt"
timeout 25 env PATH="$TESTPATH" HTTPX_BIN=httpx MOCK_HTTPX_NOLIVE=1 TLS_CHAIN_CHECK=0 RECON_CLOUD_CACHE="$ZR/c.tsv" \
  bash "$RUN_RECON" -i "$ZR/d.txt" -D "$ZR" -o "$ZR/r.csv" >/dev/null 2>"$ZR/e.log"; echo $? > "$ZR/rc"
if [ "$(cat "$ZR/rc")" = 3 ]; then _pass "0 URL rows -> exit status 3 (v1.17: 0 and \"Complete.\")"; else _fail "0 URL rows -> exit status 3  [rc=$(cat "$ZR/rc")]"; fi
assert_grep  "$ZR/e.log" 'Finished with NO results: 0 URL rows'        "0 rows is reported as no results, not Complete"
refute_grep  "$ZR/e.log" '\] Complete\.$|^\[\+\]  Complete\.'           "no \"Complete.\" banner for an empty run"
assert_grep  "$ZR/r.csv.run.json" '"exit_status": 3'                    "run.json records exit status 3"
assert_grep  "$ZR/r.csv.report.html" 'This run produced no results'     "report carries a no-results banner"
RRVER="$(sed -n 's/^VERSION="\(.*\)"$/\1/p' "$RUN_RECON")"
run_case runjson --proxy http://user:s3cret@127.0.0.1:8080
assert_grep  "$CSV.run.json" "\"version\": \"${RRVER//./\\.}\""          "run.json: run-recon version"
assert_grep  "$CSV.run.json" '"--proxy"'                                "run.json: command line"
assert_grep  "$CSV.run.json" 'http://\*\*\*@127\.0\.0\.1:8080'          "run.json: proxy credentials redacted"
refute_grep  "$CSV.run.json" 's3cret'                                   "run.json never holds the proxy password"
assert_grep  "$CSV.run.json" '"seed": "example\.com"'                   "run.json: per-seed counts"
assert_grep  "$CSV.run.json" '"exit_status": 0'                         "run.json: exit status 0 for a run with rows"
assert_grep  "$CSV.run.json" '"url_rows": [1-9]'                        "run.json: URL row count"
MOCK_KATANA_JUNK=1 run_case crawljunk
assert_grep  "$CSV" 'katana-path'                                       "crawl output still ingested"
refute_grep  "$CSV" '%5C/|\\/'                                          "URLs built from JSON-escaped paths are dropped (v1.17: http://wp.test/%5C/wp.test%5C/index.php)"

# --- v1.18: certificate chain validation against the system trust store ---------------
section "TLS chain validation (CertUntrusted from the system trust store, not tlsx's bad-CA list)"
TC="$TMP/tlschain"; rm -rf "$TC"; mkdir -p "$TC"
if command -v openssl >/dev/null 2>&1 && openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TC/k.pem" -out "$TC/c.pem" -days 2 -subj "/CN=localhost" >/dev/null 2>&1; then
  python3 - "$TC/c.pem" "$TC/k.pem" "$TC/port" <<'PYSRV' &
import ssl, socket, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[1], sys.argv[2])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 0)); s.listen(5); s.settimeout(20)
open(sys.argv[3], "w").write(str(s.getsockname()[1]))
n = 0
for _ in range(3):
    try:
        c, _a = s.accept()
    except Exception:
        break
    n += 1; s.settimeout(2)       # after the first handshake, wait briefly for duplicates
    try:
        ctx.wrap_socket(c, server_side=True).close()
    except Exception:
        pass
open(sys.argv[3] + ".n", "w").write(str(n))
PYSRV
  _srv=$!
  for _i in 1 2 3 4 5 6 7 8 9 10; do [ -s "$TC/port" ] && break; sleep 0.3; done
  TPORT="$(cat "$TC/port" 2>/dev/null)"
  CPORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
  # the same (address, port, name) three times, as when seeds share a host: one handshake
  printf '{"host":"localhost","ip":"127.0.0.1","port":"%s"}\n{"host":"localhost","ip":"127.0.0.1","port":"%s"}\nnot-json\n{"host":"localhost","ip":"127.0.0.1","port":"%s","seed":"b"}\n{"host":"localhost","ip":"127.0.0.1","port":"%s","seed":"c"}\n' "$TPORT" "$CPORT" "$TPORT" "$TPORT" > "$TC/t.jsonl"
  awk '/^tls_chain_check\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$RUN_RECON" > "$TC/fn.sh"
  ( . "$TC/fn.sh"; tls_chain_check "$TC/t.jsonl" )
  for _i in $(seq 1 30); do [ -s "$TC/port.n" ] && break; sleep 0.2; done   # the server's own count
  kill "$_srv" 2>/dev/null; wait "$_srv" 2>/dev/null
  assert_grep "$TC/t.jsonl" "\"port\": \"$TPORT\", \"chain_trusted\": false, \"chain_error\": \"[^\"]*self[- ]signed[^\"]*\", \"untrusted\": true" "self-signed chain -> untrusted, with the verifier's reason"
  assert_grep "$TC/t.jsonl" "\"port\": \"$CPORT\"}\$"                      "no handshake -> record left as it was (no flag)"
  assert_grep "$TC/t.jsonl" '^not-json$'                                  "a non-JSON line is preserved"
  if [ "$(grep -c '"chain_trusted": false' "$TC/t.jsonl")" = 3 ]; then _pass "every duplicate record gets the verdict"; else _fail "every duplicate record gets the verdict"; fi
  if [ "$(cat "$TC/port.n" 2>/dev/null)" = 1 ]; then _pass "duplicate (address, port, name) records share one handshake"; else _fail "duplicate (address, port, name) records share one handshake (got $(cat "$TC/port.n" 2>/dev/null) connections)"; fi
else
  _pass "openssl unavailable: chain validation test skipped"
fi

# --- v1.18: report (run header, names, cards, graded TLS, screenshots, zones) --------
section "report v1.18: run header, name inventory, edge/origin, graded TLS expiry, screenshot status"
R8="$TMP/rpt18"; rm -rf "$R8"; mkdir -p "$R8/screenshots-t/screenshot/www.ex.com"
python3 - "$R8" <<'PYFIX'
import sys, os, json, datetime
d = sys.argv[1]
now = datetime.datetime.now(datetime.timezone.utc)
iso = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")
hdr = "seed_domain,url,host,sources,status_code,content_length,webserver,title,technologies,ip,asn,asn_org,tls_version,tls_cipher,cert_not_after,cert_issuer,tls_flags,ipv6,cloud,rdap_org,geo,cpe\n"
rows = [
 ["ex.com", "https://www.ex.com", "www.ex.com", "katana", "200", "10", "cloudflare nginx/1.25.3", "Ex Home", "Nginx:1.25.3", "104.16.1.1", "", "", "TLS 1.3", "X", iso(now + datetime.timedelta(days=3, hours=2)), "Lab CA", "CertExpiring;CertUntrusted", "2001:db8::5", "", "", "", "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"],
 ["ex.com", "https://alias.ex.com", "alias.ex.com", "katana", "200", "10", "cloudflare", "Ex Home", "", "104.16.1.1", "", "", "", "", "", "", "", "", "", "", "", ""],
 ["ex.com", "https://soon.ex.com", "soon.ex.com", "katana", "200", "10", "nginx", "Soon", "", "203.0.113.4", "", "", "TLS 1.2", "X", iso(now + datetime.timedelta(days=20, hours=2)), "R3", "CertExpiring", "", "", "", "", ""],
 ["ex.com", "https://old.ex.com", "old.ex.com", "katana", "200", "10", "nginx", "Old", "", "203.0.113.5", "", "", "TLS 1.2", "X", iso(now - datetime.timedelta(days=2)), "R3", "CertExpired", "", "", "", "", ""],
]
open(os.path.join(d, "r.csv"), "w").write(hdr + "".join(",".join(r) + "\n" for r in rows))
json.dump({"tool": "run-recon", "version": "1.18.0", "started": iso(now), "duration_s": 75, "input": "seeds.txt",
           "args": ["-i", "seeds.txt", "--zone-exposure", "--origin"], "seeds": 2, "exit_status": 0,
           "per_seed": [{"seed": "ex.com", "candidates": 9, "resolved": 5, "live_hosts": 4},
                        {"seed": "gone.ex.com", "candidates": 1, "resolved": 0, "live_hosts": 0}],
           "tool_versions": {"httpx": "1.12.0"}, "lab_verified": "httpx=1.12.0",
           "resolvers": {"file": "r.txt", "count": 1, "check": "passed"},
           "warnings": ["[gone.ex.com] none of 1 candidate name(s) resolved, not even the seed"], "url_rows": 4},
          open(os.path.join(d, "r.csv.run.json"), "w"))
open(os.path.join(d, "r.csv.zone.txt"), "w").write(
    "[ex.com] zone-transfer-open [high] host=ex.com zone=ex.com ns=ns1.ex.com(192.0.2.53) records=9 names=5 note=x\n"
    "[ex.org] zone-checked [info] host=ex.org zone=ex.org signed=no axfr=refused(2/2) nsec=n/a\n")
open(os.path.join(d, "r.csv.origin.txt"), "w").write(
    "[ex.com] origin-exposed [high] host=www.ex.com origin=10.0.0.1 port=443 via=direct.ex.com match=body-sha256 edge=\x1b[35mcloudflare\x1b[0m note=x\n")
open(os.path.join(d, "r.csv.takeover.txt"), "w").write(
    "[ex.com] dangling-cname [medium] host=orphan.ex.com cname=gone.azurewebsites.net dns=NXDOMAIN note=x\n")
open(os.path.join(d, "r.csv.edge.tsv"), "w").write(
    "seed_domain\thost\tedge\torigin_software\tedge_evidence\tjarm\tcdn\tfavicon_mmh3\ttitle\tedge_ip\n"
    "ex.com\twww.ex.com\tcloudflare\tnginx/1.25.3\tserver-chain,cf-ray\t\tcloudflare\t-123\tEx Home\t104.16.1.1\n")
open(os.path.join(d, "r.csv.cname.tsv"), "w").write(
    "seed_domain\thost\tcname_chain\tdns\tprovider\n"
    "ex.com\talias.ex.com\twww.ex.com\tresolves\t\n"
    "ex.com\torphan.ex.com\tgone.azurewebsites.net\tNXDOMAIN\tAzure\n")
open(os.path.join(d, "r.csv.zone-names.txt"), "w").write(
    "zone\tname\tsource\nex.com\twww.ex.com\taxfr\nex.com\tvpn-old.ex.com\taxfr\nex.com\tmail.partner.org\taxfr\n")
open(os.path.join(d, "screenshots-t/screenshot/www.ex.com/a.png"), "wb").write(b"PNGDATA")
open(os.path.join(d, "r.csv.screenshots.tsv"), "w").write(
    "host\tfile\tstatus\treason\tbytes\n"
    "www.ex.com\tscreenshot/www.ex.com/a.png\tok\t\t7\n"
    "alias.ex.com\tscreenshot/www.ex.com/a.png\tsuspect\tbrowser rendered 'Proxy Error', the probe saw 'Ex Home'\t7\n"
    "soon.ex.com\t\tblank\tthe page is empty (0-byte body): nothing to capture\t0\n"
    "old.ex.com\t\tfailed\tno image\t0\n")
PYFIX
env PATH="$TESTPATH" bash "$REPORT_SH" -o "$R8/out.html" "$R8/r.csv" >/dev/null 2>"$R8/e.log"
python3 - "$R8/out.html" > "$R8/text.txt" <<'PYTXT'
import sys, re, html
s = open(sys.argv[1], encoding="utf-8").read()
print(html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s))))
PYTXT
assert_grep  "$R8/out.html" 'run-recon 1\.18\.0'                          "run header: version"
assert_grep  "$R8/text.txt" 'command line: run-recon\.sh -i seeds\.txt --zone-exposure --origin' "run header: command line"
assert_grep  "$R8/text.txt" 'check passed'                                 "run header: resolver check"
assert_grep  "$R8/text.txt" '1 warning\(s\) during the run'                "run header: warnings"
refute_grep  "$R8/out.html" $'\033'                                        "terminal colour codes stripped from findings"
assert_grep  "$R8/text.txt" 'HIGH DNS zone exposure ex\.com zone-transfer-open' "zone transfer listed as a HIGH finding"
assert_grep  "$R8/text.txt" 'DNS zones checked'                           "zones table rendered"
refute_grep  "$R8/text.txt" 'INFO DNS zone check'                         "zone-checked is evidence, not a finding"
assert_grep  "$R8/text.txt" '1 name\(s\) from the zones fall outside every seed'  "zone names outside the seeds are listed, not scanned"
assert_grep  "$R8/text.txt" 'HIGH Exposed origin www\.ex\.com origin-exposed'    "exposed origin listed as a HIGH finding"
assert_grep  "$R8/text.txt" 'Edge cloudflare → nginx/1\.25\.3 → origin 10\.0\.0\.1 \(origin-exposed\)' "host card: edge -> origin software -> verified origin"
assert_grep  "$R8/text.txt" 'Ex Home'                                      "host card: page title"
assert_grep  "$R8/text.txt" 'IPv6 2001:db8::5'                             "host card: IPv6"
assert_grep  "$R8/text.txt" 'issuer Lab CA · expires in 3 days'            "host card: certificate issuer and days left"
assert_grep  "$R8/text.txt" 'cpe:2\.3:a:f5:nginx:1\.25\.3'                 "host card: CPEs"
assert_grep  "$R8/text.txt" 'MEDIUM TLS / certificate www\.ex\.com certificate expires in 3 days' "expiry under 7 days -> MEDIUM"
assert_grep  "$R8/text.txt" 'LOW TLS / certificate soon\.ex\.com certificate expires in 20 days'  "expiry under 30 days -> LOW"
assert_grep  "$R8/text.txt" 'HIGH TLS / certificate old\.ex\.com certificate expired 2 days ago'  "expired -> HIGH"
assert_grep  "$R8/text.txt" 'MEDIUM TLS / certificate www\.ex\.com certificate chain not trusted' "CertUntrusted -> MEDIUM finding"
assert_grep  "$R8/text.txt" 'Alias of www\.ex\.com \(CNAME\)'               "alias card names its CNAME target"
assert_grep  "$R8/text.txt" 'Aliases alias\.ex\.com'                       "target card lists its aliases"
assert_grep  "$R8/out.html" 'id="h-orphanexcom"'                          "a dangling name with a finding gets a card though it is not live"
assert_grep  "$R8/text.txt" 'orphan\.ex\.com ex\.com dangling CNAME \(NXDOMAIN\)' "names table: dangling CNAME status"
assert_grep  "$R8/text.txt" 'gone\.ex\.com gone\.ex\.com does not resolve'  "names table: a seed that did not resolve"
assert_grep  "$R8/text.txt" 'vpn-old\.ex\.com ex\.com zone record'          "names table: a zone name under a seed"
assert_grep  "$R8/text.txt" 'may not show this site: browser rendered'      "suspect screenshot carries a warning"
assert_grep  "$R8/text.txt" 'blank page \(the site returned an empty body\)' "blank page shown as blank"
assert_grep  "$R8/text.txt" 'screenshot failed no image'                    "failed capture shown as failed"
assert_grep  "$R8/text.txt" ' 2 Seeds ' "summary: seed count"
refute_grep  "$R8/out.html" 'produced no results'                          "no banner for a run with rows"
printf 'seed_domain,url,host\n' > "$R8/empty.csv"
printf '{"version":"1.18.0","exit_status":3,"warnings":["[x.test] none of 1 candidate name(s) resolved, not even the seed"]}' > "$R8/empty.csv.run.json"
env PATH="$TESTPATH" bash "$REPORT_SH" -o "$R8/empty.html" "$R8/empty.csv" >/dev/null 2>&1
assert_grep  "$R8/empty.html" 'This run produced no results'               "0-row run -> banner"
assert_grep  "$R8/empty.html" 'none of 1 candidate name'                    "banner quotes the warnings that explain it"

# --- v1.20: the v1.18 follow-ups (F1-F10) --------------------------------------------
section "v1.20 follow-ups: origin candidates (SPF include/ip6/ranges, history), edges, screenshots, chains"
mk curl <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/curl.args"; echo >> "$MOCKLOG/curl.args"
case " $* " in
  *"virustotal.com/api/v3/domains/example.com/subdomains"*) printf '{"data":[]}'; exit 0;;
  *"virustotal.com/api/v3/domains/example.com"*)
    printf '{"data":{"attributes":{"reputation":0,"categories":{},"last_dns_records":[{"type":"A","value":"203.0.113.10"},{"type":"AAAA","value":"2001:db8:7::10"},{"type":"MX","value":"mx.example.com"}]}}}'; exit 0;;
  *"urlscan.io/api/v1/search"*)
    printf '{"results":[{"task":{"time":"2024-03-01T00:00:00Z"},"page":{"url":"https://example.com/","ip":"203.0.113.9"}},{"task":{"time":"2024-03-02T00:00:00Z"},"page":{"url":"https://other.org/","ip":"203.0.113.99"}}]}'; exit 0;;
esac
out=""; a=("$@"); i=0
while [ $i -lt ${#a[@]} ]; do case "${a[$i]}" in -o) i=$((i+1)); out="${a[$i]}";; esac; i=$((i+1)); done
[ -n "$out" ] && : > "$out"
printf '000'; exit 7
EOF
MOCK_SPF=include VT_API_KEY=test-vt run_case f2_cands --origin --virustotal --urlscan
assert_fgrep "$MOCKLOG/curl.args" '--resolve example.com:443:198.51.100.8 '      "SPF include: followed: its ip4: is a candidate"
assert_fgrep "$MOCKLOG/curl.args" '--resolve example.com:443:[2001:db8:5::7] '   "SPF ip6: is a candidate (bracketed)"
assert_fgrep "$MOCKLOG/curl.args" '--resolve example.com:443:198.51.100.17 '     "a small SPF range (/30) is expanded"
refute_grep  "$MOCKLOG/curl.args" 'example\.com:443:203\.0\.113\.[0-9]+ .*203\.0\.113\.0/24|example\.com:443:203\.0\.113\.200 ' "a wide SPF range (/24) is not swept"
assert_fgrep "$MOCKLOG/curl.args" '--resolve example.com:443:203.0.113.10 '      "VirusTotal's DNS history: a past A record is a candidate"
assert_fgrep "$MOCKLOG/curl.args" '--resolve example.com:443:[2001:db8:7::10] '  "VirusTotal's DNS history: a past AAAA record too"
assert_fgrep "$MOCKLOG/curl.args" '--resolve example.com:443:203.0.113.9 '       "urlscan.io: an address a past scan of the site saw"
refute_grep  "$MOCKLOG/curl.args" '203\.0\.113\.99'                             "urlscan.io: a scan of another site is not a candidate"
OP_CAND="$(find "$OUTDIR" -name origin_pairs.tsv | head -1)"
assert_grep  "$OP_CAND" '203\.0\.113\.9	.*history:urlscan'                       "the candidate list says where each address came from"
MOCK_REF_SERVER=Caddy run_case f7_caddy --origin
assert_grep  "$CSV.edge.tsv" '^example\.com	example\.com			'                  "a lone Server: Caddy is not an edge (v1.19 called Caddy one)"
MOCK_REF_SERVER=AkamaiGHost run_case f7_akamai --origin
assert_grep  "$CSV.edge.tsv" '^example\.com	example\.com	AkamaiGHost		edge-server	' "a lone CDN Server header still names the edge"

# F5: the screenshot browser resolves names as --resolvers did
SSR="$TMP/ss-resolvers.txt"; printf '10.0.0.53\n' > "$SSR"
mk chromium <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
run_case f5_rules --screenshots --resolvers "$SSR"
assert_grep  "$MOCKLOG/httpx.args" -- '-ho --host-resolver-rules=MAP example\.com 10\.0\.0\.1( |,|$)' "--resolvers: the browser gets the probe's addresses (--host-resolver-rules)"
run_case f5_norules --screenshots
refute_grep  "$MOCKLOG/httpx.args" 'host-resolver-rules'                       "no --resolvers: the browser resolves as the system does"

# F6: gowitness 3, with its JSON lines as the capture evidence
mk gowitness <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/gowitness.args"; echo >> "$MOCKLOG/gowitness.args"
f=""; sp=""; jl=""; a=("$@"); i=0
while [ $i -lt ${#a[@]} ]; do case "${a[$i]}" in
  -f) i=$((i+1)); f="${a[$i]}";; --screenshot-path) i=$((i+1)); sp="${a[$i]}";;
  --write-jsonl-file) i=$((i+1)); jl="${a[$i]}";; esac; i=$((i+1)); done
cp "$f" "$MOCKLOG/gowitness.targets"
mkdir -p "$sp"
while IFS= read -r u; do
  fn="$(printf '%s' "$u" | sed -E 's#://#---#; s#:([0-9]+)$#-\1#').jpeg"
  printf 'JPEGDATA' > "$sp/$fn"
  printf '{"url":"%s","final_url":"%s/","response_code":200,"title":"Home","file_name":"%s","failed":false}\n' "$u" "$u" "$fn" >> "$jl"
done < "$f"
exit 0
EOF
SCREENSHOT_TOOL=gowitness run_case f6_gw --screenshots
assert_grep  "$MOCKLOG/gowitness.args" -- '--write-jsonl --write-jsonl-file [^ ]+ .*--driver gorod' "gowitness records each capture (JSON lines) with the go-rod driver"
assert_grep  "$MOCKLOG/gowitness.args" -- '--chrome-path [^ ]*(chromium|chrome)' "gowitness uses the installed Chrome/Chromium (no download)"
assert_fgrep "$MOCKLOG/gowitness.targets" 'https://example.com:443'              "explicit URLs: https on 443..."
assert_fgrep "$MOCKLOG/gowitness.targets" 'http://example.com:80'                "...and http on 80 (no four-way expansion)"
assert_grep  "$CSV.screenshots.tsv" '^example\.com	https---example\.com-443\.jpeg	ok'   "one capture per host, https first, validated from its JSON line"
if find "$OUTDIR"/screenshots-* -name 'http---example.com-80.jpeg' 2>/dev/null | grep -q .; then _fail "the http capture of a host shot over https is dropped"; else _pass "the http capture of a host shot over https is dropped"; fi
SCREENSHOT_TOOL=bogus run_case f6_bad --screenshots
assert_grep  "$ERRLOG" 'SCREENSHOT_TOOL must be auto, httpx or gowitness'       "an unknown SCREENSHOT_TOOL is rejected"
ORIGIN_PORTS='443;80' run_case f1_badports --origin
assert_grep  "$ERRLOG" 'ORIGIN_PORTS must be a space-separated port list'       "a malformed ORIGIN_PORTS is rejected"
rm -f "$MOCKBIN/gowitness" "$MOCKBIN/chromium"

# F8: one chain-check pass over every seed's records, one handshake per (address, port, name)
assert_grep  "$RUN_RECON" '^  tls_chain_check "\$WORKDIR/tlsx\.jsonl"$'         "the chain check runs once, on the merged TLS records"
if [ "$(grep -c 'tls_chain_check "' "$RUN_RECON")" = 1 ]; then _pass "no per-seed chain-check call is left"; else _fail "no per-seed chain-check call is left"; fi
mk curl <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/curl.args"; echo >> "$MOCKLOG/curl.args"
exit 0
EOF


# --- v1.20 Batch 3: email/DNS posture, cloud inventory, TLD variants, vulnx -------------
section "Batch 3: --dns-posture, --cloudlist, --tld-variants, --vulnx"
mk curl <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/curl.args"; echo >> "$MOCKLOG/curl.args"
case " $* " in
  *"https://mta-sts.example.com/.well-known/mta-sts.txt"*)
    printf 'version: STSv1\nmode: enforce\nmx: mx1.example.com\nmax_age: 604800\n\n200'; exit 0;;
esac
printf '000'; exit 7
EOF
MOCK_POSTURE=bad run_case posture --dns-posture
P="$CSV.dnsposture.txt"
assert_grep  "$ERRLOG" 'Email/DNS posture: 1 seed'                         "the posture stage runs in the main process, once"
assert_grep  "$P" '^\[example\.com\] spf-neutral \[medium\] host=example\.com all=\?all '                      "SPF ?all -> spf-neutral [medium]"
assert_grep  "$P" '^\[example\.com\] spf-include-dangling \[high\] host=example\.com include=gone-spf\.net '      "an include: of a domain that does not exist -> spf-include-dangling [high]"
assert_grep  "$P" '^\[example\.com\] dmarc-partial \[low\] host=example\.com pct=50 '                           "DMARC pct=50 -> dmarc-partial [low]"
assert_grep  "$P" '^\[example\.com\] dmarc-no-rua \[info\] host=example\.com '                                 "no rua= -> dmarc-no-rua [info]"
assert_grep  "$P" '^\[example\.com\] mta-sts-mx-mismatch \[medium\] host=example\.com mx=mx-old\.gone-mail\.net ' "an MX host the enforced policy does not list -> mta-sts-mx-mismatch"
refute_grep  "$P" 'mta-sts-(testing|none|invalid|missing|policy)'          "an enforced, fetched policy is not itself a finding"
assert_fgrep "$MOCKLOG/curl.args" '--proto =https --resolve mta-sts.example.com:443:192.0.2.80 https://mta-sts.example.com/.well-known/mta-sts.txt' "the policy is fetched over HTTPS only, from the address DNS gave"
refute_grep  "$MOCKLOG/curl.args" -- ' -k | --insecure '                    "the policy fetch verifies the certificate (RFC 8461)"
assert_grep  "$P" '^\[example\.com\] tlsrpt-missing \[info\] host=example\.com '                               "no TLS-RPT -> tlsrpt-missing [info]"
assert_grep  "$P" '^\[example\.com\] mx-dangling \[high\] host=example\.com mx=mx-old\.gone-mail\.net '          "an MX host whose domain does not exist -> mx-dangling [high]"
assert_grep  "$P" '^\[example\.com\] ns-dangling \[high\] host=example\.com ns=ns-gone\.gone-dns\.net '          "a name server whose domain does not exist -> ns-dangling [high]"
assert_grep  "$P" '^\[example\.com\] ns-lame \[medium\] host=example\.com ns=ns-lame\.example\.com\(192\.0\.2\.54\) reason=refused ' "a name server that refuses the zone -> ns-lame [medium]"
refute_grep  "$P" 'ns-lame .*ns=ns1\.'                                    "the authoritative name server is not lame"
assert_grep  "$P" '^\[example\.com\] caa-missing \[low\] host=example\.com '                                   "no CAA -> caa-missing [low]"
assert_grep  "$MOCKLOG/dig.args" '\+norec @192\.0\.2\.54 SOA example\.com'    "lameness asked of the name server itself, without recursion"
assert_grep  "$CSV.dnsposture.tsv" '^example\.com	apex	example\.com	mx1\.example\.com;mx-old\.gone-mail\.net	v=spf1 include:_spf\.example\.com include:gone-spf\.net \?all	\?all	2	p=quarantine	enforce	no	-	' "dnsposture.tsv: one row per name"
assert_grep  "$CSV.run.json" '"dnsposture": 1[0-9]'                         "run.json counts the posture findings"
bash "$(dirname "$RUN_RECON")/generate-report.sh" "$CSV" -o "$OUTDIR/p.html" >/dev/null 2>&1 || true
if python3 -c 'import sys,re; s=open(sys.argv[1],encoding="utf-8").read(); t=re.sub(r"<[^>]+>"," ",s); sys.exit(0 if re.search(r"HIGH\s+Email / DNS posture\s+example\.com", t) and "Email and DNS posture" in s else 1)' "$OUTDIR/p.html" 2>/dev/null
then _pass "report: posture findings in the findings table, and the posture table"; else _fail "report: posture findings in the findings table, and the posture table"; fi
MOCK_POSTURE=bad run_case posture_passive --dns-posture --passive-only
refute_grep  "$MOCKLOG/curl.args" 'mta-sts'                               "--passive-only: the MTA-STS policy is not fetched (DNS checks still run)"
assert_grep  "$CSV.dnsposture.tsv" 'record \(policy not fetched: --passive-only\)' "...and the table says so"
MOCK_POSTURE=lookups run_case posture_lookups --dns-posture
assert_grep  "$CSV.dnsposture.txt" 'spf-too-many-lookups \[medium\] host=example\.com lookups=11 '               "11 DNS-querying terms -> spf-too-many-lookups (record split across strings)"
MOCK_POSTURE=multi run_case posture_multi --dns-posture
assert_grep  "$CSV.dnsposture.txt" 'spf-multiple \[medium\] host=example\.com records=2 '                       "two SPF records -> spf-multiple [medium]"
run_case posture_off
refute_grep  "$ERRLOG" 'Email/DNS posture'                                 "off by default"

# --cloudlist: the accounts' assets vs the scan's inventory
CLC="$TMP/cloudlist.yaml"; printf -- '- provider: aws\n  id: prod\n' > "$CLC"
mk cloudlist <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/cloudlist.args"; echo >> "$MOCKLOG/cloudlist.args"
printf '{"public":true,"provider":"aws","service":"ec2","id":"prod","public_ipv4":"10.0.0.1","dns_name":"example.com"}\n'
printf '{"public":true,"provider":"aws","service":"ec2","id":"prod","public_ipv4":"203.0.113.50","dns_name":"legacy-api.example.com"}\n'
printf '{"public":true,"provider":"aws","service":"elb","id":"prod","public_ipv4":"203.0.113.51"}\n'
printf '{"public":false,"provider":"aws","service":"ec2","id":"prod","private_ipv4":"10.9.9.9"}\n'
EOF
run_case cloud --cloudlist "$CLC"
assert_grep  "$MOCKLOG/cloudlist.args" -- "-pc $CLC -json -silent -duc"      "cloudlist runs on the provider config given"
assert_grep  "$CSV.cloud.txt" '^\[cloud\] cloud-asset-unseen \[info\] host=legacy-api\.example\.com provider=aws account=prod service=ec2 scope=in ' "a cloud asset the scan did not find (in scope) -> cloud-asset-unseen"
assert_grep  "$CSV.cloud.txt" 'cloud-asset-unseen \[info\] host=203\.0\.113\.51 provider=aws'                     "an address-only asset the scan did not find"
refute_grep  "$CSV.cloud.txt" 'host=example\.com |10\.9\.9\.9'              "assets the scan found, and internal-only addresses, are not reported"
assert_grep  "$CSV.cloud-assets.tsv" '^aws	prod	ec2	example\.com	10\.0\.0\.1	yes$' "cloud-assets.tsv marks what the scan saw"
bash "$(dirname "$RUN_RECON")/generate-report.sh" "$CSV" -o "$OUTDIR/c.html" >/dev/null 2>&1 || true
assert_grep  "$OUTDIR/c.html" 'Cloud inventory'                           "report: cloud inventory findings listed"
mkdir -p "$TMP/clhome"; HOME="$TMP/clhome" run_case cloud_nocfg --cloudlist
assert_grep  "$ERRLOG" '--cloudlist: no provider config at'                 "no provider config: a clear warning, no run"
rm -f "$MOCKBIN/cloudlist"

# --tld-variants: listed only, with an ownership hint
mk tldfinder <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/tldfinder.args"; echo >> "$MOCKLOG/tldfinder.args"
printf 'example.com\nexample.net\nexample.org\n'
EOF
run_case tld --tld-variants
assert_grep  "$MOCKLOG/tldfinder.args" -- '-d example -dm tld -silent -duc -nc'  "tldfinder looks for the seed's name under other TLDs"
assert_grep  "$CSV.tld-variants.txt" '^\[example\.com\] tld-variant \[info\] host=example\.net of=example\.com same_ns=' "variants listed with the domain they mirror"
refute_grep  "$CSV.tld-variants.txt" 'host=example\.com '                   "the seed's own domain is not a variant"
refute_grep  "$CSV" 'example\.net|example\.org'                             "variants are never scanned or added to the inventory"
rm -f "$MOCKBIN/tldfinder"

# --vulnx: product advisories for the CPEs the inventory holds
mk vulnx <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/vulnx.args"; echo >> "$MOCKLOG/vulnx.args"
case " $* " in
  *"product:nginx"*) printf '{"count":2,"facets":{"is_kev":{"buckets":{"true":1,"false":36}}},"results":[{"cve_id":"CVE-2023-44487","cvss_score":7.5,"epss_score":0.94,"is_kev":true,"is_poc":true,"severity":"high"},{"cve_id":"CVE-2021-23017","cvss_score":7.7,"epss_score":0.53,"severity":"high"}],"total":37}';;
  *) printf '{"count":0,"results":[],"total":0}';;
esac
EOF
run_case vulnx --vulnx
assert_grep  "$MOCKLOG/vulnx.args" -- 'search --json --silent --disable-update-check --no-color -n 10 --sort-desc epss_score .*affected_products\.vendor:f5 && affected_products\.product:nginx' "vulnx asked for the product's CVEs, most likely exploited first"
assert_grep  "$CSV.vulnx.txt" '^\[vulnx\] product-advisories \[info\] host=[^ ]+ product=f5:nginx versions=unknown hosts=[0-9]+ cves=37 kev=1 top=CVE-2023-44487\(kev;epss=0\.94\),CVE-2021-23017\(epss=0\.53\) ' "one advisory line per product: CVE and KEV counts, the top CVEs (versionless CPE: versions=unknown)"
assert_grep  "$CSV.vulnx.tsv" '^f5	nginx	unknown	[0-9]+	CVE-2023-44487	7\.5	0\.94	yes	yes	no$' "vulnx.tsv: one row per CVE"
refute_grep  "$CSV.vulnx.txt" 'product=php:php'                          "a product with no filed CVEs gets no line"
bash "$(dirname "$RUN_RECON")/generate-report.sh" "$CSV" -o "$OUTDIR/v.html" >/dev/null 2>&1 || true
assert_grep  "$OUTDIR/v.html" 'Product advisory \(vulnx\)'                   "report: vulnx advisories counted as context"
rm -f "$MOCKBIN/vulnx"
mk curl <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/curl.args"; echo >> "$MOCKLOG/curl.args"
exit 0
EOF

# --- Batch 4 (B4.1): --scope, --list-targets, --drop-out-of-scope ------------------
section "Batch 4: --scope FILE (fail-closed), --list-targets, --drop-out-of-scope"
SC="$TMP/scopecase"; mkdir -p "$SC"
_rc_is(){ if [ "$1" = "$2" ]; then _pass "$3"; else _fail "$3  [exit $1, want $2]"; fi; }
_none_ran(){ if [ -z "$(ls "$MOCKLOG"/*.args 2>/dev/null)" ]; then _pass "$1"; else _fail "$1  [ran: $(cd "$MOCKLOG" && ls *.args | tr '\n' ' ')]"; fi; }
# the dry run: the plan on stdout, nothing started, no work dir
printf 'example.com\nhttps://www.example.com/x\nfoo bar\n10.0.0.1\n' > "$SC/in1.txt"
rm -f "$MOCKLOG"/*.args; LT="$TMP/out_lt"; rm -rf "$LT"; mkdir -p "$LT"; _rc=0
env PATH="$TESTPATH" HTTPX_BIN=httpx bash "$RUN_RECON" -i "$SC/in1.txt" -D "$LT" --list-targets > "$LT/plan.txt" 2> "$LT/err.txt" || _rc=$?
_rc_is "$_rc" 0                                                              "--list-targets without --scope: exit 0"
assert_grep  "$LT/plan.txt" '^1 +example\.com +domain +in scope'             "--list-targets: each seed with its status"
assert_grep  "$LT/plan.txt" '^2 +www\.example\.com +domain +in scope'        "--list-targets: a URL line is shown as the seed it becomes"
assert_grep  "$LT/plan.txt" '^3 +foo bar +- +INVALID +not a domain'          "--list-targets: an invalid line and why"
assert_grep  "$LT/plan.txt" 'a bare address: write it as 10\.0\.0\.1/32'     "--list-targets: a bare address is invalid, with the fix"
_none_ran                                                                     "--list-targets: no tool is started (nothing is sent)"
if compgen -G "$LT/_work-*" >/dev/null; then _fail "--list-targets: no work dir"; else _pass "--list-targets: no work dir"; fi
# fail closed: an out-of-scope seed, a malformed entry
printf 'example.com\n!api.example.com\n10.0.0.0/24\n' > "$SC/s1.txt"
printf 'example.com\nother.net\n' > "$SC/in2.txt"
rm -f "$MOCKLOG"/*.args; _rc=0
env PATH="$TESTPATH" HTTPX_BIN=httpx bash "$RUN_RECON" -i "$SC/in2.txt" -D "$LT" -o "$LT/r.csv" --scope "$SC/s1.txt" > /dev/null 2> "$LT/err2.txt" || _rc=$?
_rc_is "$_rc" 2                                                              "--scope: an out-of-scope seed stops the run (exit 2)"
assert_grep  "$LT/err2.txt" 'line 2: other\.net: out of scope: no entry covers it' "--scope: the refusal names the seed and the reason"
_none_ran                                                                     "--scope refusal: nothing is sent (no tool started)"
assert_absent "$LT/r.csv"                                                     "--scope refusal: no output"
rm -f "$MOCKLOG"/*.args; _rc=0
env PATH="$TESTPATH" HTTPX_BIN=httpx bash "$RUN_RECON" -i "$SC/in2.txt" -D "$LT" --scope "$SC/s1.txt" --list-targets > "$LT/plan2.txt" 2>&1 || _rc=$?
_rc_is "$_rc" 2                                                              "--list-targets: exit 2 when the run would refuse"
assert_grep  "$LT/plan2.txt" 'would REFUSE to start'                         "--list-targets: says the run would refuse"
assert_grep  "$LT/plan2.txt" '^scope +: .*s1\.txt \(sha256 [0-9a-f]{16}\): 3 entries \(1 name\(s\), 1 range\(s\), 0 ASN\(s\); 1 exclusion\(s\)\)' "--list-targets: the scope file, its hash and a summary"
printf 'example.com\nhttps://x.org/a\n10.0.0.1/8\ncom\n' > "$SC/bad.txt"
_rc=0; env PATH="$TESTPATH" HTTPX_BIN=httpx bash "$RUN_RECON" -i "$SC/in2.txt" -D "$LT" --scope "$SC/bad.txt" > /dev/null 2> "$LT/err3.txt" || _rc=$?
_rc_is "$_rc" 2                                                              "--scope: a malformed scope file stops the run"
assert_grep  "$LT/err3.txt" 'line 2: https://x\.org/a: write a bare name'    "--scope: a URL entry is refused, with its line number"
assert_grep  "$LT/err3.txt" 'line 3: 10\.0\.0\.1/8 has host bits set \(did you mean 10\.0\.0\.0/8\?\)' "--scope: a CIDR with host bits set is refused"
assert_grep  "$LT/err3.txt" 'line 4: com is a whole top-level domain'        "--scope: a whole TLD is refused"
# a default run (no --scope) warns about the lines it ignores (they were dropped silently)
DOMAINS="$SC/in1.txt" run_case ignored --passive-only
assert_grep  "$ERRLOG" 'input: ignored 2 line\(s\): foo bar, 10\.0\.0\.1'   "default run: the ignored input lines are named (once silent)"

# names: exclusions hold, the crawl stays inside, tools that cannot be held are skipped
DOMAINS="$SC/in2.txt" run_case scope_names --scope "$SC/s1.txt" --drop-out-of-scope --subs --crawlers-all --nuclei --takeover
assert_grep  "$ERRLOG" '--scope: skipped line 2: other\.net: out of scope'   "--drop-out-of-scope: the seed is skipped with a warning"
refute_grep  "$CSV" 'other\.net'                                             "--drop-out-of-scope: the skipped seed is not run"
refute_grep  "$CSV" 'api\.example\.com'                                      "--scope: an excluded name (subfinder found it) is not probed or listed"
assert_grep  "$CSV" 'https://www\.example\.com[^,]*,www\.example\.com,'      "--scope: other names under the seed still run"
_ws="$(ls -d "$OUTDIR"/_work-* 2>/dev/null | head -n 1)"
assert_grep  "$_ws/raw/example.com/hosts_all.txt" '^www\.example\.com$'      "takeover candidates: the list the check reads"
refute_grep  "$_ws/raw/example.com/hosts_all.txt" 'api\.example\.com'       "--scope: the excluded name is not a takeover candidate (not probed by subzy/nuclei)"
assert_fgrep "$MOCKLOG/katana.args" '-cs ^https?://(([^/?#@]*\.)?(example\.com))(:[0-9]+)?([/?#]|$)' "--scope: katana follows links only inside the allowed names (-cs)"
assert_fgrep "$MOCKLOG/katana.args" '-cos ^https?://(([^/?#@]*\.)?(api\.example\.com))(:[0-9]+)?([/?#]|$)' "--scope: katana never follows a link to an excluded name (-cos)"
assert_absent "$MOCKLOG/gospider.args"                                       "--scope: gospider (cannot be held to the scope) is skipped"
assert_grep  "$ERRLOG" '--crawlers-all under --scope'                        "--scope: ...with a warning"
assert_grep  "$MOCKLOG/nuclei.args" -- ' -dr( |$)'                            "--scope: nuclei follows no redirects (-dr)"
assert_grep  "$CSV.scope.txt" '^\[scope\] scope-file \[info\] file=.*s1\.txt sha256=[0-9a-f]{64} entries=3 '  "<out>.scope.txt: the scope file and its hash"
assert_grep  "$CSV.scope.txt" '^\[scope\] seed-in-scope \[info\] seed=example\.com kind=domain line=1 entry=example\.com' "<out>.scope.txt: each seed and the entry that allows it"
assert_grep  "$CSV.scope.txt" '^\[scope\] seed-skipped \[info\] seed=other\.net line=2 status=out'  "<out>.scope.txt: the skipped seed"
assert_grep  "$CSV.run.json" '"seeds_out": 1'                                "run.json: the scope record (seeds skipped)"
assert_grep  "$CSV.run.json" '"sha256": "[0-9a-f]{64}"'                      "run.json: the scope file's SHA-256"
assert_grep  "$CSV.run.json" '"input": ".*in2\.txt"'                         "run.json: the input is the file given, not the filtered copy"

# addresses: a name resolving into an excluded range is held back; origin candidates
# outside the allowed ranges are not contacted
cp "$MOCKBIN/dnsx" "$MOCKBIN/dnsx.base"
mk dnsx <<'EOF'
#!/usr/bin/env bash
"$(dirname "$0")/dnsx.base" "$@" | sed -E 's/^(\{"host":"www\.example\.com","a":\[)"10\.0\.0\.1"/\1"10.9.9.9"/'
EOF
# tlsx gets its names in a file: record what each call was given
cp "$MOCKBIN/tlsx" "$MOCKBIN/tlsx.base"
mk tlsx <<'EOF'
#!/usr/bin/env bash
a=("$@"); for i in "${!a[@]}"; do [ "${a[$i]}" = -l ] && cat "${a[$((i+1))]}" >> "$MOCKLOG/tlsx.lists" 2>/dev/null; done
exec "$(dirname "$0")/tlsx.base" "$@"
EOF
printf 'example.com\n!10.9.9.0/24\n' > "$SC/s2.txt"
run_case scope_addr --scope "$SC/s2.txt" --subs --certs --origin
refute_grep  "$CSV" 'www\.example\.com'                                      "--scope: a name resolving into an excluded range is not probed"
assert_grep  "$CSV.scope.txt" 'scope-held-back \[info\] kind=name target=www\.example\.com address=10\.9\.9\.9 note=not contacted: resolves into an excluded range' "<out>.scope.txt: ...and is listed with its address"
assert_grep  "$MOCKLOG/tlsx.lists" '^api\.example\.com$'                      "certificate harvest: the names tlsx was given"
refute_grep  "$MOCKLOG/tlsx.lists" '^www\.example\.com$'                      "--scope: ...not the held-back name (checked before the harvest)"
assert_fgrep "$MOCKLOG/katana.args" '-cs ^https?://(amass-host\.example\.com|api\.example\.com|asset-host\.example\.com|' "--scope with address exclusions: katana crawls only the live hosts already checked"
refute_grep  "$MOCKLOG/katana.args" -- '-cs [^ ]*\[\^/'                      "--scope with address exclusions: ...not any name under the allowed domains"
assert_grep  "$CSV.scope.txt" 'kind=origin-candidate target=10\.0\.0\.1 via=.* note=not contacted: outside the allowed ranges' "--scope: an --origin candidate outside the allowed ranges is held back"
refute_grep  "$MOCKLOG/curl.args" -- '--resolve [^ ]*:10\.0\.0\.1 '          "--scope: ...and never requested"
assert_grep  "$CSV.run.json" '"name": 1'                                     "run.json: what was held back, by kind"
mv "$MOCKBIN/dnsx.base" "$MOCKBIN/dnsx"; mv "$MOCKBIN/tlsx.base" "$MOCKBIN/tlsx"; rm -f "$MOCKLOG/tlsx.lists"

# allowed ranges: candidates inside are verified; internet-scan hits outside are held back;
# a CIDR seed loses its excluded addresses; range-certificate names outside the scope stay out
printf 'example.com\n10.0.0.0/24\n192.0.2.0/24\n!192.0.2.5\n' > "$SC/s3.txt"
printf 'example.com\n192.0.2.0/24\n' > "$SC/in3.txt"
DOMAINS="$SC/in3.txt" run_case scope_ranges --scope "$SC/s3.txt" --origin --favicon
assert_grep  "$MOCKLOG/curl.args" -- '--resolve [^ ]*:10\.0\.0\.1 '           "--scope: an --origin candidate inside an allowed range is verified"
_ws="$(ls -d "$OUTDIR"/_work-* 2>/dev/null | head -n 1)"
assert_grep  "$_ws/raw/example.com/favicon_ips.txt" '^192\.0\.2\.77$'        "--scope: an internet-scan hit inside an allowed range is cert-scanned"
assert_grep  "$CSV.scope.txt" 'kind=internet-scan-hit target=198\.51\.100\.20:8443 note=not contacted: outside the allowed ranges' "--scope: a hit outside the allowed ranges is held back"
refute_grep  "$_ws/raw/example.com/favicon_hits_hp.txt" '198\.51\.100\.20'   "--scope: ...and not cert-scanned"
assert_grep  "$_ws/cidrs.txt" '^192\.0\.2\.4/32$'                             "--scope: a CIDR seed is swept without its excluded address"
refute_grep  "$_ws/cidrs.txt" '^192\.0\.2\.0/24$|^192\.0\.2\.5/'              "--scope: ...the excluded address is not in the sweep"
assert_grep  "$CSV.scope.txt" '^\[ranges\] scope-held-back \[info\] kind=range-certificate-name target=sneaky\.otherdomain\.com ' "--scope: a range-certificate name outside the scope is not made a seed"
refute_grep  "$CSV" 'sneaky\.otherdomain\.com'                               "--scope: ...and not scanned"
assert_grep  "$CSV" 'assets\.example\.com'                                   "--scope: a range-certificate name inside the scope is"

# the screenshot browser: held to this seed's names; gowitness cannot be, so it is skipped
run_case scope_ss --scope "$SC/s1.txt" --screenshots
assert_grep  "$MOCKLOG/httpx.args" -- '--host-resolver-rules=MAP [^ ]+ 10\.0\.0\.1, .*MAP \* ~NOTFOUND' "--scope: the browser resolves only this seed's names (MAP * ~NOTFOUND for the rest)"
SCREENSHOT_TOOL=gowitness run_case scope_gw --scope "$SC/s1.txt" --screenshots
assert_absent "$MOCKLOG/gowitness.args"                                      "--scope: gowitness (no resolver rules) is not used"
assert_grep  "$ERRLOG" '--screenshots under --scope needs httpx and dnsx'     "--scope: ...with a warning"

# MTA-STS: the policy is fetched only from an in-scope name
printf 'example.com\n!mta-sts.example.com\n' > "$SC/s4.txt"
MOCK_POSTURE=bad run_case scope_posture --scope "$SC/s4.txt" --dns-posture
refute_grep  "$MOCKLOG/curl.args" 'mta-sts\.example\.com'                     "--scope: the MTA-STS policy is not fetched from an excluded name"
assert_grep  "$CSV.dnsposture.tsv" 'policy not fetched: mta-sts\.example\.com is outside --scope' "--scope: ...the posture table says why"

# --- Batch 4 (B4.2): SHA-256 manifest of the run's outputs --------------------------
section "Batch 4: <out>.manifest.sha256 (sha256sum -c format, this run's files only)"
MF="$TMP/out_manifest"; rm -rf "$MF"; mkdir -p "$MF"
printf 'from an earlier run\n' > "$MF/r.csv.zone.txt"; touch -d '2020-01-01 00:00:00' "$MF/r.csv.zone.txt"
rm -f "$MOCKLOG"/*.args
timeout 25 env PATH="$TESTPATH" HTTPX_BIN=httpx SECLISTS="$SECLISTS_TEST" RECON_CLOUD_CACHE="$MF/cloud_ranges.tsv" TLS_CHAIN_CHECK=0 \
  bash "$RUN_RECON" -i "$DOMAINS" -D "$MF" -o "$MF/r.csv" --tls --screenshots > /dev/null 2> "$MF/stderr.log" || true
M="$MF/r.csv.manifest.sha256"
assert_exists "$M"                                                           "the run writes <out>.manifest.sha256"
assert_grep  "$M" '^[0-9a-f]{64}  r\.csv$'                                   "manifest: the CSV, by a path relative to its directory"
assert_grep  "$M" '^[0-9a-f]{64}  r\.csv\.run\.json$'                        "manifest: run.json"
assert_grep  "$M" '^[0-9a-f]{64}  r\.csv\.report\.html$'                     "manifest: the report"
assert_grep  "$M" '^[0-9a-f]{64}  screenshots-[0-9-]+/'                      "manifest: the screenshots"
refute_grep  "$M" 'manifest\.sha256'                                         "manifest: not itself"
refute_grep  "$M" 'r\.csv\.zone\.txt'                                        "manifest: an older file with the same prefix (another run) is left out"
assert_grep  "$MF/stderr.log" 'manifest: 1 older file\(s\) named like this run.s outputs were left out .*: r\.csv\.zone\.txt' "manifest: ...and named in a warning"
if ( cd "$MF" && sha256sum --quiet -c r.csv.manifest.sha256 ) >/dev/null 2>&1; then _pass "manifest: sha256sum -c verifies the set"; else _fail "manifest: sha256sum -c verifies the set"; fi
printf 'x' >> "$MF/r.csv.run.json"
if ( cd "$MF" && sha256sum --quiet -c r.csv.manifest.sha256 ) >/dev/null 2>&1; then _fail "manifest: a changed file fails the check"; else _pass "manifest: a changed file fails the check"; fi

# --- Batch 4 (B4.3, B4.4): field-by-field changes and history ---------------------
section "Batch 4: recon-db.sh diff / changes / history, --monitor -> <out>.delta.tsv"
RDB="$(dirname "$RUN_RECON")/recon-db.sh"
DL="$TMP/delta"; rm -rf "$DL"; mkdir -p "$DL/runs"
H='seed_domain,url,host,sources,status_code,content_length,webserver,title,technologies,ip,asn,asn_org,tls_version,cert_not_after,tls_flags,cpe'
{ echo "$H"
  echo 'example.com,https://example.com/,example.com,live,200,10,nginx,Home,Nginx;PHP,10.0.0.1,AS1,One,tls13,2030-01-01,,cpe:a'
  echo 'example.com,https://example.com/a,example.com,katana,200,10,nginx,A,,10.0.0.1,AS1,One,,,,'
  echo 'example.com,https://old.example.com,old.example.com,subfinder,200,5,apache,Old,,10.0.0.2,AS1,One,tls12,2027-01-01,,'
  echo 'example.com,https://cdn.example.com,cdn.example.com,subfinder,200,5,cloudflare,CDN,,104.16.0.1,AS13335,Cloudflare,tls13,2027-01-01,,'
  echo 'example.com,https://moved.example.com,moved.example.com,subfinder,200,5,nginx,M,,10.0.0.3,AS1,One,tls13,2027-01-01,,'
  echo 'other.org,https://other.org,other.org,live,200,5,iis,O,,10.1.0.1,AS2,Two,,,,'
} > "$DL/runs/recon-20261101-000000.csv"
{ echo "$H"
  echo 'example.com,https://example.com/,example.com,live,200,10,nginx,Home,PHP;Nginx,10.0.0.9,AS1,One,tls13,2031-01-01,CertExpiring,cpe:a'
  echo 'example.com,https://example.com:8443/,example.com,naabu,401,0,caddy,,,10.0.0.1,AS1,One,tls13,2031-01-01,,'
  echo 'example.com,https://cdn.example.com,cdn.example.com,subfinder,200,5,cloudflare,CDN,,104.16.0.2,AS13335,Cloudflare,tls13,2027-01-01,,'
  echo 'example.com,https://moved.example.com,moved.example.com,subfinder,200,5,nginx,M,,203.0.113.7,AS9,Nine,tls13,2027-01-01,,'
  echo 'new.org,https://new.org,new.org,live,200,5,iis,N,,10.2.0.1,AS2,Two,,,,'
} > "$DL/runs/recon-20261102-000000.csv"
env PATH="$TESTPATH" bash "$RDB" diff "$DL/runs/recon-20261101-000000.csv" "$DL/runs/recon-20261102-000000.csv" -o "$DL/d.tsv" 2> "$DL/d.err"
D="$DL/d.tsv"
assert_grep  "$D" '^change	seed	service	field	old	new$'                    "diff: a TSV with a header"
assert_grep  "$D" '^changed	example\.com	https://example\.com	cert_not_after	2030-01-01	2031-01-01$' "diff: a field that changed, old and new (the root URL's row speaks for the service)"
assert_grep  "$D" '^changed	example\.com	https://example\.com	tls_flags		CertExpiring$' "diff: a TLS flag that appeared (TLS ran in both runs, judged by tls_version)"
refute_grep  "$D" '	technologies	'                                        "diff: multi-valued fields compare as sets (order is not a change)"
refute_grep  "$D" 'https://example\.com	ip	|cdn\.example\.com	ip	'           "diff: an address change inside the same ASN is not reported (CDN, round robin)"
assert_grep  "$D" '^changed	example\.com	https://moved\.example\.com	ip	10\.0\.0\.3	203\.0\.113\.7$' "diff: an address change to another network is"
assert_grep  "$D" '^changed	example\.com	https://moved\.example\.com	asn	AS1	AS9$' "diff: ...and the ASN change"
assert_grep  "$D" '^new	example\.com	https://example\.com:8443			401$'     "diff: a new service (scheme://host:port)"
assert_grep  "$D" '^removed	example\.com	https://old\.example\.com		200 Old	$'   "diff: a removed service"
refute_grep  "$D" 'other\.org|new\.org'                                     "diff: seeds that only one run covered are not compared"
refute_grep  "$D" 'https://example\.com/a'                                  "diff: crawled URLs are not services (the unit is scheme://host:port)"
assert_grep  "$DL/d.err" 'diff: 1 new, 1 removed, 2 changed service\(s\) \(4 field change\(s\)\); seeds only in .*: other\.org; seeds only in .*: new\.org' "diff: the summary"
# a stage that was off in one run is not a change
cut -d, -f1-12 "$DL/runs/recon-20261101-000000.csv" > "$DL/notls.csv"
env PATH="$TESTPATH" bash "$RDB" diff "$DL/notls.csv" "$DL/runs/recon-20261102-000000.csv" -o "$DL/d2.tsv" 2>/dev/null
refute_grep  "$DL/d2.tsv" '	(tls_version|cert_not_after|tls_flags|cpe)	'     "diff: fields one run did not collect are not compared"
# history and change events over a directory of run CSVs (no DB)
sed 's/,Home,/,Home v2,/' "$DL/runs/recon-20261102-000000.csv" > "$DL/runs/recon-20261103-000000.csv"
env PATH="$TESTPATH" bash "$RDB" changes --csv "$DL/runs" > "$DL/c.tsv" 2>&1
assert_grep  "$DL/c.tsv" '^run_ts	seed	service	change	field	old	new$'          "changes --csv: a TSV"
assert_grep  "$DL/c.tsv" '^20261102-000000	example\.com	https://old\.example\.com	removed	'  "changes --csv: each event with the run it was seen in"
assert_grep  "$DL/c.tsv" '^20261103-000000	example\.com	https://example\.com	changed	title	Home	Home v2$' "changes --csv: events between every pair of consecutive runs"
env PATH="$TESTPATH" bash "$RDB" changes example.com:8443 --csv "$DL/runs" > "$DL/c2.tsv" 2>&1
assert_grep  "$DL/c2.tsv" 'https://example\.com:8443	new'                    "changes PATTERN: filters by service (a port works)"
refute_grep  "$DL/c2.tsv" 'old\.example\.com'                                 "changes PATTERN: ...and leaves the others out"
env PATH="$TESTPATH" bash "$RDB" changes --since 20261102-000000 --csv "$DL/runs" > "$DL/c3.tsv" 2>&1
refute_grep  "$DL/c3.tsv" '^20261102-000000'                                  "changes --since TS: only the runs after TS"
env PATH="$TESTPATH" bash "$RDB" history --csv "$DL/runs" > "$DL/h.tsv" 2>&1
assert_grep  "$DL/h.tsv" '^example\.com	https://old\.example\.com	20261101-000000	20261101-000000	1	3	gone since 20261102-000000	200 Old$' "history: first/last seen, runs seen of the seed's runs, gone since"
assert_grep  "$DL/h.tsv" '^example\.com	https://example\.com	20261101-000000	20261103-000000	3	3	present	200 Home v2$' "history: a present service and its latest state"
# the store: schema migration, the run's seeds and columns, history queries
mk psql <<'PSQLEOF'
#!/usr/bin/env bash
sql="$(cat 2>/dev/null)"; printf 'ARGS: %s\nSQL: %s\n' "$*" "$sql" >> "$MOCKLOG/psql.args"
case "$*" in
  *"SELECT 1"*) echo 1;;
  *"COPY (SELECT run_ts, seed_domain, url"*) cat "$MOCK_PG/rows.csv";;
  *"bool_or"*) cat "$MOCK_PG/ran.csv";;
  *"FROM recon_runs UNION ALL"*) cat "$MOCK_PG/seeds.csv";;
esac
exit 0
PSQLEOF
MOCK_PG="$DL/pg"; mkdir -p "$MOCK_PG"
F=status_code,title,webserver,technologies,cpe,redirect_location,auth,http_flags,missing_sec_headers,ip,ipv6,asn,tls_version,cert_not_after,cert_issuer,tls_flags,favicon_mmh3
{ echo "run_ts,seed_domain,url,$F"
  echo '20261001-000000,example.com,https://example.com/,200,Home,nginx,Nginx,,,,,,10.0.0.1,,AS1,,,,,'
  echo '20261101-000000,example.com,https://example.com/,200,Home,nginx,Nginx,cpe:a,,,,,10.0.0.1,,AS1,tls13,2030-01-01,,,'
  echo '20261102-000000,example.com,https://example.com/,200,Home,nginx,Nginx,cpe:a,,,,,10.0.0.1,,AS1,tls13,2031-01-01,,,'
} > "$MOCK_PG/rows.csv"
{ echo "run_ts,$F"
  echo '20261001-000000,t,t,t,t,f,f,f,f,f,t,f,t,f,f,f,f,f'
  echo '20261101-000000,t,t,t,t,t,f,f,f,f,t,f,t,t,t,f,f,f'
  echo '20261102-000000,t,t,t,t,t,f,f,f,f,t,f,t,t,t,f,f,f'
} > "$MOCK_PG/ran.csv"
{ echo 'run_ts,seeds,cols'
  echo '20261101-000000,example.com,status_code;title;webserver;technologies;cpe;ip;asn;tls_version;cert_not_after'
  echo '20261102-000000,example.com,status_code;title;webserver;technologies;cpe;ip;asn;tls_version;cert_not_after'
  echo '20261001-000000,example.com,'
} > "$MOCK_PG/seeds.csv"
rm -f "$MOCKLOG/psql.args"
env PATH="$TESTPATH" MOCK_PG="$MOCK_PG" RECON_DB_ENV=/nonexistent RECON_DB_DSN=postgresql://mock/recon bash "$RDB" changes > "$DL/dbc.tsv" 2>&1
assert_grep  "$DL/dbc.tsv" '^20261102-000000	example\.com	https://example\.com	changed	cert_not_after	2030-01-01	2031-01-01$' "changes (store): events from the stored runs"
refute_grep  "$DL/dbc.tsv" '	cpe	'                                            "changes (store): a run stored before 1.20 had no cpe column, so cpe is not compared with it"
assert_grep  "$MOCKLOG/psql.args" 'ADD COLUMN IF NOT EXISTS cpe text'            "store: the schema gains the compared columns (existing stores are migrated)"
rm -f "$MOCKLOG/psql.args"
printf 'example.com\nexample.net\n' > "$DL/seeds.txt"
env PATH="$TESTPATH" RECON_DB_ENV=/nonexistent RECON_DB_DSN=postgresql://mock/recon bash -c '. "$1"; db_load_csv "$2" 20261105-000000 "$3"' _ "$RDB" "$DL/runs/recon-20261102-000000.csv" "$DL/seeds.txt" > /dev/null 2>&1
assert_grep  "$MOCKLOG/psql.args" "INSERT INTO recon_runs \(run_ts, seeds, cols\) VALUES \('20261105-000000', 'example\.com;example\.net', 'status_code;title;webserver;technologies;cpe;ip;asn;tls_version;cert_not_after;tls_flags'\)" "store: each run records the seeds it covered and the columns its CSV had"
assert_grep  "$MOCKLOG/psql.args" 'tls_flags, favicon_mmh3\)'                   "store: the compared fields are loaded"
rm -f "$MOCKBIN/psql"
# --monitor: the delta next to new-assets, in run.json and in the report
run_case mon_a
cp "$CSV" "$TMP/mon_prev.csv"
run_case mon_b --subs --monitor --monitor-prev "$TMP/mon_prev.csv"
assert_exists "$CSV.delta.tsv"                                               "--monitor: <out>.delta.tsv"
assert_grep  "$CSV.delta.tsv" '^new	example\.com	https://api\.example\.com	'   "--monitor: a service found this time is new"
assert_grep  "$ERRLOG" 'Changes +: [0-9]+ new, 0 removed, 0 changed service\(s\) \(0 field change\(s\)\) vs mon_prev\.csv' "--monitor: the change summary"
assert_grep  "$CSV.run.json" '"delta_changes": [1-9]'                        "run.json: the number of changes"
assert_grep  "$CSV.report.html" 'id="changes">Changes since the previous run' "report: a Changes section"
assert_grep  "$CSV.manifest.sha256" '  r\.csv\.delta\.tsv$'                    "manifest: the delta is covered"
# --monitor with --db: probe results are measured afresh (the cache would hide a change), and stored
mk psql <<'PSQLEOF'
#!/usr/bin/env bash
sql=""; A=("$@"); i=0
while [ $i -lt ${#A[@]} ]; do case "${A[$i]}" in -c) i=$((i+1)); sql="${A[$i]}";; esac; i=$((i+1)); done
[ -z "$sql" ] && sql="$(cat 2>/dev/null)"
printf 'SQL: %s\n' "$sql" >> "$MOCKLOG/psql.args"
case "$sql" in "SELECT 1") echo 1;; esac
exit 0
PSQLEOF
run_case mon_db --db --monitor --monitor-prev "$TMP/mon_prev.csv"
refute_grep  "$MOCKLOG/psql.args" "c\.source = 'live_probe'"                   "--monitor --db: the live probe is not read from the cache"
refute_grep  "$MOCKLOG/psql.args" "c\.source = 'httpx_json_v3'"                "--monitor --db: nor the enrichment records"
assert_grep  "$MOCKLOG/psql.args" "'live_probe'"                                "--monitor --db: the fresh probe results are still stored"
assert_grep  "$MOCKLOG/psql.args" "source='urls'"                               "--monitor --db: passive lookups still use the cache"
run_case nomon_db --db
assert_grep  "$MOCKLOG/psql.args" "c\.source = 'live_probe'"                   "--db without --monitor: the live probe cache is read (unchanged)"
rm -f "$MOCKBIN/psql"

# --- Batch 4 (B4.5): an interrupted run keeps its work dir; --resume continues it -----
section "Batch 4: SIGTERM/SIGINT stop the run and keep its work; --resume skips the finished seeds"
RS="$TMP/resume"; rm -rf "$RS"; mkdir -p "$RS/out" "$RS/full"
printf 'example.com\nslow.example.org\n' > "$RS/in.txt"
cp "$MOCKBIN/gau" "$MOCKBIN/gau.base"
mk gau <<'EOF'
#!/usr/bin/env bash
in="$(cat)"; printf '%s\n' "$in" >> "$MOCKLOG/gau.seeds"
case "$in" in *slow.example.org*) [ -e "$MOCKLOG/gau.hang" ] && exec sleep 61.5;; esac
printf '%s\n' "$in" | exec "$(dirname "$0")/gau.base" "$@"
EOF
_rr(){ # <outdir> <stderr> [args...]: the run-recon command line the resume tests repeat
  local o="$1" e="$2"; shift 2
  env PATH="$TESTPATH" HTTPX_BIN=httpx SECLISTS="$SECLISTS_TEST" RECON_CLOUD_CACHE="$RS/cloud.tsv" TLS_CHAIN_CHECK=0 \
    bash "$RUN_RECON" -i "$RS/in.txt" -D "$o" -o "$o/r.csv" -t 1 --no-report "$@" > /dev/null 2> "$e"
}
_rr_bg(){ # the same, in the background: exec, so $! is run-recon itself
  local o="$1" e="$2"; shift 2
  exec env PATH="$TESTPATH" HTTPX_BIN=httpx SECLISTS="$SECLISTS_TEST" RECON_CLOUD_CACHE="$RS/cloud.tsv" TLS_CHAIN_CHECK=0 \
    bash "$RUN_RECON" -i "$RS/in.txt" -D "$o" -o "$o/r.csv" -t 1 --no-report "$@" > /dev/null 2> "$e"
}
_wait_hang(){ local _; for _ in $(seq 1 150); do grep -q slow "$MOCKLOG/gau.seeds" 2>/dev/null && compgen -G "$1/_work-*/done/example.com" >/dev/null && return 0; sleep 0.2; done; return 1; }
# the reference: the same run, never interrupted
rm -f "$MOCKLOG/gau.hang"; _rr "$RS/full" "$RS/full.err" || true
# run 1: stopped by SIGTERM while the second seed runs
: > "$MOCKLOG/gau.hang"; rm -f "$MOCKLOG/gau.seeds"
_rr_bg "$RS/out" "$RS/err1.txt" & RP=$!
_wait_hang "$RS/out" && sleep 0.5
_rc=0; _rr "$RS/out" "$RS/err0.txt" --resume || _rc=$?
_rc_is "$_rc" 2                                                             "--resume while the run is still running: refused (its work dir is locked)"
assert_grep  "$RS/err0.txt" 'is still running \(its lock is held\)'         "--resume while it runs: ...and why"
kill -TERM "$RP" 2>/dev/null; _rc=0; wait "$RP" || _rc=$?
_rc_is "$_rc" 143                                                           "SIGTERM: the run stops with exit 143"
W="$(ls -d "$RS/out"/_work-* 2>/dev/null | head -n 1)"
_rsid="$(sed -n 's/^run_id=//p' "$W/state" 2>/dev/null)"
assert_grep  "$W/state" '^status=interrupted$'                               "SIGTERM: the work dir is kept and marked interrupted"
assert_grep  "$W/state" '^args_sha256=[0-9a-f]{64}$'                         "state: a hash of the command line (no values)"
if [ -e "$W/done/example.com" ] && [ -s "$W/parts/map.example.com.tsv" ]; then _pass "SIGTERM: the finished seed's work is there"; else _fail "SIGTERM: the finished seed's work is there"; fi
assert_grep  "$RS/err1.txt" 'run the same command again with --resume' "SIGTERM: the message says how to resume"
sleep 0.5
if pgrep -f 'sleep 61\.5' >/dev/null; then _fail "SIGTERM: the stages the run started are stopped too"; pkill -f 'sleep 61\.5'; else _pass "SIGTERM: the stages the run started are stopped too"; fi
assert_absent "$RS/out/r.csv"                                                "SIGTERM: no partial CSV"
# another command line is not resumed
_rc=0; _rr "$RS/out" "$RS/err2.txt" --subs --resume || _rc=$?
_rc_is "$_rc" 2                                                             "--resume with other options: refused (exit 2)"
assert_grep  "$RS/err2.txt" 'no interrupted run in .* was started with this command line' "--resume with other options: ...and why"
# run 2: --resume
rm -f "$MOCKLOG/gau.hang" "$MOCKLOG/gau.seeds"
_rc=0; _rr "$RS/out" "$RS/err3.txt" --resume || _rc=$?
_rc_is "$_rc" 0                                                             "--resume: the run finishes"
assert_grep  "$RS/err3.txt" '--resume \(session 2\): 1 of 2 seed\(s\) had finished'  "--resume: the finished seed is kept"
refute_grep  "$MOCKLOG/gau.seeds" '^example\.com$'                           "--resume: the finished seed is not run again"
assert_grep  "$MOCKLOG/gau.seeds" '^slow\.example\.org$'                     "--resume: the interrupted seed runs again"
if diff <(sort "$RS/full/r.csv") <(sort "$RS/out/r.csv") >/dev/null 2>&1; then _pass "--resume: the CSV equals the uninterrupted run's"; else _fail "--resume: the CSV equals the uninterrupted run's"; fi
assert_grep  "$RS/out/r.csv.run.json" '"sessions": 2'                        "run.json: two sessions"
assert_grep  "$RS/out/r.csv.run.json" '"seeds_resumed": 1'                   "run.json: one seed carried over"
if [ -n "$_rsid" ] && grep -q "\"run_id\": \"$_rsid\"" "$RS/out/r.csv.run.json"; then _pass "--resume keeps the run_id (Tideline sees one run)"; else _fail "--resume keeps the run_id  [state: ${_rsid:-none}]"; fi
_rc=0; _rr "$RS/out" "$RS/err4.txt" --resume || _rc=$?
_rc_is "$_rc" 2                                                             "--resume after the run finished: nothing to resume (exit 2)"
# SIGINT (Ctrl-C) works the same way (here with SIGINT restored to its default: a script's
# background job starts with it ignored)
rm -rf "$RS/out2"; mkdir -p "$RS/out2"; : > "$MOCKLOG/gau.hang"; rm -f "$MOCKLOG/gau.seeds"
env PATH="$TESTPATH" HTTPX_BIN=httpx SECLISTS="$SECLISTS_TEST" RECON_CLOUD_CACHE="$RS/cloud.tsv" TLS_CHAIN_CHECK=0 \
  python3 -c 'import os, signal, sys; signal.signal(signal.SIGINT, signal.SIG_DFL); os.execvp("bash", ["bash"] + sys.argv[1:])' \
  "$RUN_RECON" -i "$RS/in.txt" -D "$RS/out2" -o "$RS/out2/r.csv" -t 1 --no-report > /dev/null 2> "$RS/err5.txt" & RP=$!
_wait_hang "$RS/out2" && sleep 0.5
kill -INT "$RP" 2>/dev/null; _rc=0; wait "$RP" || _rc=$?
_rc_is "$_rc" 130                                                           "SIGINT: the run stops with exit 130"
assert_grep  "$(ls -d "$RS/out2"/_work-* | head -n 1)/state" '^status=interrupted$' "SIGINT: the work dir is kept"
sleep 0.5; pkill -f 'sleep 61\.5' 2>/dev/null || true
rm -f "$MOCKLOG/gau.hang" "$MOCKLOG/gau.seeds"; mv "$MOCKBIN/gau.base" "$MOCKBIN/gau"

# --- v1.20 (Batch 5): redirect chains, login forms, the TLS version matrix, the leaf
# certificate, CPE aliases ---------------------------------------------------------------
section "Batch 5: redirect chains and login forms (aggregator, no requests)"
B5D="$TMP/b5"; rm -rf "$B5D"; mkdir -p "$B5D"
awk "/python3 - .*map.tsv.*<<'PY'/{f=1;next} f&&/^PY\$/{f=0} f" "$RUN_RECON" > "$B5D/agg.py"
printf 'ex.com\thttp://r.ex.com/\tgau\nex.com\thttps://r.ex.com/\tgau\nex.com\thttps://r.ex.com/old\tgau\nex.com\thttps://loop.ex.com/a\tgau\nex.com\thttps://loop.ex.com/b\tgau\nex.com\thttp://p.ex.com/\tgau\nex.com\thttps://s.ex.com/\tgau\nex.com\thttps://n.ex.com/\tgau\nex.com\thttps://q.ex.com/\tgau\n' > "$B5D/map.tsv"
python3 - "$B5D" <<'PYB5'
import json, sys, os
d = sys.argv[1]
def rec(u, st, loc="", ex=None):
    j = {"input": u, "url": u, "status_code": st, "content_type": "text/html", "header": {"content_type": "text/html"}}
    if loc:
        j["location"] = loc; j["header"]["location"] = loc
    if ex is not None:
        j["extracts"] = {"re": ex}
    return json.dumps(j)
pw = '<input type="password'
with open(os.path.join(d, "httpx.jsonl"), "w") as f:
    for line in (rec("http://r.ex.com/", 301, "https://r.ex.com/"), rec("https://r.ex.com/", 302, "/login"),
                 rec("https://r.ex.com/old", 301, "https://other.ex.net/x#frag"),
                 rec("https://loop.ex.com/a", 302, "/b"), rec("https://loop.ex.com/b", 302, "/a"),
                 rec("http://p.ex.com/", 200, ex=['<form method="post">', pw]),
                 rec("https://s.ex.com/", 200, ex=['<form action="/search">', '<FORM method=post action=\'/login?a=1&amp;b=2\'>', pw]),
                 rec("https://n.ex.com/", 302, "/next"),
                 rec("https://q.ex.com/", 200, ex=['<form action="/search">'])):
        f.write(line + "\n")
with open(os.path.join(d, "hops.jsonl"), "w") as f:   # what --extras fetched
    f.write(rec("https://r.ex.com/login", 200, ex=['<form method="post" action="http://r.ex.com/session">', pw]) + "\n")
PYB5
: > "$B5D/tlsx.jsonl"
( cd "$B5D" && env PATH="$TESTPATH" HOPS_FILE="$B5D/hops.jsonl" python3 agg.py map.tsv httpx.jsonl out.csv 0 2000 tlsx.jsonl >/dev/null 2>"$B5D/agg.err" )
b5col(){ python3 - "$1" "$2" "$3" <<'PYCOL'
import csv, sys
for r in csv.DictReader(open(sys.argv[1], newline="")):
    if r["url"] == sys.argv[2]:
        print(r.get(sys.argv[3], "")); break
PYCOL
}
b5eq(){ local got; got="$(b5col "$B5D/out.csv" "$1" "$2")"; if [ "$got" = "$3" ]; then _pass "$4"; else _fail "$4 (got: $got)"; fi; }
b5eq http://r.ex.com/ final_url 'https://r.ex.com/login' "http:// -> https:// -> /login: final_url is the last URL that answered (a hop --extras fetched)"
b5eq http://r.ex.com/ redirect_chain '301->https://r.ex.com/ | 302->https://r.ex.com/login' "redirect_chain: code->absolute URL per hop, joined ' | '"
b5eq http://r.ex.com/ login_form 'http://r.ex.com/session' "login_form: the password form of the page the chain ends on, made absolute"
b5eq http://r.ex.com/ http_flags 'CleartextAuth' "a form on an HTTPS page that posts to http:// -> CleartextAuth"
b5eq http://r.ex.com/ auth 'Form' "auth gains Form for a password form (WebInventory's Auth=Form)"
b5eq https://r.ex.com/old redirect_chain '301->https://other.ex.net/x' "an off-host hop is listed (fragment dropped) ..."
b5eq https://r.ex.com/old final_url 'https://r.ex.com/old' "... and not followed: final_url stays the last URL that answered"
b5eq https://loop.ex.com/a redirect_chain '302->https://loop.ex.com/b | 302->https://loop.ex.com/a' "a redirect loop stops when it comes back"
b5eq https://n.ex.com/ redirect_chain '302->https://n.ex.com/next' "a hop nobody fetched is listed ..."
b5eq https://n.ex.com/ final_url 'https://n.ex.com/' "... and the chain ends at the last URL that answered"
b5eq http://p.ex.com/ login_form 'http://p.ex.com/' "a form without action posts to its own page"
b5eq http://p.ex.com/ http_flags 'PlainHttp;CleartextAuth' "a password form on a plain-HTTP page -> CleartextAuth (after PlainHttp)"
b5eq https://s.ex.com/ login_form 'https://s.ex.com/login?a=1&b=2' "the form before the password field wins (not the search form); entities decoded"
b5eq https://s.ex.com/ http_flags '' "an HTTPS form posting to HTTPS is not cleartext"
b5eq https://q.ex.com/ auth '' "a form without a password field is not a login form"
b5eq https://q.ex.com/ final_url '' "a URL that does not redirect has no final_url or chain"
assert_absent "$B5D/agg.err" "the aggregator ran without errors"

section "Batch 5: --extras fetches same-host redirect hops; the login form joins the redirecting row"
MOCK_HTTPX_REDIRECT='https://example.com/katana-path>/portal/login' MOCK_HTTPX_LOGIN='https://example.com/portal/login' run_case b5hops --extras
assert_grep  "$MOCKLOG/httpx.args" -- "-er (\(\?is\)|[^ ]*)<form" "the enrichment request carries the login-form regex (-er)"
assert_grep  "$ERRLOG" 'redirect hops: 1 same-host target\(s\) fetched' "the one hop the run had not probed is fetched"
assert_grep  "$CSV" ',https://example\.com/katana-path,.*,https://example\.com/portal/login,302->https://example\.com/portal/login,http://example\.com/session,' "the redirecting row: final_url, redirect_chain, login_form"
assert_grep  "$CSV" ',https://example\.com/katana-path,.*,Form,.*CleartextAuth' "... with Form in auth and CleartextAuth"
refute_grep  "$CSV" ',https://example\.com/portal/login,example\.com,' "a hop is evidence for its chain, not a URL row of its own"
MOCK_HTTPX_REDIRECT='https://example.com/katana-path>https://elsewhere.example.net/' run_case b5offhost --extras
refute_grep  "$ERRLOG" 'redirect hops:'                              "an off-host target is never fetched"
assert_grep  "$CSV" ',302->https://elsewhere\.example\.net/,'        "... but it is listed in the chain"
MOCK_HTTPX_REDIRECT='https://example.com/katana-path>/portal/login' run_case b5nohops
refute_grep  "$ERRLOG" 'redirect hops'                               "without --extras no hop is fetched"

section "Batch 5: the TLS version matrix (tls_enum_probe) against a local TLS speaker"
# (not enum.py: a file of that name next to a script shadows the stdlib's enum module)
awk "/^# TLSENUM-PROBE/{f=1} f&&/^PYENUM\$/{f=0} f" "$RUN_RECON" > "$B5D/tlsenum_probe.py"
python3 - "$B5D/port" <<'PYTLS' &
# Answers each ClientHello with a ServerHello and closes: "legacy" on the first port (TLS 1.0-1.2,
# server preference ECDHE-RSA-AES128-SHA, AES128-SHA, then NULL-SHA), "modern" on the second
# (TLS 1.2 + 1.3). No key exchange: the probe stops at the ServerHello.
import socket, struct, sys, os, threading
def hello(conn):
    try:
        h = conn.recv(5)
        if len(h) < 5: return None
        body = b""
        n = (h[3] << 8) | h[4]
        while len(body) < n:
            c = conn.recv(n - len(body))
            if not c: return None
            body += c
        d = body[4:]
        ver = (d[0] << 8) | d[1]; q = 34; q += 1 + d[q]
        cl = (d[q] << 8) | d[q + 1]; suites = [(d[q + 2 + i] << 8) | d[q + 3 + i] for i in range(0, cl, 2)]; q += 2 + cl
        q += 1 + d[q]
        sv = []
        if q + 2 <= len(d):
            e = q + 2 + ((d[q] << 8) | d[q + 1]); q += 2
            while q + 4 <= e:
                t, l = (d[q] << 8) | d[q + 1], (d[q + 2] << 8) | d[q + 3]
                if t == 0x002b: sv = [(d[q + 5 + i] << 8) | d[q + 6 + i] for i in range(0, d[q + 4], 2)]
                q += 4 + l
        return ver, suites, sv
    except Exception:
        return None
def server_hello(ver, suite, tls13=False):
    ext = (struct.pack(">HHH", 0x002b, 2, 0x0304)) if tls13 else b""
    b = struct.pack(">H", 0x0303 if tls13 else ver) + os.urandom(32) + b"\x00" + struct.pack(">H", suite) + b"\x00"
    b += struct.pack(">H", len(ext)) + ext
    hs = b"\x02" + struct.pack(">I", len(b))[1:] + b
    return b"\x16" + struct.pack(">H", 0x0303 if tls13 else ver) + struct.pack(">H", len(hs)) + hs
ALERT = lambda code: b"\x15\x03\x03\x00\x02\x02" + bytes([code])
def legacy(ver, suites, sv):
    if ver < 0x0301: return ALERT(70)
    v = min(ver, 0x0303)
    for s in (0xC013, 0x002F, 0x0002):
        if s in suites: return server_hello(v, s)
    return ALERT(40)
def modern(ver, suites, sv):
    if 0x0304 in sv: return server_hello(0x0303, 0x1301, tls13=True)
    if ver < 0x0303: return ALERT(70)
    return server_hello(0x0303, 0xC02F) if 0xC02F in suites else ALERT(40)
socks = []
for prof in (legacy, modern):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 0)); s.listen(16); s.settimeout(20)
    socks.append((s, prof))
open(sys.argv[1], "w").write(" ".join(str(s.getsockname()[1]) for s, _ in socks))
def serve(s, prof):
    for _ in range(6):
        try:
            c, _a = s.accept()
        except Exception:
            return
        r = hello(c)
        if r: c.sendall(prof(*r))
        c.close()
ts = [threading.Thread(target=serve, args=x) for x in socks]
[t.start() for t in ts]; [t.join() for t in ts]
PYTLS
_tsrv=$!
for _i in $(seq 1 20); do [ -s "$B5D/port" ] && break; sleep 0.2; done
read -r LPORT MPORT < "$B5D/port"
printf 'legacy.test:%s\nmodern.test:%s\nnoaddr.test:443\n' "$LPORT" "$MPORT" > "$B5D/keys.txt"
printf '{"host":"legacy.test","port":"%s","ip":"127.0.0.1"}\n{"host":"modern.test","port":"%s","ip":"127.0.0.1"}\n{"host":"noaddr.test","port":"443"}\n' "$LPORT" "$MPORT" > "$B5D/tlsx_ip.jsonl"
TLS_ENUM_TIMEOUT=3 python3 -I "$B5D/tlsenum_probe.py" "$B5D/keys.txt" "$B5D/tlsx_ip.jsonl" > "$B5D/enum.jsonl" 2>"$B5D/enum.err"
kill "$_tsrv" 2>/dev/null; wait "$_tsrv" 2>/dev/null
assert_grep "$B5D/enum.jsonl" '"host": "legacy\.test".*"tls_supported": \["TLS 1\.2", "TLS 1\.1", "TLS 1\.0"\]' "legacy: TLS 1.2, 1.1, 1.0 (the TLS 1.3 hello answered at 1.2 is not counted; SSL 3.0 refused)"
assert_grep "$B5D/enum.jsonl" '"host": "legacy\.test".*"TLS 1\.0": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"' "legacy: the suite the server chose, per version"
assert_grep "$B5D/enum.jsonl" '"host": "legacy\.test".*"tls_weak_cipher": "TLS 1\.2:TLS_RSA_WITH_NULL_SHA"' "legacy: the weak-only hello is answered with NULL-SHA -> tls_weak_cipher"
assert_grep "$B5D/enum.jsonl" '"host": "modern\.test".*"tls_ciphers": \{"TLS 1\.2": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS 1\.3": "TLS_AES_128_GCM_SHA256"\}' "modern: TLS 1.3 from the supported_versions extension, TLS 1.2"
assert_grep "$B5D/enum.jsonl" '"host": "modern\.test".*"tls_weak_cipher": ""' "modern: no weak suite accepted"
refute_grep "$B5D/enum.jsonl" 'noaddr'                                "a host tlsx gave no address for is not contacted"
assert_absent "$B5D/enum.err" "the probe ran without errors"
# joined by the aggregator: columns and the WeakTLS / WeakCipher flags
printf 'ex.com\thttps://legacy.test:%s/\tgau\nex.com\thttps://modern.test:%s/\tgau\n' "$LPORT" "$MPORT" > "$B5D/map2.tsv"
printf '{"host":"legacy.test","port":"%s","tls_version":"tls12","cipher":"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"}\n{"host":"modern.test","port":"%s","tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256"}\n' "$LPORT" "$MPORT" > "$B5D/tlsx2.jsonl"
: > "$B5D/empty.jsonl"
( cd "$B5D" && env PATH="$TESTPATH" TLSENUM_FILE="$B5D/enum.jsonl" python3 agg.py map2.tsv empty.jsonl out2.csv 0 2000 tlsx2.jsonl >/dev/null 2>&1 )
b5eq2(){ local got; got="$(b5col "$B5D/out2.csv" "$1" "$2")"; if [ "$got" = "$3" ]; then _pass "$4"; else _fail "$4 (got: $got)"; fi; }
b5eq2 "https://legacy.test:$LPORT/" tls_supported 'TLS 1.2;TLS 1.1;TLS 1.0' "tls_supported column"
b5eq2 "https://legacy.test:$LPORT/" tls_weak_cipher 'TLS 1.2:TLS_RSA_WITH_NULL_SHA' "tls_weak_cipher column"
b5eq2 "https://legacy.test:$LPORT/" tls_flags 'WeakTLS;WeakCipher' "WeakTLS (TLS 1.0/1.1 accepted) and WeakCipher (NULL-SHA accepted)"
b5eq2 "https://modern.test:$MPORT/" tls_ciphers 'TLS 1.3=TLS_AES_128_GCM_SHA256;TLS 1.2=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' "tls_ciphers in plan order (1.3 first)"
b5eq2 "https://modern.test:$MPORT/" tls_flags '' "the modern host carries no flag"

section "Batch 5: the leaf certificate (tlsx -cert): cert_key, cert_sig_alg, WeakKey, WeakSig, DefaultCert, CertNotYetValid"
if command -v openssl >/dev/null 2>&1 \
   && openssl req -x509 -newkey rsa:1024 -sha1 -nodes -keyout "$B5D/k1.pem" -out "$B5D/weak.pem" -days 2 -subj "/CN=weak.ex.com" >/dev/null 2>&1 \
   && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes -keyout "$B5D/k2.pem" -out "$B5D/ec.pem" -days 2 -subj "/CN=ec.ex.com" >/dev/null 2>&1 \
   && openssl req -x509 -newkey rsa:2048 -sha256 -nodes -keyout "$B5D/k3.pem" -out "$B5D/def.pem" -days 2 -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=def.ex.com" >/dev/null 2>&1; then
  python3 - "$B5D" > "$B5D/tlsx3.jsonl" <<'PYCERT'
import json, sys, os, datetime
d = sys.argv[1]
now = datetime.datetime.now(datetime.timezone.utc)
iso = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
pem = lambda n: open(os.path.join(d, n)).read()
far, past, soon = iso(now + datetime.timedelta(days=300)), iso(now - datetime.timedelta(days=1)), iso(now + datetime.timedelta(days=20))
for r in [
    {"host": "weak.ex.com", "port": "443", "tls_version": "tls12", "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "not_before": past, "not_after": far, "certificate": pem("weak.pem")},
    {"host": "ec.ex.com", "port": "443", "tls_version": "tls13", "cipher": "TLS_AES_128_GCM_SHA256", "not_before": past, "not_after": far, "certificate": pem("ec.pem")},
    {"host": "def.ex.com", "port": "443", "tls_version": "tls13", "cipher": "TLS_AES_128_GCM_SHA256", "not_before": past, "not_after": far, "certificate": pem("def.pem"),
     "subject_dn": "CN=def.ex.com, O=Internet Widgits Pty Ltd, ST=Some-State, C=AU", "self_signed": True},
    {"host": "future.ex.com", "port": "443", "tls_version": "tls13", "cipher": "TLS_AES_128_GCM_SHA256", "not_before": iso(now + datetime.timedelta(days=30)), "not_after": far},
    {"host": "gone.ex.com", "port": "443", "tls_version": "tls13", "cipher": "TLS_AES_128_GCM_SHA256", "not_before": iso(now - datetime.timedelta(days=90)), "not_after": past},
    {"host": "esxi.ex.com", "port": "443", "tls_version": "tls12", "cipher": "TLS_AES_128_GCM_SHA256", "not_after": far, "issuer_dn": "CN=localhost.localdomain, OU=VMware Engineering, O=VMware"},
    {"host": "junk.ex.com", "port": "443", "tls_version": "tls13", "cipher": "TLS_AES_128_GCM_SHA256", "not_after": far, "certificate": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"},
]:
    print(json.dumps(r))
PYCERT
  printf 'ex.com\thttps://%s.ex.com/\tgau\n' weak ec def future gone esxi junk > "$B5D/map3.tsv"
  ( cd "$B5D" && env PATH="$TESTPATH" python3 agg.py map3.tsv empty.jsonl out3.csv 0 2000 tlsx3.jsonl >/dev/null 2>"$B5D/agg3.err" )
  b5eq3(){ local got; got="$(b5col "$B5D/out3.csv" "$1" "$2")"; if [ "$got" = "$3" ]; then _pass "$4"; else _fail "$4 (got: $got)"; fi; }
  b5eq3 https://weak.ex.com/ cert_key 'RSA 1024' "cert_key: RSA modulus size from the DER (stdlib parser)"
  b5eq3 https://weak.ex.com/ cert_sig_alg 'sha1WithRSAEncryption' "cert_sig_alg: the signature algorithm"
  b5eq3 https://weak.ex.com/ tls_flags 'WeakKey;WeakSig' "RSA 1024 / SHA-1 -> WeakKey;WeakSig"
  b5eq3 https://ec.ex.com/ cert_key 'EC P-256' "an EC key names its curve"
  b5eq3 https://ec.ex.com/ tls_flags '' "EC P-256 / SHA-256: no flag"
  b5eq3 https://def.ex.com/ tls_flags 'SelfSigned;DefaultCert' "OpenSSL's default subject (Internet Widgits) -> DefaultCert"
  b5eq3 https://esxi.ex.com/ tls_flags 'DefaultCert' "the VMware installer's issuer -> DefaultCert"
  b5eq3 https://future.ex.com/ tls_flags 'CertNotYetValid' "notBefore in the future -> CertNotYetValid (tlsx reports no expired flag for it)"
  b5eq3 https://future.ex.com/ cert_not_before "$(python3 -c 'import json,sys; print([json.loads(l) for l in open(sys.argv[1])][3]["not_before"])' "$B5D/tlsx3.jsonl")" "cert_not_before column"
  b5eq3 https://gone.ex.com/ tls_flags 'CertExpired' "notAfter in the past -> CertExpired even without tlsx's expired field"
  b5eq3 https://junk.ex.com/ cert_key '' "an unreadable certificate leaves the columns blank"
  refute_grep "$B5D/agg3.err" 'Traceback' "the aggregator ran without errors"
else
  _pass "openssl unavailable: certificate parsing test skipped"
fi

section "Batch 5: the chain check retries below the local OpenSSL security level"
if command -v openssl >/dev/null 2>&1 && openssl req -x509 -newkey rsa:1024 -sha1 -nodes -keyout "$B5D/lk.pem" -out "$B5D/lc.pem" -days 2 -subj "/CN=localhost" >/dev/null 2>&1; then
  # a TLS 1.0-only server (RSA 1024 / SHA-1): the local OpenSSL refuses the protocol before
  # it gets to the chain, so only the second try (level 0) can reach the verdict
  python3 - "$B5D/lc.pem" "$B5D/lk.pem" "$B5D/lport" <<'PYLSRV' &
import ssl, socket, sys, warnings
warnings.simplefilter("ignore")
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.set_ciphers("DEFAULT:@SECLEVEL=0"); ctx.load_cert_chain(sys.argv[1], sys.argv[2])
ctx.minimum_version = ssl.TLSVersion.TLSv1; ctx.maximum_version = ssl.TLSVersion.TLSv1
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 0)); s.listen(5); s.settimeout(20)
open(sys.argv[3], "w").write(str(s.getsockname()[1]))
n = 0
for _ in range(3):
    try:
        c, _a = s.accept()
    except Exception:
        break
    n += 1; s.settimeout(2)
    try:
        ctx.wrap_socket(c, server_side=True).close()
    except Exception:
        pass
open(sys.argv[3] + ".n", "w").write(str(n))
PYLSRV
  _lsrv=$!
  for _i in $(seq 1 20); do [ -s "$B5D/lport" ] && break; sleep 0.2; done
  printf '{"host":"localhost","ip":"127.0.0.1","port":"%s"}\n' "$(cat "$B5D/lport")" > "$B5D/lt.jsonl"
  awk '/^tls_chain_check\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$RUN_RECON" > "$B5D/fn.sh"
  ( . "$B5D/fn.sh"; tls_chain_check "$B5D/lt.jsonl" )
  for _i in $(seq 1 30); do [ -s "$B5D/lport.n" ] && break; sleep 0.2; done
  kill "$_lsrv" 2>/dev/null; wait "$_lsrv" 2>/dev/null
  assert_grep "$B5D/lt.jsonl" '"chain_error": "self-signed certificate", "untrusted": true' "a TLS 1.0-only self-signed host: the second try at level 0 reaches the verdict"
  if [ "$(cat "$B5D/lport.n" 2>/dev/null)" = 2 ]; then _pass "... after exactly one retry"; else _fail "... after exactly one retry (got $(cat "$B5D/lport.n" 2>/dev/null) connections)"; fi
else
  _pass "openssl unavailable: chain retry test skipped"
fi

section "Batch 5: report findings for the new flags and cleartext login forms"
R5="$TMP/rpt20"; rm -rf "$R5"; mkdir -p "$R5"
python3 - "$R5/r.csv" <<'PYR5'
import csv, sys
cols = ["seed_domain", "url", "host", "sources", "status_code", "tls_version", "tls_flags", "auth", "http_flags",
        "final_url", "redirect_chain", "login_form", "tls_supported", "tls_weak_cipher", "cert_key", "cert_sig_alg", "cert_not_before"]
rows = [
    ["ex.com", "https://legacy.ex.com/", "legacy.ex.com", "gau", "200", "TLS 1.2", "WeakTLS;WeakCipher;WeakKey;WeakSig;DefaultCert", "", "",
     "", "", "", "TLS 1.2;TLS 1.1;TLS 1.0;SSL 3.0", "TLS 1.2:TLS_RSA_WITH_NULL_SHA", "RSA 1024", "sha1WithRSAEncryption", ""],
    ["ex.com", "https://soon.ex.com/", "soon.ex.com", "gau", "200", "TLS 1.3", "CertNotYetValid", "", "",
     "", "", "", "", "", "EC P-256", "ecdsa-with-SHA256", "2031-02-03T04:05:06Z"],
    ["ex.com", "http://r.ex.com/", "r.ex.com", "gau", "301", "", "", "Form", "CleartextAuth",
     "https://r.ex.com/login", "301->https://r.ex.com/ | 302->https://r.ex.com/login", "http://r.ex.com/session", "", "", "", "", ""],
    ["ex.com", "https://r.ex.com/", "r.ex.com", "gau", "302", "", "", "Form", "CleartextAuth",
     "https://r.ex.com/login", "302->https://r.ex.com/login", "http://r.ex.com/session", "", "", "", "", ""],
]
w = csv.writer(open(sys.argv[1], "w", newline="")); w.writerow(cols); w.writerows(rows)
PYR5
env PATH="$TESTPATH" bash "$REPORT_SH" -o "$R5/out.html" "$R5/r.csv" >/dev/null 2>"$R5/e.log"
assert_grep "$R5/out.html" 'obsolete protocol versions accepted: TLS 1\.1, TLS 1\.0, SSL 3\.0' "WeakTLS names the old versions accepted"
assert_grep "$R5/out.html" 'weak cipher accepted: TLS_RSA_WITH_NULL_SHA \(TLS 1\.2\)' "WeakCipher names the suite and version"
assert_grep "$R5/out.html" 'weak certificate key \(RSA 1024\)'      "WeakKey names the key"
assert_grep "$R5/out.html" 'weak certificate signature \(sha1WithRSAEncryption\)' "WeakSig names the algorithm"
assert_grep "$R5/out.html" 'certificate not valid yet \(valid from 2031-02-03 04:05 UTC\)' "CertNotYetValid gives the start date"
assert_grep "$R5/out.html" "default certificate is still in place" "DefaultCert finding"
assert_grep "$R5/out.html" 'login form sends the password in cleartext: https://r\.ex\.com/login posts to http://r\.ex\.com/session' "a cleartext login form is one finding ..."
if [ "$(grep -o 'login form sends the password in cleartext' "$R5/out.html" | wc -l)" = "$(grep -o 'weak certificate key (RSA 1024)' "$R5/out.html" | wc -l)" ]; then
  _pass "... however many rows reach it (counted like any other single finding)"
else _fail "... however many rows reach it (counted like any other single finding)"; fi
refute_grep "$R5/out.html" 'credentials sent in cleartext: Form'     "not reported as Basic/Digest auth"
assert_grep "$R5/out.html" 'sev-high"[^>]*>HIGH</span></td><td>TLS / certificate</td><td>[^\n]*obsolete protocol versions accepted: [^<]*SSL 3\.0' "WeakTLS with SSL 3.0 accepted is graded high (POODLE)"

section "Batch 5: CPE aliases in the vulns join (cpe-aliases.json)"
X1D="$TMP/x1"; rm -rf "$X1D"; mkdir -p "$X1D/nvd"
printf 'seed_domain,url,host,status_code,technologies,cpe\nex.com,https://jira.ex.com/,jira.ex.com,200,Jira:9.4.0,cpe:2.3:a:atlassian:jira:9.4.0:*:*:*:*:*:*:*\nex.com,https://cache.ex.com/,cache.ex.com,200,Varnish,cpe:2.3:a:varnish_cache_project:varnish_cache:7.1.0:*:*:*:*:*:*:*\n' > "$X1D/r.csv"
python3 - "$X1D/nvd/nvdcve-2.0-2026.json" <<'PYX1'
import json, sys
def cve(i, crit, **rng):
    cm = {"vulnerable": True, "criteria": crit}; cm.update(rng)
    return {"cve": {"id": i, "published": "2026-01-01", "lastModified": "2026-01-02", "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "test " + i}],
            "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [cm]}]}]}}
json.dump({"vulnerabilities": [
    cve("CVE-2026-0001", "cpe:2.3:a:atlassian:jira_server:*:*:*:*:*:*:*:*", versionStartIncluding="9.0.0", versionEndExcluding="9.4.5"),
    cve("CVE-2026-0002", "cpe:2.3:a:varnish-software:varnish_cache:*:*:*:*:*:*:*:*", versionEndExcluding="7.2.0"),
    cve("CVE-2026-0003", "cpe:2.3:a:atlassian:jira_server:*:*:*:*:*:*:*:*", versionEndExcluding="9.0.0"),
    cve("CVE-2026-0004", "cpe:2.3:a:atlassian:confluence:*:*:*:*:*:*:*:*", versionEndExcluding="9.0.0"),
]}, open(sys.argv[1], "w"))
PYX1
env PATH="$TESTPATH" bash "$RDB" vulns "$X1D/r.csv" --nvd-feed "$X1D/nvd" -o "$X1D/v.csv" >/dev/null 2>&1
assert_grep  "$X1D/v.csv" '^ex\.com,jira\.ex\.com,.*,CVE-2026-0001,.*,range,' "a CVE filed under jira_server joins the service CPE'd as atlassian:jira (version range checked)"
assert_grep  "$X1D/v.csv" '^ex\.com,cache\.ex\.com,.*,CVE-2026-0002,'         "Varnish Cache under another vendor string joins too"
refute_grep  "$X1D/v.csv" 'CVE-2026-0003|CVE-2026-0004'                       "the version range still decides; other products stay out"
assert_grep  "$X1D/v.csv.provenance.json" '"cpe_aliases": \{' "provenance records the alias file ..."
assert_grep  "$X1D/v.csv.provenance.json" '"groups": 184'     "... and its 184 groups"
env PATH="$TESTPATH" CPE_ALIASES_FILE= bash "$RDB" vulns "$X1D/r.csv" --nvd-feed "$X1D/nvd" -o "$X1D/v0.csv" >/dev/null 2>&1
if [ "$(wc -l < "$X1D/v0.csv")" = 1 ]; then _pass "CPE_ALIASES_FILE= turns the aliases off (exact names only: no match)"; else _fail "CPE_ALIASES_FILE= turns the aliases off"; fi
mkdir -p "$X1D/bin"; ln -sf "$RDB" "$X1D/bin/recon-db"
env PATH="$TESTPATH" bash "$X1D/bin/recon-db" vulns "$X1D/r.csv" --nvd-feed "$X1D/nvd" -o "$X1D/v2.csv" >/dev/null 2>&1
assert_grep  "$X1D/v2.csv" 'CVE-2026-0001'                    "run through a symlink (the installed command), the alias file is still found"

# --- Batch 6: JSON lines (--json), run_id/--engagement, shipping to Tideline (--ship) ----
section "Batch 6: the CSV builder writes urls.jsonl and services.jsonl (RR_JSON=1), unguarded"
B6="$TMP/b6"; rm -rf "$B6"; mkdir -p "$B6/agg"
LABDIR6="$(dirname "$RUN_RECON")/lab"; SCHEMAS6="$(dirname "$RUN_RECON")/schemas"; SHIP6="$(dirname "$RUN_RECON")/ship-recon.sh"
awk "/^python3 - .*<<'PY'/{f=1;next} f&&/^PY\$/{f=0} f" "$RUN_RECON" > "$B6/agg/agg.py"
printf 'ex.com\thttps://a.ex.com/\tgau\nex.com\thttps://a.ex.com/login?x=1\tkatana\nex.com\thttps://a.ex.com:8443/admin\tkatana\nex.com\thttp://b.ex.com/p\tgau\nother.org\thttps://a.ex.com/\tgau\n' > "$B6/agg/map.tsv"
cat > "$B6/agg/httpx.jsonl" <<'JX'
{"input":"https://a.ex.com/","url":"https://a.ex.com/","status_code":200,"title":"=HYPERLINK(\"http://x\")","webserver":"nginx","host":"1.1.1.1","a":["1.1.1.1"]}
{"input":"https://a.ex.com/login?x=1","url":"https://a.ex.com/login?x=1","status_code":200,"title":"+1 login","host":"1.1.1.1","a":["1.1.1.1"]}
{"input":"https://a.ex.com:8443/admin","url":"https://a.ex.com:8443/admin","status_code":401,"title":"Admin","host":"1.1.1.1","a":["1.1.1.1"]}
{"input":"http://b.ex.com/p","url":"http://b.ex.com/p","status_code":404,"title":"Not found","host":"2.2.2.2","a":["2.2.2.2"]}
JX
( cd "$B6/agg" && env PATH="$TESTPATH" python3 agg.py map.tsv httpx.jsonl off.csv 0 100 >/dev/null 2>&1 )
if [ -f "$B6/agg/off.csv" ] && ! ls "$B6/agg"/off.csv.*.jsonl >/dev/null 2>&1; then _pass "without --json the CSV builder writes no JSON lines"; else _fail "without --json the CSV builder writes no JSON lines"; fi
( cd "$B6/agg" && env PATH="$TESTPATH" RR_JSON=1 python3 agg.py map.tsv httpx.jsonl out.csv 0 100 >/dev/null 2>&1 )
python3 - "$B6/agg/out.csv" > "$B6/agg/check.txt" 2>&1 <<'PYB6A'
import csv, json, sys
out = sys.argv[1]
rows = list(csv.reader(open(out, newline="", encoding="utf-8")))
hdr, body = rows[0], rows[1:]
def ung(v):
    return v[1:] if v[:1] == "'" and v[1:2] in ("=", "+", "-", "@", "\t", "\r") else v
js = [json.loads(l) for l in open(out + ".urls.jsonl", encoding="utf-8")]
print("count", len(js) == len(body))
print("order", all(list(j) == hdr for j in js))
print("equal", all([ung(c) for c in r] == [j[k] for k in hdr] for r, j in zip(body, js)))
t = {j["url"]: j["title"] for j in js}
c = {r[1]: r[7] for r in body}
print("unguarded", t["https://a.ex.com/"] == '=HYPERLINK("http://x")' and c["https://a.ex.com/"].startswith("'="))
print("strings", all(isinstance(v, str) for j in js for v in j.values()))
sv = [json.loads(l) for l in open(out + ".services.jsonl", encoding="utf-8")]
key = {(s["seed_domain"], s["service"]): s for s in sv}
a = key.get(("ex.com", "https://a.ex.com"), {})
print("services", sorted(key) == [("ex.com", "http://b.ex.com"), ("ex.com", "https://a.ex.com"), ("ex.com", "https://a.ex.com:8443"), ("other.org", "https://a.ex.com")])
print("svc_root", a.get("url") == "https://a.ex.com/" and a.get("url_count") == 2 and a.get("port") == 443 and a.get("scheme") == "https")
print("svc_port", key.get(("ex.com", "https://a.ex.com:8443"), {}).get("port") == 8443 and key.get(("ex.com", "http://b.ex.com"), {}).get("port") == 80)
print("svc_fields", list(a)[:6] == ["seed_domain", "service", "scheme", "host", "port", "url_count"] and set(a) == set(hdr) | {"service", "scheme", "port", "url_count"})
PYB6A
assert_grep  "$B6/agg/check.txt" '^count True$'      "urls.jsonl: one record per CSV row"
assert_grep  "$B6/agg/check.txt" '^order True$'      "urls.jsonl: the CSV's field names, in its column order"
assert_grep  "$B6/agg/check.txt" '^equal True$'      "urls.jsonl: every value equals the CSV cell (after the formula guard is undone)"
assert_grep  "$B6/agg/check.txt" '^unguarded True$'  "urls.jsonl: a title starting with = is the site's text (the CSV keeps its apostrophe)"
assert_grep  "$B6/agg/check.txt" '^strings True$'    "urls.jsonl: values are strings, as in the CSV"
assert_grep  "$B6/agg/check.txt" '^services True$'   "services.jsonl: one record per seed and scheme://host[:port] (default ports omitted)"
assert_grep  "$B6/agg/check.txt" '^svc_root True$'   "services.jsonl: the root URL's values, url_count over the service's URLs"
assert_grep  "$B6/agg/check.txt" '^svc_port True$'   "services.jsonl: port explicit (8443, 80)"
assert_grep  "$B6/agg/check.txt" '^svc_fields True$' "services.jsonl: service/scheme/port/url_count, then the URL fields"

section "Batch 6: the side files as JSON lines (findings, TSV inventories, warnings, seeds)"
mkdir -p "$B6/exp/wd"
awk "/<<'PYJSONL'/{f=1;next} f&&/^PYJSONL\$/{f=0} f" "$RUN_RECON" > "$B6/exp/jsonl.py"
X="$B6/exp/r.csv"
printf '[ex.com] dangling-cname [high] host=old.ex.com cname=gone.herokudns.com dns=NXDOMAIN provider=heroku note=claim it: the name points at an app that no longer exists (a=b, "q")\n[ex.com] nuclei-takeover [aws-bucket-takeover] [dns] [critical] old2.ex.com\n[ex.com] plain line without any tag http://old3.ex.com/x\n' > "$X.takeover.txt"
printf '[ex.com] nuclei [git-config] [http] [medium] https://a.ex.com:8443/.git/config\n' > "$X.nuclei.txt"
printf '[ex.com] security-txt-invalid [low] host=a.ex.com path=/.well-known/security.txt contact="mailto:x y" note=RFC 9116 requires Expires=\n\n' > "$X.extras.txt"
printf 'seed_domain\thost\tedge\torigin_software\tedge_evidence\tjarm\tcdn\tfavicon_mmh3\ttitle\tedge_ip\nex.com\ta.ex.com\tcloudflare\tnginx\tcf-ray\t\tcloudflare\t123\tA\t104.16.0.1\n' > "$X.edge.tsv"
printf 'host\tfile\tstatus\treason\tbytes\na.ex.com\ta.png\tok\t\t100\nb.ex.com\t\tfailed\tno image\n' > "$X.screenshots.tsv"
printf 'change\tseed\tservice\tfield\told\tnew\nchanged\tex.com\thttps://a.ex.com\ttitle\tOld\tNew\twith\ttabs\n' > "$X.delta.tsv"
{ for i in $(seq 1 250); do printf '\033[1;33mwarning %d\033[0m\n' "$i"; done; printf 'warning 1\n'; } > "$B6/exp/wd/warnings.txt"
printf 'ex.com\t12\t10\t3\nother.org\t-\t-\t0\n' > "$B6/exp/wd/seedstat.tsv"
( cd "$B6/exp" && python3 jsonl.py "$X" "$B6/exp/wd" > sum.txt 2> err.txt )
python3 - "$X" > "$B6/exp/check.txt" 2>&1 <<'PYB6B'
import json, sys
x = sys.argv[1]
def jl(k):
    return [json.loads(l) for l in open("%s.%s.jsonl" % (x, k), encoding="utf-8")]
f = jl("findings")
d = {(r["source"], r["check"]): r for r in f}
s = d.get(("takeover", "dangling-cname"), {})
print("structured", s.get("severity") == "high" and s.get("seed") == "ex.com" and s.get("host") == "old.ex.com"
      and s.get("fields") == {"host": "old.ex.com", "cname": "gone.herokudns.com", "dns": "NXDOMAIN", "provider": "heroku"})
print("note", s.get("note") == 'claim it: the name points at an app that no longer exists (a=b, "q")')
t = d.get(("takeover", "nuclei-takeover"), {})
print("toolline", t.get("severity") == "critical" and t.get("fields") == {} and t.get("text", "").startswith("nuclei-takeover [aws"))
p = d.get(("takeover", "plain"), {})
print("default", p.get("severity") == "high" and p.get("host") == "old3.ex.com")
n = d.get(("nuclei", "nuclei"), {})
print("nuclei", n.get("severity") == "medium" and n.get("host") == "a.ex.com")
e = d.get(("extras", "security-txt-invalid"), {})
print("quoted", e.get("fields", {}).get("contact") == "mailto:x y" and e.get("note") == "RFC 9116 requires Expires=")
print("nfind", len(f) == 5)
ed = jl("edges")
print("edges", ed == [{"seed_domain": "ex.com", "host": "a.ex.com", "edge": "cloudflare", "origin_software": "nginx",
                       "edge_evidence": "cf-ray", "jarm": "", "cdn": "cloudflare", "favicon_mmh3": "123", "title": "A",
                       "edge_ip": "104.16.0.1"}])
sh = jl("screenshots")
print("short", sh[1] == {"host": "b.ex.com", "file": "", "status": "failed", "reason": "no image", "bytes": ""})
de = jl("delta")
print("long", de[0]["new"] == "New\twith\ttabs")
w = jl("warnings")
print("warnings", len(w) == 250 and w[0] == {"message": "warning 1"} and w[-1] == {"message": "warning 250"})
se = jl("seeds")
print("seeds", se == [{"seed": "ex.com", "candidates": 12, "resolved": 10, "live_hosts": 3},
                      {"seed": "other.org", "candidates": None, "resolved": None, "live_hosts": 0}])
PYB6B
for _k in structured note toolline default nuclei quoted nfind edges short long warnings seeds; do
  case "$_k" in
    structured) _m="findings: '[seed] check [severity] key=value ... note=' -> seed, check, severity, host, fields";;
    note)       _m="findings: the note is the free text to the end of the line (= signs and quotes kept)";;
    toolline)   _m="findings: a tool's output line keeps its text, its first [severity] tag, no fields";;
    default)    _m="findings: an untagged line gets the report's default severity for its kind; host from its URL";;
    nuclei)     _m="findings: nuclei lines: severity from the tag, host from the URL (port dropped)";;
    quoted)     _m="findings: a quoted value is one field";;
    nfind)      _m="findings: every non-empty line, one record each";;
    edges)      _m="edges.jsonl: the TSV header's field names";;
    short)      _m="a short TSV row is padded with empty strings";;
    long)       _m="a TSV row with extra tabs keeps them in its last field";;
    warnings)   _m="warnings.jsonl: every warning (not capped at 200), ANSI codes stripped, duplicates once";;
    seeds)      _m="seeds.jsonl: counts as integers, null where a stage did not count";;
  esac
  assert_grep "$B6/exp/check.txt" "^$_k True\$" "$_m"
done
assert_grep  "$B6/exp/err.txt" '2 TSV row\(s\) had the wrong number of fields' "the exporter reports the TSV rows it had to fix up (one short, one long)"
assert_absent "$X.dnsposture.jsonl" "a stage that did not run gets no JSON lines file"

section "Batch 6: schema contract (schemas/: JSON Schema 2020-12, field lists match what run-recon writes)"
python3 - "$SCHEMAS6" "$RUN_RECON" "$(dirname "$RUN_RECON")/recon-db.sh" > "$B6/contract.txt" 2>&1 <<'PYB6C'
import json, os, re, sys
sd, rr, rdb = sys.argv[1:4]
S = {}
for n in sorted(os.listdir(sd)):
    if not n.endswith(".json"):
        continue
    s = json.load(open(os.path.join(sd, n)))
    S[s["x-tideline-schema"]] = s
src = open(rr, encoding="utf-8").read()
db = open(rdb, encoding="utf-8").read()
m = re.search(r"CSV_HEADER = \[(.*?)\]", src, re.S)
csvh = re.findall(r'"([a-z0-9_]+)"', m.group(1)) if m else []
print("url", list(S["run-recon.url/1"]["properties"]) == csvh and S["run-recon.url/1"]["required"] == csvh and len(csvh) == 48)
def tsv(pat, text=src):
    m = re.search(pat, text)
    return m.group(1).split("\\t") if m else None
heads = {
    "run-recon.edge/1": tsv(r"printf '(seed_domain\\thost\\tedge\\t[^']*?)\\n"),
    "run-recon.cname/1": tsv(r"printf '(seed_domain\\thost\\tcname_chain[^']*?)\\n"),
    "run-recon.zone-name/1": tsv(r"printf '(zone\\tname\\tsource)\\n"),
    "run-recon.screenshot/1": tsv(r'o\.write\("(host\\tfile\\tstatus[^"]*?)\\n"\)'),
    "run-recon.cloud-asset/1": tsv(r'"(provider\\taccount\\tservice[^"]*?)\\n"'),
    "run-recon.vulnx/1": tsv(r'"(vendor\\tproduct\\tversions_seen[^"]*?)\\n"'),
    "run-recon.delta/1": tsv(r'o\.write\("(change\\tseed\\tservice[^"]*?)\\n"\)', db),
}
m = re.search(r'COLS = \[("name", "role".*?)\]', src)
heads["run-recon.dnsposture/1"] = re.findall(r'"([a-z_]+)"', m.group(1)) if m else None
bad = [k for k, h in heads.items() if not h or list(S[k]["properties"]) != h or S[k]["required"] != h]
print("tsv", not bad, bad)
try:
    import jsonschema
    for s in S.values():
        jsonschema.Draft202012Validator.check_schema(s)
    print("metaschema True")
except ImportError:
    print("metaschema True (jsonschema not installed: skipped)")
PYB6C
assert_grep  "$B6/contract.txt" '^url True$'        "run-recon.url/1 lists exactly the CSV's 48 columns, in order"
assert_grep  "$B6/contract.txt" '^tsv True'         "each TSV schema lists exactly the header run-recon (recon-db.sh) writes"
assert_grep  "$B6/contract.txt" '^metaschema True'  "every schema is valid JSON Schema 2020-12"

# a schema validator for the checks below: jsonschema when installed, else the subset the schemas use
cat > "$B6/validate.py" <<'PYB6V'
import json, os, re, sys
sd = sys.argv[1]
S = {}
for n in os.listdir(sd):
    if not n.endswith(".json"):
        continue
    s = json.load(open(os.path.join(sd, n)))
    S[s["x-tideline-schema"]] = s
try:
    import jsonschema
    def errors(s, o):
        return [e.message for e in jsonschema.Draft202012Validator(s).iter_errors(o)]
except ImportError:
    T = {"string": str, "integer": int, "object": dict, "array": list, "null": type(None)}
    def errors(s, o, p="$"):
        e = []
        if s is True:
            return e
        if s is False:
            return [p + ": not allowed"]
        if "type" in s:
            ts = s["type"] if isinstance(s["type"], list) else [s["type"]]
            if not any(isinstance(o, T[t]) and not (t == "integer" and isinstance(o, bool)) for t in ts):
                return [p + ": type"]
        if "const" in s and o != s["const"]:
            e.append(p + ": const")
        if "enum" in s and o not in s["enum"]:
            e.append(p + ": enum")
        if isinstance(o, str):
            if "pattern" in s and not re.search(s["pattern"], o):
                e.append(p + ": pattern")
            if len(o) < s.get("minLength", 0) or len(o) > s.get("maxLength", 1 << 30):
                e.append(p + ": length")
        if isinstance(o, int) and (o < s.get("minimum", -(1 << 62)) or o > s.get("maximum", 1 << 62)):
            e.append(p + ": range")
        if "oneOf" in s and sum(1 for x in s["oneOf"] if not errors(x, o, p)) != 1:
            e.append(p + ": oneOf")
        if isinstance(o, dict):
            for r in s.get("required", []):
                if r not in o:
                    e.append(p + ": missing " + r)
            props = s.get("properties", {})
            for k, v in o.items():
                e += errors(props[k], v, p + "." + k) if k in props else errors(s.get("additionalProperties", True), v, p + "." + k)
            if "if" in s:
                e += errors(s.get("then", True) if not errors(s["if"], o, p) else s.get("else", True), o, p)
        if isinstance(o, list):
            if len(o) < s.get("minItems", 0) or len(o) > s.get("maxItems", 1 << 30):
                e.append(p + ": items")
            for i, x in enumerate(o):
                e += errors(s.get("items", True), x, "%s[%d]" % (p, i))
        return e
bad = 0
for arg in sys.argv[2:]:
    sid, path = arg.split("=", 1)
    lines = [open(path, encoding="utf-8").read()] if sid == "tideline-envelope/1" else open(path, encoding="utf-8")
    for i, l in enumerate(lines, 1):
        if l.strip():
            er = errors(S[sid], json.loads(l))
            if er:
                bad += 1
                print("%s line %d: %s" % (os.path.basename(path), i, er[:3]))
print("valid" if not bad else "INVALID %d" % bad)
PYB6V

section "Batch 6: run-recon --json, run_id, --engagement / --job-id"
run_case b6plain --tls
if ls "$OUTDIR"/r.csv.*.jsonl >/dev/null 2>&1; then _fail "without --json: no .jsonl files"; else _pass "without --json: no .jsonl files"; fi
assert_grep  "$CSV.run.json" '"run_id": "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"' "run.json: a run_id (UUID v4) on every run"
assert_grep  "$CSV.run.json" '"engagement": null'                         "run.json: engagement null when not given"
_rid1="$(sed -n 's/.*"run_id": "\([^"]*\)".*/\1/p' "$CSV.run.json")"
assert_grep  "$(ls -d "$OUTDIR"/_work-* | head -n 1)/state" "^run_id=$_rid1\$" "the run_id is kept in the work dir's state (for --resume)"
run_case b6json --json --tls --takeover --screenshots --engagement eng-2026.014 --job-id job:7
B6RUN="$OUTDIR"
for _k in urls services findings warnings seeds; do
  if [ -f "$CSV.$_k.jsonl" ]; then _pass "--json writes <out>.$_k.jsonl (empty when there is nothing of the kind)"; else _fail "--json writes <out>.$_k.jsonl"; fi
done
assert_exists "$CSV.urls.jsonl"                                           "--json: urls.jsonl has the URL rows"
assert_exists "$CSV.screenshots.jsonl"                                    "--json: screenshots.jsonl when screenshots ran"
assert_grep  "$CSV.run.json" '"engagement": "eng-2026\.014"'              "--engagement is written to run.json"
assert_grep  "$CSV.run.json" '"job_id": "job:7"'                          "--job-id is written to run.json"
assert_grep  "$CSV.manifest.sha256" '^[0-9a-f]{64}  r\.csv\.urls\.jsonl$'  "the JSON lines are in the run's manifest"
assert_grep  "$ERRLOG" 'JSON lines      : .*urls=[1-9][0-9]* services=[1-9]'  "the summary counts the JSON records"
if ( cd "$OUTDIR" && sha256sum --quiet -c r.csv.manifest.sha256 ) >/dev/null 2>&1; then _pass "--json: sha256sum -c still verifies the manifest"; else _fail "--json: sha256sum -c still verifies the manifest"; fi
_v=(); for _k in url:urls service:services finding:findings warning:warnings seed:seeds screenshot:screenshots cname:cnames; do
  [ -f "$CSV.${_k#*:}.jsonl" ] && _v+=("run-recon.${_k%%:*}/1=$CSV.${_k#*:}.jsonl")
done
python3 "$B6/validate.py" "$SCHEMAS6" "${_v[@]}" > "$B6/valid1.txt" 2>&1
assert_grep  "$B6/valid1.txt" '^valid$'                                   "every record of the run validates against its schema"
python3 -S "$B6/validate.py" "$SCHEMAS6" "${_v[@]}" > "$B6/valid1s.txt" 2>&1
assert_grep  "$B6/valid1s.txt" '^valid$'                                  "...and so does the suite's own validator (python3 -S: no jsonschema)"
printf '{"seed":"x.test","candidates":"3","resolved":null,"live_hosts":0}\n' > "$B6/badseed.jsonl"
python3 "$B6/validate.py" "$SCHEMAS6" "run-recon.seed/1=$B6/badseed.jsonl" > "$B6/bad1.txt" 2>&1
python3 -S "$B6/validate.py" "$SCHEMAS6" "run-recon.seed/1=$B6/badseed.jsonl" > "$B6/bad2.txt" 2>&1
if grep -q '^INVALID 1$' "$B6/bad1.txt" && grep -q '^INVALID 1$' "$B6/bad2.txt"; then _pass "a count given as a string fails run-recon.seed/1 (both validators)"; else _fail "a count given as a string fails run-recon.seed/1"; fi
if [ "$(grep -c '' "$CSV.urls.jsonl")" = "$(( $(grep -c '' "$CSV") - 1 ))" ]; then _pass "urls.jsonl has as many records as the CSV has rows"; else _fail "urls.jsonl has as many records as the CSV has rows"; fi
_rc=0; timeout 25 env PATH="$TESTPATH" HTTPX_BIN=httpx bash "$RUN_RECON" -i "$DOMAINS" -D "$B6/bad" -o "$B6/bad/r.csv" --engagement 'bad id!' >/dev/null 2>"$B6/bad.err" || _rc=$?
_rc_is "$_rc" 2                                                           "an invalid --engagement is refused (exit 2)"
assert_grep  "$B6/bad.err" -- '--engagement must be 1-128 characters'     "...and why"

section "Batch 6: ship-recon.sh against a mock Tideline ingest (mutual TLS on loopback)"
bash "$LABDIR6/gen-ship-certs.sh" "$B6/pki" >/dev/null 2>&1
P6="$B6/pki"; mkdir -p "$B6/store"
python3 -I "$LABDIR6/mock-tideline.py" --cert "$P6/server.pem" --key "$P6/server.key" --client-ca "$P6/root.pem" \
  --store "$B6/store" --schemas "$SCHEMAS6" --port 0 > "$B6/mock.log" 2>&1 &
B6PID=$!
for _i in $(seq 1 100); do [ -s "$B6/store/port" ] && break; sleep 0.1; done
U6="https://127.0.0.1:$(cat "$B6/store/port" 2>/dev/null)"
OK6=(--url "$U6" --cert "$P6/rr-test01.pem" --key "$P6/rr-test01.key" --ca "$P6/root.pem")
_ship(){ local _r=0; SHIP_RETRIES="${SHIP_RETRIES:-0}" bash "$SHIP6" "$@" > "$B6/ship.out" 2> "$B6/ship.err" || _r=$?; return "$_r"; }
_reqs(){ python3 -c 'import json,sys; print(" ".join("%s:%s:%s" % (j["method"], j["path"].rsplit("/", 1)[-1], j["status"]) for j in map(json.loads, open(sys.argv[1]))))' "$B6/store/requests.jsonl" 2>/dev/null; }
_newrun(){ # <src dir> <dst dir>: the same run under a new run_id (manifest updated), no ship state
  rm -rf "$2"; cp -r "$1" "$2"; rm -f "$2"/r.csv.ship-state.json "$2"/r.csv.tideline.tar
  python3 - "$2" <<'PYNEW'
import json, hashlib, uuid, sys, os
d = sys.argv[1]; p = os.path.join(d, "r.csv.run.json")
j = json.load(open(p)); j["run_id"] = str(uuid.uuid4()); json.dump(j, open(p, "w"), indent=2)
h = hashlib.sha256(open(p, "rb").read()).hexdigest()
m = os.path.join(d, "r.csv.manifest.sha256")
lines = open(m).readlines()
open(m, "w").write("".join((h + "  r.csv.run.json\n") if l.endswith("  r.csv.run.json\n") else l for l in lines))
PYNEW
}
_rc=0; _ship check "${OK6[@]}" || _rc=$?;                                              _rc_is "$_rc" 0 "check: a step-ca-shaped sensor certificate passes (no connection made)"
assert_grep "$B6/ship.err" 'settings ok: sensor rr-test01'                              "check: names the sensor from the certificate's URI SAN"
_rc=0; _ship check --url "$U6" --cert "$P6/nourn.pem" --key "$P6/nourn.key" --ca "$P6/root.pem" || _rc=$?; _rc_is "$_rc" 1 "check: a certificate without urn:tideline:sensor: is refused"
_rc=0; _ship check --url "$U6" --cert "$P6/rsa.pem" --key "$P6/rsa.key" --ca "$P6/root.pem" || _rc=$?;     _rc_is "$_rc" 1 "check: an RSA key is refused (ES256 needs ECDSA P-256)"
_rc=0; _ship check --url "$U6" --cert "$P6/rr-test01.pem" --key "$P6/rr-other.key" --ca "$P6/root.pem" || _rc=$?; _rc_is "$_rc" 1 "check: a key that is not the certificate's is refused"
_rc=0; _ship check --url "http://127.0.0.1:1" --cert "$P6/rr-test01.pem" --key "$P6/rr-test01.key" --ca "$P6/root.pem" || _rc=$?; _rc_is "$_rc" 2 "check: an http:// URL is refused"
_rc=0; _ship check --url "$U6" --key "$P6/rr-test01.key" --ca "$P6/root.pem" || _rc=$?; _rc_is "$_rc" 2 "check: no certificate given -> usage error"
cp -r "$B6RUN" "$B6/run1"
_rc=0; _ship envelope "$B6/run1/r.csv" --cert "$P6/rr-test01.pem" || _rc=$?; cp "$B6/ship.out" "$B6/envelope.json"
python3 "$B6/validate.py" "$SCHEMAS6" "tideline-envelope/1=$B6/envelope.json" > "$B6/valid2.txt" 2>&1
assert_grep "$B6/valid2.txt" '^valid$'                                                  "envelope: valid tideline-envelope/1"
python3 - "$B6/envelope.json" "$B6/run1" > "$B6/env.txt" 2>&1 <<'PYENV'
import json, sys, hashlib, os
e = json.load(open(sys.argv[1])); d = sys.argv[2]
run = json.load(open(os.path.join(d, "r.csv.run.json")))
man = {l.split("  ", 1)[1].rstrip("\n"): l.split("  ", 1)[0] for l in open(os.path.join(d, "r.csv.manifest.sha256"))}
print("ids", e["run_id"] == run["run_id"] and e["engagement"] == "eng-2026.014" and e["job_id"] == "job:7" and e["sensor"] == "rr-test01" and e["tool"] == "run-recon")
print("hashes", all(man.get(p["name"]) == p["sha256"] for p in e["parts"] if p["name"] != "r.csv.manifest.sha256"))
print("toolman", e["tool_manifest_sha256"] == hashlib.sha256(open(os.path.join(d, "r.csv.manifest.sha256"), "rb").read()).hexdigest())
print("kinds", [p["kind"] for p in e["parts"]][:2] == ["urls", "services"] and any(p.get("media") == "image/png" for p in e["parts"]))
print("profile", e["profile"] == run)
PYENV
assert_grep "$B6/env.txt" '^ids True$'      "envelope: run_id, engagement, job_id from run.json; sensor from the certificate"
assert_grep "$B6/env.txt" '^hashes True$'   "envelope: every part's sha256 is the one in the run's manifest"
assert_grep "$B6/env.txt" '^toolman True$'  "envelope: tool_manifest_sha256 is the manifest file's hash"
assert_grep "$B6/env.txt" '^kinds True$'    "envelope: the record parts, then artifacts (the manifest, the screenshots)"
assert_grep "$B6/env.txt" '^profile True$'  "envelope: profile is run.json, unchanged"
: > "$B6/store/requests.jsonl"
_rc=0; _ship ship "$B6/run1/r.csv" "${OK6[@]}" || _rc=$?;                              _rc_is "$_rc" 0 "ship: delivered (exit 0)"
_np="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["parts"]))' "$B6/envelope.json")"
_rid="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$B6/envelope.json")"
if [ "$(_reqs)" = "POST:runs:201 $(for _i in $(seq 1 "$_np"); do printf 'PUT:%d:204 ' "$_i"; done)POST:complete:202" ]; then _pass "ship: open (201), $_np parts (204 each), complete (202)"; else _fail "ship: open, parts, complete  [$(_reqs)]"; fi
assert_grep "$B6/run1/r.csv.ship-state.json" '"state": "complete"'                     "ship-state.json: complete"
assert_grep "$B6/run1/r.csv.ship-state.json" '"server_state": "verified"'              "ship-state.json: Tideline verified the run"
if cmp -s "$B6/store/runs/$_rid/manifest.json" <(head -c -1 "$B6/envelope.json"); then _pass "Tideline stored the manifest bytes that were signed"; else _fail "Tideline stored the manifest bytes that were signed"; fi
if cmp -s "$B6/store/runs/$_rid/parts/1" "$B6/run1/r.csv.urls.jsonl"; then _pass "the stored urls part equals the local urls.jsonl, byte for byte"; else _fail "the stored urls part equals the local urls.jsonl"; fi
refute_grep "$B6/store/requests.jsonl" '"status": 40[13]'                              "the signature verified (no 401/403)"
: > "$B6/store/requests.jsonl"
_rc=0; _ship ship "$B6/run1/r.csv" || _rc=$?;                                          _rc_is "$_rc" 0 "re-ship with the settings from ship-state.json: exit 0"
if [ "$(_reqs)" = "POST:runs:200" ]; then _pass "re-ship: Tideline answers 200 (same manifest) and nothing is sent again"; else _fail "re-ship: nothing sent again  [$(_reqs)]"; fi
_rc=0; _ship status "$B6/run1/r.csv" || _rc=$?;                                        _rc_is "$_rc" 0 "status: exit 0"
assert_grep "$B6/ship.out" '"state": "verified"'                                        "status: Tideline's state of the run"
_newrun "$B6/run1" "$B6/run2"
printf '[{"method":"PUT","part":2,"status":503,"times":5}]' > "$B6/store/faults.json"; : > "$B6/store/requests.jsonl"
_rc=0; _ship ship "$B6/run2/r.csv" "${OK6[@]}" || _rc=$?;                              _rc_is "$_rc" 4 "Tideline busy (503) on part 2: exit 4, retry later"
assert_grep "$B6/run2/r.csv.ship-state.json" '"state": "failed"'                        "ship-state.json: failed, with the reason"
if [ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["parts_acknowledged"])' "$B6/run2/r.csv.ship-state.json")" = "[1]" ]; then _pass "ship-state.json: the parts Tideline acknowledged ([1])..."; else _fail "ship-state.json: the parts Tideline acknowledged ([1])"; fi
assert_grep "$B6/ship.err" 'part 2 \(r\.csv\.services\.jsonl\): HTTP 503'              "...and the error names the part"
printf '[]' > "$B6/store/faults.json"; : > "$B6/store/requests.jsonl"
_rc=0; _ship ship "$B6/run2/r.csv" || _rc=$?;                                          _rc_is "$_rc" 0 "the retry delivers the run"
if _reqs | grep -qE '^POST:runs:200 PUT:2:204 ' && ! _reqs | grep -q 'PUT:1:'; then _pass "the retry re-opens the run (200) and sends only the parts Tideline lacks"; else _fail "the retry sends only the missing parts  [$(_reqs)]"; fi
_newrun "$B6/run1" "$B6/run3"
printf '[{"method":"PUT","part":3,"action":"drop","times":1}]' > "$B6/store/faults.json"
_rc=0; _ship ship "$B6/run3/r.csv" "${OK6[@]}" || _rc=$?;                              _rc_is "$_rc" 4 "a connection dropped mid-upload: exit 4"
printf '[]' > "$B6/store/faults.json"
_rc=0; _ship ship "$B6/run3/r.csv" || _rc=$?;                                          _rc_is "$_rc" 0 "...and the next attempt completes it"
_newrun "$B6/run1" "$B6/run4"; printf '{"x":1}\n' >> "$B6/run4/r.csv.warnings.jsonl"; : > "$B6/store/requests.jsonl"
_rc=0; _ship ship "$B6/run4/r.csv" "${OK6[@]}" || _rc=$?;                              _rc_is "$_rc" 1 "a part changed after the run: refused locally (exit 1)"
assert_grep "$B6/ship.err" 'r\.csv\.warnings\.jsonl changed since the run wrote its manifest' "...naming the file"
assert_absent "$B6/store/requests.jsonl"                                                "...and nothing was sent"
rm -rf "$B6/run5"; cp -r "$B6/run1" "$B6/run5"; rm -f "$B6/run5/r.csv.ship-state.json"
printf '{"message":"added"}\n' >> "$B6/run5/r.csv.warnings.jsonl"
python3 - "$B6/run5" <<'PYCONF'
import hashlib, os, sys
d = sys.argv[1]; m = os.path.join(d, "r.csv.manifest.sha256")
h = hashlib.sha256(open(os.path.join(d, "r.csv.warnings.jsonl"), "rb").read()).hexdigest()
lines = open(m).readlines()
open(m, "w").write("".join((h + "  r.csv.warnings.jsonl\n") if l.endswith("  r.csv.warnings.jsonl\n") else l for l in lines))
PYCONF
_rc=0; _ship ship "$B6/run5/r.csv" "${OK6[@]}" || _rc=$?;                              _rc_is "$_rc" 5 "the same run_id with a different manifest: Tideline refuses it (409, exit 5)"
assert_grep "$B6/ship.err" 'HTTP 409'                                                   "...with Tideline's reason"
_rc=0; _ship status "$B6/run1/r.csv" --url "$U6" --cert "$P6/rr-other.pem" --key "$P6/rr-other.key" --ca "$P6/root.pem" || _rc=$?; _rc_is "$_rc" 5 "another sensor cannot read this sensor's run (403, exit 5)"
_newrun "$B6/run1" "$B6/run6"; : > "$B6/store/requests.jsonl"
_rc=0; _ship ship "$B6/run6/r.csv" --url "$U6" --cert "$P6/rogue.pem" --key "$P6/rogue.key" --ca "$P6/root.pem" || _rc=$?; _rc_is "$_rc" 5 "a sensor certificate from another CA: refused in the handshake (exit 5)"
if [ ! -d "$B6/store/runs/$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$B6/run6/r.csv.run.json")" ]; then _pass "...and nothing was stored"; else _fail "...and nothing was stored"; fi
_rc=0; _ship ship "$B6/run6/r.csv" --url "$U6" --cert "$P6/rr-test01.pem" --key "$P6/rr-test01.key" --ca "$P6/rogue-root.pem" || _rc=$?; _rc_is "$_rc" 5 "the server does not chain to --ca: refused (exit 5)"
mkdir -p "$B6/sysca"; cp "$P6/root.pem" "$B6/sysca/"; openssl rehash "$B6/sysca" >/dev/null 2>&1 || c_rehash "$B6/sysca" >/dev/null 2>&1
_rc=0; SSL_CERT_DIR="$B6/sysca" CURL_CA_BUNDLE="$P6/root.pem" SSL_CERT_FILE="$P6/root.pem" _ship ship "$B6/run6/r.csv" --url "$U6" --cert "$P6/rr-test01.pem" --key "$P6/rr-test01.key" --ca "$P6/rogue-root.pem" || _rc=$?
_rc_is "$_rc" 5 "pinned: a trust store that would accept the server (SSL_CERT_DIR, CURL_CA_BUNDLE) is not used"
_rc=0; SHIP_RETRIES=0 _ship ship "$B6/run6/r.csv" --url "https://127.0.0.1:9" --cert "$P6/rr-test01.pem" --key "$P6/rr-test01.key" --ca "$P6/root.pem" || _rc=$?; _rc_is "$_rc" 4 "nothing listening: exit 4"
_rc=0; _ship export "$B6/run1/r.csv" --cert "$P6/rr-test01.pem" --key "$P6/rr-test01.key" || _rc=$?; _rc_is "$_rc" 0 "export: a bundle for a hand-carried upload"
python3 - "$B6/run1/r.csv.tideline.tar" "$B6/envelope.json" "$B6/run1" "$P6/rr-test01.pem" > "$B6/tar.txt" 2>&1 <<'PYTAR'
import tarfile, sys, json, gzip, hashlib, base64, subprocess, tempfile, os
t, envp, d, cert = sys.argv[1:5]
tf = tarfile.open(t)
names = tf.getnames()
body = tf.extractfile("envelope.json").read()
print("members", names[:2] == ["envelope.json", "signature.txt"] and all(n.startswith("parts/") for n in names[2:]))
print("envelope", body == open(envp, "rb").read().rstrip(b"\n"))
e = json.loads(body)
ok = True
for p in e["parts"]:
    raw = gzip.decompress(tf.extractfile("parts/%05d.gz" % p["n"]).read())
    ok = ok and hashlib.sha256(raw).hexdigest() == p["sha256"] and len(raw) == p["bytes"]
print("parts", ok and len(names) == 2 + len(e["parts"]))
sig = tf.extractfile("signature.txt").read().decode().strip()
der = base64.b64decode(sig.split("sig=", 1)[1])
with tempfile.TemporaryDirectory() as x:
    open(os.path.join(x, "b"), "wb").write(body); open(os.path.join(x, "s"), "wb").write(der)
    pub = subprocess.run(["openssl", "x509", "-in", cert, "-noout", "-pubkey"], capture_output=True).stdout
    open(os.path.join(x, "k"), "wb").write(pub)
    r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", os.path.join(x, "k"), "-signature", os.path.join(x, "s"), os.path.join(x, "b")], capture_output=True)
print("signature", sig.startswith("alg=ES256; enc=der; sig=") and r.returncode == 0)
PYTAR
for _k in members envelope parts signature; do assert_grep "$B6/tar.txt" "^$_k True\$" "export: $_k as Tideline expects (envelope.json, signature.txt, parts/NNNNN.gz)"; done
rm -rf "$B6/nojson"; mkdir -p "$B6/nojson"; cp "$B6/run1/r.csv" "$B6/run1/r.csv.run.json" "$B6/nojson/"
( cd "$B6/nojson" && sha256sum r.csv r.csv.run.json > r.csv.manifest.sha256 )
_rc=0; _ship ship "$B6/nojson/r.csv" "${OK6[@]}" || _rc=$?;                            _rc_is "$_rc" 1 "a run without --json is not shipped (exit 1)..."
assert_grep "$B6/ship.err" 'run run-recon with --json'                                  "...and the message says how to fix it"

section "Batch 6: run-recon --ship (preflight, delivery, exit 4, same outputs as --json)"
REAL_CURL="$(command -v curl)"
mv "$MOCKBIN/curl" "$MOCKBIN/curl.b6"
cat > "$MOCKBIN/curl" <<EOF
#!/usr/bin/env bash
# ship-recon's calls (-q first) go to the real curl, on loopback; every other call stays mocked
[ "\${1:-}" = -q ] && exec "$REAL_CURL" "\$@"
exec "$MOCKBIN/curl.b6" "\$@"
EOF
chmod +x "$MOCKBIN/curl"
_rr6(){ # <dir> [args...]
  local o="$1"; shift; rm -rf "$o"; mkdir -p "$o"
  timeout 60 env PATH="$TESTPATH" HTTPX_BIN=httpx SECLISTS="$SECLISTS_TEST" RECON_CLOUD_CACHE="$B6/cloud.tsv" TLS_CHAIN_CHECK=0 SHIP_RETRIES=0 \
    bash "$RUN_RECON" -i "$DOMAINS" -D "$o" -o "$o/r.csv" --tls "$@" > /dev/null 2> "$o/stderr.log"
}
rm -f "$MOCKLOG"/*.args
_rc=0; _rr6 "$B6/pre" --ship "$U6" --ship-cert "$B6/missing.pem" --ship-key "$P6/rr-test01.key" --ship-ca "$P6/root.pem" || _rc=$?
_rc_is "$_rc" 2                                                                        "--ship with an unreadable certificate: refused before the scan (exit 2)"
assert_grep  "$B6/pre/stderr.log" 'Nothing was sent'                                   "...and nothing was sent"
if [ ! -e "$MOCKLOG/gau.args" ] && [ ! -e "$B6/pre/r.csv" ]; then _pass "...no tool ran, no CSV"; else _fail "...no tool ran, no CSV"; fi
_rc=0; _rr6 "$B6/s1" --ship "$U6" --ship-cert "$P6/rr-test01.pem" --ship-key "$P6/rr-test01.key" --ship-ca "$P6/root.pem" --engagement eng-1 || _rc=$?
_rc_is "$_rc" 0                                                                        "--ship: the run is delivered (exit 0)"
assert_grep  "$B6/s1/stderr.log" 'Tideline        : run [0-9a-f-]{36} shipped and verified' "--ship: the summary says so"
assert_grep  "$B6/s1/r.csv.ship-state.json" '"state": "complete"'                     "--ship: ship-state.json complete"
assert_exists "$B6/s1/r.csv.urls.jsonl"                                                "--ship implies --json"
refute_grep  "$B6/s1/r.csv.manifest.sha256" 'ship-state'                               "ship-state.json is written after the manifest, not listed in it"
_rr6 "$B6/j1" --json --engagement eng-1 || true
if [ "$(find "$B6/j1" -mindepth 1 -maxdepth 1 -printf '%f\n' | grep -v '^_work\|stderr.log' | sort | tr '\n' ' ')" = "$(find "$B6/s1" -mindepth 1 -maxdepth 1 -printf '%f\n' | grep -v '^_work\|stderr.log\|ship-state' | sort | tr '\n' ' ')" ]; then
  _pass "--ship writes the same files as --json, plus ship-state.json only"; else _fail "--ship writes the same files as --json, plus ship-state.json only"; fi
if diff <(sort "$B6/j1/r.csv") <(sort "$B6/s1/r.csv") >/dev/null && cmp -s "$B6/j1/r.csv.urls.jsonl" "$B6/s1/r.csv.urls.jsonl"; then _pass "--ship: the CSV and urls.jsonl equal the --json run's"; else _fail "--ship: the CSV and urls.jsonl equal the --json run's"; fi
_rc=0; _rr6 "$B6/s2" --ship "https://127.0.0.1:9" --ship-cert "$P6/rr-test01.pem" --ship-key "$P6/rr-test01.key" --ship-ca "$P6/root.pem" || _rc=$?
_rc_is "$_rc" 4                                                                        "--ship to an unreachable Tideline: the run completes and exits 4"
assert_exists "$B6/s2/r.csv"                                                           "...the CSV is there"
assert_grep  "$B6/s2/r.csv.ship-state.json" '"state": "failed"'                       "...ship-state.json says failed"
assert_grep  "$B6/s2/stderr.log" 'retry with: .*ship-recon\.sh ship .*r\.csv'          "...and the message says how to retry"
assert_grep  "$B6/s2/r.csv.run.json" '"exit_status": 0'                                "run.json keeps the scan's own exit status"
mv "$MOCKBIN/curl.b6" "$MOCKBIN/curl"
kill "$B6PID" 2>/dev/null; wait "$B6PID" 2>/dev/null || true

section "Tideline identifiers are frozen (decided 2026-11-06): envelope, header, sensor URN, schema ids, checksums"
python3 - "$SCHEMAS6" "$SHIP6" "$LABDIR6/mock-tideline.py" > "$B6/frozen.txt" 2>&1 <<'PYFRZ'
import json, os, re, sys
sd, ship, mock = sys.argv[1:4]
src, msrc = open(ship, encoding="utf-8").read(), open(mock, encoding="utf-8").read()
def ok(k, c):
    print(k, bool(c))
ok("envelope", 'ENVELOPE = "tideline-envelope/1"' in src and '{"schema": ENVELOPE,' in src)
ok("header", '"Tideline-Signature: " + sig' in src and '"alg=ES256; enc=der; sig="' in src
   and 'self.headers.get("Tideline-Signature")' in msrc)
ok("sensor", 'r"URI:urn:tideline:sensor:([A-Za-z0-9][A-Za-z0-9._-]{0,63})(?=[,\\s]|$)"' in src
   and 'URN = "urn:tideline:sensor:"' in msrc)
ok("endpoints", all(e in src for e in ('"/v1/runs"', '"/v1/runs/%s/parts/%d"', '"/v1/runs/%s/complete"', '"/v1/runs/%s"')))
bad = []
for n in sorted(os.listdir(sd)):
    if not n.endswith(".json"):
        continue
    s = json.load(open(os.path.join(sd, n)))
    sid = s.get("x-tideline-schema", "")
    if s.get("$id") != "urn:tideline:schema:" + sid or n != sid.replace("/", ".") + ".json" or not re.fullmatch(r"[a-z][a-z0-9.-]*/1", sid):
        bad.append(n)
env = json.load(open(os.path.join(sd, "tideline-envelope.1.json")))
ok("schemaids", not bad and env["properties"]["schema"] == {"const": "tideline-envelope/1"})
listed = {l.split()[1].lstrip("*") for l in open(os.path.join(sd, "SHA256SUMS")) if l.strip()}
ok("sumslist", listed == {n for n in os.listdir(sd) if n.endswith(".json")})
PYFRZ
assert_grep "$B6/frozen.txt" '^envelope True$'   "frozen: the envelope schema is tideline-envelope/1"
assert_grep "$B6/frozen.txt" '^header True$'     "frozen: the signature travels as 'Tideline-Signature: alg=ES256; enc=der; sig=<base64>'"
assert_grep "$B6/frozen.txt" '^sensor True$'     "frozen: the sensor is the URI SAN urn:tideline:sensor:<id> (1-64 of A-Z a-z 0-9 . _ -)"
assert_grep "$B6/frozen.txt" '^endpoints True$'  "frozen: the /v1/runs endpoints"
assert_grep "$B6/frozen.txt" '^schemaids True$'  "frozen: every schema's \$id is urn:tideline:schema:<id>, its file <id>.json, major version 1"
assert_grep "$B6/frozen.txt" '^sumslist True$'   "schemas/SHA256SUMS lists every schema file, and only those"
if ( cd "$SCHEMAS6" && sha256sum --quiet -c SHA256SUMS ) >/dev/null 2>&1; then _pass "the frozen schemas match schemas/SHA256SUMS (a change needs a new major id, or x-minor and new sums)"
else _fail "the frozen schemas match schemas/SHA256SUMS  [a frozen schema changed: add a field as x-minor+1 and regenerate the sums, or make a /2]"; fi
T6="$B6/tenant"; mkdir -p "$T6"
_t6cert(){ # <name> <subjectAltName>: a sensor certificate from the test intermediate
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$T6/$1.key" 2>/dev/null; chmod 600 "$T6/$1.key"
  openssl req -new -key "$T6/$1.key" -subj "/CN=$1" -out "$T6/$1.csr" 2>/dev/null
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=%s\n' "$2" > "$T6/$1.ext"
  openssl x509 -req -in "$T6/$1.csr" -CA "$P6/int.pem" -CAkey "$P6/int.key" -CAserial "$T6/int.srl" -CAcreateserial -days 7 \
    -out "$T6/$1.crt" -extfile "$T6/$1.ext" 2>/dev/null
  cat "$T6/$1.crt" "$P6/int.pem" > "$T6/$1.pem"
}
_t6cert tenant 'URI:urn:tideline:sensor:rr-t1,URI:urn:tideline:tenant:acme'
_t6cert combined 'URI:urn:tideline:sensor:acme:rr-t1'
_rc=0; _ship check --url "https://127.0.0.1:9" --cert "$T6/tenant.pem" --key "$T6/tenant.key" --ca "$P6/root.pem" || _rc=$?
_rc_is "$_rc" 0                                                        "a certificate that also carries urn:tideline:tenant:acme passes"
assert_grep "$B6/ship.err" 'settings ok: sensor rr-t1,'                "...and the sensor is its urn:tideline:sensor: URI, not the tenant"
_rc=0; _ship envelope "$B6/run1/r.csv" --cert "$T6/tenant.pem" || _rc=$?
if [ "$_rc" = 0 ] && python3 -c 'import json,sys; e=json.load(open(sys.argv[1])); sys.exit(0 if e["sensor"] == "rr-t1" and "acme" not in json.dumps(e) else 1)' "$B6/ship.out"; then
  _pass "the envelope names the sensor and carries no tenant (ingest takes it from the certificate)"; else _fail "the envelope names the sensor and carries no tenant"; fi
_rc=0; _ship check --url "https://127.0.0.1:9" --cert "$T6/combined.pem" --key "$T6/combined.key" --ca "$P6/root.pem" || _rc=$?
_rc_is "$_rc" 1                                                        "a combined urn:tideline:sensor:<tenant>:<id> is refused (no colon in a sensor id)"

# --- 53) service health check: --resolvers catches dead resolvers ----------
# (placed last: swaps the dig mock for one that reports no reply)
section "service health check: --resolvers detects unreachable resolvers"
DEADRES="$TMP/dead-resolvers.txt"; printf '10.255.255.1\n10.255.255.2\n' > "$DEADRES"
mk dig <<'DIGEOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/dig.args"; echo >> "$MOCKLOG/dig.args"
exit 9   # simulate: no reply from server (dig exit 9)
DIGEOF
run_case deadres --resolve --resolvers "$DEADRES"
assert_grep "$ERRLOG" 'no resolver in .* answered a test query'  "resolver health check warns when resolvers are down"
assert_grep "$ERRLOG" 'DNS-heavy stages'                          "warning explains the timeout impact"

# --- 54) aggregator robustness: a non-object / invalid JSON line in httpx -----
# output must be skipped, not crash the whole aggregation (regression guard).
section "aggregator survives a stray non-object JSON line from httpx"
mk httpx <<'HXEOF'
#!/usr/bin/env bash
printf '%s ' "$@" >> "$MOCKLOG/httpx.args"; echo >> "$MOCKLOG/httpx.args"
for a in "$@"; do [ "$a" = "-h" ] && { echo "  -td, -tech-detect"; exit 0; }; done
mode=probe; for a in "$@"; do [ "$a" = "-json" ] && mode=json; done
list=""; args=("$@"); i=0
while [ $i -lt ${#args[@]} ]; do case "${args[$i]}" in -l|-list) i=$((i+1)); list="${args[$i]:-}";; esac; i=$((i+1)); done
[ -n "$list" ] && [ -f "$list" ] && exec < "$list"
if [ "$mode" = json ]; then
  echo '[]'        # valid JSON but not an object -> must be skipped
  echo 'not-json'  # invalid JSON -> must be skipped
  while IFS= read -r u; do [ -z "$u" ] && continue
    printf '{"input":"%s","url":"%s","status_code":200,"content_length":100,"webserver":"nginx","title":"H","tech":["nginx"],"host":"93.184.216.34"}\n' "$u" "$u"
  done
else while IFS= read -r h; do [ -z "$h" ] && continue; printf 'https://%s\n' "$h"; done; fi
HXEOF
run_case aggjson
assert_grep "$CSV" ',example\.com,gau,200,100,nginx,'  "aggregation completes despite stray [] / invalid JSON lines"

# --- 55) enrichment join robustness (URL normalization + host fallback) ------
# Extract the embedded aggregator and feed it URLs that do NOT exactly match
# httpx's url/input (default port, trailing slash, http->https redirect), plus a
# record whose host matches but URL doesn't -- all must still enrich, and a total
# miss must emit a clear diagnostic (so empty E-L is never silent).
section "enrichment join: URL normalization + host fallback + diagnostics"
AGGDIR="$TMP/aggjoin"; rm -rf "$AGGDIR"; mkdir -p "$AGGDIR"
awk "/^python3 - .*<<'PY'/{f=1;next} f&&/^PY\$/{f=0} f" "$RUN_RECON" > "$AGGDIR/agg.py"
# map URLs deliberately differ from httpx's (port :443, trailing slash, http scheme)
printf 'example.com\thttps://a.example.com:443/\tgau\nexample.com\thttp://b.example.com/\tkatana\n' > "$AGGDIR/map.tsv"
cat > "$AGGDIR/httpx.jsonl" <<'JX'
{"input":"https://a.example.com:443/","url":"https://a.example.com","status_code":200,"content_length":1256,"webserver":"nginx","title":"Alpha","tech":["Nginx"],"host":"1.1.1.1","a":["1.1.1.1"]}
{"url":"https://b.example.com","status_code":301,"content_length":0,"webserver":"Apache","title":"Moved","host":"2.2.2.2","a":["2.2.2.2"]}
JX
( cd "$AGGDIR" && env PATH="$TESTPATH" python3 agg.py map.tsv httpx.jsonl out.csv 0 100 >/dev/null 2>/dev/null )
assert_grep "$AGGDIR/out.csv" 'a\.example\.com:443/,a\.example\.com,gau,200,1256,nginx,Alpha,Nginx,1\.1\.1\.1'  "port/slash mismatch still enriched (URL normalization)"
assert_grep "$AGGDIR/out.csv" 'b\.example\.com/,b\.example\.com,katana,301,0,Apache,Moved,,2\.2\.2\.2'    "http->https redirect still enriched (host fallback)"
# total-miss diagnostic
printf 'example.com\thttps://real.example.com/\tgau\n' > "$AGGDIR/m2.tsv"
printf '{"url":"https://wrong.other.com","status_code":200,"host":"9.9.9.9","a":["9.9.9.9"]}\n' > "$AGGDIR/h2.jsonl"
( cd "$AGGDIR" && env PATH="$TESTPATH" python3 agg.py m2.tsv h2.jsonl o2.csv 0 100 >/dev/null 2>e2.log )
assert_grep "$AGGDIR/e2.log" 'the URL join failed'                     "join failure is diagnosed (records exist, none matched)"
# no-records diagnostic
printf 'example.com\thttps://x.example.com/\tgau\n' > "$AGGDIR/m3.tsv"; : > "$AGGDIR/h3.jsonl"
( cd "$AGGDIR" && env PATH="$TESTPATH" python3 agg.py m3.tsv h3.jsonl o3.csv 0 100 >/dev/null 2>e3.log )
assert_grep "$AGGDIR/e3.log" 'httpx produced 0 JSON records'           "empty httpx output is diagnosed (not silent)"




printf '\n%s========================================%s\n' "$C_Y" "$C_0"
printf ' Total: %d   %sPASS: %d%s   %sFAIL: %d%s\n' "$TESTS" "$C_G" "$PASSN" "$C_0" "$C_R" "$FAILN" "$C_0"
if [ "$FAILN" -gt 0 ]; then
  printf ' Failed:\n'; for f in "${FAILED[@]}"; do printf '   - %s\n' "$f"; done
  printf '%s========================================%s\n' "$C_Y" "$C_0"
  exit 1
fi
printf '%s========================================%s\n' "$C_Y" "$C_0"
exit 0
