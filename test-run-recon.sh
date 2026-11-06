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
__vf=" -timeout -rl -rate-limit -r -resolvers -l -list -o -output -srd -store-response-dir -mc -match-code -t -threads -retries -H -header -p -ports -delay -proxy -http-proxy -ho -headless-options -hash -st -screenshot-timeout -path "
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
cat >/dev/null
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
__vf=" -timeout -rl -rate-limit -r -resolvers -l -list -o -output -srd -store-response-dir -mc -match-code -t -threads -retries -H -header -p -ports -delay -proxy -http-proxy -ho -headless-options -hash -st -screenshot-timeout -path "
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
assert_grep  "$MOCKLOG/notify.args" -- ''                            "notify invoked on the new-asset list"

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
# --tls-full adds the enumeration flags
run_case tlsfull --tls-full
assert_grep "$MOCKLOG/tlsx.args" -- '-version-enum'               "--tls-full enables -version-enum"
assert_grep "$MOCKLOG/tlsx.args" -- '-cipher-enum'                "--tls-full enables -cipher-enum"

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
assert_grep   "$MOCKLOG/psql.args" "'httpx_json_v2','https://example\.com/" "--db: enrichment records that came back are cached (key httpx_json_v2: records cached before 1.19 have no headers)"
assert_grep   "$MOCKLOG/psql.args" "'live_probe!neg'|'live_probe','"      "--db: the live probe keeps its cache entries (dead hosts may be negative-cached)"
refute_grep   "$MOCKLOG/psql.args" "\\('httpx_json_v2!neg','"                  "--db: a URL with no record is NOT negative-cached (retried next run, not blank for NEG_TTL)"
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
assert_grep  "$CSV" '^seed_domain,url,host,.*,cpe,redirect_location,response_ms,body_sha256,content_type,powered_by,auth,cookies,cookie_issues,missing_sec_headers,hsts_max_age,alt_svc,http_flags,favicon_mmh3,favicon_md5,ptr,robots,security_txt.?$' "17 HTTP columns appended after cpe (existing positions unchanged)"
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
assert_grep  "$CSV" ',-732438843,1e23ac45e53e0bd440ab397425229b87,,200 disallow=2 allow=0 sitemap=1,expired contact=mailto:security@example\.com expires=2021-01-01T00:00:00Z.?$' "favicon, robots and security.txt columns on the host's rows"
MOCK_EXTRAS_NOSEC=1 run_case extras_nosec --extras
assert_grep  "$CSV" ',missing.?$'                                           "no security.txt -> security_txt=missing"
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
