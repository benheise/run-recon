#!/usr/bin/env bash
# =============================================================================
# bench-run-recon.sh  --  containerized test range + benchmark harness for
#                         run-recon, modelled on WebInventory's regression lab
#                         and PERFORMANCE.md so the two tools compare.
#
# The range (lab/docker-compose.yml) runs web services at PINNED versions behind
# a vhost-routing TLS ingress, reusing WebInventory's farm composition -- nginx,
# WordPress, a 120 KB SPA, a TLS CI service (Jenkins) -- under RFC 6761 `.test`
# names served by a lab DNS server:
#   lab  : nginx.test wp.test spa.test ci.test        accuracy  (lab/expected.csv)
#   farm : f01..fNN.farm.test, round-robin backends   load      (lab/expected-farm.csv)
# Method (WebInventory's): N runs per scenario, medians, CPU of the whole run-recon
# process tree, accuracy scored every run; a change is kept only if it is faster
# AND its output is field-for-field identical (`compare --exact`).
#
# Commands:
#   up [--farm N]          generate SPA/farm/DNS files, compose up, provision WordPress
#   down                   compose down -v
#   hosts                  print /etc/hosts lines for the lab + farm names
#   run [-o OUT] [--farm] [RUN-RECON FLAGS]
#                          one run-recon run against the lab (or farm) targets
#   compare EXPECTED ACTUAL [--exact]
#                          accuracy vs expected, or field-by-field A/B of two runs
#   bench [--runs N] [--farm] [--flags "..."] [--label L]
#         [--baseline-script PATH | --ab "BASELINE_FLAGS"] [--results FILE]
#                          medians of wall/CPU/RSS + accuracy; with a baseline,
#                          speed-up and an --exact identity check
#   takeover               --takeover against the CNAME fixtures (orphan.test must be
#                          flagged as a dangling CNAME, alias.test must not)
#   zone                   --zone-exposure against the zone fixtures (xfr.test: open AXFR,
#                          walk.test: walkable NSEC chain, test.: neither) -- needs ldnsutils
#   origin                 --origin against the forgotten-origin fixture (nginx.test must be
#                          origin-exposed at LAB_ORIGIN_IP; spa.test and wp.test must not)
#   checks                 takeover + zone + origin; non-zero if any fails
#   help
#
# Needs docker (+compose) and the run-recon toolchain for up/run/bench; compare
# needs only bash + python3.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LAB="$HERE/lab"
RUN_RECON="${RUN_RECON:-$HERE/run-recon.sh}"
COMPOSE_FILE="$LAB/docker-compose.yml"
RESOLVERS_FILE="$LAB/resolvers.txt"
# lab DNS listen address; any 127.0.0.0/8 address works if 127.0.0.1:53 is taken
# (Pi-hole/dnsmasq on the VM). `up` writes it to resolvers.txt; compose reads it.
LAB_DNS_IP="${LAB_DNS_IP:-127.0.0.1}"
# the "forgotten origin": nginx's backend published directly on this loopback address,
# leaked through direct.nginx.test and nginx.test's SPF record (origin-identification fixture)
LAB_ORIGIN_IP="${LAB_ORIGIN_IP:-127.0.0.5}"
LAB_HOSTS="nginx.test wp.test spa.test ci.test"
FARM_N_DEFAULT=50
FARM_BACKENDS=(nginx wordpress spa jenkins)

c_y=$'\033[1;33m'; c_0=$'\033[0m'
log(){ printf '%s[bench]%s %s\n' "$c_y" "$c_0" "$*" >&2; }
die(){ printf '[bench] error: %s\n' "$*" >&2; exit 2; }
have(){ command -v "$1" >/dev/null 2>&1; }
compose(){
  if have docker && docker compose version >/dev/null 2>&1; then docker compose "$@"
  elif have docker-compose; then docker-compose "$@"
  else return 127; fi
}
# lab traffic is local: keep `.test` off any outbound HTTP(S) proxy (scoped; the
# proxy stays in force for everything else -- e.g. run-recon's internet lookups).
lab_env(){
  case ",${NO_PROXY:-}," in *",.test,"*) ;; *) export NO_PROXY="${NO_PROXY:+$NO_PROXY,}.test";; esac
  case ",${no_proxy:-}," in *",.test,"*) ;; *) export no_proxy="${no_proxy:+$no_proxy,}.test";; esac
}

# ---- generated fixtures ------------------------------------------------------
gen_lab(){ # <farm_n>
  local n="${1:-$FARM_N_DEFAULT}" i b name
  case "$n" in ''|*[!0-9]*) n=$FARM_N_DEFAULT;; esac
  mkdir -p "$LAB/spa"
  # 120 KB single-bundle SPA (WebInventory's farm uses a 120 KB SPA)
  {
    printf '<!doctype html><html><head><meta charset="utf-8"><title>Lab SPA</title></head>'
    printf '<body><div id="app"></div><script>\n'
    i=0; while [ "$i" -lt 1600 ]; do
      printf '/* %05d */ var _f%05d=function(){return "lab-spa-payload-token-%05d";};\n' "$i" "$i" "$i"; i=$((i+1))
    done
    printf '</script></body></html>\n'
  } > "$LAB/spa/index.html"
  case "$LAB_DNS_IP" in 127.*) ;; *) die "LAB_DNS_IP must be a loopback (127.0.0.0/8) address: $LAB_DNS_IP";; esac
  printf '%s\n' "$LAB_DNS_IP" > "$RESOLVERS_FILE"
  : > "$LAB/farm.caddy"; : > "$LAB/targets-farm.txt"
  printf 'host,status,technologies,cpe,tls_flags,ipv6,min_urls\n' > "$LAB/expected-farm.csv"
  {
    printf '127.0.0.1 %s\n' "$LAB_HOSTS"
    printf '2001:db8:1::10 nginx.test wp.test\n'
  } > "$LAB/lab.hosts"
  i=1
  while [ "$i" -le "$n" ]; do
    name="$(printf 'f%02d.farm.test' "$i")"
    b="${FARM_BACKENDS[$(( (i-1) % ${#FARM_BACKENDS[@]} ))]}"
    case "$b" in
      wordpress)
        # WordPress serves its configured site name; present that Host upstream
        printf 'http://%s, https://%s {\n\treverse_proxy wordpress:80 {\n\t\theader_up Host wp.test\n\t}\n}\n\n' "$name" "$name" >> "$LAB/farm.caddy"
        printf '%s,200,WordPress;PHP;Apache HTTP Server,cpe:2.3:a:wordpress:wordpress:6.4.3;cpe:2.3:a:apache:http_server:2.4.57;cpe:2.3:a:php:php:8.2.17,CertExpiring;CertUntrusted,-,1\n' "$name" >> "$LAB/expected-farm.csv";;
      jenkins)
        printf 'http://%s, https://%s {\n\treverse_proxy jenkins:8080\n}\n\n' "$name" "$name" >> "$LAB/farm.caddy"
        printf '%s,403,Jenkins;Jetty,cpe:2.3:a:jenkins:jenkins:2.426.1;cpe:2.3:a:eclipse:jetty:10.0.17,CertExpiring;CertUntrusted,-,1\n' "$name" >> "$LAB/expected-farm.csv";;
      *)
        printf 'http://%s, https://%s {\n\treverse_proxy %s:80\n}\n\n' "$name" "$name" "$b" >> "$LAB/farm.caddy"
        printf '%s,200,Nginx,cpe:2.3:a:f5:nginx:1.21.6,CertExpiring;CertUntrusted,-,1\n' "$name" >> "$LAB/expected-farm.csv";;
    esac
    printf '127.0.0.1 %s\n' "$name" >> "$LAB/lab.hosts"
    printf '%s\n' "$name" >> "$LAB/targets-farm.txt"
    i=$((i+1))
  done
  # Zone files use BIND's db.<zone> naming (files ending in .zone did not survive some
  # synced folders). Serial = epoch, so CoreDNS reloads a zone when it is regenerated.
  local serial; serial="$(date +%s)"
  # test.: every A/AAAA record above, plus fixtures for three checks
  #   takeover: alias.test -> nginx.test (healthy, must not be flagged) and orphan.test ->
  #             gone.cloud.test, a name that does not exist (a dangling CNAME)
  #   origin:   direct.nginx.test and nginx.test's SPF record leak $LAB_ORIGIN_IP, where the
  #             nginx backend answers directly, bypassing the Caddy edge
  #   zone:     test. itself is unsigned and refuses AXFR (the negative case)
  {
    printf '$ORIGIN test.\n$TTL 60\n'
    printf '@ IN SOA ns.test. hostmaster.test. %s 7200 3600 1209600 60\n' "$serial"
    printf '@ IN NS ns.test.\nns IN A 127.0.0.1\n'
    awk '{ ip=$1; t=(ip ~ /:/) ? "AAAA" : "A"; for (i=2; i<=NF; i++) printf "%s. IN %s %s\n", $i, t, ip }' "$LAB/lab.hosts"
    printf 'alias IN CNAME nginx.test.\norphan IN CNAME gone.cloud.test.\n'
    printf 'direct.nginx.test. IN A %s\n' "$LAB_ORIGIN_IP"
    printf 'nginx.test. IN TXT "v=spf1 ip4:%s -all"\n' "$LAB_ORIGIN_IP"
  } > "$LAB/db.test"
  rm -f "$LAB/test.zone"
  # zone-exposure fixtures: names that no wordlist or passive source would find
  #   walk.test   DNSSEC-signed with NSEC  -> the chain can be walked
  #   xfr.test    unsigned, AXFR allowed   -> the whole zone in one query
  # (No NSEC3 zone: CoreDNS's file plugin cannot serve NSEC3; the suite covers it.)
  local z
  for z in walk.test xfr.test; do
    {
      printf '$ORIGIN %s.\n$TTL 60\n' "$z"
      printf '@ IN SOA ns.%s. hostmaster.%s. %s 7200 3600 1209600 60\n' "$z" "$z" "$serial"
      printf '@ IN NS ns.%s.\nns IN A 127.0.0.1\n@ IN A 127.0.0.1\nwww IN A 127.0.0.1\n' "$z"
      case "$z" in
        walk.test)  printf 'secret-admin IN A 127.0.0.1\nvpn-legacy IN A 127.0.0.1\nq7-billing-replica IN A 127.0.0.1\n';;
        xfr.test)   printf 'hidden-ops IN A 127.0.0.1\nstaging-api-2019 IN A 127.0.0.1\n';;
      esac
    } > "$LAB/db.$z"
  done
  sign_zone walk.test 0
  rm -f "$LAB"/db.nsec3.test* "$LAB"/dnssec/Knsec3.test.*
  printf 'walk.test\nxfr.test\nnginx.test\n' > "$LAB/targets-zone.txt"
  printf 'nginx.test\nalias.test\norphan.test\n' > "$LAB/targets-takeover.txt"
  printf 'nginx.test\nspa.test\nwp.test\n' > "$LAB/targets-origin.txt"
  log "generated: SPA (120 KB), farm of $n vhosts, zones db.test db.walk.test db.xfr.test, targets and ground truth"
}

# sign_zone ZONE NSEC3(0|1): DNSSEC-sign lab/db.ZONE into lab/db.ZONE.signed with
# throwaway keys in lab/dnssec/ (ldnsutils). Without ldns the zone is served unsigned,
# and the zone check will (correctly) report it as not walkable.
sign_zone(){
  local z="$1" n3="$2" f="$LAB/db.$1" kd="$LAB/dnssec" zsk ksk
  if ! have ldns-signzone || ! have ldns-keygen; then
    log "ldnsutils not installed: $z served UNSIGNED (apt install ldnsutils, then rerun up)"
    cp "$f" "$f.signed"; return 0
  fi
  mkdir -p "$kd"; rm -f "$kd/K$z."*
  zsk="$(cd "$kd" && ldns-keygen -a ECDSAP256SHA256 "$z")" || die "ldns-keygen failed for $z"
  ksk="$(cd "$kd" && ldns-keygen -k -a ECDSAP256SHA256 "$z")" || die "ldns-keygen failed for $z"
  if [ "$n3" = 1 ]; then
    ( cd "$kd" && ldns-signzone -n -t 5 -s 1a2b3c4d -o "$z" -f "$f.signed" "$f" "$zsk" "$ksk" ) || die "ldns-signzone failed for $z"
  else
    ( cd "$kd" && ldns-signzone -o "$z" -f "$f.signed" "$f" "$zsk" "$ksk" ) || die "ldns-signzone failed for $z"
  fi
}

# lab curl: pin the URL's host to the loopback ingress, so the harness's own checks
# never depend on /etc/hosts or the system resolver. Checks use plain http:// (the
# ingress serves every name on :80 too), so no certificate check is ever skipped.
lcurl(){ # <url> [curl args...]
  local u="$1"; shift
  local h="${u#*://}"; h="${h%%/*}"; h="${h%%:*}"
  curl -s --resolve "$h:80:127.0.0.1" --resolve "$h:443:127.0.0.1" "$@" "$u"
}

wait_http(){ # <url> <acceptable-codes-regex> <tries>
  local u="$1" ok="$2" n="${3:-60}" c i
  for i in $(seq 1 "$n"); do
    c="$(lcurl "$u" -o /dev/null -w '%{http_code}' --max-time 5 2>/dev/null)"
    printf '%s' "$c" | grep -Eq "^($ok)$" && return 0
    sleep 3
  done
  return 1
}

provision(){
  lab_env
  log "waiting for WordPress + Jenkins (first boot can take a minute or two)..."
  wait_http "http://wp.test/" '200|302' 80 || die "WordPress did not come up"
  if lcurl "http://wp.test/" -o /dev/null -w '%{http_code}' | grep -q 302; then
    local pw; pw="lab-$(head -c9 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    lcurl "http://wp.test/wp-admin/install.php?step=2" -o /dev/null --max-time 120 -X POST \
      --data-urlencode "weblog_title=Lab WordPress" --data-urlencode "user_name=labadmin" \
      --data-urlencode "admin_password=$pw" --data-urlencode "admin_password2=$pw" \
      --data-urlencode "pw_weak=1" --data-urlencode "admin_email=lab@wp.test" --data-urlencode "blog_public=0"
    log "WordPress installed (throwaway admin password, not stored)."
  fi
  wait_http "http://wp.test/" '200' 40 || die "WordPress install did not complete"
  wait_http "http://ci.test/" '403|200' 80 || die "Jenkins did not come up"
  log "lab ready."
}

cmd_up(){
  local farm="$FARM_N_DEFAULT"
  while [ "$#" -gt 0 ]; do case "$1" in --farm) farm="${2:-$FARM_N_DEFAULT}"; shift 2 || shift;; *) shift;; esac; done
  have docker || die "docker not found. Install Docker + compose, then re-run on your lab host."
  gen_lab "$farm"
  log "starting the range (lab DNS on $LAB_DNS_IP:53, exposed origin on $LAB_ORIGIN_IP:80)..."
  export LAB_DNS_IP LAB_ORIGIN_IP
  compose -f "$COMPOSE_FILE" up -d \
    || die "compose up failed (if $LAB_DNS_IP:53 is in use, retry with LAB_DNS_IP=127.0.0.2)"
  if ! grep -q 'nginx\.test' /etc/hosts 2>/dev/null; then
    log "add the lab names to /etc/hosts:   sudo sh -c '$0 hosts >> /etc/hosts'"
    log "(lab DNS on $LAB_DNS_IP serves them too; /etc/hosts covers tools that use the system resolver)"
  fi
  provision
  log "then:  $0 bench --runs 3            (lab accuracy)"
  log "       $0 bench --runs 3 --farm     (farm load)"
}
cmd_down(){ export LAB_DNS_IP LAB_ORIGIN_IP; compose -f "$COMPOSE_FILE" down -v 2>/dev/null; log "range down."; }
cmd_hosts(){
  printf '127.0.0.1 %s\n' "$LAB_HOSTS"
  [ -f "$LAB/targets-farm.txt" ] && while IFS= read -r h; do [ -n "$h" ] && printf '127.0.0.1 %s\n' "$h"; done < "$LAB/targets-farm.txt"
}

# ---- measurement ---------------------------------------------------------------
# measure <logprefix> <cmd...> -> stdout "wall_s cpu_s rss_kb"; stderr of cmd -> <logprefix>.err
measure(){
  local lp="$1"; shift
  local tf; tf="$(mktemp)"
  if [ -x /usr/bin/time ] && /usr/bin/time -v true >/dev/null 2>&1; then
    /usr/bin/time -v -o "$tf" "$@" >"$lp.out" 2>"$lp.err" || true
    awk '
      /Elapsed \(wall clock\)/ { n=split($NF,a,":"); w=(n==3)?a[1]*3600+a[2]*60+a[3]:(n==2)?a[1]*60+a[2]:a[1] }
      /User time/   { u=$NF }
      /System time/ { s=$NF }
      /Maximum resident set size/ { r=$NF }
      END { printf "%.2f %.2f %d\n", w+0, u+s+0, r+0 }' "$tf"
  else
    local b e; b="$(date +%s.%N)"; "$@" >"$lp.out" 2>"$lp.err" || true; e="$(date +%s.%N)"
    awk -v b="$b" -v e="$e" 'BEGIN{printf "%.2f 0.00 0\n", e-b}'
  fi
  rm -f "$tf"
}
median(){ sort -n | awk '{a[NR]=$1} END{ if(NR==0){print 0} else if(NR%2){print a[(NR+1)/2]} else {printf "%.2f\n",(a[NR/2]+a[NR/2+1])/2} }'; }

cmd_run(){
  lab_env
  local out="" farm=0 pass=()
  while [ "$#" -gt 0 ]; do
    case "$1" in -o|--output) out="${2:-}"; shift 2 || shift;; --farm) farm=1; shift;; *) pass+=("$1"); shift;; esac
  done
  [ -f "$RUN_RECON" ] || die "run-recon not found at $RUN_RECON (set RUN_RECON=...)"
  local targets="$LAB/targets.txt"; [ "$farm" = 1 ] && targets="$LAB/targets-farm.txt"
  [ -f "$targets" ] || die "missing $targets (run: $0 up)"
  [ -n "$out" ] || out="$HERE/bench-out.csv"
  bash "$RUN_RECON" -i "$targets" -o "$out" --resolvers "$RESOLVERS_FILE" "${pass[@]}"
}

# ---- compare: accuracy vs expected, or field-by-field A/B ---------------------
cmd_compare(){
  local exact=0 a="" b=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --exact) exact=1; shift;;
      -h|--help) echo "usage: $0 compare EXPECTED ACTUAL [--exact]" >&2; return 0;;
      -*) die "compare: unknown option: $1";;
      *) if [ -z "$a" ]; then a="$1"; elif [ -z "$b" ]; then b="$1"; fi; shift;;
    esac
  done
  [ -n "$a" ] && [ -n "$b" ] || die "usage: $0 compare EXPECTED ACTUAL [--exact]"
  [ -f "$a" ] || die "compare: not found: $a"
  [ -f "$b" ] || die "compare: not found: $b"
  have python3 || die "compare: python3 required"
  BENCH_EXACT="$exact" python3 -I - "$a" "$b" <<'PYCMP'
import sys, os, csv, re

a_path, b_path = sys.argv[1], sys.argv[2]
EXACT = os.environ.get("BENCH_EXACT", "0") == "1"
# columns that legitimately differ run-to-run and are excluded from --exact
VOLATILE = {"cert_not_after"}

def rows(path):
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        return list(csv.DictReader(fh))

def norm(s):
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())

ar, br = rows(a_path), rows(b_path)

if EXACT:
    # A/B reproducibility: key rows by (seed_domain,url); compare shared columns.
    def key(r): return (r.get("seed_domain", ""), r.get("url", ""))
    am = {key(r): r for r in ar}
    bm = {key(r): r for r in br}
    cols = [c for c in (ar[0].keys() if ar else []) if c in (br[0].keys() if br else []) and c not in VOLATILE]
    diffs = 0
    only_a = sorted(set(am) - set(bm))
    only_b = sorted(set(bm) - set(am))
    for k in only_a: print("only in A: %s %s" % k); diffs += 1
    for k in only_b: print("only in B: %s %s" % k); diffs += 1
    for k in sorted(set(am) & set(bm)):
        for c in cols:
            if (am[k].get(c) or "") != (bm[k].get(c) or ""):
                print("differ %s %s [%s]: %r != %r" % (k[0], k[1], c, am[k].get(c), bm[k].get(c)))
                diffs += 1
    a_cols = set(ar[0].keys()) if ar else set()
    b_cols = set(br[0].keys()) if br else set()
    if b_cols - a_cols:
        print("columns only in B (new, not compared): %s" % ",".join(sorted(b_cols - a_cols)))
    if a_cols - b_cols:
        print("columns only in A (dropped, not compared): %s" % ",".join(sorted(a_cols - b_cols)))
    print("EXACT: %d row(s) A, %d row(s) B, %d difference(s)" % (len(ar), len(br), diffs))
    print("RESULT: %s" % ("identical" if diffs == 0 else "DIFFERENT"))
    sys.exit(0 if diffs == 0 else 1)

# accuracy vs expected: a=EXPECTED, b=ACTUAL. Expected columns (any subset):
# host, status, technologies (;), cpe (;), tls_flags (;), ipv6 ("-" = must be empty),
# min_urls (crawl coverage: at least this many rows for the host).
by_host = {}
for r in br:
    h = (r.get("host") or "").strip().lower()
    if not h:
        continue
    d = by_host.setdefault(h, {"status": set(), "tech": "", "cpe": "", "tls": "", "ipv6": set(), "n": 0})
    d["n"] += 1
    if r.get("status_code"): d["status"].add(r["status_code"].strip())
    d["tech"] += ";" + norm(r.get("technologies", ""))
    d["cpe"]  += ";" + (r.get("cpe", "") or "").lower()
    d["tls"]  += ";" + (r.get("tls_flags", "") or "").lower()
    v6 = (r.get("ipv6") or "").strip()
    if v6: d["ipv6"].add(v6)

total = diffs = found = 0
for exp in ar:
    h = (exp.get("host") or "").strip().lower()
    if not h:
        continue
    total += 1
    act = by_host.get(h)
    if not act:
        print("MISS host not discovered: %s" % h); diffs += 1; continue
    found += 1
    want_n = (exp.get("min_urls") or "").strip()
    if want_n.isdigit() and act["n"] < int(want_n):
        print("DIFF %s coverage: want >= %s URL rows, got %d" % (h, want_n, act["n"])); diffs += 1
    want_status = (exp.get("status") or "").strip()
    if want_status and want_status not in act["status"]:
        print("DIFF %s status: want %s, got {%s}" % (h, want_status, ",".join(sorted(act["status"])))); diffs += 1
    for t in (exp.get("technologies") or "").split(";"):
        t = norm(t)
        if t and t not in act["tech"]:
            print("DIFF %s missing technology: %s" % (h, t)); diffs += 1
    for cp in (exp.get("cpe") or "").split(";"):
        cp = cp.strip().lower()
        if cp and cp not in act["cpe"]:
            print("DIFF %s missing cpe: %s" % (h, cp)); diffs += 1
    for fl in (exp.get("tls_flags") or "").split(";"):
        fl = fl.strip().lower()
        if fl and fl not in act["tls"]:
            print("DIFF %s missing tls_flag: %s" % (h, fl)); diffs += 1
    want6 = (exp.get("ipv6") or "").strip()
    if want6 == "-":
        if act["ipv6"]:
            print("DIFF %s ipv6: want none, got {%s}" % (h, ",".join(sorted(act["ipv6"])))); diffs += 1
    elif want6 and not any(want6 in v for v in act["ipv6"]):
        print("DIFF %s ipv6: want %s, got {%s}" % (h, want6, ",".join(sorted(act["ipv6"])))); diffs += 1

print("ACCURACY: %d/%d expected host(s) discovered, %d difference(s)" % (found, total, diffs))
print("RESULT: %s" % ("identical" if diffs == 0 and found == total else "DIFFERENCES"))
sys.exit(0 if (diffs == 0 and found == total) else 1)
PYCMP
}

# ---- bench ---------------------------------------------------------------------
cmd_bench(){
  lab_env
  local runs=3 farm=0 flags="" label="" base_script="" ab="" results=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --runs)            runs="${2:-3}"; shift 2 || shift;;
      --farm)            farm=1; shift;;
      --flags)           flags="${2:-}"; shift 2 || shift;;
      --label)           label="${2:-}"; shift 2 || shift;;
      --baseline-script) base_script="${2:-}"; shift 2 || shift;;
      --ab)              ab="${2:-}"; shift 2 || shift;;
      --results)         results="${2:-}"; shift 2 || shift;;
      -h|--help) sed -n '2,41p' "$0" | sed 's/^# \{0,1\}//'; return 0;;
      -*) die "bench: unknown option: $1";;
      *) shift;;
    esac
  done
  case "$runs" in ''|*[!0-9]*) runs=3;; esac
  [ -f "$RUN_RECON" ] || die "run-recon not found at $RUN_RECON"
  local targets="$LAB/targets.txt" expected="$LAB/expected.csv" scen="lab"
  if [ "$farm" = 1 ]; then targets="$LAB/targets-farm.txt"; expected="$LAB/expected-farm.csv"; scen="farm"; fi
  [ -f "$targets" ] || die "missing $targets (run: $0 up)"
  [ -n "$label" ] || label="$scen${flags:+ $flags}"
  local tdir; tdir="$(mktemp -d "${TMPDIR:-/tmp}/bench.XXXXXX")"

  _one(){ # <tag> <script> <flags> -> "wall cpu rss acc" medians; last CSV at $tdir/<tag>.csv
    local tag="$1" script="$2" fl="$3" i walls="" cpus="" rsss="" accs="" out w c r a
    for i in $(seq 1 "$runs"); do
      out="$tdir/$tag.$i.csv"; rm -rf "$tdir/$tag.$i.d"; mkdir -p "$tdir/$tag.$i.d"
      # shellcheck disable=SC2086
      read -r w c r < <(cd "$tdir/$tag.$i.d" && measure "$tdir/$tag.$i" bash "$script" -i "$targets" -o "$out" --resolvers "$RESOLVERS_FILE" --no-report $fl)
      a="n/a"
      if [ -f "$expected" ] && [ -f "$out" ]; then
        if cmd_compare "$expected" "$out" >"$tdir/$tag.$i.acc" 2>&1; then a="ok"
        else a="$(grep -cE '^(DIFF|MISS)' "$tdir/$tag.$i.acc")d"; fi
      fi
      log "  $tag run $i/$runs: wall ${w}s cpu ${c}s rss ${r}KB accuracy $a"
      walls+="$w"$'\n'; cpus+="$c"$'\n'; rsss+="$r"$'\n'; accs+="$a "
    done
    cp "$tdir/$tag.$runs.csv" "$tdir/$tag.csv" 2>/dev/null || true
    local okn; okn="$(printf '%s' "$accs" | tr ' ' '\n' | grep -c '^ok$')"
    printf '%s %s %s %s\n' "$(printf '%s' "$walls" | median)" "$(printf '%s' "$cpus" | median)" \
      "$(printf '%s' "$rsss" | median)" "$okn/$runs"
  }

  log "scenario '$label' ($runs run(s); targets $(wc -l < "$targets") host(s))"
  local w1 c1 r1 a1; read -r w1 c1 r1 a1 < <(_one cand "$RUN_RECON" "$flags")
  printf '\n%-34s %9s %9s %11s  %s\n' "scenario" "wall s" "cpu s" "maxRSS KB" "accuracy (runs exact vs expected)"
  printf '%-34s %9s %9s %11s  %s\n' "$label" "$w1" "$c1" "$r1" "$a1"
  local line="$label|$w1|$c1|$r1|$a1"

  if [ -n "$base_script" ] || [ -n "$ab" ]; then
    local bs="${base_script:-$RUN_RECON}" bf="${ab:-$flags}"
    [ -f "$bs" ] || die "baseline script not found: $bs"
    log "baseline ($( [ -n "$base_script" ] && echo "script $bs" || echo "flags: $bf"))"
    local w0 c0 r0 a0; read -r w0 c0 r0 a0 < <(_one base "$bs" "$bf")
    local ident; if cmd_compare "$tdir/base.csv" "$tdir/cand.csv" --exact >"$tdir/ab.log" 2>&1; then ident="identical"
      else ident="DIFFERENT ($(grep -c '^differ\|^only' "$tdir/ab.log") field(s); see $tdir/ab.log)"; fi
    local sp csp
    sp="$(awk -v a="$w0" -v b="$w1" 'BEGIN{ if(b>0) printf "%.2fx", a/b; else print "n/a"}')"
    csp="$(awk -v a="$c0" -v b="$c1" 'BEGIN{ if(a>0) printf "%.0f%%", 100*(a-b)/a; else print "n/a"}')"
    printf '%-34s %9s %9s %11s  %s\n' "  baseline" "$w0" "$c0" "$r0" "$a0"
    printf '\nA/B: wall %ss -> %ss (%s speed-up), CPU saved %s; output %s\n' "$w0" "$w1" "$sp" "$csp" "$ident"
    printf '(WebInventory bar: keep a change only if it is faster AND output is field-for-field identical.)\n'
    line="$line|base:$w0|$c0|$r0|$a0|$sp|$csp|$ident"
  fi
  [ -n "$results" ] && printf '%s\n' "$line" >> "$results"
  log "run CSVs, stderr logs and accuracy reports: $tdir"
}

# takeover: the CNAME fixtures in lab/db.test, checked end to end with the real tools
cmd_takeover(){
  lab_env
  [ -f "$RUN_RECON" ] || die "run-recon not found at $RUN_RECON"
  [ -s "$LAB/targets-takeover.txt" ] || die "no lab/targets-takeover.txt (run: $0 up)"
  local t; t="$(mktemp -d /tmp/bench-takeover.XXXXXX)"
  log "takeover check against lab/targets-takeover.txt -> $t"
  ( cd "$t" && bash "$RUN_RECON" -i "$LAB/targets-takeover.txt" -o "$t/tk.csv" \
      --resolvers "$RESOLVERS_FILE" --takeover --resolve --no-report >"$t/run.out" 2>"$t/run.err" ) || true
  local f="$t/tk.csv.takeover.txt" fail=0
  if grep -qE 'dangling-cname \[(medium|high)\] host=orphan\.test cname=gone\.cloud\.test dns=NXDOMAIN' "$f" 2>/dev/null; then
    log "  ok   orphan.test -> gone.cloud.test flagged as a dangling CNAME"
  else log "  FAIL orphan.test not flagged (see $f, $t/run.err)"; fail=1; fi
  if grep -qE 'host=alias\.test' "$f" 2>/dev/null; then log "  FAIL healthy alias.test was flagged"; fail=1
  else log "  ok   healthy alias.test (-> nginx.test) not flagged"; fi
  if grep -qE 'Show only potentially' "$f" 2>/dev/null; then log "  FAIL subzy banner recorded as a finding"; fail=1; fi
  if grep -qE '^alias\.test	alias\.test	nginx\.test	resolves' "$t/tk.csv.cname.tsv" 2>/dev/null; then
    log "  ok   CNAME inventory lists alias.test"
  else log "  FAIL CNAME inventory incomplete ($t/tk.csv.cname.tsv)"; fail=1; fi
  [ "$fail" = 0 ] && log "takeover check: PASS" || log "takeover check: FAIL"
  return "$fail"
}

# zone: the --zone-exposure fixtures (db.xfr.test, db.walk.test.signed, db.test)
cmd_zone(){
  lab_env
  [ -f "$RUN_RECON" ] || die "run-recon not found at $RUN_RECON"
  [ -s "$LAB/targets-zone.txt" ] || die "no lab/targets-zone.txt (run: $0 up)"
  local t; t="$(mktemp -d /tmp/bench-zone.XXXXXX)"
  log "zone exposure check against lab/targets-zone.txt -> $t"
  ( cd "$t" && bash "$RUN_RECON" -i "$LAB/targets-zone.txt" -o "$t/z.csv" \
      --resolvers "$RESOLVERS_FILE" --zone-exposure --resolve --no-report >"$t/run.out" 2>"$t/run.err" ) || true
  local f="$t/z.csv.zone.txt" n="$t/z.csv.zone-names.txt" fail=0
  _ck(){ if grep -qE "$2" "$1" 2>/dev/null; then log "  ok   $3"; else log "  FAIL $3 (see $1, $t/run.err)"; fail=1; fi; }
  _ck "$f" '^\[xfr\.test\] zone-transfer-open \[high\] host=xfr\.test zone=xfr\.test ns=ns\.xfr\.test' "xfr.test: open zone transfer flagged [high]"
  _ck "$n" '^xfr\.test	hidden-ops\.xfr\.test	axfr$'                "xfr.test: hidden-ops harvested by AXFR"
  if grep -q 'NSEC' "$LAB/db.walk.test.signed" 2>/dev/null; then
    _ck "$f" '^\[walk\.test\] nsec-zone-walkable \[medium\] host=walk\.test zone=walk\.test names=5' "walk.test: NSEC chain walked [medium], 5 names"
    _ck "$n" '^walk\.test	secret-admin\.walk\.test	nsec$'           "walk.test: secret-admin harvested by the walk"
  else
    log "  skip walk.test is unsigned (install ldnsutils, then rerun up)"
  fi
  _ck "$f" '^\[test\] zone-checked \[info\] host=test zone=test signed=no axfr=refused' "test.: transfer refused, unsigned -> zone-checked [info]"
  if grep -qE 'zone-transfer-open.*zone=test |nsec-zone-walkable.*zone=test ' "$f" 2>/dev/null; then log "  FAIL test. reported as exposed"; fail=1; fi
  _ck "$t/z.csv" ',http[s]?://secret-admin\.walk\.test,|,http[s]?://hidden-ops\.xfr\.test,' "harvested names are probed and inventoried"
  [ "$fail" = 0 ] && log "zone check: PASS" || log "zone check: FAIL"
  return "$fail"
}

# origin: nginx's backend answers directly on LAB_ORIGIN_IP (leaked by direct.nginx.test
# and nginx.test's SPF record); spa.test and wp.test have no reachable origin
cmd_origin(){
  lab_env
  [ -f "$RUN_RECON" ] || die "run-recon not found at $RUN_RECON"
  [ -s "$LAB/targets-origin.txt" ] || die "no lab/targets-origin.txt (run: $0 up)"
  local t; t="$(mktemp -d /tmp/bench-origin.XXXXXX)"
  log "origin check against lab/targets-origin.txt -> $t"
  ( cd "$t" && bash "$RUN_RECON" -i "$LAB/targets-origin.txt" -o "$t/o.csv" \
      --resolvers "$RESOLVERS_FILE" --origin --no-report >"$t/run.out" 2>"$t/run.err" ) || true
  local f="$t/o.csv.origin.txt" e="$t/o.csv.edge.tsv" fail=0 ip
  ip="$(printf '%s' "$LAB_ORIGIN_IP" | sed 's/\./\\./g')"
  if grep -qE "origin-exposed \[high\] host=nginx\.test origin=$ip port=80 via=[^ ]*(direct\.nginx\.test|spf)" "$f" 2>/dev/null; then
    log "  ok   nginx.test: origin $LAB_ORIGIN_IP verified behind the edge"
  else log "  FAIL nginx.test origin not found (see $f, $t/run.err)"; fail=1; fi
  if grep -qE 'host=(spa|wp)\.test' "$f" 2>/dev/null; then log "  FAIL spa.test/wp.test reported (no exposed origin there)"; fail=1
  else log "  ok   spa.test and wp.test not reported"; fi
  if grep -qE '^nginx\.test	nginx\.test	Caddy	nginx/' "$e" 2>/dev/null; then log "  ok   edge.tsv: nginx.test edge Caddy, origin software nginx"
  else log "  FAIL edge.tsv incomplete ($e)"; fail=1; fi
  if grep -q $'\033' "$f" "$e" 2>/dev/null; then log "  FAIL terminal colour codes in the artifacts"; fail=1; fi
  [ "$fail" = 0 ] && log "origin check: PASS" || log "origin check: FAIL"
  return "$fail"
}

cmd_checks(){
  local rc=0
  cmd_takeover || rc=1
  cmd_zone || rc=1
  cmd_origin || rc=1
  [ "$rc" = 0 ] && log "lab checks: PASS (takeover, zone, origin)" || log "lab checks: FAIL"
  return "$rc"
}

case "${1:-help}" in
  up)       shift; cmd_up "$@";;
  takeover) cmd_takeover;;
  zone)     cmd_zone;;
  origin)   cmd_origin;;
  checks)   cmd_checks;;
  down)     cmd_down;;
  hosts)    cmd_hosts;;
  run)      shift; cmd_run "$@";;
  compare)  shift; cmd_compare "$@";;
  bench)    shift; cmd_bench "$@";;
  help|-h|--help) sed -n '2,41p' "$0" | sed 's/^# \{0,1\}//';;
  *) die "unknown command: ${1:-} (try: up|down|hosts|run|compare|bench|takeover|zone|origin|checks)";;
esac
