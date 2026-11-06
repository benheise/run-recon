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
#                          walk.test: walkable NSEC chain, nsec3.test: NSEC3 on BIND,
#                          test.: none of these) -- needs ldnsutils
#   origin                 --origin against the origin fixtures (nginx.test must be
#                          origin-exposed at LAB_ORIGIN_IP; spa.test origin-protected at
#                          LAB_PROTECTED_IP; wp.test not reported)
#   http                   HTTP detail (1.19): security headers, HSTS, cookies, cleartext auth,
#                          robots.txt / security.txt / 404 probe (--extras), favicon, PTR (--enrich)
#   posture                --dns-posture against posture.test (permissive SPF, DMARC p=none,
#                          MTA-STS testing, dangling MX and NS, a lame NS) and the clean
#                          good.posture.test; --cloudlist against a lab Terraform state
#   discovery              the discovery tools end to end: naabu (an alternate port), alterx
#                          (--permute), shuffledns+massdns (--brute), cdncheck, uncover without
#                          keys, and --monitor --notify to a local webhook
#   scope                  --scope / --list-targets: the seed check, origin candidates held back, the
#                          browser held to the names, an address exclusion proved at the origin's
#                          access log (and a control run without --scope)
#   resume                 SIGTERM after two seeds, then --resume: the CSV must equal an uninterrupted run
#   history                --monitor's field-by-field delta and recon-db.sh history/changes across two runs
#                          with the spa backend stopped in between (the store too, with RECON_DB_DSN)
#   checks                 takeover + zone + origin + http + posture + discovery + scope + resume + history;
#                          non-zero if any fails
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
# the "protected origin": origin.spa.test points here, where the ingress answers every
# request with 403 (an origin locked to its CDN): --origin must say origin-protected
LAB_PROTECTED_IP="${LAB_PROTECTED_IP:-127.0.0.6}"
# BIND, authoritative for the NSEC3-signed nsec3.test (CoreDNS's file plugin cannot serve
# NSEC3): ns.nsec3.test answers on this address, CoreDNS forwards the zone to it
LAB_NSEC3_IP="${LAB_NSEC3_IP:-127.0.0.7}"
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
  local _v
  for _v in LAB_DNS_IP LAB_ORIGIN_IP LAB_PROTECTED_IP LAB_NSEC3_IP; do
    case "${!_v}" in 127.*) ;; *) die "$_v must be a loopback (127.0.0.0/8) address: ${!_v}";; esac
  done
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
  #             nginx backend answers directly, bypassing the Caddy edge; origin.spa.test
  #             points to $LAB_PROTECTED_IP, which refuses the site (403): origin-protected
  #   zone:     test. itself is unsigned and refuses AXFR (the negative case)
  {
    printf '$ORIGIN test.\n$TTL 60\n'
    printf '@ IN SOA ns.test. hostmaster.test. %s 7200 3600 1209600 60\n' "$serial"
    printf '@ IN NS ns.test.\nns IN A 127.0.0.1\n'
    awk '{ ip=$1; t=(ip ~ /:/) ? "AAAA" : "A"; for (i=2; i<=NF; i++) printf "%s. IN %s %s\n", $i, t, ip }' "$LAB/lab.hosts"
    printf 'alias IN CNAME nginx.test.\norphan IN CNAME gone.cloud.test.\n'
    printf 'direct.nginx.test. IN A %s\n' "$LAB_ORIGIN_IP"
    printf 'nginx.test. IN TXT "v=spf1 ip4:%s -all"\n' "$LAB_ORIGIN_IP"
    printf 'origin.spa.test. IN A %s\n' "$LAB_PROTECTED_IP"
    # discovery fixtures: a name only alterx's permutations guess (--permute) and one only
    # the lab wordlist holds (--brute)
    printf 'grafana.nginx.test. IN A 127.0.0.1\nbackup-db.nginx.test. IN A 127.0.0.1\n'
  } > "$LAB/db.test"
  printf 'www\nbackup-db\nnot-there-1\nnot-there-2\n' > "$LAB/brute-wordlist.txt"
  printf 'nginx.test\n' > "$LAB/targets-discovery.txt"
  rm -f "$LAB/test.zone"
  # zone-exposure fixtures: names that no wordlist or passive source would find
  #   walk.test   DNSSEC-signed with NSEC  -> the chain can be walked
  #   xfr.test    unsigned, AXFR allowed   -> the whole zone in one query
  #   nsec3.test  signed with NSEC3, served by BIND on $LAB_NSEC3_IP (CoreDNS forwards
  #               to it): the hashed chain is reported, not walked
  local z ns
  for z in walk.test xfr.test nsec3.test; do
    ns=127.0.0.1; [ "$z" = nsec3.test ] && ns="$LAB_NSEC3_IP"
    {
      printf '$ORIGIN %s.\n$TTL 60\n' "$z"
      printf '@ IN SOA ns.%s. hostmaster.%s. %s 7200 3600 1209600 60\n' "$z" "$z" "$serial"
      printf '@ IN NS ns.%s.\nns IN A %s\n@ IN A 127.0.0.1\nwww IN A 127.0.0.1\n' "$z" "$ns"
      case "$z" in
        walk.test)  printf 'secret-admin IN A 127.0.0.1\nvpn-legacy IN A 127.0.0.1\nq7-billing-replica IN A 127.0.0.1\n';;
        xfr.test)   printf 'hidden-ops IN A 127.0.0.1\nstaging-api-2019 IN A 127.0.0.1\n';;
        nsec3.test) printf 'hashed-only IN A 127.0.0.1\n';;
      esac
    } > "$LAB/db.$z"
  done
  sign_zone walk.test 0
  sign_zone nsec3.test 1
  # email/DNS posture fixtures (--dns-posture): posture.test gets everything wrong, its
  # subdomain good.posture.test gets everything right
  #   NS  ns.posture.test (CoreDNS, authoritative), ns-gone.nowhere.test (nowhere.test does
  #       not exist: dangling), ns-lame.posture.test -> BIND, which refuses posture.test (lame)
  #   MX  mx1.posture.test (exists), mx-old.gone-mail.test (gone-mail.test does not exist)
  #   SPF include:_spf.posture.test +all; DMARC p=none without rua; MTA-STS testing whose
  #   policy lists mx1 only; no TLS-RPT; CAA letsencrypt.org
  {
    printf '$ORIGIN posture.test.\n$TTL 60\n'
    printf '@ IN SOA ns.posture.test. hostmaster.posture.test. %s 7200 3600 1209600 60\n' "$serial"
    printf '@ IN NS ns.posture.test.\n@ IN NS ns-gone.nowhere.test.\n@ IN NS ns-lame.posture.test.\n'
    printf 'ns IN A 127.0.0.1\nns-lame IN A %s\n@ IN A 127.0.0.1\nmx1 IN A 127.0.0.1\nmta-sts IN A 127.0.0.1\n' "$LAB_NSEC3_IP"
    printf '@ IN MX 10 mx1.posture.test.\n@ IN MX 20 mx-old.gone-mail.test.\n'
    printf '@ IN TXT "v=spf1 include:_spf.posture.test +all"\n_spf IN TXT "v=spf1 ip4:127.0.0.1 -all"\n'
    printf '_dmarc IN TXT "v=DMARC1; p=none"\n_mta-sts IN TXT "v=STSv1; id=20261101"\n'
    printf '@ IN CAA 0 issue "letsencrypt.org"\n'
    printf 'good IN A 127.0.0.1\ngood IN MX 10 mx1.posture.test.\ngood IN TXT "v=spf1 mx -all"\n'
    printf '_dmarc.good IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@posture.test"\n'
    printf '_mta-sts.good IN TXT "v=STSv1; id=20261101"\nmta-sts.good IN A 127.0.0.1\n'
    printf '_smtp._tls.good IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@posture.test"\n'
  } > "$LAB/db.posture.test"
  printf 'posture.test\ngood.posture.test\n' > "$LAB/targets-posture.txt"
  # --cloudlist: a Terraform state (cloudlist's terraform provider reads it offline) with the
  # ingress address the scan sees, and one the scan never finds
  {
    printf '{"version": 4, "terraform_version": "1.6.0", "serial": 1, "lineage": "run-recon-lab", "outputs": {},\n'
    printf ' "resources": [\n'
    printf '  {"mode": "managed", "type": "aws_instance", "name": "web", "instances": [{"attributes": {"id": "i-lab0001", "public_ip": "127.0.0.1"}}]},\n'
    printf '  {"mode": "managed", "type": "aws_instance", "name": "forgotten", "instances": [{"attributes": {"id": "i-lab0002", "public_ip": "127.0.0.8"}}]}\n'
    printf ' ]}\n'
  } > "$LAB/cloud.tfstate"
  printf -- '- provider: terraform\n  id: lab\n  tf_state_file: %s\n' "$LAB/cloud.tfstate" > "$LAB/cloudlist.yaml"
  printf 'walk.test\nxfr.test\nnsec3.test\nnginx.test\n' > "$LAB/targets-zone.txt"
  printf 'nginx.test\nalias.test\norphan.test\n' > "$LAB/targets-takeover.txt"
  printf 'nginx.test\nspa.test\nwp.test\n' > "$LAB/targets-origin.txt"
  # reverse zone for 127.0.0.0/8: the PTR fixtures for --enrich's ptr column
  {
    printf '$ORIGIN 127.in-addr.arpa.\n$TTL 60\n'
    printf '@ IN SOA ns.test. hostmaster.test. %s 7200 3600 1209600 60\n@ IN NS ns.test.\n' "$serial"
    printf '1.0.0 IN PTR ingress.lab.test.\n'
    printf '%s IN PTR origin-nginx.lab.test.\n' "$(printf '%s' "$LAB_ORIGIN_IP" | awk -F. '{print $4"."$3"."$2}')"
  } > "$LAB/db.127"
  # HTTP-detail check (bench-run-recon.sh http): the four sites, the cleartext-auth VPN and a
  # catch-all name from the walk.test zone
  printf 'nginx.test\nspa.test\nwp.test\nci.test\nvpn-legacy.walk.test\nwww.walk.test\n' > "$LAB/targets-http.txt"
  log "generated: SPA (120 KB), farm of $n vhosts, zones db.test db.walk.test db.xfr.test db.nsec3.test db.posture.test db.127, targets and ground truth"
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
  log "starting the range (lab DNS on $LAB_DNS_IP:53, exposed origin on $LAB_ORIGIN_IP:80, protected origin on $LAB_PROTECTED_IP:80, BIND on $LAB_NSEC3_IP:53)..."
  export LAB_DNS_IP LAB_ORIGIN_IP LAB_PROTECTED_IP LAB_NSEC3_IP
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
cmd_down(){ export LAB_DNS_IP LAB_ORIGIN_IP LAB_PROTECTED_IP LAB_NSEC3_IP; compose -f "$COMPOSE_FILE" down -v 2>/dev/null; log "range down."; }
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
  local exact=0 a="" b="" noise=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --exact) exact=1; shift;;
      # --noise RUN: another run of A's version; fields that differ between A and it are
      # run-to-run noise (a page with a per-request nonce), not a difference between versions
      --noise) [ -f "${2:-}" ] && noise="${noise:+$noise:}$2"; shift 2 || shift;;
      -h|--help) echo "usage: $0 compare EXPECTED ACTUAL [--exact [--noise OTHER-RUN-OF-EXPECTED]...]" >&2; return 0;;
      -*) die "compare: unknown option: $1";;
      *) if [ -z "$a" ]; then a="$1"; elif [ -z "$b" ]; then b="$1"; fi; shift;;
    esac
  done
  [ -n "$a" ] && [ -n "$b" ] || die "usage: $0 compare EXPECTED ACTUAL [--exact]"
  [ -f "$a" ] || die "compare: not found: $a"
  [ -f "$b" ] || die "compare: not found: $b"
  have python3 || die "compare: python3 required"
  BENCH_EXACT="$exact" BENCH_NOISE="$noise" python3 -I - "$a" "$b" <<'PYCMP'
import sys, os, csv, re

a_path, b_path = sys.argv[1], sys.argv[2]
EXACT = os.environ.get("BENCH_EXACT", "0") == "1"
# columns that legitimately differ run-to-run and are excluded from --exact
VOLATILE = {"cert_not_after", "response_ms"}

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
    # the noise floor: (row, column) pairs that already differ between runs of A's version
    noisy = set()
    for npath in [x for x in os.environ.get("BENCH_NOISE", "").split(":") if x]:
        nm = {key(r): r for r in rows(npath)}
        for k in set(am) & set(nm):
            for c in cols:
                if (am[k].get(c) or "") != (nm[k].get(c) or ""):
                    noisy.add((k, c))
    if noisy:
        from collections import Counter
        print("noise: %d field(s) differ between runs of A's own version, not compared (%s)"
              % (len(noisy), ", ".join("%s x%d" % kv for kv in sorted(Counter(c for _, c in noisy).items()))))
    diffs = 0
    only_a = sorted(set(am) - set(bm))
    only_b = sorted(set(bm) - set(am))
    for k in only_a: print("only in A: %s %s" % k); diffs += 1
    for k in only_b: print("only in B: %s %s" % k); diffs += 1
    for k in sorted(set(am) & set(bm)):
        for c in cols:
            if (k, c) not in noisy and (am[k].get(c) or "") != (bm[k].get(c) or ""):
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
      -h|--help) awk 'NR > 1 && !/^#/ { exit } NR > 1 && !/^# ?=+$/' "$0" | sed 's/^# \{0,1\}//'; return 0;;
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
    # runs 1..N-1 of the baseline give the noise floor (base.csv is run N)
    local _nz=() _k; for _k in $(seq 1 $((runs - 1))); do _nz+=(--noise "$tdir/base.$_k.csv"); done
    local ident; if cmd_compare "$tdir/base.csv" "$tdir/cand.csv" --exact "${_nz[@]}" >"$tdir/ab.log" 2>&1; then ident="identical"
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
  if grep -q 'NSEC3PARAM' "$LAB/db.nsec3.test.signed" 2>/dev/null; then
    _ck "$f" '^\[nsec3\.test\] nsec3-hashes-exposed \[low\] host=nsec3\.test zone=nsec3\.test params="1 0 5 1A2B3C4D"' "nsec3.test: NSEC3 on BIND reported [low] with its parameters"
    if grep -qE '^nsec3\.test	hashed-only\.nsec3\.test	nsec$' "$n" 2>/dev/null; then log "  FAIL nsec3.test: an NSEC3 zone was walked like NSEC"; fail=1
    else log "  ok   nsec3.test: hashed names not walked"; fi
    _ck "$f" '^\[nsec3\.test\] dnssec-unanchored \[low\] host=nsec3\.test' "nsec3.test: signed without a DS in the parent -> dnssec-unanchored [low]"
  else
    log "  skip nsec3.test is unsigned (install ldnsutils, then rerun up)"
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
  if grep -qE 'origin-(exposed|alternate|candidate)[^ ]* \[[a-z]+\] host=(spa|wp)\.test' "$f" 2>/dev/null; then log "  FAIL spa.test/wp.test reported as exposed (no exposed origin there)"; fail=1
  else log "  ok   spa.test and wp.test not reported as exposed"; fi
  ip="$(printf '%s' "$LAB_PROTECTED_IP" | sed 's/\./\\./g')"
  if grep -qE "origin-protected \[info\] host=spa\.test origin=$ip via=[^ ]*origin\.spa\.test reason=[^ ]*status-403" "$f" 2>/dev/null; then
    log "  ok   spa.test: origin.spa.test ($LAB_PROTECTED_IP) refuses the site -> origin-protected [info]"
  else log "  FAIL spa.test origin-protected not reported (see $f)"; fail=1; fi
  if grep -qE 'host=wp\.test' "$f" 2>/dev/null; then log "  FAIL wp.test reported (no origin name there)"; fail=1
  else log "  ok   wp.test not reported"; fi
  if grep -qE '^nginx\.test	nginx\.test	Caddy	nginx/' "$e" 2>/dev/null; then log "  ok   edge.tsv: nginx.test edge Caddy, origin software nginx"
  else log "  FAIL edge.tsv incomplete ($e)"; fail=1; fi
  if grep -q $'\033' "$f" "$e" 2>/dev/null; then log "  FAIL terminal colour codes in the artifacts"; fail=1; fi
  [ "$fail" = 0 ] && log "origin check: PASS" || log "origin check: FAIL"
  return "$fail"
}

# posture: the email/DNS posture fixtures (lab/db.posture.test, the MTA-STS policies in the
# Caddyfile) and the cloud inventory diff against lab/cloud.tfstate (run-recon 1.20)
cmd_posture(){
  lab_env
  [ -f "$RUN_RECON" ] || die "run-recon not found at $RUN_RECON"
  [ -s "$LAB/targets-posture.txt" ] || die "no lab/targets-posture.txt (run: $0 up)"
  local t; t="$(mktemp -d /tmp/bench-posture.XXXXXX)"
  # MTA-STS policies are fetched with certificate checks; the lab's are issued by Caddy's local CA
  export LAB_DNS_IP LAB_ORIGIN_IP LAB_PROTECTED_IP LAB_NSEC3_IP
  compose -f "$COMPOSE_FILE" exec -T ingress cat /data/caddy/pki/authorities/local/root.crt > "$t/caddy-root.crt" 2>/dev/null
  [ -s "$t/caddy-root.crt" ] || die "could not read the ingress's local CA (is the lab up?)"
  local cl=(); if have cloudlist; then cl=(--cloudlist "$LAB/cloudlist.yaml"); else log "  skip cloudlist not installed: no cloud inventory check"; fi
  log "email/DNS posture check against lab/targets-posture.txt -> $t"
  ( cd "$t" && bash "$RUN_RECON" -i "$LAB/targets-posture.txt" -o "$t/p.csv" --resolvers "$RESOLVERS_FILE" \
      --dns-posture --mta-sts-ca "$t/caddy-root.crt" "${cl[@]}" --no-report >"$t/run.out" 2>"$t/run.err" ) || true
  local f="$t/p.csv.dnsposture.txt" v="$t/p.csv.dnsposture.tsv" fail=0
  _ck(){ if grep -qE "$2" "$1" 2>/dev/null; then log "  ok   $3"; else log "  FAIL $3 (see $1, $t/run.err)"; fail=1; fi; }
  _ck "$f" '^\[posture\.test\] spf-permissive \[high\] host=posture\.test all=\+all '                  "posture.test: SPF +all -> spf-permissive [high]"
  _ck "$f" '^\[posture\.test\] dmarc-none \[low\] host=posture\.test '                               "posture.test: DMARC p=none -> dmarc-none [low]"
  _ck "$f" '^\[posture\.test\] dmarc-no-rua \[info\] host=posture\.test '                            "posture.test: no rua -> dmarc-no-rua [info]"
  _ck "$f" '^\[posture\.test\] mta-sts-testing \[info\] host=posture\.test '                         "posture.test: policy fetched over verified TLS, mode testing"
  _ck "$f" '^\[posture\.test\] mta-sts-mx-mismatch \[medium\] host=posture\.test mx=mx-old\.gone-mail\.test ' "posture.test: an MX host the policy does not list"
  _ck "$f" '^\[posture\.test\] tlsrpt-missing \[info\] host=posture\.test '                         "posture.test: no TLS-RPT"
  _ck "$f" '^\[posture\.test\] mx-dangling \[high\] host=posture\.test mx=mx-old\.gone-mail\.test '  "posture.test: MX host whose domain does not exist -> mx-dangling [high]"
  _ck "$f" '^\[posture\.test\] ns-dangling \[high\] host=posture\.test ns=ns-gone\.nowhere\.test '   "posture.test: NS host whose domain does not exist -> ns-dangling [high]"
  _ck "$f" "^\\[posture\\.test\\] ns-lame \\[medium\\] host=posture\\.test ns=ns-lame\\.posture\\.test\\($(printf '%s' "$LAB_NSEC3_IP" | sed 's/\./\\./g')\\) reason=refused " "posture.test: BIND refuses the zone -> ns-lame [medium]"
  if grep -qE 'caa-missing.*host=posture\.test|ns-lame.*ns=ns\.posture\.test' "$f" 2>/dev/null; then log "  FAIL posture.test: CAA present / CoreDNS authoritative, yet reported"; fail=1
  else log "  ok   posture.test: CAA present and ns.posture.test authoritative: not reported"; fi
  if grep -q 'host=good\.posture\.test' "$f" 2>/dev/null; then log "  FAIL good.posture.test reported: $(grep 'host=good\.posture\.test' "$f" | head -n 2 | tr '\n' ' ')"; fail=1
  else log "  ok   good.posture.test (SPF mx -all, DMARC reject+rua, MTA-STS enforce, TLS-RPT): no finding"; fi
  _ck "$v" '^good\.posture\.test	seed	posture\.test	mx1\.posture\.test	v=spf1 mx -all	-all	1	p=reject	enforce	yes	' "dnsposture.tsv: the clean name's row"
  if [ "${#cl[@]}" -gt 0 ]; then
    _ck "$t/p.csv.cloud.txt" '^\[cloud\] cloud-asset-unseen \[info\] host=127\.0\.0\.8 provider=terraform account=lab ' "cloudlist: an account's address the scan never saw -> cloud-asset-unseen"
    _ck "$t/p.csv.cloud-assets.tsv" '^terraform	lab	[^	]*		127\.0\.0\.1	yes$'             "cloudlist: the ingress address is matched to the scan's inventory"
  fi
  [ "$fail" = 0 ] && log "posture check: PASS" || log "posture check: FAIL"
  return "$fail"
}

# discovery: the discovery tools against the lab (run-recon 1.20). Run A is the baseline
# inventory; run B adds --ports/--permute/--brute and --monitor --notify against run A, so the
# alternate-port URL is a new asset and reaches a local webhook.
cmd_discovery(){
  lab_env
  [ -f "$RUN_RECON" ] || die "run-recon not found at $RUN_RECON"
  [ -s "$LAB/targets-discovery.txt" ] || die "no lab/targets-discovery.txt (run: $0 up)"
  local t fail=0 port; t="$(mktemp -d /tmp/bench-discovery.XXXXXX)"
  _ck(){ if grep -qE "$2" "$1" 2>/dev/null; then log "  ok   $3"; else log "  FAIL $3 (see $1)"; fail=1; fi; }
  log "discovery check against lab/targets-discovery.txt -> $t"
  ( cd "$t" && bash "$RUN_RECON" -i "$LAB/targets-discovery.txt" -o "$t/a.csv" --resolvers "$RESOLVERS_FILE" \
      --resolve --no-report >"$t/a.out" 2>"$t/a.err" ) || true
  # a local webhook (loopback, random port) that records what notify posts
  port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
  python3 -I -c '
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        b = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        open(sys.argv[2], "ab").write(b + b"\n"); self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()' "$port" "$t/webhook.txt" &
  local hook=$!
  printf 'custom:\n  - id: lab\n    custom_webhook_url: http://127.0.0.1:%s/hook\n    custom_method: POST\n    custom_format: "{{data}}"\n    custom_headers:\n      Content-Type: text/plain\n' "$port" > "$t/notify.yaml"
  ( cd "$t" && NOTIFY_CONFIG="$t/notify.yaml" bash "$RUN_RECON" -i "$LAB/targets-discovery.txt" -o "$t/b.csv" \
      --resolvers "$RESOLVERS_FILE" --resolve --permute --brute --brute-wordlist "$LAB/brute-wordlist.txt" \
      --ports --port-spec 80,443,8443 --origin --monitor --monitor-prev "$t/a.csv" --notify --no-report >"$t/b.out" 2>"$t/b.err" ) || true
  sleep 1; kill "$hook" 2>/dev/null; wait "$hook" 2>/dev/null
  if have naabu; then _ck "$t/b.csv" ',https://nginx\.test:8443(/[^,]*)?,nginx\.test,'        "naabu: the alternate port 8443 found and probed"
  else log "  skip naabu not installed"; fi
  if have alterx; then _ck "$t/b.csv" ',https?://grafana\.nginx\.test[^,]*,grafana\.nginx\.test,[^,]*alterx' "alterx (--permute): grafana.nginx.test guessed and validated"
  else log "  skip alterx not installed"; fi
  if have shuffledns && have massdns; then _ck "$t/b.csv" ',https?://backup-db\.nginx\.test[^,]*,backup-db\.nginx\.test,[^,]*bruteforce' "shuffledns+massdns (--brute): backup-db.nginx.test from the wordlist"
  else log "  skip shuffledns+massdns not installed (massdns: build from github.com/blechschmidt/massdns)"; fi
  if grep -qE 'grafana|backup-db|not-there' "$t/a.csv" 2>/dev/null; then log "  FAIL the baseline run found names only permutations or the wordlist hold"; fail=1
  else log "  ok   the baseline run (no --permute/--brute) does not have them"; fi
  if have cdncheck; then
    _ck "$t/b.csv.edge.tsv" '^nginx\.test	nginx\.test	Caddy	nginx/[^	]*	[^	]*	[^	]*		'   "cdncheck: no CDN tag for the loopback edge"
    # the same call origin_check makes, on a Cloudflare address (cdncheck's ranges are built in)
    if echo 104.16.0.1 | cdncheck -resp -silent -nc 2>/dev/null | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' | grep -q '^104\.16\.0\.1 .*\[cloudflare\]'; then
      log "  ok   cdncheck: 104.16.0.1 tagged cloudflare in the format origin_check parses"
    else log "  FAIL cdncheck output format changed (origin_check expects 'IP [type] [provider]')"; fail=1; fi
  fi
  _ck "$t/b.csv.new-assets.txt" '^https://nginx\.test:8443'                                    "--monitor: the alternate-port URL is a new asset vs run A"
  if have notify; then _ck "$t/webhook.txt" 'new asset\(s\) vs a\.csv'                         "--notify: one message (-bulk) posted to the lab webhook (NOTIFY_CONFIG)"
    _ck "$t/webhook.txt" 'https://nginx\.test:8443'                                            "--notify: the message lists the new asset"
  else log "  skip notify not installed"; fi
  if have uncover; then
    mkdir -p "$t/nokeys"
    HOME="$t/nokeys" uncover -q 'ssl:"nginx.test"' -silent -duc >/dev/null 2>"$t/uncover.err" || true
    _ck "$t/uncover.err" 'requires keys but no keys'                                            "uncover without keys: the message run-recon turns into a warning"
  fi
  [ "$fail" = 0 ] && log "discovery check: PASS" || log "discovery check: FAIL"
  return "$fail"
}

# http: the HTTP-detail fixtures in lab/Caddyfile and lab/db.127 (run-recon 1.19)
cmd_http(){
  lab_env
  [ -f "$RUN_RECON" ] || die "run-recon not found at $RUN_RECON"
  [ -s "$LAB/targets-http.txt" ] || die "no lab/targets-http.txt (run: $0 up)"
  local t; t="$(mktemp -d /tmp/bench-http.XXXXXX)"
  log "HTTP detail check against lab/targets-http.txt -> $t"
  ( cd "$t" && bash "$RUN_RECON" -i "$LAB/targets-http.txt" -o "$t/h.csv" \
      --resolvers "$RESOLVERS_FILE" --extras --enrich --resolve --no-report >"$t/run.out" 2>"$t/run.err" ) || true
  python3 -I - "$t/h.csv" "$t/h.csv.extras.txt" <<'PYHTTP'
import sys, csv, re
csv_f, ex_f = sys.argv[1:3]
try:
    rows = list(csv.DictReader(open(csv_f, newline="", encoding="utf-8")))
except OSError:
    rows = []
try:
    extras = open(ex_f, encoding="utf-8").read()
except OSError:
    extras = ""
def row(url):
    return next((r for r in rows if r["url"].rstrip("/") == url.rstrip("/")), {})
fails = 0
def ck(ok, msg):
    global fails
    print("[bench]   %s %s" % ("ok  " if ok else "FAIL", msg))
    fails += 0 if ok else 1
n, s_, v, pv = row("https://nginx.test"), row("https://spa.test"), row("http://vpn-legacy.walk.test"), row("https://nginx.test/private/")
ck(n.get("missing_sec_headers") == "Content-Security-Policy;X-Frame-Options;X-Content-Type-Options;Strict-Transport-Security",
   "nginx.test: all four security headers missing (nginx defaults)")
ck(re.fullmatch(r"[0-9a-f]{64}", n.get("body_sha256", "")) is not None and n.get("response_ms", "").isdigit()
   and "h3=" in n.get("alt_svc", ""), "nginx.test: body SHA-256, response time, Alt-Svc h3")
ck(s_.get("missing_sec_headers", "x") == "" and s_.get("hsts_max_age") == "31536000",
   "spa.test: no header missing (CSP frame-ancestors covers X-Frame-Options), HSTS max-age 31536000")
ck("CleartextAuth" in v.get("http_flags", "") and v.get("auth") == 'Basic realm="Legacy VPN"',
   "vpn-legacy.walk.test: Basic auth over HTTP -> CleartextAuth")
ck(pv.get("sources") == "robots" and pv.get("status_code") == "401" and pv.get("auth") == 'Basic realm="Lab Private"'
   and "CleartextAuth" not in pv.get("http_flags", ""), "nginx.test/private/: found via robots.txt, 401 Basic over HTTPS (not cleartext)")
ck(n.get("robots", "").startswith("200 disallow=2") and n.get("security_txt", "").startswith("expired")
   and s_.get("security_txt", "").startswith("present"), "robots.txt and security.txt columns (nginx expired, spa valid)")
ck(re.search(r"security-txt-expired \[low\] host=nginx\.test", extras) is not None, "nginx.test: security-txt-expired [low]")
ck(re.search(r"catch-all-200 \[info\] host=www\.walk\.test", extras) is not None, "www.walk.test: catch-all 200 detected by the 404 probe")
ck(row("https://ci.test").get("favicon_mmh3") == "81586312", "ci.test: Jenkins favicon mmh3 81586312")
ck(any("wordpress_test_cookie" in r.get("cookie_issues", "") for r in rows), "wp.test: wordpress_test_cookie flag gaps")
ck(n.get("ptr") == "ingress.lab.test", "PTR of 127.0.0.1 from the lab's reverse zone (--enrich, your resolver)")
sys.exit(1 if fails else 0)
PYHTTP
  local rc=$?
  [ "$rc" = 0 ] && log "http check: PASS" || log "http check: FAIL (see $t/run.err)"
  return "$rc"
}

# scope: --scope against the lab (run-recon 1.20). The seed check before anything is sent,
# origin candidates outside the allowed ranges (not contacted), the browser held to the
# scope, and an address exclusion proved at the origin's own access log: a request to
# LAB_ORIGIN_IP reaches the nginx container from the docker bridge gateway.
cmd_scope(){
  lab_env
  [ -f "$RUN_RECON" ] || die "run-recon not found at $RUN_RECON"
  local t fail=0 rc ip pip cid gw n0 n1 n2
  t="$(mktemp -d /tmp/bench-scope.XXXXXX)"
  _ck(){ if grep -qE "$2" "$1" 2>/dev/null; then log "  ok   $3"; else log "  FAIL $3 (see $1)"; fail=1; fi; }
  _nck(){ if grep -qE "$2" "$1" 2>/dev/null; then log "  FAIL $3 (see $1)"; fail=1; else log "  ok   $3"; fi; }
  ip="$(printf '%s' "$LAB_ORIGIN_IP" | sed 's/\./\\./g')"; pip="$(printf '%s' "$LAB_PROTECTED_IP" | sed 's/\./\\./g')"
  log "scope check -> $t"
  printf 'nginx.test\nspa.test\nwp.test\n' > "$t/s1.txt"
  printf 'nginx.test\nspa.test\nwp.test\nci.test\n' > "$t/in.txt"
  # 1. the dry run: ci.test is outside the scope, so the run would refuse to start
  rc=0; bash "$RUN_RECON" -i "$t/in.txt" --scope "$t/s1.txt" --list-targets > "$t/plan.txt" 2>&1 || rc=$?
  if [ "$rc" = 2 ] && grep -qE '^4 +ci\.test +domain +OUT OF SCOPE +no entry covers it' "$t/plan.txt"; then
    log "  ok   --list-targets: ci.test out of scope, exit 2 (the run would refuse)"
  else log "  FAIL --list-targets (exit $rc, see $t/plan.txt)"; fail=1; fi
  # 2. no address entries: the origin candidates are held back, the browser is held to the names
  ( cd "$t" && bash "$RUN_RECON" -i "$t/in.txt" -o "$t/a.csv" --resolvers "$RESOLVERS_FILE" --scope "$t/s1.txt" \
      --drop-out-of-scope --origin --screenshots --no-report >"$t/a.out" 2>"$t/a.err" ) || true
  _nck "$t/a.csv" ',ci\.test,'                                          "--drop-out-of-scope: ci.test is not run"
  _nck "$t/a.csv.origin.txt" 'origin-(exposed|protected)'             "no address entries: no origin candidate is contacted"
  _ck  "$t/a.csv.scope.txt" "kind=origin-candidate target=$ip via=[^ ]*direct\.nginx\.test" "the origin candidate $LAB_ORIGIN_IP is listed as held back"
  _ck  "$t/a.csv.screenshots.tsv" '^nginx\.test	[^	]*	ok'               "the browser, held to the scope's names (MAP * ~NOTFOUND), still renders nginx.test"
  # 3. the origin addresses allowed: the same verdicts as without --scope
  printf 'nginx.test\nspa.test\nwp.test\n%s/32\n%s/32\n' "$LAB_ORIGIN_IP" "$LAB_PROTECTED_IP" > "$t/s2.txt"
  ( cd "$t" && bash "$RUN_RECON" -i "$LAB/targets-origin.txt" -o "$t/b.csv" --resolvers "$RESOLVERS_FILE" --scope "$t/s2.txt" \
      --origin --no-report >"$t/b.out" 2>"$t/b.err" ) || true
  _ck "$t/b.csv.origin.txt" "origin-exposed \[high\] host=nginx\.test origin=$ip port=80"  "allowed ranges: nginx.test's origin $LAB_ORIGIN_IP verified"
  _ck "$t/b.csv.origin.txt" "origin-protected \[info\] host=spa\.test origin=$pip"          "allowed ranges: spa.test origin-protected"
  # 4. an address exclusion, checked at the origin's access log
  cid="$(compose -f "$COMPOSE_FILE" ps -q nginx 2>/dev/null | head -n 1)"
  gw="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}} {{end}}' "$cid" 2>/dev/null | awk '{print $1}')"
  _direct(){ docker logs "$cid" 2>&1 | grep -c "^$gw " || true; }
  printf 'direct\nbackup-db\nnot-there-1\n' > "$t/wl.txt"
  printf 'nginx.test\n' > "$t/in-n.txt"
  printf 'nginx.test\n!%s\n!backup-db.nginx.test\n' "$LAB_ORIGIN_IP" > "$t/s3.txt"
  n0="$(_direct)"
  ( cd "$t" && bash "$RUN_RECON" -i "$t/in-n.txt" -o "$t/c.csv" --resolvers "$RESOLVERS_FILE" --scope "$t/s3.txt" \
      --resolve --brute --brute-wordlist "$t/wl.txt" --certs --no-report >"$t/c.out" 2>"$t/c.err" ) || true
  sleep 1; n1="$(_direct)"
  _nck "$t/c.csv" 'direct\.nginx\.test|backup-db\.nginx\.test'         "excluded: direct.nginx.test (its address) and backup-db.nginx.test (its name) are not in the CSV"
  _ck  "$t/c.csv.scope.txt" "kind=name target=direct\.nginx\.test address=$ip "   "direct.nginx.test listed as held back (resolves into $LAB_ORIGIN_IP)"
  if [ -n "$gw" ] && [ "$n1" = "$n0" ]; then log "  ok   no request reached $LAB_ORIGIN_IP (origin access log: $n0 -> $n1 direct requests)"
  else log "  FAIL requests reached $LAB_ORIGIN_IP under --scope (origin access log: $n0 -> $n1; gateway ${gw:-?})"; fail=1; fi
  ( cd "$t" && bash "$RUN_RECON" -i "$t/in-n.txt" -o "$t/d.csv" --resolvers "$RESOLVERS_FILE" \
      --resolve --brute --brute-wordlist "$t/wl.txt" --certs --no-report >"$t/d.out" 2>"$t/d.err" ) || true
  sleep 1; n2="$(_direct)"
  if [ "$n2" -gt "$n1" ] && grep -q 'direct\.nginx\.test' "$t/d.csv"; then
    log "  ok   control: without --scope the same run probes direct.nginx.test ($((n2 - n1)) direct request(s) logged)"
  else log "  FAIL control: the run without --scope did not reach $LAB_ORIGIN_IP ($n1 -> $n2), so the check proves nothing"; fail=1; fi
  # 5. MTA-STS: the policy host outside the scope is not fetched
  printf 'posture.test\n!mta-sts.posture.test\n' > "$t/s4.txt"; printf 'posture.test\n' > "$t/in-p.txt"
  ( cd "$t" && bash "$RUN_RECON" -i "$t/in-p.txt" -o "$t/e.csv" --resolvers "$RESOLVERS_FILE" --scope "$t/s4.txt" \
      --dns-posture --no-report >"$t/e.out" 2>"$t/e.err" ) || true
  _ck "$t/e.csv.dnsposture.tsv" 'policy not fetched: mta-sts\.posture\.test is outside --scope' "MTA-STS: the policy is not fetched from an excluded name"
  [ "$fail" = 0 ] && log "scope check: PASS" || log "scope check: FAIL"
  return "$fail"
}

# resume: a lab run stopped by SIGTERM after two seeds, then --resume; its CSV must equal an
# uninterrupted run's (field by field; the second reference run is the noise floor)
cmd_resume(){
  lab_env
  [ -f "$RUN_RECON" ] || die "run-recon not found at $RUN_RECON"
  local t fail=0 rc pid i
  t="$(mktemp -d /tmp/bench-resume.XXXXXX)"
  log "resume check -> $t"
  _rrun(){ local d="$1"; shift; mkdir -p "$t/$d"; ( cd "$t" && exec bash "$RUN_RECON" -i "$LAB/targets.txt" -D "$t/$d" -o "$t/$d/r.csv" \
      --resolvers "$RESOLVERS_FILE" --tls -t 1 --no-report "$@" >"$t/$d.out" 2>>"$t/$d.err" ); }
  _rrun ref1 || true; _rrun ref2 || true
  # in the background with exec, so $! is run-recon itself (not a subshell around it)
  mkdir -p "$t/cut"
  ( cd "$t" && exec bash "$RUN_RECON" -i "$LAB/targets.txt" -D "$t/cut" -o "$t/cut/r.csv" \
      --resolvers "$RESOLVERS_FILE" --tls -t 1 --no-report >"$t/cut.out" 2>>"$t/cut.err" ) & pid=$!
  for i in $(seq 1 600); do
    [ "$(find "$t/cut" -path '*/_work-*/done/*' -type f 2>/dev/null | wc -l)" -ge 2 ] && break; sleep 0.2
  done
  kill -TERM "$pid" 2>/dev/null; rc=0; wait "$pid" || rc=$?
  if [ "$rc" = 143 ] && grep -qx 'status=interrupted' "$t"/cut/_work-*/state 2>/dev/null; then
    log "  ok   SIGTERM after $(find "$t/cut" -path '*/_work-*/done/*' -type f | wc -l) of 4 seeds: exit 143, work dir kept"
  else log "  FAIL SIGTERM: exit $rc (want 143), state $(grep -h '^status=' "$t"/cut/_work-*/state 2>/dev/null)"; fail=1; fi
  sleep 1
  rc=0; _rrun cut --resume || rc=$?
  if [ "$rc" = 0 ] && grep -qE -- '--resume \(session 2\): [0-9]+ of 4 seed' "$t/cut.err"; then log "  ok   --resume finished the run ($(grep -oE '[0-9]+ of 4 seed\(s\) had finished' "$t/cut.err" | tail -n 1))"
  else log "  FAIL --resume (exit $rc, see $t/cut.err)"; fail=1; fi
  if [ -f "$t/ref1/r.csv" ] && [ -f "$t/ref2/r.csv" ] && [ -f "$t/cut/r.csv" ] \
     && ( cmd_compare "$t/ref1/r.csv" "$t/cut/r.csv" --exact --noise "$t/ref2/r.csv" ) > "$t/cmp.txt" 2>&1 && grep -q 'RESULT: identical' "$t/cmp.txt"; then
    log "  ok   the resumed run's CSV equals the uninterrupted run's (compare --exact, noise floor from a second run)"
  else log "  FAIL the resumed CSV differs (see $t/cmp.txt)"; fail=1; fi
  [ "$fail" = 0 ] && log "resume check: PASS" || log "resume check: FAIL"
  return "$fail"
}

# history: two lab runs with the spa backend stopped in between. --monitor must report the
# change field by field (<out>.delta.tsv), and recon-db.sh changes/history must find it, from
# the run CSVs and, when RECON_DB_DSN points at a PostgreSQL database, from the store (--db).
cmd_history(){
  lab_env
  [ -f "$RUN_RECON" ] || die "run-recon not found at $RUN_RECON"
  local t fail=0 db=()
  t="$(mktemp -d /tmp/bench-history.XXXXXX)"
  [ -n "${RECON_DB_DSN:-}" ] && db=(--db)
  _ck(){ if grep -qE "$2" "$1" 2>/dev/null; then log "  ok   $3"; else log "  FAIL $3 (see $1)"; fail=1; fi; }
  log "history check -> $t${RECON_DB_DSN:+ (store: \$RECON_DB_DSN)}"
  mkdir -p "$t/runs"
  ( cd "$t" && bash "$RUN_RECON" -i "$LAB/targets.txt" -D "$t/runs" --resolvers "$RESOLVERS_FILE" --tls "${db[@]}" --no-report >"$t/a.out" 2>"$t/a.err" ) || true
  sleep 1
  compose -f "$COMPOSE_FILE" stop spa >/dev/null 2>&1
  ( cd "$t" && bash "$RUN_RECON" -i "$LAB/targets.txt" -D "$t/runs" --resolvers "$RESOLVERS_FILE" --tls "${db[@]}" --monitor >"$t/b.out" 2>"$t/b.err" ) || true
  compose -f "$COMPOSE_FILE" start spa >/dev/null 2>&1
  local b; b="$(ls -t "$t"/runs/recon-*.csv | head -n 1)"
  _ck "$b.delta.tsv" '^changed	spa\.test	https://spa\.test	status_code	200	502$'  "--monitor: spa.test's status 200 -> 502, field by field"
  if awk -F'\t' 'NR > 1 && $2 != "spa.test"' "$b.delta.tsv" | grep -q .; then log "  FAIL changes reported for the services that did not change (see $b.delta.tsv)"; fail=1
  else log "  ok   nothing else changed (nginx, wp, ci: no delta lines)"; fi
  _ck "$b.report.html" 'Changes since the previous run'                              "report: the Changes section"
  bash "$HERE/recon-db.sh" changes spa.test --csv "$t/runs" > "$t/changes.tsv" 2>&1
  _ck "$t/changes.tsv" '	spa\.test	https://spa\.test	changed	status_code	200	502$'       "recon-db.sh changes --csv: the same event, with its run"
  if [ -n "${RECON_DB_DSN:-}" ]; then
    bash "$HERE/recon-db.sh" changes spa.test > "$t/db-changes.tsv" 2>&1
    _ck "$t/db-changes.tsv" '	spa\.test	https://spa\.test	changed	status_code	200	502$'  "recon-db.sh changes (PostgreSQL store, --db): the same event"
    bash "$HERE/recon-db.sh" history nginx.test > "$t/db-history.tsv" 2>&1
    _ck "$t/db-history.tsv" '^nginx\.test	https://nginx\.test	[0-9-]+	[0-9-]+	[0-9]+	[0-9]+	present	200 ' "recon-db.sh history (store): nginx.test present, first/last seen"
  else
    log "  skip the store (set RECON_DB_DSN to a PostgreSQL database to check --db history)"
  fi
  [ "$fail" = 0 ] && log "history check: PASS" || log "history check: FAIL"
  return "$fail"
}

cmd_checks(){
  local rc=0
  cmd_takeover || rc=1
  cmd_zone || rc=1
  cmd_origin || rc=1
  cmd_http || rc=1
  cmd_posture || rc=1
  cmd_discovery || rc=1
  cmd_scope || rc=1
  cmd_resume || rc=1
  cmd_history || rc=1
  [ "$rc" = 0 ] && log "lab checks: PASS (takeover, zone, origin, http, posture, discovery, scope, resume, history)" || log "lab checks: FAIL"
  return "$rc"
}

case "${1:-help}" in
  up)       shift; cmd_up "$@";;
  takeover) cmd_takeover;;
  posture)  cmd_posture;;
  discovery) cmd_discovery;;
  scope)    cmd_scope;;
  resume)   cmd_resume;;
  history)  cmd_history;;
  zone)     cmd_zone;;
  origin)   cmd_origin;;
  http)     cmd_http;;
  checks)   cmd_checks;;
  down)     cmd_down;;
  hosts)    cmd_hosts;;
  run)      shift; cmd_run "$@";;
  compare)  shift; cmd_compare "$@";;
  bench)    shift; cmd_bench "$@";;
  help|-h|--help) awk 'NR > 1 && !/^#/ { exit } NR > 1 && !/^# ?=+$/' "$0" | sed 's/^# \{0,1\}//';;
  *) die "unknown command: ${1:-} (try: up|down|hosts|run|compare|bench|takeover|zone|origin|http|posture|discovery|scope|resume|history|checks)";;
esac
