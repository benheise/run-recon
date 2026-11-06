# run-recon benchmark lab

A self-contained web range you run **on a host you own** (your Kali VM or any
Docker host) to benchmark and regression-test `run-recon.sh`. It reuses
WebInventory's regression-farm composition — nginx, WordPress, a 120 KB
single-page app and a TLS CI service — at **pinned versions**, so the products,
versions and CPEs run-recon should report are fixed and line up with what
WebInventory's rules expect for the same service types.

Everything binds to loopback and every name is under `.test`, which RFC 6761
reserves for testing (it can never resolve on the internet). This is a range you
control; never point the scanner anywhere else.

## Layout

| file | what it is |
|---|---|
| `docker-compose.yml` | the range: `dns` (CoreDNS), `ingress` (Caddy TLS vhost router), `nginx`, `wordpress` + `db`, `spa`, `jenkins` — all pinned. `nginx` is also published directly on `LAB_ORIGIN_IP:80` (default `127.0.0.5`): the "forgotten origin" fixture |
| `Caddyfile` | vhost routing; serves every name on both `http://` and `https://` with certificates from Caddy's local CA, plus the HTTP-detail fixtures below |
| `Corefile` | CoreDNS: authoritative for `test.`, `walk.test.` and `xfr.test.` from the generated zone files |
| `resolvers.txt` | the lab DNS server, passed to run-recon as `--resolvers` (dnsx/tlsx/httpx use it) |
| `targets.txt` | lab seeds: `nginx.test wp.test spa.test ci.test` |
| `expected.csv` | ground truth for the lab seeds (status, technologies, CPEs, TLS flags, IPv6) |
| *generated at `up`* | |
| `spa/index.html` | the 120 KB single-bundle SPA (WebInventory's SPA size) |
| `farm.caddy` | farm vhosts `f01..fNN.farm.test`, round-robin over the four backends |
| `lab.hosts` | address lines for the lab and the farm (the source for `db.test` and for `hosts`) |
| `db.test` | the `test.` zone: every A/AAAA record plus the takeover and origin fixtures below. Zone files use BIND's `db.<zone>` naming: files ending in `.zone` did not survive some synced folders |
| `db.walk.test`, `db.walk.test.signed` | `walk.test.`, DNSSEC-signed with NSEC by `ldns-signzone` (throwaway keys in `dnssec/`) |
| `db.xfr.test` | `xfr.test.`, unsigned, zone transfers allowed to anyone |
| `db.127` | reverse zone for `127.0.0.0/8`: PTR fixtures for `--enrich` |
| `targets-takeover.txt` | seeds for the takeover check: `nginx.test alias.test orphan.test` |
| `targets-zone.txt` | seeds for the zone check: `walk.test xfr.test nginx.test` |
| `targets-origin.txt` | seeds for the origin check: `nginx.test spa.test wp.test` |
| `targets-http.txt` | seeds for the HTTP-detail check: the four sites, `vpn-legacy.walk.test`, `www.walk.test` |
| `targets-farm.txt`, `expected-farm.csv` | farm seeds and their ground truth |

## Pinned services and what run-recon must report

| name | backend | status | technologies | CPEs | IPv6 (`--ipv6`) |
|---|---|---|---|---|---|
| `nginx.test` | `nginx:1.21.6` | 200 | Nginx | `cpe:2.3:a:f5:nginx:1.21.6` | `2001:db8:1::10` |
| `wp.test` | `wordpress:6.4-apache` (WordPress 6.4.3, Apache 2.4.57, PHP 8.2.17) + `mariadb:10.11` | 200 | WordPress, PHP, Apache HTTP Server | `wordpress:wordpress:6.4.3`, `apache:http_server:2.4.57`, `php:php:8.2.17` | `2001:db8:1::10` |
| `spa.test` | `nginx:1.21.6` serving the 120 KB SPA | 200 | Nginx | `cpe:2.3:a:f5:nginx:1.21.6` | none |
| `ci.test` | `jenkins/jenkins:2.426.1-lts-jdk17` | 403 (locked down) | Jenkins, Jetty | `jenkins:jenkins:2.426.1`, `eclipse:jetty:10.0.17` | none |

All four carry the TLS flags `CertExpiring` and (from v1.18) `CertUntrusted` under
`--tls` (see the notes below). `expected.csv` holds exactly this; it was confirmed
against the real toolchain (httpx 1.12.0, tlsx 1.4.0, dnsx 1.3.1, katana 1.8.0), not
written from documentation.

## Run it

```bash
# from the toolkit root (where bench-run-recon.sh lives)
./bench-run-recon.sh up --farm 50        # generate files, compose up, install WordPress, wait for Jenkins
sudo sh -c './bench-run-recon.sh hosts >> /etc/hosts'   # once: names for tools that use the system resolver

./bench-run-recon.sh bench --runs 3 --flags "--tls --ipv6"                    # lab: accuracy
./bench-run-recon.sh bench --runs 3 --farm --flags "--tls --ipv6 -t 10"       # farm: load
./bench-run-recon.sh compare lab/expected.csv some-run.csv                     # score any run
./bench-run-recon.sh compare run-a.csv run-b.csv --exact                       # A/B identity
./bench-run-recon.sh takeover                                                  # CNAME fixtures, real dnsx/subzy
./bench-run-recon.sh zone                                                      # AXFR / NSEC fixtures, real dig
./bench-run-recon.sh origin                                                    # forgotten-origin fixture
./bench-run-recon.sh http                                                      # headers, cookies, auth, robots/security.txt, favicon, PTR
./bench-run-recon.sh checks                                                    # all four; non-zero if any fails

./bench-run-recon.sh down                # tear down and remove volumes
```

`up` needs **ldnsutils** (`sudo apt install ldnsutils`) to sign `walk.test`; without it the
zone is served unsigned and `zone` skips the NSEC case. If `127.0.0.5` is taken, set
`LAB_ORIGIN_IP` to another loopback address for `up` and the checks.

First boot takes a minute or two (WordPress install, Jenkins start). `up`
installs WordPress with a throwaway admin password that is generated, used once
and not stored. See `../BENCHMARK.md` for the method, the results and the A/B
rule ("faster **and** identical").

## Name resolution and proxies

- **Lab DNS.** CoreDNS listens on `127.0.0.1:53` and answers for `test.`;
  `bench` always passes `--resolvers lab/resolvers.txt`, so dnsx, tlsx and httpx
  resolve through it. Tools that use the system resolver (katana, curl) need the
  `/etc/hosts` lines from `hosts`.
- **Port 53 already taken** (Pi-hole, dnsmasq or another resolver on the VM):
  bring the lab up with another loopback address, e.g.
  `LAB_DNS_IP=127.0.0.2 ./bench-run-recon.sh up --farm 50`. All of `127.0.0.0/8`
  is local on Linux; `up` writes that address into `resolvers.txt`.
- **HTTP(S) proxy.** If your shell exports `HTTPS_PROXY`, the harness adds
  `.test` to `NO_PROXY` for its own commands so lab traffic stays on loopback. The
  proxy still applies to everything else.
- **Passive sources.** run-recon skips internet archives and subdomain APIs for
  special-use names such as `.test` (`SKIP_SPECIAL_USE=1`, the default): they can
  hold nothing for a name that can never exist. `SKIP_SPECIAL_USE=0` sends those
  queries anyway; use it only to measure the passive collectors' latency.

## Takeover fixtures

The zone carries two CNAMEs so `--takeover` can be checked with the real tools:

| name | CNAME | expected |
|---|---|---|
| `alias.test` | `nginx.test` (exists) | listed in `<out>.cname.tsv`, **not** flagged |
| `orphan.test` | `gone.cloud.test` (does not exist: NXDOMAIN) | `dangling-cname [medium]` in `<out>.takeover.txt` |

`./bench-run-recon.sh takeover` runs run-recon with `--takeover --resolve` on
`targets-takeover.txt` and checks exactly that, plus that subzy's settings banner is not
recorded as a finding. The `[high]` grade (a dangling CNAME into a takeover-prone service
such as `*.azurewebsites.net`) needs real provider domains, so it is covered by the test
suite's mocks rather than the lab.

## Zone exposure fixtures

| zone | setup | `--zone-exposure` must report |
|---|---|---|
| `xfr.test` | unsigned; `transfer { to * }` | `zone-transfer-open [high]` naming `ns.xfr.test(127.0.0.1)`, and the names `hidden-ops` and `staging-api-2019`, which no wordlist or passive source would find |
| `walk.test` | signed with NSEC | `nsec-zone-walkable [medium]` with 5 names, including `secret-admin`, `vpn-legacy` and `q7-billing-replica` |
| `test.` | unsigned; transfers refused | `zone-checked [info]` only |

Names found under a seed are probed like any other candidate, so `secret-admin.walk.test`
appears in the CSV. There is **no NSEC3 fixture**: CoreDNS's file plugin cannot serve an
NSEC3-signed zone (a failed reload also keeps the previous configuration live), so the
`nsec3-hashes-exposed [low]` case is covered by the test suite's mocks. CoreDNS answers
denials so that `ldns-walk` stops at the apex; run-recon walks by asking for each owner
name's NSEC record (`dig +dnssec +norec NSEC <name>`), which works against CoreDNS, BIND
and Knot alike.

## Origin fixture

`nginx.test` is served through the Caddy edge (two `Server` headers: `Caddy` and
`nginx/1.21.6`). Its backend is also published directly on `LAB_ORIGIN_IP:80`, and two
records leak that address: `direct.nginx.test A 127.0.0.5` and nginx.test's SPF record
`v=spf1 ip4:127.0.0.5 -all`. `./bench-run-recon.sh origin` checks that `--origin` reports
`origin-exposed [high] host=nginx.test origin=127.0.0.5 port=80 match=body-sha256`, that
`spa.test` and `wp.test` (origins only on the container network) are not reported, and that
`<out>.edge.tsv` names the edge and the origin software.

## HTTP-detail fixtures (run-recon 1.19)

| name | what the lab serves | run-recon must report |
|---|---|---|
| `nginx.test` | nginx defaults: no security headers. Caddy adds a robots.txt (`Disallow: /private/`, a wildcard rule, a sitemap) and an **expired** security.txt; `/private/` asks for basic auth | `missing_sec_headers` = all four; robots `200 disallow=2 allow=0 sitemap=1`; `security-txt-expired [low]`; a `https://nginx.test/private/` row from robots.txt with status 401 and `auth=Basic realm="Lab Private"`, not `CleartextAuth` (it is HTTPS) |
| `spa.test` | CSP with `frame-ancestors`, HSTS one year, nosniff; a valid security.txt | nothing missing (CSP covers X-Frame-Options); `hsts_max_age=31536000`; security.txt present |
| `wp.test` | WordPress sets `wordpress_test_cookie` without HttpOnly on `wp-login.php` | `cookie_issues` names it |
| `ci.test` | Jenkins: favicon, a `Secure; HttpOnly` session cookie, a robots.txt that disallows `/` | `favicon_mmh3=81586312`; no cookie issue |
| `vpn-legacy.walk.test` | HTTP only, basic auth (realm "Legacy VPN") | `http_flags=CleartextAuth` |
| `www.walk.test` | Caddy's default site: an empty 200 for every path | `catch-all-200 [info]` from the 404 probe |
| reverse zone | `127.0.0.1` → `ingress.lab.test`, `LAB_ORIGIN_IP` → `origin-nginx.lab.test` | `ptr=ingress.lab.test` with `--enrich` (non-public addresses are asked only of the resolver passed with `--resolvers`) |

The basic-auth password in the Caddyfile is a throwaway lab value. katana reads robots.txt too, so
`/private/` and the sitemap URL also appear in default runs of the lab, for every version alike.

## Accuracy notes

- **Products and CPEs are the firm ground truth.** They follow from the pinned
  images. A missing version shows up as a missing CPE, which is the point: this
  measures real fingerprint recall.
- **TLS flags.** Caddy's local CA issues 12-hour leaf certificates, so every
  name is `CertExpiring`. tlsx's `untrusted` field only means "issued by a known
  untrusted or interception CA", so up to v1.17 the private Caddy CA was not
  flagged. From v1.18, `--tls` also validates each chain against the system trust
  store (Python `ssl`), so every lab name is `CertUntrusted`, as WebInventory
  reports it.
- **IPv6.** The AAAA records use the documentation prefix `2001:db8::/32`
  (never routed). `--ipv6` must report them for nginx and wp and nothing for spa
  and ci.
- **HTTP/3.** Caddy advertises `Alt-Svc: h3` on HTTPS only, so httpx lists
  `HTTP/3` for `https://` rows and not for `http://` rows. That is correct, and
  it is why scheme-correct probing changed those rows (see `../BENCHMARK.md`).
- **Farm.** WordPress farm vhosts are proxied with `Host: wp.test` so WordPress
  does not redirect them to its canonical name; the farm's ground truth is
  generated together with the vhosts.
