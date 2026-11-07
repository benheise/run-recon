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
| `docker-compose.yml` | the range: `dns` (CoreDNS), `bind` (BIND 9.18, for the NSEC3 zone), `ingress` (Caddy TLS vhost router), `nginx`, `wordpress` + `db`, `spa`, `jenkins` — all pinned. `nginx` is also published directly on `LAB_ORIGIN_IP:80` (default `127.0.0.5`): the "forgotten origin" fixture. The ingress also answers `403` to everything on `LAB_PROTECTED_IP:80` (default `127.0.0.6`): the "protected origin". BIND answers as `ns.nsec3.test` on `LAB_NSEC3_IP:53` (default `127.0.0.7`). `tlslab` (nginx 1.21.6) serves the TLS fixtures, each on its own address: `LAB_TLS_LEGACY_IP` … `LAB_TLS_MODERN_IP` (default `127.0.0.9`–`127.0.0.12`) |
| `tls-nginx.conf` | the TLS fixtures' nginx: one listener per fixture, its own protocols and ciphers (see "TLS fixtures" below) |
| `gen-tls-certs.py` | makes the TLS fixtures' certificates at `up` (needs `openssl` and `python3-cryptography`) |
| `Caddyfile` | vhost routing; serves every name on both `http://` and `https://` with certificates from Caddy's local CA, plus the HTTP-detail fixtures below |
| `Corefile` | CoreDNS: authoritative for `test.`, `walk.test.` and `xfr.test.` from the generated zone files; forwards `nsec3.test.` to BIND |
| `named.conf` | BIND: authoritative only, for `nsec3.test.`, transfers refused; shares the `dns` container's network and listens on `:5353` |
| `resolvers.txt` | the lab DNS server, passed to run-recon as `--resolvers` (dnsx/tlsx/httpx use it) |
| `targets.txt` | lab seeds: `nginx.test wp.test spa.test ci.test` |
| `targets-http.txt`, `targets-tls.txt` | *generated*: the seeds of the `http` and `tls` checks |
| `tls/` | *generated*: the TLS fixtures' certificates and throwaway keys (gitignored) |
| `expected.csv` | ground truth for the lab seeds (status, technologies, CPEs, TLS flags, IPv6) |
| *generated at `up`* | |
| `spa/index.html` | the 120 KB single-bundle SPA (WebInventory's SPA size) |
| `farm.caddy` | farm vhosts `f01..fNN.farm.test`, round-robin over the four backends |
| `lab.hosts` | address lines for the lab and the farm (the source for `db.test` and for `hosts`) |
| `db.test` | the `test.` zone: every A/AAAA record plus the takeover and origin fixtures below. Zone files use BIND's `db.<zone>` naming: files ending in `.zone` did not survive some synced folders |
| `db.walk.test`, `db.walk.test.signed` | `walk.test.`, DNSSEC-signed with NSEC by `ldns-signzone` (throwaway keys in `dnssec/`) |
| `db.xfr.test` | `xfr.test.`, unsigned, zone transfers allowed to anyone |
| `db.nsec3.test`, `db.nsec3.test.signed` | `nsec3.test.`, signed with NSEC3 (1 0 5 1A2B3C4D) by `ldns-signzone -n`, served by BIND |
| `db.posture.test` | `posture.test.` and `good.posture.test`: the email/DNS posture fixtures |
| `cloud.tfstate`, `cloudlist.yaml` | a Terraform state and the cloudlist provider config that reads it (offline) |
| `brute-wordlist.txt` | the `--brute` wordlist of the discovery check |
| `targets-posture.txt`, `targets-discovery.txt` | seeds for the posture and discovery checks |
| `db.127` | reverse zone for `127.0.0.0/8`: PTR fixtures for `--enrich` |
| `targets-takeover.txt` | seeds for the takeover check: `nginx.test alias.test orphan.test` |
| `targets-zone.txt` | seeds for the zone check: `walk.test xfr.test nsec3.test nginx.test` |
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
./bench-run-recon.sh http                                                      # headers, cookies, auth, robots/security.txt, favicon, PTR, redirects, login forms
./bench-run-recon.sh tls                                                       # --tls-enum: version matrix, weak suites, weak/default/future certificates
./bench-run-recon.sh posture                                                   # SPF/DMARC/MTA-STS/CAA, dangling MX/NS, lame NS, cloudlist
./bench-run-recon.sh discovery                                                 # naabu, alterx, shuffledns, cdncheck, uncover, notify
./bench-run-recon.sh scope                                                     # --scope / --list-targets; proved at the origin's access log
./bench-run-recon.sh resume                                                    # SIGTERM mid-run, --resume, CSV equals an uninterrupted run
RECON_DB_DSN=postgresql://... ./bench-run-recon.sh history                     # --monitor delta + recon-db history (store with RECON_DB_DSN)
./bench-run-recon.sh checks                                                    # all ten; non-zero if any fails

./bench-run-recon.sh down                # tear down and remove volumes
```

`up` needs **ldnsutils** (`sudo apt install ldnsutils`; the setup scripts install it) to sign
`walk.test` and `nsec3.test`; without it the zones are served unsigned and `zone` skips the NSEC and
NSEC3 cases. It also needs **python3-cryptography** and `openssl` for the TLS fixtures' certificates
(the setup scripts install it too). If `127.0.0.5`, `127.0.0.6`, `127.0.0.7` or `127.0.0.9`–`127.0.0.12` is taken,
set `LAB_ORIGIN_IP`, `LAB_PROTECTED_IP`, `LAB_NSEC3_IP` or `LAB_TLS_LEGACY_IP` … `LAB_TLS_MODERN_IP` to
another loopback address for `up` and the checks.

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
| `walk.test` | signed with NSEC | `nsec-zone-walkable [medium]` with 5 names, including `secret-admin`, `vpn-legacy` and `q7-billing-replica`; `dnssec-unanchored [low]` (no DS in `test.`) |
| `nsec3.test` | signed with NSEC3, on BIND (`ns.nsec3.test` = `LAB_NSEC3_IP`); transfers refused | `nsec3-hashes-exposed [low]` with `params="1 0 5 1A2B3C4D"`, its names **not** walked; `dnssec-unanchored [low]` |
| `test.` | unsigned; transfers refused | `zone-checked [info]` only |

Names found under a seed are probed like any other candidate, so `secret-admin.walk.test`
appears in the CSV. CoreDNS's file plugin cannot serve an NSEC3-signed zone (a failed reload
also keeps the previous configuration live), so `nsec3.test` is served by BIND, which runs in
the `dns` container's network: CoreDNS forwards the zone to it, and the zone check reaches it
directly as the zone's name server. CoreDNS answers denials so that `ldns-walk` stops at the
apex; run-recon walks by asking for each owner name's NSEC record
(`dig +dnssec +norec NSEC <name>`), which works against CoreDNS, BIND and Knot alike. Neither
signed zone has a DS in its parent (CoreDNS answers a zone's DS query from the zone itself), so
the `ds=yes` case is covered by the suite's mocks.

## Origin fixture

`nginx.test` is served through the Caddy edge (two `Server` headers: `Caddy` and
`nginx/1.21.6`). Its backend is also published directly on `LAB_ORIGIN_IP:80`, and two
records leak that address: `direct.nginx.test A 127.0.0.5` and nginx.test's SPF record
`v=spf1 ip4:127.0.0.5 -all`. `./bench-run-recon.sh origin` checks that `--origin` reports
`origin-exposed [high] host=nginx.test origin=127.0.0.5 port=80 match=body-sha256`, that
`spa.test` and `wp.test` (origins only on the container network) are not reported as exposed, and
that `<out>.edge.tsv` names the edge and the origin software.

`origin.spa.test` points to `LAB_PROTECTED_IP`, where the ingress answers every request with
`403 direct access denied` (an origin locked to its CDN), and nothing listens on 443. The check
expects `origin-protected [info] host=spa.test origin=127.0.0.6 via=origin.spa.test
reason=443:refused,80:status-403-other-content`, and nothing at all for `wp.test`.

## Email/DNS posture fixtures (run-recon 1.20)

`posture.test` gets everything wrong and its subdomain `good.posture.test` everything right. Both are
served by CoreDNS from `db.posture.test`; the MTA-STS policies come from the Caddy ingress, whose
certificates are issued by Caddy's local CA, so `bench-run-recon.sh posture` reads that CA out of the
ingress container and passes it with `--mta-sts-ca` (certificate verification stays on).

| Record | posture.test | expected | good.posture.test |
|---|---|---|---|
| NS | `ns` (CoreDNS), `ns-gone.nowhere.test` (`nowhere.test` does not exist), `ns-lame` → `LAB_NSEC3_IP` (BIND refuses the zone) | `ns-dangling [high]`, `ns-lame [medium] reason=refused`; CoreDNS not lame | (the zone's) |
| MX | `mx1` (exists), `mx-old.gone-mail.test` (`gone-mail.test` does not exist) | `mx-dangling [high]` | `mx1` |
| SPF | `include:_spf.posture.test +all` | `spf-permissive [high]` | `mx -all` |
| DMARC | `p=none`, no `rua` | `dmarc-none [low]`, `dmarc-no-rua [info]` | `p=reject; rua=...` |
| MTA-STS | `testing`, lists `mx1` only | `mta-sts-testing [info]`, `mta-sts-mx-mismatch [medium]` | `enforce`, lists `mx1` |
| TLS-RPT | none | `tlsrpt-missing [info]` | present |
| CAA | `0 issue "letsencrypt.org"` | nothing | (the zone's) |

`good.posture.test` must have no finding at all. The same check runs `--cloudlist` against `cloud.tfstate`
(cloudlist's Terraform provider reads it offline): `127.0.0.1` is matched to the scan's inventory, and
`127.0.0.8`, which nothing in the lab serves, is `cloud-asset-unseen [info]`.

## Discovery fixtures (run-recon 1.20)

`bench-run-recon.sh discovery` runs the discovery tools for real: a baseline run on `nginx.test`, then a
second with `--ports --port-spec 80,443,8443 --permute --brute --origin --monitor --notify` against it.

| Tool | Fixture | Expected |
|---|---|---|
| naabu | the ingress also serves `https://nginx.test:8443` (published on 127.0.0.1:8443) | a `https://nginx.test:8443` row |
| alterx | `grafana.nginx.test` exists in `db.test`; alterx guesses it from `nginx.test` | a row with source `alterx` |
| shuffledns + massdns | `backup-db.nginx.test` exists; `brute-wordlist.txt` holds `backup-db` | a row with source `bruteforce` |
| cdncheck | the loopback edge; and `104.16.0.1` checked directly | no CDN tag; `104.16.0.1 [waf] [cloudflare]` in the format `--origin` parses |
| notify | a webhook on a random loopback port, `NOTIFY_CONFIG` pointing at it | one message (`-bulk`) naming the new `:8443` asset |
| uncover | run with an empty `HOME` (no keys) | the "requires keys" message that run-recon turns into a warning |

The baseline run must not have the alterx or wordlist names. massdns has no package on most systems; the
setup scripts build it from source (`github.com/blechschmidt/massdns`).

## Scope, resume and history checks (run-recon 1.20)

These need no new fixtures; they use the lab's names and the origin fixture.

`bench-run-recon.sh scope`:
1. `--list-targets` with `ci.test` outside the scope: exit 2, and `ci.test` is shown as out of scope.
2. A scope with names only, and `--origin --screenshots`: the origin candidates (`127.0.0.5`, `127.0.0.6`)
   are listed in `<out>.scope.txt` and not contacted. The browser, held to the seed's names, still
   renders `nginx.test`.
3. The same with the two origin addresses allowed: `origin-exposed` for nginx.test and `origin-protected`
   for spa.test, as without `--scope`.
4. `!127.0.0.5` and `!backup-db.nginx.test`, with a wordlist that finds `direct.nginx.test` (127.0.0.5) and
   `backup-db.nginx.test`: neither name is in the CSV. The proof is the nginx container's own log. A
   request to `LAB_ORIGIN_IP` arrives from the docker bridge gateway, so the count of such lines must not
   change during the run. The same run without `--scope` must change it, which shows the check can see
   that traffic.
5. MTA-STS: with `!mta-sts.posture.test`, the posture table says the policy was not fetched.

`bench-run-recon.sh resume`: two uninterrupted runs of the lab targets with `-t 1 --tls`, then a third one
stopped by SIGTERM after two seeds (exit 143, state `interrupted`) and resumed. The resumed CSV must equal
the first run's under `compare --exact`, with the second run as the noise floor.

`bench-run-recon.sh history`:
1. A run of the lab targets, then the `spa` backend is stopped and a second run is made with `--monitor`.
2. `<out>.delta.tsv` must show `spa.test` status `200` → `502` and nothing for the other three hosts, and
   the report must have the Changes section. `recon-db.sh changes --csv` must find the same event.
3. With `RECON_DB_DSN` set (a PostgreSQL database), both runs also go to the store (`--db`), and
   `recon-db.sh changes` / `history` must find the event and nginx.test's first/last seen there.

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

## Redirect and login-form fixtures (run-recon 1.20)

Part of `bench-run-recon.sh http` (`--extras`), from the Caddyfile:

| URL | what the lab serves | run-recon must report |
|---|---|---|
| `https://redir.test/` | `302` → `/login`, a page with a password form whose `action` is `http://redir.test/session` | `final_url=https://redir.test/login`, `redirect_chain=302->https://redir.test/login` (`/login` is a hop `--extras` fetched, not a URL row), `login_form=http://redir.test/session`, `auth=Form`, `CleartextAuth` on the HTTPS row |
| `http://redir.test/session` | found by the crawl in that form; `301` → `https://redir.test/session` (`200`) | the http:// → https:// hop followed |
| `https://redir.test/old` | `301` → `https://elsewhere.test/` (no such site) | the hop listed in `redirect_chain`, not followed; `final_url` stays `https://redir.test/old` |
| `http://plainlogin.redir.test/` | a password form on a plain-HTTP page | `login_form=http://plainlogin.redir.test/login`, `http_flags=PlainHttp;CleartextAuth` |

## TLS fixtures (run-recon 1.20)

`bench-run-recon.sh tls` runs `--tls-enum` against `targets-tls.txt`. One nginx 1.21.6 (OpenSSL 1.1.1n)
serves four names, each on its own loopback address so each has its own protocol and cipher policy
(`tls-nginx.conf`). The certificates are made at `up` by `gen-tls-certs.py`; the legacy one with the
`openssl` command, since python3-cryptography refuses to sign with SHA-1.

| name | what it serves | run-recon must report |
|---|---|---|
| `legacy.tls.test` | TLS 1.0–1.2; CBC-SHA suites, and `NULL-SHA` when a client offers only weak suites; RSA 1024 / SHA-1, self-signed | `tls_supported=TLS 1.2;TLS 1.1;TLS 1.0`, `tls_weak_cipher=TLS 1.2:TLS_RSA_WITH_NULL_SHA`, `cert_key=RSA 1024`; `WeakTLS`, `WeakCipher`, `WeakKey`, `WeakSig`, `SelfSigned`, `CertUntrusted` |
| `future.tls.test` | a certificate valid from 30 days after `up` | `CertNotYetValid` (tlsx sets no `expired` for it) |
| `default.tls.test` | OpenSSL's default subject, `O=Internet Widgits Pty Ltd` | `DefaultCert` |
| `modern.tls.test` | TLS 1.2–1.3, ECDSA P-256: the control | `tls_supported=TLS 1.3;TLS 1.2`, `cert_key=EC P-256`, none of the flags above |

The check also reads the matrix a second way, with tlsx's own per-version handshakes
(`-min-version`/`-max-version`), and asks the container's openssl whether `legacy.tls.test` negotiates
`NULL-SHA`. Debian's OpenSSL 1.1.1 is built without 3DES and RC4, so `NULL-SHA` stands in for them: the
same `WeakCipher`. Nothing here can serve SSL 3.0; the probe's SSL 3.0 hello is covered by the suite's
local TLS speaker instead.

`legacy.tls.test` also shows why the chain check retries: the local OpenSSL refuses its key size
and protocol before it gets to the chain, so the first handshake fails without a verdict. The
second try, at security level 0, reaches one (`self-signed certificate` → `CertUntrusted`).

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
