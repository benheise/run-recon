# Lab report review: generate-report.sh on run-recon v1.17.0 (fixed in v1.18.0)

**Run:** seeds `nginx.test wp.test spa.test ci.test alias.test orphan.test` with
`--tls --ipv6 --enrich --takeover --origin --screenshots --resolve`. The result was 91 URL rows,
5 live hosts, a takeover file, an origin file, a CNAME inventory and screenshots. The report
(`lab-report.html`) shows 9 findings, all MEDIUM.

## Status in v1.18.0

Every item below is fixed in run-recon / generate-report v1.18.0, with a lab fixture or a suite test for
each. The regenerated lab report is `lab-report/lab-report.html`.

| # | Issue | v1.18.0 | Checked by |
|---|---|---|---|
| §1 | No zone walking / AXFR | `--zone-exposure`: AXFR on every name server, NSEC walk, NSEC3 parameters; names found under a seed are scanned | `bench-run-recon.sh zone` (xfr.test, walk.test, test.); suite mocks for NSEC3 |
| §3, 1 | Origin never identified | `--origin`: edge detection (`.edge.tsv`), candidates from sibling names, SPF/MX and zone names, verification with `curl --resolve`, `origin-exposed` only on a match | `bench-run-recon.sh origin`: nginx.test → 127.0.0.5, nothing for spa/wp |
| 2 | 4 false "exposed origin" findings | JARM and CDN tags are host attributes in `.edge.tsv`; `.origin.txt` holds verified origins only | suite + lab check |
| 3 | Colour codes in findings | `tlsx -nc`; codes stripped in run-recon and in the report | suite (mock emits them) |
| 4 | Screenshots of the proxy error page, 0-byte images | the browser gets `--proxy-server` / a `--proxy-bypass-list` from `NO_PROXY` and an installed Chrome; every capture validated into `.screenshots.tsv` (ok / blank / failed / suspect) | lab: real captures of nginx, wp, spa, ci; suite: suspect, blank, routing flags |
| 5 | "Complete" with 0 rows | the preflight resolves the first seed (SERVFAIL/REFUSED fail, NXDOMAIN called out); per-seed warnings; 0 rows → "Finished with NO results", exit 3, report banner | suite |
| 6 | Data the report never showed | host cards: title, IPv6, server, edge → origin, JARM, favicon, certificate issuer and days left, CNAME chain, aliases, CPEs | suite |
| 7 | TLS severity | expiry graded by days left (expired High, < 7 days Medium, < 30 days Low); `CertExpiring` at 30 days (WebInventory); chain validation against the system trust store → `CertUntrusted` | suite (local TLS server), lab (Caddy CA now `CertUntrusted`) |
| 8 | Incomplete inventory | "Names" table: every name with its DNS state; aliases under their target; cards for dangling names with findings; seeds / names / live hosts in the summary | suite |
| 9 | Crawl junk | URLs with `\/` or `%5C/` dropped before normalisation | suite; lab A/B (the only default-path difference) |
| 10 | No run metadata | `<out>.run.json` and a run header in the report | suite |
| 11 | Vulnerabilities silently absent | "Known vulnerabilities: not checked" plus the CPEs that would be checked | suite |

One change from the design below: the forgotten origin listens on `127.0.0.5` (`LAB_ORIGIN_IP`), not
`127.0.0.2`, which the lab DNS override documents as an alternative DNS address. There is no NSEC3 lab
fixture because CoreDNS cannot serve an NSEC3 zone.

### Re-review of the v1.18.0 lab report

Seeds: the four lab sites, the takeover fixtures and the zone fixtures, with
`--tls --ipv6 --enrich --takeover --origin --zone-exposure --screenshots --resolve`. Result: 99 URL rows,
17 names, 16 live hosts, 12 findings (2 high, 10 medium), exit 0, one warning (orphan.test does not
resolve, which is the dangling-CNAME fixture working).

What is now right: the origin (127.0.0.5) is named with how it was found and how it was verified; the four
false JARM findings are gone; the open transfer and the walkable zone are the first findings after the
origin; every harvested name has a card that says it came from the zone; screenshots are real or marked
blank; certificate expiry reads "expires in 10 hours"; the run header says what produced the report.

Smaller things left, none of which makes the report say something untrue:

| Observation | Possible refinement |
|---|---|
| A lone `Server: Caddy` is recorded as an edge (`[edge-server]`) on the 12 Caddy default pages | call a single Server header an edge only for CDN/WAF products; keep reverse proxies to the server-chain rule |
| "10 CPEs would be checked" includes versionless ones (`caddyserver:caddy:*`), which a vulnerability join cannot match by version | list versioned CPEs, count versionless ones separately |
| The per-seed "did not resolve" warning for orphan.test does not say the name has a dangling CNAME | mention the CNAME when the takeover check has one |
| Medium findings are dominated by the lab's private CA (8 of 10) | expected in the lab; in production a private CA on an internet-facing site is a real finding |
| No HTTP security headers, cookie flags or HSTS yet | batch 2 of `TOOL-COVERAGE.md` |

## 1. Zone walking (the NSEC chain): not used by run-recon

The test-report finding describes **DNSSEC zone walking**. In a zone signed with NSEC records, each
NSEC record names the *next* name in the zone. Asking for a name, then the name it points to, and so
on, lists every name until the chain returns to the apex. NSEC3 hashes the names, so walking it yields
hashes that can be cracked offline with a dictionary. The other classic exposure is an **open zone
transfer** (AXFR), which hands over the whole zone in one query.

run-recon does neither. It has no AXFR attempt, no NSEC/NSEC3 handling and no DNSSEC checks; a
search of every script found none. Its DNS stages are:

- passive subdomain sources (subfinder, amass, CT logs);
- dictionary brute force (shuffledns / puredns) and permutations (alterx);
- the dnsx resolve gate and wildcard filter;
- AAAA records (`--ipv6`) and CNAMEs (`--takeover`).

**Recommendation: add a `--zone-exposure` check.** For each seed's zone, find the authoritative
name servers (NS), then:

| Check | Method | Finding | Names harvested |
|---|---|---|---|
| Open zone transfer | `dig AXFR <zone> @<each NS>` | `zone-transfer-open [high]`, per name server | all of them, fed into the candidate list |
| NSEC walk | `ldns-walk` (ldnsutils), `dnsrecon -t zonewalk`, or a `dig +dnssec NSEC` loop | `nsec-zone-walkable [medium]` | every name in the zone |
| NSEC3 | collect hashes (`nsec3map`); flag no salt / few iterations / opt-out | `nsec3-hashes-exposed [low]` | only after offline cracking (not by default) |
| Signing status | DNSKEY / DS present | context only (unsigned zones cannot be walked) | |

This is scoped like the rest of the tool: only the seed zones' own name servers are queried.
The names it returns become candidates, so they reach the takeover check, the probe and the origin
search described below. **Lab fixtures:**

- Pre-sign `test.zone` with NSEC (`ldns-signzone` or `dnssec-signzone`) so CoreDNS serves a walkable
  chain. CoreDNS's own on-the-fly `dnssec` plugin uses minimal "white lies" that cannot be walked,
  which makes it a useful negative case.
- Add a second zone with `transfer { to * }`, so the AXFR check has a positive case.

## 2. What the report gets wrong or leaves out

Ordered by impact.

| # | Issue | Evidence from this run | Fix |
|---|---|---|---|
| 1 | **The origin is never identified.** Every host card shows `127.0.0.1`, which is the edge (the Caddy reverse proxy), not the origin. | Through the edge, the responses carry two `Server` headers (`Caddy` and `nginx/1.21.6`); httpx merged them into one value (`webserver: Caddy nginx/1.21.6`). The real origin, `172.18.0.2`, answers `Host: nginx.test` directly with the same page (`Welcome to nginx!`). | See §3 |
| 2 | **4 of the 9 findings are false.** The JARM lines in `.origin.txt` are labelled "Exposed origin IP" at MEDIUM. | The 4 hashes are identical: that is the edge's JARM (Caddy), not an exposed origin. `--origin` only collects hints (JARM, cdncheck); nothing is verified. | JARM and CDN tags become host attributes. "Exposed origin" is reported only for a verified origin (§3). |
| 3 | **Raw terminal colour codes in findings.** | `jarm ci.test:443 [␛[35m40d40d…␛[0m]` | Run `tlsx -jarm` with `-nc`, and strip ANSI codes from every side artifact before the report reads it. |
| 4 | **The screenshots are not of the sites.** | ci, spa and wp produced 0-byte PNGs (they appear as broken images). nginx and alias show this sandbox's outbound-proxy error page: the headless browser took the environment proxy and ignored the `.test` exclusion and `--resolvers`. Nothing flagged it. | Validate each capture: non-empty, and the page title matches the probed title. Mark failures as failed. Give the browser the same proxy/resolver settings as httpx. On a corporate network with a proxy, this also keeps internal hostnames from going to the proxy. (WebInventory confines its browser with a scope proxy.) |
| 5 | **A run where nothing resolved still says "Complete".** | Before the lab zone was regenerated, the lab DNS returned SERVFAIL for every name. The preflight said `resolver check passed (127.0.0.1 responding)`; the run wrote 0 rows, printed `Complete.` and exited 0. | The preflight must resolve a known name (or a seed), not just get an answer. Warn per seed when the seed itself does not resolve. Return a non-zero exit code and a report banner when a run produces 0 rows. |
| 6 | **Data in the CSV that the report never shows.** | Page titles (`Lab WordPress`, `Lab SPA`), IPv6 addresses (`2001:db8:1::10`), certificate issuer (`Caddy Local Authority - ECC Intermediate`) and expiry date, CPEs, the server chain, cloud/RDAP/geo, and the CNAME inventory (`.cname.tsv` is not read at all). | Host card: title, IP + IPv6, edge → origin chain, CNAME chain, certificate (issuer, expiry date, days left), CPEs. |
| 7 | **TLS severity is miscalibrated.** | Certificates that expire in **12 hours** are shown as "expiring within 21 days", as context rather than findings, so they count as 0 low / 0 medium. A private CA is not flagged untrusted (tlsx's "untrusted" is a bad-CA list, not chain validation). | Show days left; grade expired / under 7 days / under 30 days. Add real chain validation against the system trust store (Python `ssl`), so `CertUntrusted` matches WebInventory. |
| 8 | **The inventory is incomplete.** | `orphan.test` has a finding but no host card, because it is not live. `alias.test` appears as a separate host ("Caddy") with no link to its CNAME target `nginx.test`. The header says 5 hosts for 6 seeds. | List every name with its DNS status (live / dangling / NXDOMAIN). Group aliases under their CNAME target. Summary: seeds, names, live hosts. |
| 9 | **Junk URLs from the crawl.** | `http://wp.test/%5C/wp.test%5C/index.php`, `…%5C/wp-emoji-release.min.js` (katana parsed JSON-escaped `\/` paths). | Unescape `\/` before URL normalisation, or drop URLs containing `%5C/`. |
| 10 | **No run metadata.** | The report doesn't say which seeds, flags, run-recon version, tool versions, resolvers or duration produced it. | A run header from a `run.json` written by run-recon (the tool versions are already logged). This matches WebInventory's run record and manifest. |
| 11 | **Vulnerabilities silently absent.** | No NVD/KEV/EPSS feeds were available, so there is no vulnerability section and no note saying the check was not run. | Show "Vulnerabilities: not checked (no feeds)" plus the CPE list, so the gap is visible. |

## 3. Identifying the origin

What is needed is the address that serves the site **behind** the CDN, WAF or reverse proxy. If
that address answers directly, the edge's protections can be bypassed: that is the actual "exposed
origin" finding. Three steps:

1. **Detect the edge, per host.** Signals: several `Server` headers (here `Caddy` + `nginx/1.21.6`);
   `Via`; CDN headers (`cf-ray`, `x-amz-cf-id`, `x-served-by`, `x-akamai-*`); a cdncheck CDN/WAF tag;
   the same JARM and certificate across unrelated sites. The output is new columns `edge` and
   `origin_software` (here `Caddy` and `nginx/1.21.6`).
2. **Collect candidate origin IPs** from sources the tool already has or that §1 adds:
   - A records of sibling names that are not CDN addresses (`direct.`, `origin.`, `mail.`, `ftp.`, `cpanel.`);
   - SPF `ip4:` / `ip6:` and MX addresses;
   - names from AXFR or NSEC walking (§1);
   - a certificate SAN scan of owned ranges (ASN seeds);
   - uncover searches for the site's certificate serial or SHA-256, favicon mmh3 and title (Shodan/Censys keys);
   - historical DNS, as a later option.
3. **Verify each candidate.** Request it directly with `Host:` / SNI set to the site's name, and
   compare it with the edge response: title, body SHA-256 (or similarity), favicon mmh3, certificate.
   A match gives a new finding, `origin-exposed [high] host=nginx.test origin=172.18.0.2 match=title+body`;
   WebInventory's SAN-vhost probe uses the same comparison. A candidate that refuses the direct request,
   for example because it only accepts traffic from the edge, is recorded as `origin-protected`.

**Lab fixture.** Publish the nginx backend directly on `127.0.0.2:80` (a "forgotten" origin) and
leak that address through a sibling record (`direct.nginx.test A 127.0.0.2`) and an SPF record.
The check must then report `origin-exposed` for nginx.test, and nothing for the other three sites,
whose origins stay on the container network.

## 4. Suggested order

| Priority | Items | Why first |
|---|---|---|
| P1 | 2, 3, 4, 5 | The report currently says things that are not true: false findings, fake screenshots, a "Complete" run with nothing in it. |
| P2 | §3 origin identification, §1 zone exposure | These are the capabilities you asked about. Both need the lab fixtures above, and they feed each other: walked names become origin candidates. |
| P3 | 6, 7, 8, 9, 10, 11 | Surface data that is already collected, calibrate severities, and add evidence (WebInventory parity). |
