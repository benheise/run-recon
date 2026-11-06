# Extending `run-recon.sh`: Additional Sources & Tools

*Focus: certificate-based discovery, plus a survey of how the major open-source recon frameworks chain their sources — mapped to your existing pipeline and biased toward defensive EASM (you own the assets).*

---

## 1. Where the current pipeline stands, and the gaps

`run-recon.sh` today does: passive URL collection (`gau` + `waybackurls`, `waymore` in `--deep`), optional passive subdomain enum (`subfinder`), live probing + enrichment (`httpx`), crawl (`katana`), content brute-force (`feroxbuster`/`ffuf`), and normalize/dedup (`uro`/`anew`). That's a solid **URL-centric** pipeline. The gaps, roughly in order of value for an asset-owner:

1. **Certificate-based discovery beyond `subfinder`'s passive sources** — specifically *active* TLS SAN grabbing (`tlsx`) and the ASN→CIDR→cert pivot. This is the thing you asked about, and it's genuinely high-value.
2. **Active DNS**: bruteforce + permutations + resolution/wildcard-filtering. This is the *only* way to find hosts hidden behind wildcard certs (see §2).
3. **ASN / CIDR expansion** — for EASM you know your own IP space; enumerate it directly.
4. **Port discovery** (`naabu`) so web services on non-standard ports aren't missed before `httpx`.
5. **DNS resolution/validation** (`dnsx`) to kill false positives before probing.
6. **Triage & defensive checks**: screenshots for eyeballing, and subdomain-takeover detection for *your own* dangling CNAMEs.

---

## 2. Certificate-based discovery — the two techniques

There are two fundamentally different ways to get hostnames out of certificates, and good recon uses both.

### 2a. Passive — Certificate Transparency (CT) logs

Every certificate issued by a publicly-trusted CA is appended to public, append-only CT logs. The **Subject Alternative Name (SAN)** field lists every hostname a cert covers, so querying CT logs for a domain yields subdomains — including internal/staging/dev names that were briefly given a cert — **without ever touching the target**. Because logs are append-only, you also see names that no longer resolve (historical assets).

**How to query it directly (no tool needed):**

```bash
# crt.sh JSON API — query both wildcard and bare forms, merge, strip *. , dedup
curl -s 'https://crt.sh/?q=%25.example.com&output=json' \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | tr 'A-Z' 'a-z' | sort -u

# crt.sh Postgres interface (heavier queries, no HTTP rate limit)
echo "SELECT ci.NAME_VALUE FROM certificate_identity ci \
 WHERE ci.NAME_TYPE='dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.example.com'));" \
 | psql -tA -h crt.sh -p 5432 -U guest certwatch | sed 's/\*\.//g' | sort -u
```

**Dedicated tools:** `ctfr` (queries crt.sh for subdomains), `certspotter` (SSLMate's CT monitor API), `tls.bufferover`/`dns.bufferover` (used by reconFTW).

> **Reality check:** `subfinder` *already* uses crt.sh and certspotter among its sources. So bolting on a dedicated CT tool adds only marginal coverage over what you're getting. The bigger, less-redundant win is the **active** side below.

**The wildcard blind spot (this is the key insight):** CT logs only record what's *in* the issued cert. If an org uses a wildcard cert `*.example.com`, the log shows exactly that — not `admin.example.com`, `jenkins.example.com`, etc. Those hostnames appear in **no** passive source. The only way to find them is active DNS (§4). ProjectDiscovery makes this point explicitly as the motivation for `alterx`.

### 2b. Active — TLS certificate grabbing (`tlsx`, `cero`)

Instead of reading logs, you **connect to live hosts (or entire IP ranges)** and pull the cert off the wire, then extract SAN/CN. This surfaces names that were never logged publicly and, crucially, lets you sweep IP space you own.

**`tlsx` (ProjectDiscovery)** — the one that slots straight into your PD-based stack:

```bash
# Grab SANs/CNs from a host list (e.g. your live hosts from httpx), emit just the names
cat live-hosts.txt | tlsx -san -cn -resp-only -silent | sort -u

# Sweep a CIDR you own: every domain served on that IP space
echo 203.0.113.0/24 | tlsx -san -cn -silent -resp-only | dnsx -silent | httpx -silent

# The EASM power move — ASN → CIDR → cert scan → your own domains
asnmap -d example.com -silent | tlsx -san -cn -resp-only -silent | anew certs-subs.txt
```

`tlsx` flags worth knowing: `-san`/`-cn`/`-so` (org), `-dns` (unique hostnames only), `-resp-only` (names only, no host prefix), `-j`/`-json`, `-p` (ports, default 443), `-scan-all-ips`/`-sa`, `-c` (concurrency, default 300). It also does misconfiguration flags (`-ex` expired, `-ss` self-signed, `-mm` mismatched, `-re` revoked, `-untrusted`, `-wc` wildcard) and **JARM/JA3** fingerprinting — a mismatched cert or an off JARM hash on an IP is a classic tell for an **origin server behind a CDN/WAF**.

**Feedback loop (recommend adding this):** after `httpx` gives you live hosts, run `tlsx -san -cn` against them and re-feed the discovered names back through your scope filter → `dnsx` → `httpx`. Certs routinely name sibling hosts you didn't have.

**Lighter alternatives:** `cero` (dead-simple: connects to `host:443` and scrapes SANs), `getaltname`/`certrip` (Python, per-host SAN extraction).

---

## 3. How the major frameworks chain their sources

The value here isn't any single tool — it's the **pattern**. Every serious framework does: *many passive sources → active DNS (brute + permute + resolve + wildcard-filter) → probe → crawl → fuzz → (vuln)*, deduping with `anew` between stages.

**reconFTW** (six2dez — the most comprehensive OSS reference):
- Passive subdomains: `subfinder` + `assetfinder` + `amass` + `findomain` (+ historically `crobat`/Rapid7 Sonar)
- CT logs: `ctfr` + `tls.bufferover` + `dns.bufferover`
- Historical URLs: `gau`
- JS scraping for subdomains: `JSFinder` / `galer`
- Permutations: `dnsgen` (skips if >100 subs — otherwise >8M combos)
- Resolution/wildcard filtering: `puredns` + `massdns`
- Web probe: `httpx` across **87 common web ports** (not just 80/443)
- Port scan: `naabu`
- Takeover: `subzy` (21 fingerprints; `nuclei` has ~75)
- Screenshots for triage

**BBOT** — modular/event-driven; `bbot -t target -f subdomain-enum` chains passive+active, and modules like `naabu`/`gowitness` bolt on. Good model for a "recursive" pipeline where discovered assets feed back as new seeds.

**Osmedeus / reNgine** — workflow orchestrators (YAML/DB-driven) wrapping the same underlying tools; useful as inspiration for how to make stages configurable, less so as tools to embed.

**GarudRecon / smartrecon / Sudomy** — bash orchestrators closer to your script's spirit; their tool lists are a good "menu" (they lean heavily on the PD suite + `gowitness` + `dalfox`/`nuclei`).

The universal lessons for `run-recon.sh`: **(a)** run several subdomain sources and dedup, **(b)** always *resolve/validate* discovered names to strip false positives before you probe, **(c)** probe more than 80/443, **(d)** feed discovered assets back as new seeds (recursion).

---

## 4. Tool catalog by pipeline stage

Only tools that realistically fit an EASM URL-discovery pipeline. ⭐ = highest ROI for your use case. "Kali apt" = installable via `apt`; otherwise `go install` or `pdtm` (ProjectDiscovery Tool Manager, which installs/updates the whole PD suite).

### Stage A — Subdomain discovery (produces more seed hosts)
| Tool | What it adds | Install |
|---|---|---|
| `amass` (enum) | Largest source set + own DB; `-passive` or `-active` | Kali apt |
| `assetfinder` | Fast, complementary passive sources | `go install` |
| `findomain` | Fast passive; occasional unique hits | Kali apt |
| `github-subdomains` | Subdomains scraped from GitHub code/commits (needs GH token) | `go install` |

*Note:* `subfinder -all` already covers most passive sources. Add `amass` + `assetfinder` for breadth; the rest is diminishing returns.

### Stage B — Certificate-based ⭐ (the focus)
| Tool | What it adds | Install |
|---|---|---|
| `tlsx` ⭐ | Active SAN/CN grab from hosts **and CIDRs**; JARM for origin discovery | `go install` / `pdtm` |
| `ctfr` | Passive CT-log (crt.sh) subdomains | pip/`go` |
| `cero` | Minimal active SAN scraper (host:443 → SANs) | `go install` |

### Stage C — ASN / CIDR / IP expansion (asset-owner EASM) ⭐
| Tool | What it adds | Install |
|---|---|---|
| `asnmap` ⭐ | Org/domain/IP → owned CIDR ranges (needs free PDCP key) | `go install` / `pdtm` |
| `mapcidr` | Expand/aggregate/slice CIDRs into IP lists | Kali apt / `pdtm` |
| `cdncheck` | Is this IP CDN/edge or true origin? | `go install` / `pdtm` |
| `uncover` | Query Shodan/Censys/Fofa/Quake/ZoomEye by org or favicon hash | `go install` / `pdtm` |

### Stage D — Active DNS: bruteforce, permutations, resolve/wildcard-filter ⭐
| Tool | What it adds | Install |
|---|---|---|
| `dnsx` ⭐ | Resolve/validate names, wildcard filtering, A/AAAA/CNAME/etc. — **zero external deps** | Kali apt / `pdtm` |
| `puredns` | massdns-backed brute+resolve with best-in-class wildcard + poison filtering | `go install` |
| `shuffledns` | massdns wrapper: brute/resolve/filter modes, lazy wildcard detection | `go install` / `pdtm` |
| `alterx` ⭐ | Pattern/DSL permutations — minimal, high-signal (vs. `dnsgen` millions) | `go install` / `pdtm` |
| `gotator` / `dnsgen` | Older blind permutation generators (huge output) | `go install` / pip |

*Dependencies:* `puredns`/`shuffledns` need **`massdns`** + a **fresh resolver list** (`trickest/resolvers`). Cert-derived brute wordlists: `n0kovo_subdomains_huge.txt` (3M, harvested from IPv4 TLS certs), Assetnote `best-dns-wordlist.txt` (9M) — run these on a VPS, not over home DNS.

### Stage E — Port discovery (before `httpx`) ⭐
| Tool | What it adds | Install |
|---|---|---|
| `naabu` ⭐ | Fast SYN/CONNECT/UDP scan; `-ec` skips full scans on CDN/WAF; `-top-ports` | Kali apt (needs `libpcap-dev`) |

Feeding `naabu` output to `httpx` catches web apps on 8080/8443/3000/5000/etc. that a 80/443-only probe misses.

### Stage F — More URL / endpoint sources (augment `gau`/`katana`)
| Tool | What it adds | Install |
|---|---|---|
| `urlfinder` | PD's newer passive URL collector (gau-like, actively maintained) | `pdtm` |
| `github-endpoints` | URLs/paths from GitHub (needs token) | `go install` |
| `hakrawler` / `gospider` | Alternative crawlers (different coverage than katana) | `go install` |
| `subjs` / `getJS` → `xnLinkFinder` / `jsluice` | Pull JS files, then mine them for endpoints/params/secrets | `go`/pip |

### Stage G — Triage & defensive checks (high EASM value) ⭐
| Tool | What it adds | Install |
|---|---|---|
| `httpx -screenshot` or `gowitness` ⭐ | Screenshots for fast visual triage of large host lists | httpx built-in / `go install` |
| `subzy` ⭐ | Subdomain-takeover detection — find *your own* dangling CNAMEs | `go install` |
| `nuclei` | Broad misconfig/exposure/CVE/takeover templates (bigger scope) | Kali apt / `pdtm` |

---

## 5. Concrete recommendations for `run-recon.sh`

Tiered by ROI and by how cleanly they fit the current design (all Tier-1 picks are stdin-friendly PD tools, so they drop into the existing per-domain worker with minimal plumbing).

### Tier 1 — do these first (low friction, high signal)
- **`dnsx` as a validation gate.** After subdomain collection and before `httpx`, pipe discovered names through `dnsx` to drop non-resolving junk and wildcard noise. Directly improves CSV quality and cuts wasted `httpx` probes. New flag idea: `--resolve` (on by default when `dnsx` present).
- **`tlsx` SAN harvest as a discovery source + feedback loop.** Add a `--certs` stage: run `tlsx -san -cn -resp-only` against live hosts (and, if given, CIDRs), send names back through your existing `scope_filter` → `dnsx` → `httpx`. This is the certificate feature you asked for, and it composes with what you already have.
- **`alterx` permutations (guarded).** New flag `--permute`: `discovered-subs | alterx | dnsx -silent`. Gate it (like reconFTW's >100 rule) so you don't explode on large sets.

### Tier 2 — asset-owner EASM expansion
- **`asnmap` + `mapcidr` + `tlsx` CIDR sweep.** New input mode: accept an **ASN or CIDR** seed (not just domains), expand with `asnmap`/`mapcidr`, cert-scan with `tlsx`, and roll discovered domains into the normal pipeline. Since you *own* the ranges, this is clean, authorized, and finds forgotten assets no passive source has.
- **`naabu` before `httpx`.** Optional `--ports` stage to catch non-standard web ports; feed results to `httpx`.
- **`subzy` (or `nuclei` takeover templates).** Optional `--takeover` pass over discovered hosts — a defensive priority (dangling CNAMEs are yours to fix).

### Tier 3 — breadth / triage
- `amass` + `assetfinder` for extra passive subdomain coverage.
- `gowitness` / `httpx -screenshot` for visual triage of the CSV.
- JS endpoint miners (`subjs`/`getJS` → `xnLinkFinder`) if you want deeper URL discovery than `katana` alone.

### Sketch of the augmented subdomain→cert→DNS front-end
```
seeds (domains | ASN | CIDR)
  ├─ domains → subfinder(+amass,assetfinder) ─┐
  ├─ ASN/CIDR → asnmap|mapcidr → tlsx -san -cn ┤→ merge+anew → scope_filter
  └─ (passive CT already inside subfinder)     ┘        │
                                                        ▼
                                   alterx (permute, guarded) ─┐
                                                              ▼
                                        dnsx  (resolve + wildcard filter)
                                                              │
                                                     live hostnames
                                                              ▼
                              naabu (optional non-standard ports) → httpx (probe+enrich)
                                                              ▼
                              tlsx -san -cn on live hosts → NEW names → (loop back to scope_filter)
                                                              ▼
                                     katana / fuzz / CSV  (existing pipeline)
```

---

## 6. Operational caveats

- **Resolvers make or break active DNS.** Stale/poisoned public resolvers cause false negatives (missed real subs) and false positives. Use a fresh `trickest/resolvers` list via `-r`, and always run `dnsx`/`puredns` **wildcard filtering** or a single `*.` record will inflate results into the thousands.
- **Active tools generate traffic.** `tlsx`, `naabu`, `dnsx` bruteforce, and crawling all touch the target. For **your own assets** that's fine; keep any third-party scope tightly gated (you already default to passive-first — preserve that).
- **`asnmap` now needs a free PDCP API key** (`asnmap -auth`). Factor that into setup.
- **Kali packaging:** `naabu`, `dnsx`, `subfinder`, `httpx-toolkit`, `mapcidr`, `nuclei`, `findomain` are in `apt`; `tlsx`, `alterx`, `asnmap`, `cdncheck`, `uncover`, `urlfinder`, `subzy` are `go install` — or install/update the whole PD suite at once with **`pdtm`** (`go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest && pdtm -ia`). `naabu` also needs `libpcap-dev`.
- **Your Pi-hole/DNS history:** active DNS through a local Pi-hole will rate-limit hard. Point `dnsx`/`puredns` at dedicated resolvers (`-r resolvers.txt`) so the bruteforce burst bypasses local DNS entirely — same class of fix as the earlier WSL/Pi-hole issue.
- **Wordlists** (`n0kovo`, Assetnote) are cert-harvested and huge; VPS-only, and pair with rate-limited resolvers.

---

## 7. Key sources
- ProjectDiscovery: `tlsx`, `dnsx`, `shuffledns`, `alterx`, `asnmap`, `naabu`, `mapcidr`, `uncover`, `cdncheck` READMEs & blog (tlsx SSL-cert guide; alterx active-enum post; asnmap intro).
- reconFTW (six2dez) methodology writeups; sidxparab "Subdomain Enumeration Guide" (CT, bruteforce, permutations, resolvers).
- `puredns` (d3mondev), `massdns` (blechschmidt), `trickest/resolvers`.
- crt.sh JSON + Postgres query patterns (0xffsec handbook); `ctfr`, `cero`, `getaltname`.
- HackTricks External Recon methodology; Pentest-Book subdomain tool review.
