# run-recon.sh vs. SecurityScorecard — a capability comparison

**Bottom line up front:** these are different species of tool, not competitors. `run-recon.sh` is an
**inside-out, active, single-organization discovery engine** you point at assets you own. SecurityScorecard
is an **outside-in, passive, planetary-scale security-*ratings* + third-party-risk + threat-intelligence
platform**. Their overlap — asset discovery and some misconfiguration detection — is narrow, and even there
they differ in *method* (active vs. passive) and *output* (raw findings vs. a graded, benchmarked score).
For the job `run-recon` does (deep active enumeration of your own attack surface for remediation), it is
*deeper* than SecurityScorecard. For the job SecurityScorecard does (scoring, supply-chain monitoring,
board/insurer/regulator reporting), `run-recon` does not compete at all. They are complementary.

---

## 1. What each one actually is

| | `run-recon.sh` | SecurityScorecard |
|---|---|---|
| Category | OSS External Attack Surface **discovery/enumeration** pipeline | Commercial security **ratings** + TPRM + threat-intel SaaS |
| Vantage point | Inside-out (you define & own the scope) | Outside-in, non-intrusive ("what your building looks like from the street") |
| Method | **Active** (port scans, HTTP probing, brute force, crawling) **+ passive** | **Passive only** — non-intrusive collection and inference |
| Scope per run | One org's domains / ASNs / CIDRs that you seed | 12M+ companies continuously rated; ~3.9–4.1B IPs indexed |
| Primary output | CSV mapping seed → live URLs, + scoped side-artifact files | An A–F letter grade (+ issue detail, benchmarks, dashboards) |
| Audience | The operator / red-teamer / vuln-management engineer | CISO, board, procurement, cyber-insurers, regulators, vendor-risk |
| Cost | Free / self-hosted; you supply compute & maintenance | Subscription (~US$16.5k+/yr entry, add-ons e.g. Atlas), enterprise-custom |
| Control | Total — you saw new tools added in an afternoon | Black-box scoring; findings you can dispute but not re-tune |

The one-line framing:

- **`run-recon` answers:** *"What is actually exposed and reachable on the domains/ranges I own, right now, at a depth I control?"*
- **SecurityScorecard answers:** *"How does my (and my vendors') posture look from the outside — scored, benchmarked, correlated with global threat intel, in a form I can hand a board or an insurer — continuously, at portfolio scale?"*

---

## 2. Methodology — the core difference

SecurityScorecard is built on **massive proprietary passive collection**. Per their own materials: ~99% of
their data is collected in-house across systems distributed over six continents / 87 countries (including
their own Autonomous System); they scan the full routable IPv4 space (~3.9B addresses) roughly every 10 days
across 1,500+ ports; they run a DNS sinkhole ingesting ~2B malware requests/day, a honeypot network, and a
ransomware-leak-site crawler tracking 40+ groups; and a Chrome-based web crawler feeds ~50 issue types into
their Application Security factor. Assets are tied to organizations by an **automatic attribution engine**
(Automatic Vendor Detection). Nothing here touches *your* infrastructure directly — it observes the internet
at scale and infers.

`run-recon` is the opposite posture: **you seed the scope, and it actively interrogates it.** It resolves
names (dnsx gate), probes hosts (httpx), scans ports on demand (naabu), crawls and brute-forces content
(katana/gospider/hakrawler, feroxbuster/ffuf), mines JS (subjs/getJS → xnLinkFinder), verifies takeovers
(subzy), runs templated checks (nuclei), and enumerates cloud storage (cloud_enum). It *verifies liveness and
behavior* rather than inferring posture from a passive index.

Two consequences fall directly out of this:

- **Currency & control.** `run-recon` runs *now*, at *your* chosen depth/rate. SecurityScorecard's IPv4 index
  refreshes on a ~10-day cadence (digital-footprint rescans are daily for paying customers) and you can't dial
  its depth.
- **Verification vs. inference.** `run-recon` confirms things (a host resolves, responds 200, is actually
  takeover-able, a template actually fires). SecurityScorecard largely *infers* from banners/versions — which
  is why back-ported patches and shared-hosting attribution produce the false positives customers routinely
  report and have to dispute.

---

## 3. Feature-by-feature

Legend: ✅ strong / native · ◑ partial or indirect · ❌ absent

| Capability | `run-recon.sh` | SecurityScorecard | Notes |
|---|:---:|:---:|---|
| Subdomain discovery (passive) | ✅ | ✅ | run-recon: subfinder+amass+assetfinder+findomain, recursive. SSC: DNS/WHOIS/cert-graph + attribution across its global index |
| Cert-transitive discovery | ✅ | ✅ | run-recon: tlsx two-phase (candidate + live-host SAN feedback) + ASN/CIDR cert-scan. SSC: SSL cert relationships |
| GitHub / code-leak mining | ✅ | ◑ | run-recon: github-subdomains/-endpoints. SSC surfaces leaked-credential/dark-web data, not repo-derived assets per se |
| DNS dictionary brute force | ✅ | ❌ | Active technique; SSC won't brute your DNS |
| Name permutation + resolve | ✅ | ❌ | alterx + dnsx |
| **Automatic attribution** ("is this asset ours?") | ◑ | ✅ | run-recon needs you to *seed* scope (ASN/CIDR/cert transitive help); SSC's engine attributes automatically (with a known error rate) |
| "Unknown-unknowns" beyond seeded scope | ◑ | ✅ | SSC's global index surfaces forgotten cloud IPs/subsidiaries you never seeded |
| Port discovery | ✅ (active, on-demand, your ports) | ◑ (whole-internet, ~10-day, passive) | Different tradeoff: fresh+controlled vs. broad+stale |
| Live-host probing / tech fingerprint | ✅ (httpx) | ✅ (Chrome crawler) | |
| **Active content discovery / dir brute** | ✅ | ❌ | feroxbuster/ffuf — structurally not something a passive rater does |
| Crawling | ✅ (katana/gospider/hakrawler) | ◑ (their crawler, for factor signals) | |
| JS endpoint & secret mining | ✅ | ❌ | subjs/getJS→xnLinkFinder; secretfinder/trufflehog |
| Parameter discovery | ✅ (arjun) | ❌ | |
| Subdomain-takeover **verification** | ✅ (subzy) | ◑ (flagged as an issue type) | |
| Templated vuln/misconfig scanning | ✅ (nuclei, active) | ◑ (version→CVE inference; confirmed CVEs in ASI) | run-recon verifies; SSC infers + adds exploit/threat context |
| HTTP-header / TLS-config hygiene | ◑ (via httpx/nuclei if templated) | ✅ (a core rated factor) | This is SSC's home turf on web apps |
| Cloud storage bucket enum | ✅ (cloud_enum S3/Azure/GCP) | ◑ (cloud assets in footprint) | |
| Screenshots / visual triage | ✅ (httpx -ss / gowitness) | ◑ (crawler captures screenshots) | |
| **Security rating / A–F score** | ❌ | ✅ | SSC's entire reason for existing |
| **Peer benchmarking / trend** | ❌ | ✅ | Logarithmic scale vs. 12M orgs; BSI breach-likelihood analytic |
| **Third-party / 4th/Nth-party risk** | ❌ | ✅ | Portfolio tiering, vendor collaboration, breach alerts |
| **Security questionnaires** | ❌ | ✅ (Atlas, add-on) | Send/complete/auto-validate against the rating |
| **Breach / leaked-credential / dark-web data** | ❌ | ✅ | Sinkholes, honeypots, 7B+ leaked-cred records, threat-actor graph |
| **Threat-actor / exploited-in-wild correlation** | ◑ (EPSS/KEV added in your own pipeline) | ✅ | STRIKE team, ransomware tracking, Exposure Indexes |
| Continuous monitoring | ◑ (`--monitor` diff + notify, self-scheduled) | ✅ (managed, daily, event-triggered alerts) | |
| Board / executive reporting | ❌ | ✅ (MAX dashboards, ChatSSC agentic Q&A) | |
| Compliance / insurer / regulator use | ◑ (findings feed your GRC manually) | ✅ (defensible record, underwriting, oversight) | |
| ITSM/SIEM/GRC integrations | ◑ (DIY — you own the CSV/JSON) | ✅ (ServiceNow, Splunk, Jira, Archer, OneTrust, XSOAR, 20+) | |
| Data ownership / privacy | ✅ (all yours, self-hosted) | ◑ (their platform, their data) | |
| Cost at scale | ✅ (free) | ❌ (per-entity subscription + add-ons) | |

---

## 4. Where `run-recon` is genuinely deeper

These are things SecurityScorecard **structurally cannot do**, because a passive, non-intrusive rater does not
actively touch your assets:

1. **Active depth.** On-demand port scanning of your ranges at a depth *you* pick; directory/file brute
   forcing; parameter discovery; JS endpoint extraction; active takeover verification; templated exploit
   checks (nuclei); secret scanning; cloud-bucket enumeration. A ratings platform observes; it does not fuzz.
2. **Currency & control.** Run it the moment you push infra, at the rate and scope you choose — not on a
   10-day global-index cadence you can't influence.
3. **Verification over inference.** A dnsx resolve gate, an httpx 200, a nuclei template firing — these are
   confirmations. SSC's version-fingerprint→CVE inference is where its false-positive reputation comes from.
4. **No attribution disputes.** You define scope (`scope_filter` enforces host ∈ seed). You never argue with a
   vendor's engine about whether a shared-hosting IP is "yours."
5. **Total customizability, data ownership, and zero marginal cost.** You control every stage, keep all raw
   data on-prem, and pay nothing per asset. (Cost: you maintain it, tool CLIs drift, you supply compute, and
   there's no vendor support line.)

For a vuln-management program that already runs Qualys/Wiz and enriches with EPSS/KEV, `run-recon` is the
*front of the funnel*: it finds and validates the assets and URLs your scanners then chew on — including the
forgotten ones your scanners never had in scope.

---

## 5. Where SecurityScorecard is in a different league

These are things `run-recon` **does not attempt**, and mostly *can't* without a proprietary global data moat:

1. **Third-party / supply-chain risk.** The core product: automatic vendor detection, 4th/Nth-party mapping,
   portfolio tiering, vendor collaboration, questionnaires, breach notifications for monitored suppliers. This
   is simply not a first-party-tool use case.
2. **A rating and a benchmark.** An A–F grade, logarithmically calibrated against 12M+ organizations, with
   historical trend and a breach-likelihood signal (they cite F-rated orgs as ~13.8× more likely to be
   breached than A-rated). `run-recon` emits raw findings, not a score.
3. **Proprietary threat intelligence.** DNS sinkholes, honeypots, ransomware-leak crawling, billions of leaked
   credentials, a threat-actor association graph, a dedicated research team (STRIKE). No OSS pipeline
   replicates planetary passive collection.
4. **Breach / credential / dark-web exposure** tied to your organization — a whole data class `run-recon` has
   nothing for.
5. **The business/reporting layer.** Board-ready summaries, executive dashboards, an agentic AI assistant
   (ChatSSC), and turnkey ServiceNow/Splunk/Archer/OneTrust integrations. Used directly in **cyber-insurance
   underwriting and regulatory oversight** — a currency `run-recon` output does not carry.
6. **Managed, continuous, scale.** Always-on monitoring of your footprint *and* thousands of vendors, with
   event-based alerting, requiring no infrastructure or upkeep from you.

---

## 6. The honest gaps in `run-recon` that this comparison surfaces

Worth noting as candidate additions or "get-this-elsewhere" items:

- **Attribution / unknown-unknowns beyond seeded scope.** `run-recon` finds what you point it at (ASN/CIDR
  and cert-transitive modes stretch this, but there's no global index of "assets that look like yours").
  SSC's automatic attribution is its headline value — and its headline weakness (misattribution/false
  positives). Mitigation on our side is partial by design.
- **Leaked-credential / breach / dark-web exposure.** No coverage. If that matters, it's a HIBP/DeHashed/
  intel-feed job, not a recon-pipeline job. (Relevant given your prior OSINT/identity-exposure audit.)
- **Exploited-in-the-wild / threat-actor context.** `run-recon` produces findings; it doesn't tell you which
  exposure an actor is actively hitting. You already bolt EPSS/CISA-KEV on in the ServiceNow VR pipeline —
  that's the right place for it, not here.
- **Scoring, trending, and non-technical reporting.** Deliberately out of scope — but it's the language execs
  and insurers speak.
- **Continuous managed monitoring** is DIY (`--monitor` + cron + your storage) rather than turnkey.

None of these are defects in `run-recon` — they're the boundary of "active first-party discovery tool" vs.
"risk-rating/TPRM/threat-intel platform."

---

## 7. When to use which — and together

- **Use `run-recon` for:** deep, current, active assessment of assets **you own or are authorized to test**;
  feeding validated hosts/URLs into your scanners; finding forgotten first-party infrastructure and verifying
  it's actually live/exploitable; anything requiring active techniques (fuzzing, brute force, takeover
  verification, bucket enum) that a passive rater refuses to do.
- **Use SecurityScorecard for:** third-party / supply-chain monitoring at portfolio scale; a defensible,
  benchmarked posture score for boards, insurers, and regulators; leaked-credential / dark-web / threat-actor
  intelligence; continuous managed monitoring without standing up infrastructure.
- **Together (the sensible pattern):** SecurityScorecard for outside-in scoring, vendor risk, and the
  reporting/compliance layer; `run-recon` (plus Qualys/Wiz) for inside-out active depth on your own estate.
  Even ASM-platform vendors concede the point that discovery/rating tools *don't replace* active scanners —
  they scope and prioritize; your scanner (and `run-recon` in front of it) does the deep, verified work.

A blunt way to put it: SecurityScorecard tells you (and everyone else) *what your posture looks like from the
outside and how it compares*; `run-recon` tells *you* what's actually there and reachable so you can go fix
it. Neither replaces the other.

---

### Sources & caveats

Drawn from SecurityScorecard's own product, documentation, and support materials (Security Ratings / TITAN AI,
Attack Surface Intelligence pages and ASI data-collection docs, 2025 feature-release notes, AWS Marketplace
listings) plus third-party reviews (Gartner Peer Insights, Capterra) and marketplace/pricing write-ups,
retrieved July 2026. Vendor figures (12M+ rated companies, ~3.9–4.1B IPs, 1,500+ ports, ~2B sinkhole
requests/day, ~99% in-house data, US$16.5k+ entry pricing) are **SecurityScorecard's own claims**, not
independently verified here, and their product lineup and numbers change — confirm specifics against current
vendor material before citing externally. The `run-recon.sh` side reflects the toolkit at v1.5.0.
