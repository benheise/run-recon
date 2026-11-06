#!/usr/bin/env bash
# =============================================================================
# generate-report.sh  --  build a single self-contained HTML report from a
#                         run-recon run's output files.
#
# Ties everything gathered about each host together: the CSV inventory
# (ip/asn/tech/status/TLS/CPEs), findings from the side-artifact files (nuclei,
# active scan, secrets, subdomain takeover, DNS zone exposure, exposed origins,
# exposed buckets, CMS, OSINT/VirusTotal/urlscan/social), the edge/origin and
# CNAME inventories, the run record and screenshots -- and highlights
# vulnerabilities / weaknesses / misconfigurations up front.
#
# Usage:
#   ./generate-report.sh results.csv                 # -> results.csv.report.html
#   ./generate-report.sh -o report.html results.csv
#   ./generate-report.sh --shots screenshots-DIR --title "Acme EASM" results.csv
#   ./generate-report.sh --vulns results.vulns.csv results.csv
#
# Options:
#   -o, --out FILE     output HTML path (default: <csv>.report.html)
#   --shots DIR        screenshots directory (default: auto-detect screenshots-* next to the CSV)
#   --vulns FILE       vulnerability join CSV (default: auto-detect <csv>.vulns.csv next to the CSV)
#   --title STR        report title (default: derived from the CSV name)
#   -h, --help         this help
#
# Reads (when present, derived from <csv>): <csv>.nuclei.txt, .activescan.txt,
#   .secrets.txt, .takeover.txt, .zone.txt, .origin.txt, .extras.txt, .favicon.txt, .buckets.txt, .cms.txt,
#   .params.txt, .osint.txt, .virustotal.txt, .urlscan.txt, .social.txt,
#   .new-assets.txt, .edge.tsv, .cname.tsv, .zone-names.txt, .screenshots.tsv,
#   .run.json, and the vuln join <csv>.vulns.csv (recon-db.sh vulns).
# Requires: python3.  Exit 0 on success, 2 on bad input.
# =============================================================================
set -uo pipefail

CSV=""; OUT=""; SHOTS=""; TITLE=""; VULNS=""
usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--out)   OUT="$2"; shift 2;;
    --shots)    SHOTS="$2"; shift 2;;
    --vulns)    VULNS="$2"; shift 2;;
    --title)    TITLE="$2"; shift 2;;
    -h|--help)  usage;;
    -*)         echo "unknown option: $1" >&2; exit 2;;
    *)          CSV="$1"; shift;;
  esac
done

[ -n "$CSV" ]     || { echo "error: no CSV given (usage: $0 [options] <results.csv>)" >&2; exit 2; }
[ -f "$CSV" ]     || { echo "error: CSV not found: $CSV" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "error: python3 is required" >&2; exit 2; }

[ -n "$OUT" ]   || OUT="$CSV.report.html"
[ -n "$TITLE" ] || TITLE="Recon report - $(basename "$CSV")"

# auto-detect the newest screenshots-* dir next to the CSV if not given
if [ -z "$SHOTS" ]; then
  _d="$(dirname "$CSV")"
  for _s in "$_d"/screenshots-*; do
    [ -d "$_s" ] || continue
    if [ -z "$SHOTS" ] || [ "$_s" -nt "$SHOTS" ]; then SHOTS="$_s"; fi
  done
fi

# auto-detect the vuln-join CSV (recon-db.sh vulns writes <csv>.vulns.csv) if not given
if [ -z "$VULNS" ] && [ -f "$CSV.vulns.csv" ]; then VULNS="$CSV.vulns.csv"; fi
[ -n "$VULNS" ] && [ ! -f "$VULNS" ] && { echo "warning: --vulns file not found: $VULNS" >&2; VULNS=""; }

python3 - "$CSV" "$OUT" "$SHOTS" "$TITLE" "$VULNS" <<'PY'
import sys, os, csv, html, glob, re, datetime, json

csv_path, out_path, shots_dir, title = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
vulns_path = sys.argv[5] if len(sys.argv) > 5 else ""
out_dir = os.path.dirname(os.path.abspath(out_path)) or "."

def esc(s): return html.escape(str(s) if s is not None else "")
def norm(s): return re.sub(r'[^a-z0-9]+', '', str(s).lower())
# terminal colour codes some tools print even into files (tlsx -jarm wrote them)
ANSI = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]')
def clean(s): return ANSI.sub("", s or "")
def rel_out(p):
    try:
        return os.path.relpath(p, out_dir)
    except Exception:
        return p
def read_tsv(path):
    """rows of a headed TSV as dicts ([] when absent)"""
    if not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = [clean(l.rstrip("\n")) for l in fh if l.strip()]
    except Exception:
        return []
    if not lines:
        return []
    head = lines[0].split("\t")
    return [dict(zip(head, (l.split("\t") + [""] * len(head))[:len(head)])) for l in lines[1:]]

# --- run record (<csv>.run.json from run-recon) -------------------------------
run = {}
if os.path.isfile(csv_path + ".run.json"):
    try:
        with open(csv_path + ".run.json", encoding="utf-8") as fh:
            run = json.load(fh) or {}
    except Exception as e:
        sys.stderr.write(f"[report] warning: could not read the run record: {e}\n")
        run = {}
UTC = datetime.timezone.utc
def parse_dt(s):
    s = (s or "").strip()
    if not s:
        return None
    try:
        d = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=UTC)
    except Exception:
        pass
    for n, fmt in ((19, "%Y-%m-%dT%H:%M:%S"), (19, "%Y-%m-%d %H:%M:%S"), (10, "%Y-%m-%d")):
        try:
            return datetime.datetime.strptime(s[:n], fmt).replace(tzinfo=UTC)
        except Exception:
            continue
    return None
# certificate days-left are computed against the run's start (the moment the data
# was collected), not against when the report happens to be generated
ref_time = parse_dt(run.get("started")) or datetime.datetime.now(UTC)

# --- severity model --------------------------------------------------------
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_RANK  = {s: i for i, s in enumerate(SEV_ORDER)}
SEV_TAG   = re.compile(r'\[(critical|high|medium|low|info)\]', re.I)
# default severity per artifact kind when a line carries no [severity] tag
KIND_SEV = {
    "takeover": "high", "secrets": "high", "buckets": "medium",
    "origin": "info", "zone": "info", "extras": "info", "favicon": "info", "params": "info", "cms": "info",
    "osint": "info", "virustotal": "info", "urlscan": "info", "social": "info",
}
KIND_LABEL = {
    "nuclei": "Vulnerability (nuclei)", "activescan": "Exposed path",
    "takeover": "Subdomain takeover", "secrets": "Exposed secret",
    "buckets": "Exposed cloud bucket", "origin": "Exposed origin",
    "zone": "DNS zone exposure", "zonecheck": "DNS zone check", "edgehint": "Edge fingerprint",
    "originprotected": "Protected origin",
    "http": "HTTP", "extras": "security.txt", "extrasinfo": "Web server note", "favicon": "Favicon pivot",
    "tls": "TLS / certificate",
    "params": "Parameterized URL", "cms": "CMS / tech", "osint": "OSINT",
    "virustotal": "VirusTotal", "urlscan": "urlscan.io", "social": "Social account",
    "vuln": "Known CVE (NVD/KEV)",
}
# evidence of a check that ran, not a finding: kept out of the severity counts
EVIDENCE_KINDS = {"zonecheck", "edgehint", "extrasinfo", "originprotected"}

def sev_from_nuclei(text):
    m = re.search(r'\[(critical|high|medium|low|info|unknown)\]', text, re.I)
    return (m.group(1).lower() if m else "info")

url_re  = re.compile(r'https?://[^\s"\'<>]+')
def host_of(text):
    m = url_re.search(text)
    if m:
        h = re.sub(r'^https?://', '', m.group(0)).split('/')[0].split(':')[0]
        return h.lower()
    return ""
def kv(text, key):
    m = re.search(r'\b' + re.escape(key) + r'=("[^"]*"|\S+)', text)
    return m.group(1).strip('"') if m else ""

# --- load the CSV inventory ------------------------------------------------
hosts = {}   # host -> attributes collected over its URL rows
rows = 0
csv_cols = []
def new_host(seed=""):
    return {"ip": "", "asn": "", "asn_org": "", "status": set(), "tech": set(), "urls": set(),
            "tls_flags": set(), "tls_version": "", "tls_cipher": "", "seed": seed, "findings": [],
            "title": "", "_tlen": 10 ** 9, "webserver": "", "ipv6": set(), "cert_not_after": "",
            "cert_issuer": "", "cpe": set(), "cloud": "", "rdap_org": "", "geo": "", "in_csv": True,
            "http_root": {}, "_hrk": (9, 9, 10 ** 9), "hflags": {}, "cookie_issues": set(), "auths": set()}
# 1.19 HTTP columns that describe the site: taken from its root row (https preferred)
HTTP_HOST_COLS = ("content_type", "missing_sec_headers", "hsts_max_age", "alt_svc", "powered_by",
                  "favicon_mmh3", "favicon_md5", "ptr", "robots", "security_txt")
try:
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
        r = csv.DictReader(fh)
        csv_cols = r.fieldnames or []
        for row in r:
            rows += 1
            # undo run-recon's CSV formula guard (a leading ' before = + - @)
            row = {k: (v[1:] if isinstance(v, str) and v[:1] == "'" and v[1:2] in ("=", "+", "-", "@", "\t", "\r") else v)
                   for k, v in row.items()}
            h = (row.get("host") or "").strip().lower()
            if not h:
                continue
            d = hosts.setdefault(h, new_host(row.get("seed_domain", "")))
            if row.get("ip"):      d["ip"] = row["ip"]
            if row.get("asn"):     d["asn"] = row["asn"]
            if row.get("asn_org"): d["asn_org"] = row["asn_org"]
            if row.get("status_code"): d["status"].add(row["status_code"])
            for t in (row.get("technologies") or "").replace(";", ",").split(","):
                t = t.strip()
                if t: d["tech"].add(t)
            u = row.get("url") or ""
            if u: d["urls"].add(u)
            # the title of the shortest URL is the site's (the root page)
            if row.get("title") and len(u) < d["_tlen"]:
                d["title"], d["_tlen"] = row["title"], len(u)
            for k in ("webserver", "tls_version", "tls_cipher", "cert_not_after", "cert_issuer",
                      "cloud", "rdap_org", "geo"):
                if row.get(k): d[k] = row[k]
            for fl in (row.get("tls_flags") or "").split(";"):
                fl = fl.strip()
                if fl: d["tls_flags"].add(fl)
            for v6 in (row.get("ipv6") or "").split(";"):
                if v6.strip(): d["ipv6"].add(v6.strip())
            for c in (row.get("cpe") or "").split(";"):
                if c.strip(): d["cpe"].add(c.strip())
            # HTTP detail (run-recon 1.19+; absent in older CSVs)
            for fl in (row.get("http_flags") or "").split(";"):
                if fl: d["hflags"].setdefault(fl, set()).add(u)
            for ci in (row.get("cookie_issues") or "").split(";"):
                if ci: d["cookie_issues"].add(ci)
            if row.get("auth"):
                d["auths"].add((u, row["auth"]))
            _path = re.sub(r"^[a-z]+://[^/]+", "", u, flags=re.I)
            _rk = (0 if _path in ("", "/") else 1, 0 if u.lower().startswith("https") else 1, len(u))
            if any(row.get(k) for k in HTTP_HOST_COLS) and _rk < d["_hrk"]:
                d["http_root"], d["_hrk"] = {k: row.get(k, "") or "" for k in HTTP_HOST_COLS}, _rk
except Exception as e:
    sys.stderr.write(f"[report] warning: could not fully read CSV: {e}\n")

def is_live(d):
    return any(str(s).startswith(("2", "3", "401", "403")) for s in d["status"])
live_hosts = sum(1 for h in hosts.values() if is_live(h))

# --- inventories written next to the CSV --------------------------------------
edge = {r.get("host", "").lower(): r for r in read_tsv(csv_path + ".edge.tsv") if r.get("host")}
cname = {r.get("host", "").lower(): r for r in read_tsv(csv_path + ".cname.tsv") if r.get("host")}
zone_names = read_tsv(csv_path + ".zone-names.txt")
shot_manifest = {r.get("host", "").lower(): r for r in read_tsv(csv_path + ".screenshots.tsv") if r.get("host")}

# --- load side-artifact findings -------------------------------------------
findings = []   # dict(kind, sev, host, seed, text)
sev_counts = {s: 0 for s in SEV_ORDER}
kind_counts = {}
extra_names = {}   # names with findings but no CSV row (not live): host -> dict
ORIGIN_FINDINGS = ("origin-exposed", "origin-alternate", "origin-candidate")

for kind in ["nuclei", "activescan", "takeover", "secrets", "buckets", "zone", "origin", "extras", "favicon",
             "params", "cms", "osint", "virustotal", "urlscan", "social"]:
    path = f"{csv_path}.{kind}.txt"
    if not os.path.isfile(path):
        continue
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = clean(line.rstrip("\n"))
                if not line.strip():
                    continue
                # lines look like: "[seed] <kind> <detail...>"
                m = re.match(r'^\[([^\]]+)\]\s+(.*)$', line)
                if m:
                    seed, detail = m.group(1), m.group(2)
                else:
                    seed, detail = "", line
                # drop only a leading token that exactly equals the kind (e.g.
                # "nuclei ", "secrets "), but KEEP sub-sources like "rdap",
                # "shodan-internetdb", "asn", "content(...)", "social(user)".
                _p = detail.split(maxsplit=1)
                if _p and _p[0].lower() == kind:
                    detail = _p[1] if len(_p) > 1 else ""
                tok0 = (detail.split(maxsplit=1) or [""])[0].lower()
                kind_eff = kind
                tagged = SEV_TAG.match(detail.split(maxsplit=1)[1]) if len(detail.split(maxsplit=1)) > 1 else None
                # activescan carries both content() hits and nuclei findings
                if kind == "activescan" and "nuclei" in line.split(maxsplit=2)[1:2]:
                    sev = sev_from_nuclei(line)
                elif kind == "nuclei":
                    sev = sev_from_nuclei(line)
                elif kind == "origin" and tok0 == "origin-protected":
                    # the origin exists and refuses the site: good news, kept as evidence
                    kind_eff, sev = "originprotected", "info"
                elif kind == "origin" and tok0 not in ORIGIN_FINDINGS:
                    # older runs listed JARM/CDN hints here: attributes, not exposed origins
                    kind_eff, sev = "edgehint", "info"
                elif kind == "zone" and tok0 == "zone-checked":
                    kind_eff, sev = "zonecheck", "info"
                elif kind == "extras" and not (tagged and tagged.group(1).lower() in ("low", "medium", "high", "critical")):
                    kind_eff, sev = "extrasinfo", "info"   # catch-all 200, error-page notes
                elif tagged:
                    sev = tagged.group(1).lower()   # "<check> [severity] key=value ..."
                elif kind == "takeover" and SEV_TAG.search(line):
                    sev = sev_from_nuclei(line)
                else:
                    sev = KIND_SEV.get(kind, "info")
                # skip the uro summary noise
                if kind == "activescan" and detail.startswith("uro filtered content"):
                    continue
                # host attribution: for findings whose URL IS the affected target,
                # use the URL's host; for OSINT/reference findings (social account
                # links, VT/passive-DNS, etc.) tie to the seed domain/brand instead.
                TARGET_URL_KINDS = {"nuclei", "activescan", "secrets", "takeover", "zone", "extras", "favicon",
                                    "buckets", "origin", "params", "cms", "urlscan"}
                uh = host_of(line)
                if not uh:   # DNS findings name the affected host as host=<name>
                    _hm = re.search(r'\bhost=([A-Za-z0-9_.-]+)', line)
                    uh = _hm.group(1).lower() if _hm else ""
                if kind in TARGET_URL_KINDS and uh:
                    h = uh
                else:
                    h = (seed.lower() if seed else uh)
                f = {"kind": kind_eff, "sev": sev, "host": h, "seed": seed, "text": detail or line}
                findings.append(f)
                if kind_eff not in EVIDENCE_KINDS:
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                kind_counts[kind_eff] = kind_counts.get(kind_eff, 0) + 1
                # attach to the host card; a name that is not live still gets a card
                if h in hosts:
                    hosts[h]["findings"].append(f)
                elif h and kind_eff not in EVIDENCE_KINDS and kind in ("takeover", "zone", "origin"):
                    extra_names.setdefault(h, {"seed": seed, "findings": []})["findings"].append(f)
    except Exception as e:
        sys.stderr.write(f"[report] warning: {path}: {e}\n")

# --- TLS posture (from the CSV) as findings, expiry graded by days left -----------
TLS_FLAG_SEV = {"WeakCipher": "high", "CertRevoked": "high", "CertUntrusted": "medium",
                "WeakTLS": "medium", "SelfSigned": "medium", "CertNameMismatch": "medium"}
TLS_FLAG_DESC = {"WeakTLS": "obsolete TLS version supported (< TLS 1.2)", "WeakCipher": "weak cipher offered",
                 "SelfSigned": "self-signed certificate", "CertNameMismatch": "certificate name mismatch",
                 "CertUntrusted": "certificate chain not trusted by the system trust store",
                 "CertRevoked": "revoked certificate"}
def days_left(d):
    dt = parse_dt(d.get("cert_not_after"))
    return None if dt is None else (dt - ref_time).total_seconds() / 86400.0
def span(days):
    a = abs(days)
    if a < 1:
        n = max(1, int(round(a * 24))); return "%d hour%s" % (n, "" if n == 1 else "s")
    n = int(a); return "%d day%s" % (n, "" if n == 1 else "s")
def expiry_text(d):
    dl = days_left(d)
    if dl is None:
        return ""
    when = parse_dt(d["cert_not_after"]).strftime("%Y-%m-%d %H:%M UTC")
    return ("expired %s ago (%s)" % (span(dl), when)) if dl < 0 else ("expires in %s (%s)" % (span(dl), when))
for _h, _d in hosts.items():
    fl = _d.get("tls_flags", set())
    for _fl in sorted(fl):
        if _fl in ("CertExpiring", "CertExpired", "Wildcard"):
            continue   # expiry is graded below; a wildcard certificate is an attribute
        _sev = TLS_FLAG_SEV.get(_fl, "info")
        _f = {"kind": "tls", "sev": _sev, "host": _h, "seed": _d.get("seed", ""),
              "text": "%s (%s)" % (TLS_FLAG_DESC.get(_fl, _fl), _d.get("tls_version") or "TLS")}
        findings.append(_f); _d["findings"].append(_f)
        sev_counts[_sev] = sev_counts.get(_sev, 0) + 1
        kind_counts["tls"] = kind_counts.get("tls", 0) + 1
    dl = days_left(_d)
    _sev = None
    if dl is not None:
        _sev = "high" if dl < 0 else "medium" if dl < 7 else "low" if dl < 30 else None
        _txt = "certificate " + expiry_text(_d)
    elif "CertExpired" in fl:
        _sev, _txt = "high", "certificate expired"
    elif "CertExpiring" in fl:
        _sev, _txt = "medium", "certificate expiring soon"
    if _sev:
        _f = {"kind": "tls", "sev": _sev, "host": _h, "seed": _d.get("seed", ""), "text": _txt}
        findings.append(_f); _d["findings"].append(_f)
        sev_counts[_sev] = sev_counts.get(_sev, 0) + 1
        kind_counts["tls"] = kind_counts.get("tls", 0) + 1

# --- HTTP findings (1.19 columns): credentials over cleartext, sites served on plain HTTP --
def _add(kind, sev, h, d, text):
    f = {"kind": kind, "sev": sev, "host": h, "seed": d.get("seed", ""), "text": text}
    findings.append(f); d["findings"].append(f)
    sev_counts[sev] = sev_counts.get(sev, 0) + 1
    kind_counts[kind] = kind_counts.get(kind, 0) + 1
for _h, _d in hosts.items():
    for _u in sorted(_d["hflags"].get("CleartextAuth", ())):
        _realm = next((a for (uu, a) in sorted(_d["auths"]) if uu == _u), "basic auth")
        _add("http", "medium", _h, _d, "credentials sent in cleartext: %s on %s (use HTTPS)" % (_realm, _u))
    _pl = sorted(_d["hflags"].get("PlainHttp", ()))
    if _pl:
        _add("http", "low", _h, _d, "served over plain HTTP without a redirect to HTTPS: %s%s"
             % (_pl[0], (" and %d more URL(s)" % (len(_pl) - 1)) if len(_pl) > 1 else ""))

# --- known-CVE findings from the offline vuln join (recon-db.sh vulns) -------
# One finding per (host, CVE). KEV -> critical; otherwise CVSS severity/score,
# bumped to at least High when EPSS shows a high real-world exploit probability.
vuln_total = 0
vuln_kev = 0
def _sev_vuln(kev, csev, cscore, ep):
    if kev:
        return "critical"
    s = (csev or "").strip().lower()
    if s not in SEV_ORDER:
        try: sc = float(cscore)
        except Exception: sc = 0.0
        s = ("critical" if sc >= 9 else "high" if sc >= 7 else
             "medium" if sc >= 4 else "low" if sc > 0 else "info")
    try: epv = float(ep)
    except Exception: epv = 0.0
    if epv >= 0.5 and SEV_RANK.get(s, 9) > SEV_RANK["high"]:
        s = "high"
    return s
if vulns_path and os.path.isfile(vulns_path):
    try:
        with open(vulns_path, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                cve = (row.get("cve") or "").strip()
                if not cve:
                    continue
                h = (row.get("host") or "").strip().lower()
                kev = (row.get("kev") or "").strip().lower() in ("yes", "true", "1")
                csev, cscore = row.get("cvss_severity", ""), row.get("cvss_score", "")
                ep = row.get("epss", "")
                sev = _sev_vuln(kev, csev, cscore, ep)
                vuln_total += 1
                if kev:
                    vuln_kev += 1
                bits = [cve]
                if cscore:
                    bits.append("CVSS %s%s" % (cscore, (" " + csev) if csev else ""))
                if ep:
                    try: bits.append("EPSS %.2f" % float(ep))
                    except Exception: pass
                if kev:
                    ransom = (row.get("kev_ransomware") or "").strip().lower() == "known"
                    bits.append("KEV/ransomware" if ransom else "KEV")
                if row.get("match"):
                    bits.append("[%s]" % row["match"])
                desc = (row.get("description") or "").strip()
                if desc:
                    bits.append("- " + desc)
                _f = {"kind": "vuln", "sev": sev, "host": h,
                      "seed": row.get("seed_domain", ""), "text": "  ".join(bits)}
                findings.append(_f)
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                kind_counts["vuln"] = kind_counts.get("vuln", 0) + 1
                if h in hosts:
                    hosts[h]["findings"].append(_f)
    except Exception as e:
        sys.stderr.write(f"[report] warning: could not read vulns CSV {vulns_path}: {e}\n")

# new-assets (monitoring) is a plain URL list
new_assets = []
na_path = f"{csv_path}.new-assets.txt"
if os.path.isfile(na_path):
    try:
        with open(na_path, encoding="utf-8", errors="replace") as fh:
            new_assets = [l.strip() for l in fh if l.strip()]
    except Exception:
        pass

# --- the name inventory: every name, live or not, with its DNS state ----------------
# live hosts (CSV), names with a CNAME (takeover check), names with a DNS finding, seeds
# that produced nothing (run record) and names from zone transfers / NSEC walks.
names = {}
def name_entry(n, seed=""):
    return names.setdefault(n, {"seed": seed, "dns": "", "http": "", "cname": "", "alias_of": "",
                                "source": set(), "live": False})
for h, d in hosts.items():
    e = name_entry(h, d["seed"])
    e["live"] = is_live(d)
    e["http"] = ", ".join(sorted(d["status"]))
    e["dns"] = "resolves" if (d["ip"] or e["live"]) else ""
    e["source"].add("scan")
for h, c in cname.items():
    e = name_entry(h, c.get("seed_domain", ""))
    e["cname"] = c.get("cname_chain", "")
    st = c.get("dns", "")
    if st:
        e["dns"] = ("dangling CNAME (%s)" % st) if st.upper() in ("NXDOMAIN", "SERVFAIL") else st
    chain = [x for x in e["cname"].split(">") if x]
    tgt = next((x for x in reversed(chain) if x in hosts and x != h), "")
    if tgt:
        e["alias_of"] = tgt
for h, x in extra_names.items():
    e = name_entry(h, x["seed"])
    e["source"].add("finding")
for ps in run.get("per_seed") or []:
    s = (ps.get("seed") or "").lower()
    if s and s not in names and ps.get("resolved") == 0:
        e = name_entry(s, s); e["dns"] = "does not resolve"; e["source"].add("seed")
seed_set = set(d["seed"] for d in hosts.values() if d["seed"]) | set(
    (ps.get("seed") or "").lower() for ps in (run.get("per_seed") or []) if ps.get("seed"))
zone_outside = []
for z in zone_names:
    n = (z.get("name") or "").lower()
    if not n:
        continue
    under = next((s for s in seed_set if n == s or n.endswith("." + s)), "")
    if n in names:
        names[n]["source"].add("zone (%s)" % z.get("source", ""))
    elif under:
        e = name_entry(n, under); e["dns"] = e["dns"] or "zone record"; e["source"].add("zone (%s)" % z.get("source", ""))
    else:
        zone_outside.append((n, z.get("zone", ""), z.get("source", "")))
aliases = {}
for n, e in names.items():
    if e["alias_of"]:
        aliases.setdefault(e["alias_of"], []).append(n)
def group_key(n):
    e = names.get(n, {})
    return (e.get("alias_of") or n, 1 if e.get("alias_of") else 0, n)

# --- screenshots: host -> (image path relative to the report, status, reason) --------
# With the manifest (<csv>.screenshots.tsv, run-recon 1.18+) each host has a validated
# status. Without it (older runs, gowitness), match images by name and never show an
# empty file as a screenshot.
shot_for = {}
if shot_manifest and shots_dir and os.path.isdir(shots_dir):
    for h, m in shot_manifest.items():
        p = os.path.join(shots_dir, m.get("file", "")) if m.get("file") else ""
        shot_for[h] = (rel_out(p) if p and os.path.isfile(p) else "", m.get("status", ""), m.get("reason", ""))
elif shots_dir and os.path.isdir(shots_dir):
    imgs = []
    for ext in ("png", "jpg", "jpeg"):
        imgs += glob.glob(os.path.join(shots_dir, "**", f"*.{ext}"), recursive=True)
    # Match on the path RELATIVE to shots_dir (not just the basename): some tools
    # put the host in a subdirectory with a generic filename (e.g.
    # screenshot/<host>/screenshot.png), so the host may live in a dir component.
    nmap = []
    for p in imgs:
        try:
            rel = os.path.relpath(p, shots_dir)
        except Exception:
            rel = os.path.basename(p)
        nmap.append((norm(rel), p))
    # match longer (more specific) hostnames first, and let each image be claimed
    # only once, so a subdomain's screenshot isn't also grabbed by a shorter apex
    # whose normalized form is a substring of it.
    used = set()
    for h in sorted(hosts, key=len, reverse=True):
        nh = norm(h)
        if not nh:
            continue
        for i, (nb, p) in enumerate(nmap):
            if i not in used and nh in nb:
                used.add(i)
                empty = os.path.getsize(p) == 0
                shot_for[h] = ("" if empty else rel_out(p), "failed" if empty else "ok",
                               "empty image (0 bytes)" if empty else "")
                break

# --- HTML ------------------------------------------------------------------
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
sev_color = {"critical": "#8b0000", "high": "#d7301f", "medium": "#ef8a00",
             "low": "#c9a400", "info": "#4a7fb5"}
highlight_kinds = {"nuclei", "takeover", "secrets", "buckets", "origin", "zone", "http", "extras", "tls", "vuln"}
total_findings = sum(1 for f in findings if f["kind"] not in EVIDENCE_KINDS)
top_asns = {}
for h in hosts.values():
    if h["asn_org"]:
        top_asns[h["asn_org"]] = top_asns.get(h["asn_org"], 0) + 1
top_asns = sorted(top_asns.items(), key=lambda kv: -kv[1])[:8]
exit_status = run.get("exit_status")
no_results = rows == 0 or exit_status == 3

def badge(sev):
    return f'<span class="sev sev-{sev}" style="background:{sev_color.get(sev,"#666")}">{esc(sev.upper())}</span>'
def hlink(h):
    return f'<a href="#h-{esc(norm(h))}">{esc(h)}</a>' if (h in hosts or h in extra_names) else esc(h)

out = []
out.append(f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>
:root{{--bg:#0f1419;--panel:#1a2029;--panel2:#212a35;--line:#2c3947;--fg:#e6edf3;--mut:#8b98a5;--accent:#4a9eff;--warn:#ef8a00;--bad:#d7301f}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}}
a{{color:var(--accent);text-decoration:none}} a:hover{{text-decoration:underline}}
.wrap{{max-width:1200px;margin:0 auto;padding:24px 16px}}
header{{border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:24px}}
h1{{margin:0 0 4px;font-size:22px}} h2{{font-size:18px;border-bottom:1px solid var(--line);padding-bottom:6px;margin-top:36px}}
.mut{{color:var(--mut);font-size:12px}}
.run{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin-top:12px;font-size:12px;color:var(--mut)}}
.run b{{color:var(--fg);font-weight:600}} .run code{{font-family:ui-monospace,monospace;color:#cdd9e5;word-break:break-all}}
.run details{{margin-top:6px}} .run li{{margin:2px 0}}
.banner{{background:#3a1212;border:1px solid var(--bad);color:#ffd7d0;border-radius:8px;padding:12px 16px;margin:16px 0;font-weight:600}}
.banner .mut{{font-weight:400;color:#f0b5ab}}
.note{{background:var(--panel);border-left:3px solid var(--warn);padding:8px 12px;margin:12px 0;font-size:13px}}
.cards{{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 18px;min-width:110px}}
.card .n{{font-size:26px;font-weight:700}} .card .l{{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
.sev{{display:inline-block;color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;letter-spacing:.03em}}
.tbl{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;margin:10px 0}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em;position:sticky;top:0;background:var(--bg)}}
td.detail{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;word-break:break-all;color:#cdd9e5}}
tr.sub td:first-child{{padding-left:28px}}
.host{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin:14px 0}}
.host.alias{{margin-left:28px;border-left:3px solid var(--accent)}}
.host.dead{{border-style:dashed}}
.host h3{{margin:0 0 2px;font-size:16px;font-family:ui-monospace,monospace;word-break:break-all}}
.host .ttl{{color:var(--mut);font-size:13px;margin-bottom:8px}}
.host .meta{{display:flex;flex-wrap:wrap;gap:6px 18px;color:var(--mut);font-size:12px;margin-bottom:8px}}
.host .meta b{{color:var(--fg);font-weight:600;word-break:break-all}}
.pill{{display:inline-block;background:var(--panel2);border:1px solid var(--line);border-radius:20px;padding:1px 10px;margin:2px 4px 2px 0;font-size:11px;color:#cdd9e5}}
.pill.cpe{{font-family:ui-monospace,monospace;border-radius:4px}}
.pill.bad{{border-color:var(--bad);color:#ffb4a8}}
.grid{{display:grid;grid-template-columns:220px 1fr;gap:16px}}
@media(max-width:720px){{.grid{{grid-template-columns:1fr}} .host.alias{{margin-left:10px}}}}
.shot{{border:1px solid var(--line);border-radius:6px;overflow:hidden;background:#000}}
.shot img{{width:100%;display:block}}
.shotwarn{{background:#3a2a10;color:#ffd59a;font-size:11px;padding:6px 8px}}
.noshot{{border:1px dashed var(--line);border-radius:6px;color:var(--mut);font-size:12px;padding:24px;text-align:center}}
.fnd{{font-family:ui-monospace,monospace;font-size:12px;padding:4px 0;border-bottom:1px solid var(--line);word-break:break-all}}
.k{{display:inline-block;min-width:150px;color:var(--mut)}}
footer{{margin-top:40px;border-top:1px solid var(--line);padding-top:14px;color:var(--mut);font-size:12px}}
.empty{{color:var(--mut);font-style:italic;padding:8px 0}}
.tabs a{{margin-right:14px}}
</style></head><body><div class="wrap">
<header>
  <h1>{esc(title)}</h1>
  <div class="mut">Generated {esc(now)} &middot; source: {esc(os.path.basename(csv_path))} &middot;
     {rows} URL row(s), {len(hosts)} host(s), {len(names)} name(s)</div>""")
# run header: what produced this output
if run:
    _dur = run.get("duration_s")
    _dur = ("%dm %02ds" % divmod(int(_dur), 60)) if isinstance(_dur, int) else "?"
    _tv = ", ".join("%s %s" % kv_ for kv_ in sorted((run.get("tool_versions") or {}).items())) or "not recorded"
    _res = run.get("resolvers") or {}
    _args = " ".join(run.get("args") or [])
    out.append('<div class="run">'
               f'<b>run-recon {esc(run.get("version", "?"))}</b> &middot; started <b>{esc(run.get("started", "?"))}</b>'
               f' &middot; took <b>{esc(_dur)}</b> &middot; exit status <b>{esc(exit_status)}</b>'
               f' &middot; seeds <b>{esc(run.get("seeds", "?"))}</b> ({esc(run.get("input", ""))})<br>'
               f'command line: <code>run-recon.sh {esc(_args)}</code><br>'
               f'tools: {esc(_tv)} (lab-verified: {esc(run.get("lab_verified", ""))})<br>'
               f'resolvers: {esc(_res.get("file") or "system")} ({esc(_res.get("count", 0))}), check {esc(_res.get("check", "not run"))}'
               + (f' &middot; proxy {esc(run.get("proxy"))}' if run.get("proxy") else "") )
    _w = run.get("warnings") or []
    if _w:
        out.append(f'<details><summary>{len(_w)} warning(s) during the run</summary><ul>'
                   + "".join(f"<li>{esc(x)}</li>" for x in _w) + "</ul></details>")
    out.append('</div>')
out.append("""  <div class="tabs mut" style="margin-top:8px">
    <a href="#summary">Summary</a><a href="#findings">Findings</a><a href="#names">Names</a><a href="#hosts">Hosts</a>
  </div>
</header>""")
if no_results:
    _why = [w for w in (run.get("warnings") or []) if re.search(r"resolv|DNS|live|NO results", w)][:6]
    out.append('<div class="banner">This run produced no results (0 URL rows): the inventory below is empty, '
               'not clean.' + ('<div class="mut">' + "<br>".join(esc(w) for w in _why) + '</div>' if _why else
               '<div class="mut">Check the run log: DNS resolution, the resolve gate and the live probe.</div>') + '</div>')

out.append('<h2 id="summary">Summary</h2><div class="cards">')
out.append(f'<div class="card"><div class="n">{len(seed_set) or run.get("seeds", 0)}</div><div class="l">Seeds</div></div>')
out.append(f'<div class="card"><div class="n">{len(names)}</div><div class="l">Names</div></div>')
out.append(f'<div class="card"><div class="n">{live_hosts}</div><div class="l">Live hosts</div></div>')
out.append(f'<div class="card"><div class="n">{total_findings}</div><div class="l">Findings</div></div>')
for s in SEV_ORDER:
    out.append(f'<div class="card"><div class="n" style="color:{sev_color[s]}">{sev_counts.get(s,0)}</div>'
               f'<div class="l">{esc(s)}</div></div>')
if vuln_total:
    out.append(f'<div class="card"><div class="n" style="color:{sev_color["critical"]}">{vuln_kev}</div>'
               f'<div class="l">KEV</div></div>')
    out.append(f'<div class="card"><div class="n">{vuln_total}</div><div class="l">Known CVEs</div></div>')
out.append("</div>")
if top_asns:
    out.append('<div class="mut">Top networks (by host): ' +
               " &middot; ".join(f'{esc(o)} <b style="color:#cdd9e5">({n})</b>' for o, n in top_asns) + "</div>")
if new_assets:
    out.append(f'<div class="mut" style="margin-top:8px">New assets vs previous run: '
               f'<b style="color:#cdd9e5">{len(new_assets)}</b></div>')
# DNS zones checked (--zone-exposure): each zone's result, findings or not
zrows = [f for f in findings if f["kind"] in ("zone", "zonecheck")]
if zrows:
    out.append('<h3 style="font-size:15px;margin-top:22px">DNS zones checked</h3><div class="tbl"><table><thead><tr>'
               '<th>Zone</th><th>Result</th><th>Names exposed</th><th>Detail</th></tr></thead><tbody>')
    for f in sorted(zrows, key=lambda f: (SEV_RANK.get(f["sev"], 9), f["host"])):
        z = kv(f["text"], "zone") or f["host"]
        res = f["text"].split()[0]
        nn = sum(1 for r in zone_names if (r.get("zone") or "") == z)
        det = " ".join("%s=%s" % (k, v) for k, v in re.findall(r'([A-Za-z][\w-]*)=("[^"]*"|\S+)', f["text"])
                       if k not in ("host", "zone", "note"))
        out.append(f'<tr><td>{esc(z)}</td><td>{badge(f["sev"])} {esc(res)}</td><td>{nn or "-"}</td>'
                   f'<td class="detail">{esc(det)}</td></tr>')
    out.append('</tbody></table></div>')
    if zone_outside:
        out.append(f'<div class="mut">{len(zone_outside)} name(s) from the zones fall outside every seed and were '
                   'listed, not scanned: ' + ", ".join(esc(n) for n, _, _ in zone_outside[:40]) +
                   (" ..." if len(zone_outside) > 40 else "") + '</div>')

# ---- Findings table (highlighted first: vulns/weaknesses/misconfigs) -------
out.append('<h2 id="findings">Findings</h2>')
hi = [f for f in findings if f["kind"] in highlight_kinds]
# within a severity: exposure findings first, certificate hygiene last
KIND_ORDER = {k: i for i, k in enumerate(["vuln", "nuclei", "secrets", "origin", "zone", "takeover", "http", "buckets", "extras", "tls"])}
hi.sort(key=lambda f: (SEV_RANK.get(f["sev"], 9), KIND_ORDER.get(f["kind"], 99), f["host"]))
if hi:
    out.append('<p class="mut">Vulnerabilities, weaknesses and misconfigurations, most severe first.</p>')
    out.append('<div class="tbl"><table><thead><tr><th>Severity</th><th>Type</th><th>Host</th><th>Detail</th></tr></thead><tbody>')
    for f in hi:
        out.append(f'<tr><td>{badge(f["sev"])}</td><td>{esc(KIND_LABEL.get(f["kind"],f["kind"]))}</td>'
                   f'<td>{hlink(f["host"]) if f["host"] else esc(f["seed"])}</td><td class="detail">{esc(f["text"])}</td></tr>')
    out.append("</tbody></table></div>")
else:
    out.append('<p class="empty">No vulnerabilities, takeovers, secrets, exposed buckets, zone exposures, exposed origins '
               'or TLS weaknesses were recorded (run with --nuclei/--activescan/--secrets/--takeover/--buckets/'
               '--zone-exposure/--origin/--tls to look).</p>')
# known vulnerabilities: say when the check did not run, so the gap is visible
if not (vulns_path and os.path.isfile(vulns_path)):
    # A CPE without a version (cpe:2.3:a:vendor:product:*:...) names the product only: a
    # join would match every CVE ever filed against it, so those are counted apart
    def _versioned(c):
        f = c.split(":")
        return len(f) > 5 and f[5] not in ("", "*", "-")
    cpes = sorted(set(c for d in hosts.values() for c in d["cpe"]))
    vcpes = [c for c in cpes if _versioned(c)]
    ucpes = [c for c in cpes if not _versioned(c)]
    nv_hosts = sum(1 for d in hosts.values() if any(_versioned(c) for c in d["cpe"]))
    nu_hosts = sum(1 for d in hosts.values() if any(not _versioned(c) for c in d["cpe"]))
    pills = lambda xs: '<div style="margin-top:6px">' + "".join(f'<span class="pill cpe">{esc(c)}</span>' for c in xs) + '</div>'
    msg = ""
    if vcpes:
        msg += f'{len(vcpes)} versioned CPE(s) on {nv_hosts} host(s) would be checked:' + pills(vcpes)
    if ucpes:
        msg += ('<div style="margin-top:8px">' if vcpes else '<div>') + \
               f'{len(ucpes)} CPE(s) on {nu_hosts} host(s) carry no version, so they cannot be matched to ' \
               'specific CVEs (the product was identified, its version was not):' + pills(ucpes) + '</div>'
    if not cpes:
        msg = 'No CPEs were identified either (enrichment off, or no versioned products seen).'
    out.append('<div class="note"><b>Known vulnerabilities: not checked.</b> No NVD/KEV/EPSS join was supplied '
               f'(<code>{esc(os.path.basename(csv_path))}.vulns.csv</code>, written by <code>recon-db.sh vulns</code>). '
               + msg + '</div>')

# context findings summary (osint/vt/urlscan/social/cms/params) by count
ctx = {k: kind_counts[k] for k in kind_counts if k not in highlight_kinds}
if ctx:
    out.append('<p class="mut" style="margin-top:14px">Context / OSINT gathered: ' +
               " &middot; ".join(f'{esc(KIND_LABEL.get(k,k))} <b style="color:#cdd9e5">({v})</b>'
                                 for k, v in sorted(ctx.items(), key=lambda kv: -kv[1])) + "</p>")

# ---- Name inventory --------------------------------------------------------------
out.append('<h2 id="names">Names</h2>')
if names:
    out.append('<p class="mut">Every name seen: live hosts, names that only have DNS records, dangling CNAMEs '
               'and seeds that did not resolve. Aliases are listed under their CNAME target.</p>')
    out.append('<div class="tbl"><table><thead><tr><th>Name</th><th>Seed</th><th>DNS</th><th>HTTP</th>'
               '<th>CNAME</th><th>Seen by</th></tr></thead><tbody>')
    for n in sorted(names, key=group_key):
        e = names[n]
        cls = ' class="sub"' if e["alias_of"] else ""
        note = (f'alias of {hlink(e["alias_of"])}; ' if e["alias_of"] else "")
        out.append(f'<tr{cls}><td>{hlink(n)}</td><td>{esc(e["seed"])}</td><td>{esc(e["dns"] or "-")}'
                   f'{" &middot; live" if e["live"] else ""}</td><td>{esc(e["http"] or "-")}</td>'
                   f'<td class="detail">{esc(e["cname"].replace(">", " > ") or "-")}</td>'
                   f'<td class="mut">{note}{esc(", ".join(sorted(e["source"])))}</td></tr>')
    out.append('</tbody></table></div>')
else:
    out.append('<p class="empty">No names.</p>')

# ---- Per-host cards --------------------------------------------------------
def origin_of(h):
    for f in hosts.get(h, {}).get("findings", []):
        if f["kind"] == "origin":
            return kv(f["text"], "origin"), f["text"].split()[0], f["sev"]
    return "", "", ""
def shot_html(h):
    if h not in shot_for:
        if shot_manifest:
            return '<div class="noshot">not captured</div>'
        return '<div class="noshot">no screenshot<br>(run with --screenshots)</div>'
    p, st, why = shot_for[h]
    if st in ("ok", "suspect") and p:
        sp = esc(p)
        warn = (f'<div class="shotwarn">may not show this site: {esc(why)}</div>' if st == "suspect" else "")
        return (f'<div class="shot">{warn}<a href="{sp}" target="_blank" rel="noopener">'
                f'<img src="{sp}" alt="screenshot of {esc(h)}" loading="lazy"></a></div>')
    if st == "blank":
        return '<div class="noshot">blank page<br>(the site returned an empty body)</div>'
    return f'<div class="noshot">screenshot failed<br>{esc(why or "no image")}</div>'

out.append('<h2 id="hosts">Hosts</h2>')
card_names = sorted(set(hosts) | set(extra_names), key=group_key)
if not card_names:
    out.append('<p class="empty">No hosts in the CSV.</p>')
for h in card_names:
    e = names.get(h, {})
    d = hosts.get(h)
    hid = norm(h)
    cls = "host" + (" alias" if e.get("alias_of") else "") + ("" if d else " dead")
    out.append(f'<div class="{cls}" id="h-{esc(hid)}"><h3>{esc(h)}</h3>')
    if d and d["title"]:
        out.append(f'<div class="ttl">{esc(d["title"])}</div>')
    meta = []
    if e.get("alias_of"):
        meta.append(f'<span>Alias of <b>{hlink(e["alias_of"])}</b> (CNAME)</span>')
    if d:
        if d["ip"]:      meta.append(f'<span>IP <b>{esc(d["ip"])}</b></span>')
        if d["ipv6"]:    meta.append('<span>IPv6 <b>' + esc(", ".join(sorted(d["ipv6"]))) + '</b></span>')
        if d["asn"]:     meta.append(f'<span>ASN <b>{esc(d["asn"])}</b></span>')
        if d["asn_org"]: meta.append(f'<span>Network <b>{esc(d["asn_org"])}</b></span>')
        if d["status"]:  meta.append('<span>Status <b>' + esc(", ".join(sorted(d["status"]))) + '</b></span>')
        if d["webserver"]: meta.append(f'<span>Server <b>{esc(d["webserver"])}</b></span>')
        for k, lab in (("cloud", "Cloud"), ("rdap_org", "Registrant"), ("geo", "Geo")):
            if d[k]: meta.append(f'<span>{lab} <b>{esc(d[k])}</b></span>')
    else:
        meta.append(f'<span>DNS <b>{esc(e.get("dns") or "not live")}</b></span>')
    seed = (d or {}).get("seed") or e.get("seed") or (extra_names.get(h) or {}).get("seed", "")
    if seed: meta.append(f'<span>Seed <b>{esc(seed)}</b></span>')
    zsrc = sorted(x for x in e.get("source", ()) if x.startswith("zone"))
    if zsrc: meta.append(f'<span>Found by <b>{esc(", ".join(zsrc))}</b></span>')
    out.append('<div class="meta">' + "".join(meta) + '</div>')
    # edge -> origin, TLS, CNAME, aliases
    meta2 = []
    eg = edge.get(h)
    o_ip, o_kind, o_sev = origin_of(h)
    if eg and (eg.get("edge") or eg.get("cdn")):
        chain = esc(eg.get("edge") or eg.get("cdn"))
        if eg.get("origin_software"):
            chain += " &rarr; " + esc(eg["origin_software"])
        if o_ip:
            chain += f' &rarr; origin <b>{esc(o_ip)}</b> ({esc(o_kind)})'
        meta2.append(f'<span>Edge <b>{chain}</b> <span class="mut">[{esc(eg.get("edge_evidence", ""))}]</span></span>')
    elif o_ip:
        meta2.append(f'<span>Origin <b>{esc(o_ip)}</b> ({esc(o_kind)})</span>')
    if eg and eg.get("jarm"):
        meta2.append(f'<span>JARM <b title="{esc(eg["jarm"])}">{esc(eg["jarm"][:16])}&hellip;</b></span>')
    if eg and eg.get("favicon_mmh3"):
        meta2.append(f'<span>Favicon mmh3 <b>{esc(eg["favicon_mmh3"])}</b></span>')
    if d and (d["tls_version"] or d["cert_issuer"]):
        tl = esc(d["tls_version"] or "TLS")
        if d["cert_issuer"]: tl += " &middot; issuer " + esc(d["cert_issuer"])
        if d["cert_not_after"]:
            dl = days_left(d)
            et = expiry_text(d) or ("expires " + d["cert_not_after"])
            tl += f' &middot; <span class="{"pill bad" if dl is not None and dl < 30 else ""}">{esc(et)}</span>'
        if "Wildcard" in d["tls_flags"]: tl += " &middot; wildcard"
        meta2.append(f'<span>TLS <b>{tl}</b></span>')
    if e.get("cname"):
        hops = " &rarr; ".join(esc(x) for x in [h] + [y for y in e["cname"].split(">") if y])
        meta2.append(f'<span>CNAME <b>{hops}</b> ({esc(e.get("dns") or "?")})</span>')
    if aliases.get(h):
        meta2.append('<span>Aliases <b>' + ", ".join(hlink(a) for a in sorted(aliases[h])) + '</b></span>')
    if meta2:
        out.append('<div class="meta">' + "".join(meta2) + '</div>')
    # HTTP posture (1.19 columns): headers of the root page, cookies, auth, favicon, PTR, well-known files
    meta3 = []
    hr = (d or {}).get("http_root") or {}
    if hr:
        if "html" in hr.get("content_type", ""):
            ms = [x for x in hr.get("missing_sec_headers", "").split(";") if x]
            short = {"Content-Security-Policy": "CSP", "X-Frame-Options": "X-Frame-Options",
                     "X-Content-Type-Options": "X-Content-Type-Options", "Strict-Transport-Security": "HSTS"}
            meta3.append('<span>Security headers <b>' + (('missing ' + esc(", ".join(short.get(x, x) for x in ms)))
                         if ms else 'all present') + '</b></span>')
        if hr.get("hsts_max_age"):
            meta3.append(f'<span>HSTS max-age <b>{esc(hr["hsts_max_age"])}</b></span>')
        if hr.get("alt_svc"):
            meta3.append(f'<span>Alt-Svc <b>{esc(hr["alt_svc"][:60])}</b></span>')
        if hr.get("powered_by"):
            meta3.append(f'<span>X-Powered-By <b>{esc(hr["powered_by"])}</b></span>')
        if hr.get("favicon_mmh3"):
            meta3.append(f'<span>Favicon <b>mmh3 {esc(hr["favicon_mmh3"])}</b>'
                         + (f' <span class="mut">md5 {esc(hr["favicon_md5"])}</span>' if hr.get("favicon_md5") else "") + '</span>')
        if hr.get("ptr"):
            meta3.append(f'<span>PTR <b>{esc(hr["ptr"])}</b></span>')
        if hr.get("robots"):
            meta3.append(f'<span>robots.txt <b>{esc(hr["robots"])}</b></span>')
        if hr.get("security_txt"):
            st = hr["security_txt"]
            meta3.append(f'<span>security.txt <b class="{"pill bad" if st.startswith(("expired", "missing")) else ""}">{esc(st[:90])}</b></span>')
    if d and d["cookie_issues"]:
        meta3.append('<span>Cookie flags <b>' + esc("; ".join(sorted(d["cookie_issues"]))[:200]) + '</b></span>')
    if d and d["auths"]:
        meta3.append('<span>Auth <b>' + esc("; ".join(sorted(set(a for _, a in d["auths"])))[:160]) + '</b></span>')
    if meta3:
        out.append('<div class="meta">' + "".join(meta3) + '</div>')
    if d and d["tech"]:
        out.append('<div>' + "".join(f'<span class="pill">{esc(t)}</span>' for t in sorted(d["tech"])) + '</div>')
    if d and d["cpe"]:
        out.append('<div>' + "".join(f'<span class="pill cpe">{esc(c)}</span>' for c in sorted(d["cpe"])) + '</div>')
    out.append('<div class="grid" style="margin-top:12px">')
    out.append(shot_html(h) if d else '<div class="noshot">not live</div>')
    # findings for this host
    out.append('<div>')
    hf = sorted((d or extra_names.get(h) or {}).get("findings", []), key=lambda f: (SEV_RANK.get(f["sev"], 9), f["kind"]))
    if hf:
        for f in hf:
            b = badge(f["sev"]) if f["kind"] in highlight_kinds or f["kind"] in ("nuclei", "activescan") else ""
            out.append(f'<div class="fnd">{b} <span class="k">{esc(KIND_LABEL.get(f["kind"],f["kind"]))}</span> {esc(f["text"])}</div>')
    else:
        out.append('<div class="empty">no findings tied to this host</div>')
    # sample URLs
    if d and d["urls"]:
        sample = sorted(d["urls"])[:12]
        out.append('<div style="margin-top:10px" class="mut">URLs (' + str(len(d["urls"])) + '):</div>')
        for u in sample:
            out.append(f'<div class="fnd"><a href="{esc(u)}" target="_blank" rel="noopener">{esc(u)}</a></div>')
        if len(d["urls"]) > len(sample):
            out.append(f'<div class="mut">... and {len(d["urls"])-len(sample)} more</div>')
    out.append('</div></div></div>')

# ---- footer: raw artifact links --------------------------------------------
arts = []
for kind in ["nuclei", "activescan", "takeover", "secrets", "buckets", "zone", "origin", "extras", "favicon",
             "params", "cms", "osint", "virustotal", "urlscan", "social", "new-assets"]:
    p = f"{csv_path}.{kind}.txt"
    if os.path.isfile(p):
        arts.append(f'<a href="{esc(rel_out(p))}">{esc(kind)}</a>')
for suf, lab in ((".edge.tsv", "edge/origin"), (".cname.tsv", "CNAMEs"), (".zone-names.txt", "zone names"),
                 (".screenshots.tsv", "screenshot list"), (".run.json", "run record")):
    if os.path.isfile(csv_path + suf):
        arts.append(f'<a href="{esc(rel_out(csv_path + suf))}">{esc(lab)}</a>')
arts.append(f'<a href="{esc(rel_out(csv_path))}">CSV</a>')
if vulns_path and os.path.isfile(vulns_path):
    arts.append(f'<a href="{esc(rel_out(vulns_path))}">vulns</a>')
out.append('<footer>Raw artifacts: ' + " &middot; ".join(arts) +
           '<br>Generated by generate-report.sh (run-recon). Review findings manually; '
           'automated severities are heuristic.</footer>')
out.append("</div></body></html>")

with open(out_path, "w", encoding="utf-8") as fo:
    fo.write("\n".join(out))
print(f"REPORT_HOSTS={len(hosts)}")
print(f"REPORT_NAMES={len(names)}")
print(f"REPORT_FINDINGS={total_findings}")
print(f"REPORT_OUT={out_path}")
PY
rc=$?
if [ "$rc" -eq 0 ]; then echo "[+] report written -> $OUT" >&2; fi
exit "$rc"
