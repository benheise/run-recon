#!/usr/bin/env bash
#
# ship-recon.sh  --  send a finished Outcrop (run-recon) run to Tideline (the recon results platform)
#
#   ship-recon.sh ship     <csv> [--url URL --cert C --key K --ca CA] [--proxy P] [--dry-run]
#   ship-recon.sh status   <csv> [--url URL --cert C --key K --ca CA] [--proxy P]
#   ship-recon.sh export   <csv> --cert C --key K [-o BUNDLE.tar]
#   ship-recon.sh envelope <csv> --cert C
#   ship-recon.sh check    --url URL --cert C --key K --ca CA [--proxy P]
#
# A run is shipped as a signed manifest (tideline-envelope/1, ES256 over its exact bytes,
# sent in the Tideline-Signature header) plus one gzip part per file: the run's JSON lines
# (run-recon --json), its SHA-256 manifest and its screenshots. Each part's SHA-256 is the
# one in <csv>.manifest.sha256, so nothing is shipped that the run did not write. The
# transport is HTTPS with mutual TLS: TLS 1.2 or later, ECDHE with AES-GCM only, the server
# checked against --ca alone (never the system trust store), the client certificate and key
# from step-ca (its URI SAN urn:tideline:sensor:<id> is the sensor's identity).
#
# Shipping is resumable and idempotent: <csv>.ship-state.json records what Tideline
# acknowledged, and a later `ship` re-opens the run (same manifest, same run_id) and sends
# only the parts Tideline does not have. The run's files are read, never changed.
#
# Settings may also come from the environment (SHIP_URL, SHIP_CERT, SHIP_KEY, SHIP_CA,
# SHIP_PROXY) or, for a retry, from <csv>.ship-state.json. SHIP_RETRIES (default 4) and
# SHIP_TIMEOUT (seconds per request, default 300) tune the transport.
#
# Exit status: 0 delivered (or Tideline already had the run); 1 a local problem (missing or
# changed files, unusable certificate or key, missing tools); 2 bad arguments; 4 not
# delivered, try again later (network, timeout, Tideline busy or down): the state is kept;
# 5 refused by Tideline or its TLS endpoint (certificate, sensor, conflicting run, invalid
# part): fix the cause first. `status`: 0 known, 4 unreachable, 5 unknown or refused.
#
set -euo pipefail
VERSION="1.21.0-dev"
exec python3 -I - "$VERSION" "$@" <<'PYSHIP'
import sys, os, re, json, hashlib, subprocess, tempfile, shutil, gzip, time, datetime, fcntl, tarfile, io, stat

VERSION = sys.argv[1]
ARGV = sys.argv[2:]
TOOL = "run-recon"          # frozen tool id (tideline-envelope/1, run-recon.*/1): Outcrop keeps it
ENVELOPE = "tideline-envelope/1"
UA = "outcrop-ship/" + VERSION
KINDS = [("urls", "run-recon.url/1"), ("services", "run-recon.service/1"), ("findings", "run-recon.finding/1"),
         ("dnsposture", "run-recon.dnsposture/1"), ("edges", "run-recon.edge/1"), ("cnames", "run-recon.cname/1"),
         ("zone-names", "run-recon.zone-name/1"), ("screenshots", "run-recon.screenshot/1"),
         ("cloud-assets", "run-recon.cloud-asset/1"), ("vulnx", "run-recon.vulnx/1"), ("delta", "run-recon.delta/1"),
         ("warnings", "run-recon.warning/1"), ("seeds", "run-recon.seed/1")]
MEDIA = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}
LIMIT_MANIFEST, LIMIT_PART = 1 << 20, 512 << 20
TLS12 = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"
TLS13 = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SENSOR = re.compile(r"URI:urn:tideline:sensor:([A-Za-z0-9][A-Za-z0-9._-]{0,63})(?=[,\s]|$)")
OK, LOCAL, USAGE, RETRY, REFUSED = 0, 1, 2, 4, 5
USAGE_TEXT = """usage: ship-recon.sh ship     <csv> [--url URL --cert FILE --key FILE --ca FILE] [--proxy URL] [--dry-run]
       ship-recon.sh status   <csv> [--url URL --cert FILE --key FILE --ca FILE] [--proxy URL]
       ship-recon.sh export   <csv> --cert FILE --key FILE [-o BUNDLE.tar]
       ship-recon.sh envelope <csv> --cert FILE
       ship-recon.sh check    --url URL --cert FILE --key FILE --ca FILE [--proxy URL]
Send a finished Outcrop run (made with --json) to Tideline. See SHIPPING.md."""


class Fail(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


def log(msg):
    sys.stderr.write("[ship] %s\n" % msg)


def redact(u):
    return re.sub(r"(://)[^/@\s]*@", r"\1***@", u or "")


def sh(cmd, data=None):
    p = subprocess.run(cmd, input=data, stdin=None if data is not None else subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- arguments ------------------------------------------------------------------
def parse(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE_TEXT)
        sys.exit(OK if argv else USAGE)
    if argv[0] == "--version":
        print("ship-recon.sh v" + VERSION)
        sys.exit(OK)
    cmd, rest = argv[0], argv[1:]
    if cmd not in ("ship", "status", "export", "envelope", "check"):
        raise Fail(USAGE, "unknown command: %s\n%s" % (cmd, USAGE_TEXT))
    o = {"cmd": cmd, "csv": "", "url": None, "cert": None, "key": None, "ca": None, "proxy": None,
         "output": "", "dry_run": False}
    names = {"--url": "url", "--cert": "cert", "--key": "key", "--ca": "ca", "--proxy": "proxy",
             "-o": "output", "--output": "output"}
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in names:
            if i + 1 >= len(rest):
                raise Fail(USAGE, "%s needs a value" % a)
            o[names[a]] = rest[i + 1]
            i += 2
        elif a == "--dry-run":
            o["dry_run"] = True
            i += 1
        elif a.startswith("-"):
            raise Fail(USAGE, "unknown option: %s\n%s" % (a, USAGE_TEXT))
        elif not o["csv"]:
            o["csv"] = a
            i += 1
        else:
            raise Fail(USAGE, "unexpected argument: %s" % a)
    if cmd != "check" and not o["csv"]:
        raise Fail(USAGE, "%s needs the run's CSV\n%s" % (cmd, USAGE_TEXT))
    if cmd == "check" and o["csv"]:
        raise Fail(USAGE, "check takes no CSV")
    return o


def settings(o, state):
    """explicit option, else environment, else the last shipping attempt's state"""
    env = {"url": "SHIP_URL", "cert": "SHIP_CERT", "key": "SHIP_KEY", "ca": "SHIP_CA", "proxy": "SHIP_PROXY"}
    for k, e in env.items():
        if o[k] is None:
            v = os.environ.get(e) or ""
            if not v and state and not (k == "proxy" and "***@" in (state.get(k) or "")):
                v = state.get(k) or ""     # a proxy with credentials is stored redacted: give it again
            o[k] = v
    for k in ("cert", "key", "ca"):
        if o[k]:
            o[k] = os.path.abspath(o[k])
    return o


# --- local checks -----------------------------------------------------------------
def need_tools(*tools):
    miss = [t for t in tools if not shutil.which(t)]
    if miss:
        raise Fail(LOCAL, "missing tool(s): %s" % ", ".join(miss))


def norm_url(u):
    u = (u or "").strip()
    if not u:
        raise Fail(USAGE, "no Tideline URL (--url, or SHIP_URL)")
    if not re.match(r"^https://[A-Za-z0-9.\-\[\]:]+(/[A-Za-z0-9._~/-]*)?$", u) or "@" in u:
        raise Fail(USAGE, "the Tideline URL must be https://host[:port][/path] with no credentials or query (got: %s)" % redact(u))
    return u.rstrip("/")


def readable(label, p):
    if not p:
        raise Fail(USAGE, "%s is required" % label)
    if not os.path.isfile(p) or not os.access(p, os.R_OK):
        raise Fail(LOCAL, "%s: cannot read %s" % (label, p))


def cert_sensor(cert):
    rc, out, err = sh(["openssl", "x509", "-in", cert, "-noout", "-ext", "subjectAltName"])
    if rc != 0:
        rc, out, err = sh(["openssl", "x509", "-in", cert, "-noout", "-text"])
    if rc != 0:
        raise Fail(LOCAL, "certificate %s: not a PEM certificate (%s)" % (cert, err.strip().splitlines()[-1:] or ""))
    m = SENSOR.findall(out.decode("utf-8", "replace"))
    if len(set(m)) != 1:
        raise Fail(LOCAL, "certificate %s: %s URI SAN urn:tideline:sensor:<id> (enroll it with step-ca)"
                   % (cert, "no" if not m else "more than one"))
    return m[0]


def check(o, network=True):
    need_tools("openssl", "python3", *(["curl"] if network else []))
    if network:
        o["url"] = norm_url(o["url"])
        readable("--ca (Tideline's root CA)", o["ca"])
        rc, _, err = sh(["openssl", "x509", "-in", o["ca"], "-noout"])
        if rc != 0:
            raise Fail(LOCAL, "--ca %s: not a PEM certificate" % o["ca"])
        if o["proxy"] and not re.match(r"^(https?|socks5h?)://[^\s]+$", o["proxy"]):
            raise Fail(USAGE, "--proxy must be http(s):// or socks5(h):// (got: %s)" % redact(o["proxy"]))
    readable("--cert (this sensor's certificate)", o["cert"])
    sensor = cert_sensor(o["cert"])
    if sh(["openssl", "x509", "-in", o["cert"], "-noout", "-checkend", "0"])[0] != 0:
        raise Fail(LOCAL, "certificate %s has expired (renew it: step ca renew)" % o["cert"])
    if sh(["openssl", "x509", "-in", o["cert"], "-noout", "-checkend", "86400"])[0] != 0:
        log("warning: certificate %s expires within 24 hours (step ca renew)" % o["cert"])
    readable("--key (the certificate's key)", o["key"])
    if os.stat(o["key"]).st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        log("warning: %s is readable by other users; chmod 600 it" % o["key"])
    rc, kt, err = sh(["openssl", "pkey", "-in", o["key"], "-noout", "-text", "-passin", "pass:"])
    if rc != 0:
        raise Fail(LOCAL, "--key %s: cannot read the key (an encrypted key is not supported)" % o["key"])
    kt = kt.decode("utf-8", "replace")
    if not re.search(r"prime256v1|P-256", kt):
        raise Fail(LOCAL, "--key %s: not an ECDSA P-256 key; Tideline signatures are ES256" % o["key"])
    k1 = sh(["openssl", "pkey", "-in", o["key"], "-pubout", "-passin", "pass:"])[1]
    k2 = sh(["openssl", "x509", "-in", o["cert"], "-noout", "-pubkey"])[1]
    if not k1 or k1.strip() != k2.strip():
        raise Fail(LOCAL, "--key %s does not belong to --cert %s" % (o["key"], o["cert"]))
    if network and sh(["openssl", "verify", "-CAfile", o["ca"], "-untrusted", o["cert"], o["cert"]])[0] != 0:
        log("warning: %s does not chain to %s; Tideline may refuse it (both come from the same step-ca)"
            % (o["cert"], o["ca"]))
    return sensor


# --- the run --------------------------------------------------------------------
def run_paths(csvp):
    csvp = os.path.abspath(csvp)
    for p, what in ((csvp, "the CSV"), (csvp + ".run.json", "the run record"),
                    (csvp + ".manifest.sha256", "the run's SHA-256 manifest")):
        if not os.path.isfile(p):
            raise Fail(LOCAL, "%s is missing: %s" % (what, p))
    return csvp


def load_manifest(man):
    m = {}
    for line in open(man, encoding="utf-8", errors="replace"):
        x = re.match(r"^([0-9a-f]{64}) [ *](.+)$", line.rstrip("\n"))
        if x:
            m[x.group(2)] = x.group(1)
    return m


def build(csvp, sensor):
    d, base = os.path.dirname(csvp), os.path.basename(csvp)
    man_p = csvp + ".manifest.sha256"
    man = load_manifest(man_p)
    def checked(rel):
        p = os.path.join(d, rel)
        if not os.path.isfile(p):
            raise Fail(LOCAL, "%s is listed in the run's manifest but missing" % rel)
        h = sha256_file(p)
        if h != man[rel]:
            raise Fail(LOCAL, "%s changed since the run wrote its manifest (sha256 %s, manifest %s); not shipping it"
                       % (rel, h[:16], man[rel][:16]))
        return p, h
    if base + ".run.json" not in man:
        raise Fail(LOCAL, "the run record is not in the run's manifest")
    rp, _ = checked(base + ".run.json")
    run = json.load(open(rp, encoding="utf-8"))
    rid = run.get("run_id") or ""
    if not UUID4.match(rid):
        raise Fail(LOCAL, "%s has no run_id: it was written before 1.20 (run-recon); re-run with --json" % rp)
    if base + ".urls.jsonl" not in man:
        raise Fail(LOCAL, "the run has no JSON lines (%s.urls.jsonl): run outcrop with --json (or --ship)" % base)
    parts = []
    for kind, sid in KINDS:
        rel = "%s.%s.jsonl" % (base, kind)
        if rel not in man:
            continue
        p, h = checked(rel)
        size = os.path.getsize(p)
        if size > LIMIT_PART:
            raise Fail(LOCAL, "%s is %d bytes, over Tideline's 512 MiB part limit" % (rel, size))
        n = 0
        last = b"\n"
        with open(p, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                n += b.count(b"\n")
                last = b[-1:]
        n += 0 if last == b"\n" else 1
        parts.append({"kind": kind, "schema": sid, "name": rel, "records": n, "bytes": size, "sha256": h,
                      "_path": p, "_ctype": "application/x-ndjson"})
    mh = sha256_file(man_p)
    parts.append({"kind": "artifact", "media": "text/plain", "name": base + ".manifest.sha256",
                  "bytes": os.path.getsize(man_p), "sha256": mh, "_path": man_p, "_ctype": "text/plain"})
    for rel in sorted(man):
        ext = os.path.splitext(rel)[1].lower()
        if rel.startswith("screenshots-") and "/" in rel and ext in MEDIA:
            p, h = checked(rel)
            parts.append({"kind": "artifact", "media": MEDIA[ext], "name": rel, "bytes": os.path.getsize(p),
                          "sha256": h, "_path": p, "_ctype": MEDIA[ext]})
    for i, pt in enumerate(parts, 1):
        pt["n"] = i
    started = run.get("started") or ""
    try:
        t0 = datetime.datetime.strptime(started, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise Fail(LOCAL, "run.json: no usable start time (%r)" % started)
    fin = (t0 + datetime.timedelta(seconds=int(run.get("duration_s") or 0))).strftime("%Y-%m-%dT%H:%M:%SZ")
    env = {"schema": ENVELOPE, "run_id": rid, "tool": TOOL, "tool_version": str(run.get("version") or "unknown"),
           "sensor": sensor, "engagement": run.get("engagement") or None, "job_id": run.get("job_id") or None,
           "started": started, "finished": fin, "exit_code": int(run.get("exit_status") or 0),
           "profile": run, "tool_manifest_sha256": mh,
           "parts": [{k: v for k, v in pt.items() if not k.startswith("_")} for pt in parts]}
    body = json.dumps(env, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) > LIMIT_MANIFEST:
        raise Fail(LOCAL, "the manifest is %d bytes, over Tideline's 1 MiB limit (%d parts)" % (len(body), len(parts)))
    return env, body, parts


def sign(key, body, tmp):
    ep, sp = os.path.join(tmp, "envelope.json"), os.path.join(tmp, "envelope.sig")
    with open(ep, "wb") as f:
        f.write(body)
    rc, _, err = sh(["openssl", "dgst", "-sha256", "-sign", key, "-passin", "pass:", "-out", sp, ep])
    if rc != 0:
        raise Fail(LOCAL, "could not sign the manifest: %s" % err.strip())
    import base64
    sig = open(sp, "rb").read()
    return ep, sig, "alg=ES256; enc=der; sig=" + base64.b64encode(sig).decode("ascii")


def gz(src, dst):
    with open(src, "rb") as f, open(dst, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6) as g:
            shutil.copyfileobj(f, g, 1 << 20)
    return os.path.getsize(dst)


# --- state ----------------------------------------------------------------------
def state_path(csvp):
    return csvp + ".ship-state.json"


def load_state(csvp):
    p = state_path(csvp)
    try:
        return json.load(open(p, encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(csvp, st):
    p = state_path(csvp)
    with open(p + ".tmp", "w", encoding="utf-8") as f:
        json.dump(st, f, indent=2)
        f.write("\n")
    os.replace(p + ".tmp", p)


# --- transport ------------------------------------------------------------------
class Http:
    def __init__(self, o, tmp):
        self.o, self.tmp = o, tmp
        self.empty = os.path.join(tmp, "no-system-cas")
        os.makedirs(self.empty, exist_ok=True)
        self.retries = os.environ.get("SHIP_RETRIES", "4")
        self.timeout = os.environ.get("SHIP_TIMEOUT", "300")
        if not (self.retries.isdigit() and self.timeout.isdigit()):
            raise Fail(USAGE, "SHIP_RETRIES and SHIP_TIMEOUT must be whole numbers")

    def call(self, method, path, upload=None, data=None, headers=()):
        bodyf = os.path.join(self.tmp, "response")
        if os.path.exists(bodyf):
            os.remove(bodyf)
        # -q first: no ~/.curlrc. --cacert plus an empty --capath: Tideline's CA and nothing else
        # (curl still loads the system CA directory when only --cacert is given).
        a = ["curl", "-q", "-sS", "--proto", "=https", "--tlsv1.2", "--ciphers", TLS12, "--tls13-ciphers", TLS13,
             "--cert", self.o["cert"], "--key", self.o["key"], "--cacert", self.o["ca"], "--capath", self.empty,
             "--connect-timeout", "15", "--max-time", self.timeout, "--retry", self.retries, "--retry-connrefused",
             "--retry-max-time", "120", "-A", UA, "-o", bodyf, "-w", "%{http_code}", "-X", method]
        a += ["--proxy", self.o["proxy"]] if self.o["proxy"] else ["--noproxy", "*"]
        for h in headers:
            a += ["-H", h]
        if upload:
            a += ["-T", upload]
        elif data:
            a += ["--data-binary", "@" + data]
        a.append(self.o["url"] + path)
        rc, out, err = sh(a)
        code = int(out.decode() or 0) if out.decode().isdigit() else 0
        body = open(bodyf, "rb").read() if os.path.exists(bodyf) else b""
        if rc != 0:
            lines = [x for x in err.strip().splitlines() if x.startswith("curl: (")] or err.strip().splitlines()
            msg = lines[0] if lines else "curl exit %d" % rc
            if rc in (35, 53, 54, 58, 59, 60, 64, 66, 77, 80, 83, 90, 91) or (rc == 56 and "alert" in err):
                raise Fail(REFUSED, "TLS with %s failed: %s" % (self.o["url"], msg))
            raise Fail(RETRY, "%s %s: %s" % (method, path, msg))
        return code, body

    @staticmethod
    def reason(code, body):
        try:
            j = json.loads(body.decode("utf-8", "replace"))
            t = j.get("error") or j.get("reason") or json.dumps(j)
        except ValueError:
            t = body.decode("utf-8", "replace").strip()
        return "HTTP %d%s" % (code, (": " + t[:500]) if t else "")

    def expect(self, code, body, ok, what):
        if code in ok:
            try:
                return json.loads(body.decode("utf-8")) if body.strip() else {}
            except ValueError:
                return {}
        if code in (408, 425, 429) or code >= 500 or code == 0:
            raise Fail(RETRY, "%s: %s" % (what, self.reason(code, body)))
        raise Fail(REFUSED, "%s: Tideline refused it: %s" % (what, self.reason(code, body)))


# --- commands -------------------------------------------------------------------
def cmd_check(o):
    settings(o, {})
    sensor = check(o)
    exp = sh(["openssl", "x509", "-in", o["cert"], "-noout", "-enddate"])[1].decode().strip().split("=", 1)[-1]
    log("settings ok: sensor %s, certificate valid until %s, key ECDSA P-256, Tideline %s"
        % (sensor, exp, o["url"]))
    return OK


def cmd_envelope(o):
    csvp = run_paths(o["csv"])
    settings(o, load_state(csvp))
    readable("--cert (this sensor's certificate)", o["cert"])
    _, body, _ = build(csvp, cert_sensor(o["cert"]))
    sys.stdout.buffer.write(body + b"\n")
    return OK


def summary(parts):
    by = {}
    for p in parts:
        k = p["kind"]
        by.setdefault(k, [0, 0])
        by[k][0] += p.get("records", 1)
        by[k][1] += p["bytes"]
    return ", ".join("%s %d" % (k, v[0]) for k, v in by.items())


def cmd_ship(o):
    csvp = run_paths(o["csv"])
    lockf = open(csvp, "rb")
    try:
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise Fail(LOCAL, "another ship-recon.sh is shipping this run")
    st = load_state(csvp)
    settings(o, st)
    sensor = check(o, network=not o["dry_run"] or bool(o["url"]))
    env, body, parts = build(csvp, sensor)
    esha = hashlib.sha256(body).hexdigest()
    rid = env["run_id"]
    if o["dry_run"]:
        log("dry run: run %s, sensor %s, engagement %s, %d part(s): %s; manifest %d bytes (sha256 %s)"
            % (rid, sensor, env["engagement"] or "-", len(parts), summary(parts), len(body), esha[:16]))
        return OK
    if st.get("run_id") not in (None, rid) or (st.get("envelope_sha256") and st["envelope_sha256"] != esha
                                                and st.get("state") == "complete"):
        log("note: the previous shipping attempt recorded a different manifest; Tideline decides (409 = conflict)")
    st.update({"tool": "ship-recon", "version": VERSION, "run_id": rid, "sensor": sensor,
               "engagement": env["engagement"], "url": o["url"], "cert": o["cert"], "key": o["key"], "ca": o["ca"],
               "proxy": redact(o["proxy"]), "envelope_sha256": esha, "parts_total": len(parts),
               "attempts": int(st.get("attempts") or 0) + 1, "first_attempt": st.get("first_attempt") or now(),
               "last_attempt": now()})
    if st.get("envelope_sha256") != esha:
        st["parts_acknowledged"] = []
    st.setdefault("parts_acknowledged", [])
    st["state"], st["last_error"] = "opening", ""
    save_state(csvp, st)
    tmp = tempfile.mkdtemp(prefix="ship-recon.")
    try:
        try:
            return ship(o, csvp, st, env, body, parts, tmp)
        except Fail as e:
            st["state"], st["last_error"] = "failed", str(e)
            save_state(csvp, st)
            raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def ship(o, csvp, st, env, body, parts, tmp):
    rid = env["run_id"]
    http = Http(o, tmp)
    ep, _, sig = sign(o["key"], body, tmp)
    code, rb = http.call("POST", "/v1/runs", data=ep,
                         headers=("Content-Type: application/json", "Tideline-Signature: " + sig))
    r = http.expect(code, rb, (200, 201), "opening run %s" % rid)
    server = r.get("state") or ""
    have = {int(n) for n in (r.get("received") or []) if str(n).isdigit()}
    st["server_state"] = server
    st["parts_acknowledged"] = sorted(have)
    if server in ("verified", "normalized"):
        st["state"] = "complete"
        save_state(csvp, st)
        log("Tideline already has run %s (%s); nothing to send" % (rid, server))
        return OK
    st["state"] = "uploading"
    save_state(csvp, st)
    sent = sent_gz = 0
    for rnd in range(3):
        todo = [p for p in parts if p["n"] not in have]
        for p in todo:
            gzp = os.path.join(tmp, "part.gz")
            sent_gz += gz(p["_path"], gzp)
            code, rb = http.call("PUT", "/v1/runs/%s/parts/%d" % (rid, p["n"]), upload=gzp,
                                 headers=("Content-Type: " + p["_ctype"], "Content-Encoding: gzip"))
            http.expect(code, rb, (200, 201, 204), "part %d (%s)" % (p["n"], p["name"]))
            have.add(p["n"])
            sent += 1
            st["parts_acknowledged"] = sorted(have)
            save_state(csvp, st)
        code, rb = http.call("POST", "/v1/runs/%s/complete" % rid)
        if code == 409:
            try:
                miss = {int(n) for n in json.loads(rb.decode("utf-8")).get("missing") or []}
            except (ValueError, TypeError):
                miss = set()
            if miss and rnd < 2:
                log("Tideline is missing part(s) %s; sending them again" % ",".join(map(str, sorted(miss))))
                have -= miss
                continue
        r = http.expect(code, rb, (200, 202), "completing run %s" % rid)
        st["server_state"] = r.get("state") or "verified"
        st["state"], st["last_error"], st["completed"] = "complete", "", now()
        save_state(csvp, st)
        log("run %s delivered: %d part(s) sent (%d bytes gzip), %d already there; Tideline: %s"
            % (rid, sent, sent_gz, len(parts) - sent, st["server_state"]))
        return OK
    raise Fail(RETRY, "Tideline kept reporting missing parts")


def cmd_status(o):
    csvp = run_paths(o["csv"])
    st = load_state(csvp)
    settings(o, st)
    check(o)
    run = json.load(open(csvp + ".run.json", encoding="utf-8"))
    rid = run.get("run_id") or ""
    if not UUID4.match(rid):
        raise Fail(LOCAL, "the run has no run_id")
    tmp = tempfile.mkdtemp(prefix="ship-recon.")
    try:
        http = Http(o, tmp)
        code, rb = http.call("GET", "/v1/runs/%s" % rid)
        if code == 404:
            log("Tideline has no run %s" % rid)
            return REFUSED
        r = http.expect(code, rb, (200,), "status of run %s" % rid)
        json.dump(r, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return OK
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def cmd_export(o):
    csvp = run_paths(o["csv"])
    settings(o, load_state(csvp))
    sensor = check(o, network=False)
    env, body, parts = build(csvp, sensor)
    out = os.path.abspath(o["output"] or csvp + ".tideline.tar")
    tmp = tempfile.mkdtemp(prefix="ship-recon.")
    try:
        _, sigder, sig = sign(o["key"], body, tmp)
        def add(tf, name, data):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = len(data), 0, 0o644, 0, 0, "", ""
            tf.addfile(ti, io.BytesIO(data))
        with tarfile.open(out + ".tmp", "w", format=tarfile.PAX_FORMAT) as tf:
            add(tf, "envelope.json", body)
            add(tf, "signature.txt", (sig + "\n").encode("ascii"))
            for p in parts:
                gzp = os.path.join(tmp, "part.gz")
                gz(p["_path"], gzp)
                add(tf, "parts/%05d.gz" % p["n"], open(gzp, "rb").read())
        os.replace(out + ".tmp", out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    log("bundle for a hand-carried upload: %s (run %s, %d part(s), sha256 %s)"
        % (out, env["run_id"], len(parts), sha256_file(out)[:16]))
    return OK


def main():
    try:
        o = parse(ARGV)
        return {"ship": cmd_ship, "status": cmd_status, "export": cmd_export, "envelope": cmd_envelope,
                "check": cmd_check}[o["cmd"]](o)
    except Fail as e:
        for line in str(e).splitlines():
            log(line)
        return e.code
    except KeyboardInterrupt:
        log("interrupted; the state is kept, run the same command again to continue")
        return 130


sys.exit(main())
PYSHIP
