#!/usr/bin/env python3
"""mock-tideline.py -- a stand-in for Tideline's ingest service, for the suite and the lab.

It implements the sensor-facing side of the ingest protocol (recon-platform-plan section 5) and
checks what a real ingest checks, so a passing shipper is a correct one:

  POST /v1/runs                      signed manifest -> 201 (new) | 200 (same bytes) | 409 (other bytes)
  PUT  /v1/runs/{run_id}/parts/{n}   gzip part -> 204 | 422 (hash, size, schema) | 413 | 415
  POST /v1/runs/{run_id}/complete    202 | 409 {"missing": [...]}
  GET  /v1/runs/{run_id}             200 {state, received, missing} | 404

- TLS 1.2+, client certificate required and chained to --client-ca; the sensor is the
  certificate's URI SAN urn:tideline:sensor:<id>, never a payload field.
- The manifest's sensor must equal the certificate's; its ES256 signature (DER or P1363,
  Tideline-Signature header) must verify with the presented certificate's key.
- Each part is decompressed under limits, hashed, and (with --schemas) validated line by
  line against the schema named in the manifest; one bad line refuses the whole part.

Everything lands in --store: runs/<run_id>/{manifest.json, signature.txt, state.json,
parts/<n>}, plus requests.jsonl (one line per request). faults.json in the store, read on
every request, injects failures, e.g.
  [{"method": "PUT", "part": 2, "status": 503, "times": 3}, {"method": "PUT", "part": 3, "action": "drop"}]
Loopback only: --bind must be a loopback address. Uses the openssl CLI for signatures.
"""
import argparse, base64, gzip, hashlib, http.server, ipaddress, json, os, re, socketserver, ssl, subprocess
import sys, tempfile, threading, zlib

LIMIT_MANIFEST, LIMIT_GZ, LIMIT_RAW, LIMIT_LINE, RATIO = 1 << 20, 64 << 20, 512 << 20, 1 << 20, 50
URN = "urn:tideline:sensor:"
RUN_PATH = re.compile(r"^/v1/runs/([0-9a-f-]{36})(?:/(complete|parts/(\d+)))?$")
LOCK = threading.Lock()
ARGS = None
SCHEMAS = {}


def jload(p, default):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def jsave(p, obj):
    with open(p + ".tmp", "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1)
    os.replace(p + ".tmp", p)


def der_from_p1363(sig):
    def i(b):
        b = b.lstrip(b"\x00") or b"\x00"
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    h = len(sig) // 2
    body = i(sig[:h]) + i(sig[h:])
    return b"\x30" + bytes([len(body)]) + body


def verify_es256(cert_der, data, header):
    m = dict(re.findall(r"(\w+)=([^;\s]+)", header or ""))
    if m.get("alg") != "ES256" or m.get("enc") not in ("der", "p1363") or "sig" not in m:
        return "Tideline-Signature must be alg=ES256; enc=der|p1363; sig=<base64>"
    try:
        sig = base64.b64decode(m["sig"], validate=True)
    except ValueError:
        return "signature is not base64"
    if m["enc"] == "p1363":
        if len(sig) != 64:
            return "a P1363 ES256 signature is 64 bytes"
        sig = der_from_p1363(sig)
    with tempfile.TemporaryDirectory() as t:
        open(os.path.join(t, "c.der"), "wb").write(cert_der)
        open(os.path.join(t, "d"), "wb").write(data)
        open(os.path.join(t, "s"), "wb").write(sig)
        pub = subprocess.run(["openssl", "x509", "-inform", "DER", "-in", os.path.join(t, "c.der"), "-noout", "-pubkey"],
                             capture_output=True, stdin=subprocess.DEVNULL).stdout
        open(os.path.join(t, "k"), "wb").write(pub)
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", os.path.join(t, "k"), "-signature",
                            os.path.join(t, "s"), os.path.join(t, "d")], capture_output=True, stdin=subprocess.DEVNULL)
    return None if r.returncode == 0 else "signature does not verify with the client certificate's key"


def validator(sid):
    if sid not in SCHEMAS:
        return None
    v = SCHEMAS[sid]
    if v is None or callable(v):
        return v
    try:
        import jsonschema
        SCHEMAS[sid] = jsonschema.Draft202012Validator(v).iter_errors
    except ImportError:
        SCHEMAS[sid] = None
    return SCHEMAS[sid]


def load_schemas(d):
    for n in sorted(os.listdir(d)):
        if n.endswith(".json"):
            s = jload(os.path.join(d, n), None)
            if isinstance(s, dict) and s.get("x-tideline-schema"):
                SCHEMAS[s["x-tideline-schema"]] = s


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mock-tideline/1"

    def log_message(self, fmt, *a):
        pass

    # -- plumbing ----------------------------------------------------------------
    def reply(self, code, obj=None):
        body = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(code)
        if obj is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)
        self.record(code, (obj or {}).get("error", "") if isinstance(obj, dict) else "")

    def record(self, code, err=""):
        with LOCK, open(os.path.join(ARGS.store, "requests.jsonl"), "a") as f:
            f.write(json.dumps({"method": self.command, "path": self.path, "status": code,
                                "sensor": getattr(self, "sensor", ""), "error": err}) + "\n")

    def body(self, limit):
        n = self.headers.get("Content-Length")
        if n is None or not n.isdigit():
            return None, 411
        n = int(n)
        if n > limit:
            return None, 413
        return self.rfile.read(n), 0

    def fault(self, part=None, kind=""):
        p = os.path.join(ARGS.store, "faults.json")
        with LOCK:
            fl = jload(p, [])
            for f in fl:
                if f.get("method") != self.command or f.get("times", 1) <= 0:
                    continue
                if "part" in f and f["part"] != part:
                    continue
                if "path" in f and f["path"] != kind:
                    continue
                f["times"] = f.get("times", 1) - 1
                jsave(p, fl)
                return f
        return None

    def identify(self):
        c = self.connection.getpeercert()
        sans = [v for k, v in (c or {}).get("subjectAltName", ()) if k == "URI" and v.startswith(URN)]
        self.sensor = sans[0][len(URN):] if len(sans) == 1 else ""
        if not self.sensor:
            self.reply(403, {"error": "the client certificate names no sensor (URI SAN %s<id>)" % URN})
            return False
        sensors = jload(os.path.join(ARGS.store, "sensors.json"), None)
        if sensors is not None and (sensors.get(self.sensor) or {}).get("status") != "active":
            self.reply(403, {"error": "sensor %s is not active" % self.sensor})
            return False
        return True

    def rundir(self, rid):
        return os.path.join(ARGS.store, "runs", rid)

    def status_of(self, rid):
        st = jload(os.path.join(self.rundir(rid), "state.json"), None)
        man = jload(os.path.join(self.rundir(rid), "manifest.json"), None)
        if st is None or man is None:
            return None, None
        allp = [p["n"] for p in man["parts"]]
        rec = sorted(int(n) for n in st["received"])
        return man, {"run_id": rid, "state": st["state"], "received": rec,
                     "missing": [n for n in allp if n not in rec]}

    # -- endpoints ---------------------------------------------------------------
    def do_GET(self):
        if not self.identify():
            return
        m = RUN_PATH.match(self.path)
        if not m or m.group(2):
            return self.reply(404, {"error": "no such endpoint"})
        man, s = self.status_of(m.group(1))
        if s is None:
            return self.reply(404, {"error": "unknown run"})
        if man["sensor"] != self.sensor:
            return self.reply(403, {"error": "run belongs to another sensor"})
        self.reply(200, s)

    def do_POST(self):
        if not self.identify():
            return
        if self.path == "/v1/runs":
            return self.open_run()
        m = RUN_PATH.match(self.path)
        if not m or m.group(2) != "complete":
            return self.reply(404, {"error": "no such endpoint"})
        f = self.fault(kind="complete")
        if f and f.get("status"):
            return self.reply(f["status"], {"error": "injected"})
        rid = m.group(1)
        man, s = self.status_of(rid)
        if s is None:
            return self.reply(404, {"error": "unknown run"})
        if man["sensor"] != self.sensor:
            return self.reply(403, {"error": "run belongs to another sensor"})
        if s["missing"]:
            return self.reply(409, {"error": "parts missing", "missing": s["missing"]})
        with LOCK:
            st = jload(os.path.join(self.rundir(rid), "state.json"), {})
            st["state"] = "verified"
            jsave(os.path.join(self.rundir(rid), "state.json"), st)
        self.reply(202, {"run_id": rid, "state": "verified"})

    def open_run(self):
        f = self.fault(kind="runs")
        if f and f.get("status"):
            return self.reply(f["status"], {"error": "injected"})
        data, err = self.body(LIMIT_MANIFEST)
        if err:
            return self.reply(err, {"error": "manifest over 1 MiB" if err == 413 else "Content-Length required"})
        if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
            return self.reply(415, {"error": "manifest must be application/json"})
        try:
            man = json.loads(data.decode("utf-8"))
        except ValueError:
            return self.reply(400, {"error": "manifest is not JSON"})
        v = validator("tideline-envelope/1")
        if v:
            errs = [e.message for e in v(man)]
            if errs:
                return self.reply(400, {"error": "manifest fails tideline-envelope/1: " + "; ".join(errs[:3])})
        elif not isinstance(man, dict) or man.get("schema") != "tideline-envelope/1" or not man.get("parts"):
            return self.reply(400, {"error": "not a tideline-envelope/1 manifest"})
        if man.get("sensor") != self.sensor:
            return self.reply(403, {"error": "manifest names sensor %r, the certificate %r" % (man.get("sensor"), self.sensor)})
        e = verify_es256(self.connection.getpeercert(True), data, self.headers.get("Tideline-Signature"))
        if e:
            return self.reply(401, {"error": e})
        ns = [p["n"] for p in man["parts"]]
        if ns != list(range(1, len(ns) + 1)):
            return self.reply(400, {"error": "parts must be numbered 1..N"})
        rid = man["run_id"]
        d = self.rundir(rid)
        with LOCK:
            if os.path.isdir(d):
                old = open(os.path.join(d, "manifest.json"), "rb").read()
                if old != data:
                    code = 409
                else:
                    code = 200
            else:
                os.makedirs(os.path.join(d, "parts"))
                open(os.path.join(d, "manifest.json"), "wb").write(data)
                open(os.path.join(d, "signature.txt"), "w").write(self.headers.get("Tideline-Signature") + "\n")
                jsave(os.path.join(d, "state.json"), {"state": "receiving", "received": []})
                code = 201
        if code == 409:
            return self.reply(409, {"error": "run %s exists with a different manifest" % rid})
        _, s = self.status_of(rid)
        if code == 201:
            s["parts"] = [{"n": n, "path": "/v1/runs/%s/parts/%d" % (rid, n)} for n in ns]
        self.reply(code, s)

    def do_PUT(self):
        if not self.identify():
            return
        m = RUN_PATH.match(self.path)
        if not m or not m.group(3):
            return self.reply(404, {"error": "no such endpoint"})
        rid, n = m.group(1), int(m.group(3))
        f = self.fault(part=n)
        if f and f.get("action") == "drop":
            self.record(0, "injected drop")
            self.close_connection = True
            self.connection.close()
            return
        if f and f.get("status"):
            self.body(LIMIT_GZ)
            return self.reply(f["status"], {"error": "injected"})
        man, s = self.status_of(rid)
        if s is None:
            return self.reply(404, {"error": "unknown run"})
        if man["sensor"] != self.sensor:
            return self.reply(403, {"error": "run belongs to another sensor"})
        part = next((p for p in man["parts"] if p["n"] == n), None)
        if part is None:
            return self.reply(404, {"error": "no part %d in the manifest" % n})
        if (self.headers.get("Content-Encoding") or "").lower() != "gzip":
            return self.reply(415, {"error": "parts must be gzip (Content-Encoding: gzip)"})
        data, err = self.body(LIMIT_GZ)
        if err:
            return self.reply(err, {"error": "part over 64 MiB compressed" if err == 413 else "Content-Length required"})
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            raw = d.decompress(data, LIMIT_RAW + 1)
            if len(raw) > LIMIT_RAW or d.unconsumed_tail:
                return self.reply(413, {"error": "part over 512 MiB uncompressed"})
            if len(raw) > (1 << 20) and len(raw) > RATIO * max(1, len(data)):
                return self.reply(413, {"error": "compression ratio over %d:1" % RATIO})
        except zlib.error:
            return self.reply(422, {"error": "part is not valid gzip"})
        h = hashlib.sha256(raw).hexdigest()
        if h != part["sha256"] or len(raw) != part["bytes"]:
            return self.reply(422, {"error": "part %d: sha256/bytes do not match the manifest" % n})
        if part["kind"] != "artifact":
            bad, cnt = [], 0
            v = validator(part.get("schema"))
            for i, line in enumerate(raw.split(b"\n"), 1):
                if not line:
                    continue
                cnt += 1
                if len(line) > LIMIT_LINE:
                    bad.append(i)
                    continue
                try:
                    o = json.loads(line.decode("utf-8"))
                except ValueError:
                    bad.append(i)
                    continue
                if not isinstance(o, dict) or (v and next(iter(v(o)), None) is not None):
                    bad.append(i)
            if bad:
                return self.reply(422, {"error": "part %d: invalid record(s)" % n, "lines": bad[:50]})
            if cnt != part.get("records"):
                return self.reply(422, {"error": "part %d: %d records, the manifest says %s" % (n, cnt, part.get("records"))})
        dd = self.rundir(rid)
        with LOCK:
            open(os.path.join(dd, "parts", str(n)), "wb").write(raw)
            st = jload(os.path.join(dd, "state.json"), {})
            if n not in st["received"]:
                st["received"].append(n)
            jsave(os.path.join(dd, "state.json"), st)
        self.reply(204)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def finish_request(self, request, client_address):
        try:
            request = self.ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as e:
            with LOCK, open(os.path.join(ARGS.store, "requests.jsonl"), "a") as f:
                f.write(json.dumps({"method": "", "path": "", "status": 0, "sensor": "",
                                    "error": "TLS: %s" % (getattr(e, "reason", None) or str(e))}) + "\n")
            return
        self.RequestHandlerClass(request, client_address, self)

    def handle_error(self, request, client_address):
        pass   # a dropped connection (fault injection) or a client that went away


def main():
    global ARGS
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0, help="0 = any free port (written to --store/port)")
    ap.add_argument("--cert", required=True, help="server certificate chain (PEM)")
    ap.add_argument("--key", required=True, help="server key (PEM)")
    ap.add_argument("--client-ca", required=True, help="root CA client certificates must chain to")
    ap.add_argument("--store", required=True)
    ap.add_argument("--schemas", help="directory of JSON Schemas (x-tideline-schema ids)")
    ARGS = ap.parse_args()
    if not ipaddress.ip_address(ARGS.bind).is_loopback:
        sys.exit("mock-tideline: --bind must be a loopback address")
    os.makedirs(os.path.join(ARGS.store, "runs"), exist_ok=True)
    if ARGS.schemas:
        load_schemas(ARGS.schemas)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(ARGS.cert, ARGS.key)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(ARGS.client_ca)
    srv = Server((ARGS.bind, ARGS.port), Handler)
    srv.ctx = ctx
    with open(os.path.join(ARGS.store, "port.tmp"), "w") as f:
        f.write(str(srv.server_address[1]))
    os.replace(os.path.join(ARGS.store, "port.tmp"), os.path.join(ARGS.store, "port"))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
