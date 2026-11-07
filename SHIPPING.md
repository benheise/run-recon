# Shipping runs to Tideline

Tideline is the recon results platform (project doc `claude/recon-platform-plan-v0.5.md`). Outcrop
sends it a finished run as a signed manifest plus one gzip part per file, over HTTPS with mutual TLS.
Shipping is an output stage. It reads the files the run already wrote and changes none of them, and
it sends nothing to a scan target. `--ship` changes neither the scan nor the CSV.

## Quick start

```bash
outcrop -i seeds.txt --tls --ipv6 --engagement eng-2026-014 \
  --ship https://tideline.internal:8443 \
  --ship-cert ~/.tideline/rr-kali01.crt --ship-key ~/.tideline/rr-kali01.key \
  --ship-ca ~/.tideline/root_ca.crt
```

The four settings can also come from the environment: `SHIP_URL`, `SHIP_CERT`, `SHIP_KEY`, `SHIP_CA`
(and `SHIP_PROXY`). That suits a cron job.

Delivery can fail, for example when Tideline is down. The run still completes locally and exits 4.
To retry:

```bash
ship-recon.sh ship recon-output/recon-20261106-140211.csv
```

A retry reuses the settings the failed attempt saved in `<csv>.ship-state.json` and sends only the
parts Tideline does not have yet.

## Options

| Option | Meaning |
|---|---|
| `--json` | Also write every record kind as JSON lines (see [Record files](#record-files)). No other effect. |
| `--ship URL` | Ship the run after it finishes. Implies `--json`. The URL is `https://host[:port][/prefix]`; anything else is refused. |
| `--ship-cert FILE` | This sensor's certificate from step-ca, in PEM. The file may carry the intermediate too. The sensor ID is its URI SAN `urn:tideline:sensor:<id>`. |
| `--ship-key FILE` | The certificate's key: ECDSA P-256, PEM, unencrypted. Keep it at mode 0600 or tighter; a key others can read gets a warning. |
| `--ship-ca FILE` | Tideline's root CA. The ingest server must chain to it and to nothing else. |
| `--ship-proxy URL` | A proxy for shipping only. By default shipping connects directly. |
| `--engagement ID` | Written to `run.json` and the manifest. Tideline checks that the sensor is assigned to it. |
| `--job-id ID` | Set by the Tideline runner for a job it claimed. Written likewise. |

`--engagement` and `--job-id` take 1–128 characters of `A-Z a-z 0-9 . _ : -`.

**Checked before the scan.** With `--ship`, Outcrop checks the settings before anything is sent to
a target. A missing file, a certificate with no sensor URI, an expired certificate, a key that is not
ECDSA P-256 or does not belong to the certificate, or a URL that is not https stops the run with
exit 2. Nothing has been scanned at that point. No connection is made for this check.
`ship-recon.sh check` runs the same checks on their own.

## What is sent

**The manifest.** It is `tideline-envelope/1` (`schemas/tideline-envelope.1.json`) and holds:
- `run_id`;
- the tool and its version;
- the sensor, taken from the certificate (a payload never names its own identity);
- the engagement and the job;
- the start and end times and the scan's own exit status;
- `profile`: the whole of `run.json`, unchanged;
- the SHA-256 of `<csv>.manifest.sha256`;
- one entry per part, with its kind, schema, record count, bytes and SHA-256.

**The signature.** ES256 is computed with `openssl dgst -sha256 -sign` over the manifest's exact
bytes. It travels in a header, `Tideline-Signature: alg=ES256; enc=der; sig=<base64>`.

**The parts.** One part per file, in this order:
1. the record files (`<csv>.<kind>.jsonl`);
2. `<csv>.manifest.sha256`;
3. the screenshots (`image/png` or `image/jpeg`).

Each part is gzipped for transport (`Content-Encoding: gzip`). Its `sha256` and `bytes` are taken over
the file as the run wrote it, and must equal the line in the run's manifest. A file that changed after
the run is refused locally (exit 1), with nothing sent. The CSV and the HTML report are not shipped:
Tideline builds its own reports from the records.

**The exchange:**

| Step | Request | Tideline answers |
|---|---|---|
| open | `POST /v1/runs` with the manifest | 201 new, 200 already known (with the parts it has), 409 the `run_id` exists with a different manifest |
| upload | `PUT /v1/runs/{run_id}/parts/{n}` for each part it lacks | 204 |
| close | `POST /v1/runs/{run_id}/complete` | 202, or 409 with the parts still missing |

Opening the same run again is safe: the manifest is rebuilt byte for byte from the same files.
`<csv>.ship-state.json` records each part Tideline acknowledged. It is written after the run's
manifest and is not listed in it, so a shipped run's files are exactly those of an unshipped
`--json` run, plus that state file.

## Frozen identifiers

Decided on 2026-11-06: the protocol keeps the Tideline names, and they are frozen. Sensor certificates
carry them, and step-ca's renewal template copies them, so a later change would mean re-enrolling every
sensor.

| Identifier | Value |
|---|---|
| Tool id | `run-recon`: the manifest's `tool`, run.json's `tool` and the record schemas' prefix. Outcrop was named run-recon until 1.21 and keeps this id, the way WebInventory keeps `webinventory` |
| Manifest schema | `tideline-envelope/1` (the `schema` field) |
| Signature header | `Tideline-Signature: alg=ES256; enc=der; sig=<base64>` (`enc=p1363` from Windows PowerShell) |
| Sensor identity | the certificate's URI SAN `urn:tideline:sensor:<id>`, with `<id>` 1–64 of `A-Z a-z 0-9 . _ -` |
| Tenant | a second URI SAN, `urn:tideline:tenant:<label>`. ship-recon does not read it and the manifest does not carry it: ingest takes it from the certificate |
| Schema ids | `urn:tideline:schema:<id>` in `$id`; `<id>` in `x-tideline-schema` and in each part's `schema`; record schemas `run-recon.<kind>/1` |
| Endpoints | `POST /v1/runs`, `PUT /v1/runs/{run_id}/parts/{n}`, `POST /v1/runs/{run_id}/complete`, `GET /v1/runs/{run_id}` |

**How they can change:**
- **A new field** in a record kind is a minor change: the id stays `/1`, `x-minor` goes up, and
  `schemas/SHA256SUMS` is regenerated.
- **A renamed or removed field** is a new major version: a new file (`/2`), with ingest accepting the
  previous major for one release.
- **Enforced by the suite:**
  - each identifier above, in `ship-recon.sh` and `lab/mock-tideline.py`;
  - every schema's `$id` and file name;
  - the schemas against `schemas/SHA256SUMS`, so a frozen schema cannot change by accident;
  - a certificate that carries the tenant URI still passes, and a combined
    `urn:tideline:sensor:<tenant>:<id>` is refused.

**Source of truth.** The `tideline-schemas` repository (project doc `claude/tideline-schemas-v1.md`) holds
these schemas unchanged. Once it has a tagged release, Outcrop vendors its `schemas/` and `SHA256SUMS` from
that release.

## Transport

- **TLS.** TLS 1.2 or later, with ECDHE and AES-GCM suites only.
- **Client certificate.** The `--ship-cert`/`--ship-key` pair is the sensor's identity, and the key
  also signs the manifest. A sensor holds one credential.
- **The server is checked against `--ship-ca` only.** curl's `--cacert` alone does not do this: curl
  still loads the system CA directory (`CApath: /etc/ssl/certs` in `curl -v`), so a server with a
  publicly trusted certificate, or one behind a TLS-intercepting proxy, would pass. ship-recon also
  passes an empty `--capath`. The suite checks that a trust store in `SSL_CERT_DIR` or
  `CURL_CA_BUNDLE` that would accept the server is ignored.
- **`-q`.** curl runs with `-q`, so a `~/.curlrc` cannot add options.
- **Proxy.** Shipping connects directly unless `--ship-proxy` is given. The scan's `--proxy`
  exports `HTTP(S)_PROXY` for the scan's tools, and shipping does not use those.
- **Retries.** curl retries a refused connection, a timeout, 408, 429 and 5xx with exponential
  backoff. `SHIP_RETRIES` sets the count (default 4) and `SHIP_TIMEOUT` the seconds per request
  (default 300).

## Exit status

| Code | Outcrop | ship-recon.sh |
|---|---|---|
| 0 | finished with results (and delivered, with `--ship`) | delivered, or Tideline already had the run |
| 1 | — | local problem: a missing or changed file, an unusable certificate or key, a missing tool, or a run without `--json` |
| 2 | bad arguments, or unusable `--ship` settings (nothing scanned) | bad arguments |
| 3 | finished with no results | — |
| 4 | finished with results, not delivered: retry with `ship-recon.sh ship` | not delivered, try again later: network, timeout, Tideline busy or down |
| 5 | — | refused: a TLS or certificate problem, an unknown or inactive sensor, another sensor's run, a conflicting manifest, an invalid part. Fix the cause first |

An empty run keeps exit 3 even when its delivery fails. `run.json`'s `exit_status` is always the
scan's own status.

## ship-recon.sh

```text
ship-recon.sh ship     <csv> [--url URL --cert C --key K --ca CA] [--proxy P] [--dry-run]
ship-recon.sh status   <csv> [connection options]      Tideline's state of the run (JSON)
ship-recon.sh export   <csv> --cert C --key K [-o F]   bundle for a hand-carried upload
ship-recon.sh envelope <csv> --cert C                  print the manifest that would be signed
ship-recon.sh check    --url URL --cert C --key K --ca CA
```

- **Settings.** Connection settings come from the options, then the `SHIP_*` environment, then
  `<csv>.ship-state.json`.
- **Bundles.** `export` writes `<csv>.tideline.tar`. It holds `envelope.json`, `signature.txt` (the
  header value) and `parts/NNNNN.gz`, the same bytes `ship` would send. An admin uploads it through
  the UI when the sensor cannot reach Tideline.
- **One shipper per run.** ship-recon takes a lock on the CSV, so a second ship-recon on the same
  run stops instead of interleaving.

## Record files

`--json` writes one JSON object per line. Each kind has a JSON Schema (2020-12) in `schemas/`, named by
its `x-tideline-schema` id. These files are to move to the shared `tideline-schemas` repository.

| File | Schema | One record per |
|---|---|---|
| `<csv>.urls.jsonl` | `run-recon.url/1` | CSV row: the same 48 fields in the same order |
| `<csv>.services.jsonl` | `run-recon.service/1` | service (`scheme://host[:port]` under a seed), with its root URL's values |
| `<csv>.findings.jsonl` | `run-recon.finding/1` | line of any `<csv>.<kind>.txt` finding file |
| `<csv>.dnsposture.jsonl` | `run-recon.dnsposture/1` | row of `.dnsposture.tsv` |
| `<csv>.edges.jsonl` | `run-recon.edge/1` | row of `.edge.tsv` |
| `<csv>.cnames.jsonl` | `run-recon.cname/1` | row of `.cname.tsv` |
| `<csv>.zone-names.jsonl` | `run-recon.zone-name/1` | row of `.zone-names.txt` |
| `<csv>.screenshots.jsonl` | `run-recon.screenshot/1` | row of `.screenshots.tsv`: ok, blank, failed or suspect |
| `<csv>.cloud-assets.jsonl` | `run-recon.cloud-asset/1` | row of `.cloud-assets.tsv` |
| `<csv>.vulnx.jsonl` | `run-recon.vulnx/1` | row of `.vulnx.tsv` |
| `<csv>.delta.jsonl` | `run-recon.delta/1` | row of `.delta.tsv` (`--monitor`) |
| `<csv>.warnings.jsonl` | `run-recon.warning/1` | warning, in order, each once (all of them; `run.json` keeps 200) |
| `<csv>.seeds.jsonl` | `run-recon.seed/1` | seed: candidates, resolved, live hosts |

`urls`, `services`, `findings`, `warnings` and `seeds` are always written. The other kinds are written
only when their stage ran.

- **The CSV builder writes `urls` and `services` itself**, from the rows it writes to the CSV. The
  values are the CSV cells as strings, but without the formula guard: a title that starts with `=`
  is the site's own text, not `'=…`.
- **A service** follows `recon-db.sh diff`'s rule: its values come from the root URL's row (else its
  smallest URL's), so Tideline's change events agree with `--monitor`. `service` omits the default
  port; `port` is always explicit, and `port` and `url_count` are integers.
- **A finding** has these fields:
  - `source`: the file's kind;
  - `seed`;
  - `check`: the line's first token;
  - `severity`: the line's `[severity]` tag, else its first tag (nuclei), else the report's default
    for the kind;
  - `host`;
  - `fields`: the `key=value` pairs of a structured line;
  - `note`: the free text after `note=`;
  - `text`: the line itself.
- **The TSV kinds** use their header as field names, and their values are strings.
- **Versions.** A field added in a later release is a minor version: the schema id stays `/1`, and
  consumers accept unknown string fields. A renamed or removed field is a new major version.

The suite checks that each schema lists exactly the fields Outcrop writes. It reads `CSV_HEADER` and
each TSV header from the source, so a new column fails the suite until its schema is updated.

## Enrolling a sensor with step-ca

Every sensor has one ECDSA P-256 certificate from Tideline's step-ca. The sensor ID is the
certificate's URI SAN. In outline (plan section 9):

1. **Issue a token.** An admin issues a one-time token for the sensor, with the URI SAN:
   `step ca token rr-kali01 --san urn:tideline:sensor:rr-kali01 --not-after 30m`.
   step-ca requires the request to carry exactly the token's SANs.
2. **Get the certificate.** On the sensor, use the token with `step ca certificate` (EC P-256 is
   step's default key type). Fetch the root once (`step ca root`) and keep it as the `--ship-ca` file.
3. **Protect the key.** Keep the key readable only by the user Outcrop runs as (`chmod 600`).
4. **Renew.** Keep the certificate current with `step ca renew --daemon` under systemd; the plan
   suggests 7-day certificates. ship-recon refuses an expired certificate and warns 24 hours ahead.

Disabling the sensor in Tideline blocks it at the next request.

## Testing

**Mock ingest.** `lab/mock-tideline.py` is a stand-in for Tideline's ingest service, loopback only. It
checks what a real ingest checks:
- the client certificate chains to the CA, and its sensor URI is active;
- the manifest's sensor is the certificate's, and the ES256 signature verifies with the certificate's
  key (DER or P1363);
- each part's SHA-256 and size match, with its records validated against their schema (one bad line
  refuses the part);
- request size limits are enforced.

`faults.json` in its store injects failures: an HTTP status, or a dropped connection, for a given
request.

**Test PKI.** `lab/gen-ship-certs.sh DIR` makes a step-ca-shaped PKI for it: root, intermediate, a
server certificate and sensor certificates. It also makes the misfits the tests need: a sensor from
another CA, one without a sensor URI, an RSA sensor, and a server from another CA.

**Suite** (`test-run-recon.sh`, section "Batch 6"):
- `urls`/`services` parity with the CSV;
- the findings parser;
- the schema contract;
- the envelope;
- delivery, a second delivery, resume after a 503 and after a dropped connection;
- a changed file, a conflicting manifest, another sensor, a rogue client CA, a server from another
  CA, the pinning check, export;
- `outcrop --ship`'s preflight, delivery and exit 4.

**Lab** (`bench-run-recon.sh ship`): a real lab run with screenshots is shipped to the mock. Tideline
must store every part byte for byte, and the shipped URL records must equal the CSV row for row. A
second delivery sends nothing; a 503 and then a retry sends only the missing parts.
