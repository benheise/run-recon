#!/usr/bin/env python3
# TLS-posture fixtures for the run-recon lab (bench-run-recon.sh up; run-recon 1.20).
# Writes four self-signed certificates and keys into the directory given:
#   legacy   RSA 1024, signed with SHA-1, valid now        -> WeakKey:1024, WeakSig
#   future   ECDSA P-256 / SHA-256, valid from in 30 days  -> CertNotYetValid
#   default  RSA 2048 / SHA-256, OpenSSL's default subject  -> DefaultCert
#            ("O=Internet Widgits Pty Ltd", what `openssl req` fills in when asked nothing)
#   modern   ECDSA P-256 / SHA-256, valid now               -> the control: none of these flags
# Each is named <name>.tls.test, with that name as its only SAN. Needs python3-cryptography
# and openssl (cryptography refuses to sign with SHA-1, so `openssl req` makes the legacy one).
# Throwaway lab keys: they never leave the lab directory (gitignored).
import datetime
import os
import subprocess
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    sys.exit("python3-cryptography is needed for the TLS fixtures (apt install python3-cryptography)")

out = sys.argv[1] if len(sys.argv) > 1 else "."
os.makedirs(out, exist_ok=True)
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
day = datetime.timedelta(days=1)

# legacy: openssl (SHA-1 signature)
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:1024", "-sha1", "-nodes", "-days", "365",
                "-subj", "/O=run-recon lab/CN=legacy.tls.test", "-addext", "subjectAltName=DNS:legacy.tls.test",
                "-keyout", os.path.join(out, "legacy.key"), "-out", os.path.join(out, "legacy.crt")],
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
os.chmod(os.path.join(out, "legacy.key"), 0o644)   # read by nginx in the container (lab only)

SPECS = {
    "future": dict(key="p256", sig=hashes.SHA256(), start=now + 30 * day, days=365, org="run-recon lab"),
    "default": dict(key="rsa2048", sig=hashes.SHA256(), start=now - day, days=365, org="Internet Widgits Pty Ltd",
                    extra=[(NameOID.COUNTRY_NAME, "AU"), (NameOID.STATE_OR_PROVINCE_NAME, "Some-State")]),
    "modern": dict(key="p256", sig=hashes.SHA256(), start=now - day, days=365, org="run-recon lab"),
}

for name, s in SPECS.items():
    host = "%s.tls.test" % name
    if s["key"] == "p256":
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=int(s["key"][3:]))
    attrs = [x509.NameAttribute(oid, v) for oid, v in s.get("extra", [])]
    attrs += [x509.NameAttribute(NameOID.ORGANIZATION_NAME, s["org"]), x509.NameAttribute(NameOID.COMMON_NAME, host)]
    subject = x509.Name(attrs)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(s["start"]).not_valid_after(s["start"] + s["days"] * day)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, s["sig"]))
    with open(os.path.join(out, name + ".key"), "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    os.chmod(os.path.join(out, name + ".key"), 0o644)   # read by nginx in the container (lab only)
    with open(os.path.join(out, name + ".crt"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
print("ok")
