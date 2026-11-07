#!/usr/bin/env bash
# gen-ship-certs.sh DIR : a throwaway PKI for testing --ship against lab/mock-tideline.py.
# Shaped like step-ca's: an offline root, an intermediate that issues everything, ECDSA P-256
# keys, the sensor ID as a URI SAN (urn:tideline:sensor:<id>), certificate files that carry
# the leaf and the intermediate. Plus the misfits the tests need: a sensor from another CA,
# one without a sensor URI, an RSA sensor, and a server certificate from another CA.
#   DIR/root.pem                 the root a sensor pins (--ship-ca) and the mock trusts
#   DIR/server.{pem,key}         ingest server (127.0.0.1, ::1, localhost, tideline.test)
#   DIR/rr-test01.{pem,key}      sensor rr-test01        DIR/rr-other.{pem,key}  sensor rr-other
#   DIR/rogue.{pem,key}          sensor rr-test01 from another root (rogue-root.pem)
#   DIR/nourn.{pem,key}          no sensor URI           DIR/rsa.{pem,key}       RSA 2048 key
#   DIR/rogue-server.{pem,key}   a server certificate from the other root
set -euo pipefail
d="${1:?usage: gen-ship-certs.sh DIR}"
mkdir -p "$d"; cd "$d"
umask 077
ec(){ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
ca(){ # name subject [issuer-name]
  ec "$1.key"
  if [ -z "${3:-}" ]; then
    openssl req -x509 -new -key "$1.key" -subj "/CN=$2" -days 30 -out "$1.pem" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  else
    openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr" 2>/dev/null
    printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$1.ext"
    openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -CAcreateserial -days 30 -out "$1.pem" \
      -extfile "$1.ext" 2>/dev/null
  fi
}
leaf(){ # name subject issuer ext-lines [rsa]
  if [ "${5:-}" = rsa ]; then openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" 2>/dev/null; else ec "$1.key"; fi
  openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr" 2>/dev/null
  printf '%b' "$4" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -CAcreateserial -days 7 -out "$1.crt" -extfile "$1.ext" 2>/dev/null
  cat "$1.crt" "$3.pem" > "$1.pem"
}
CLIENT='basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n'
SERVER='basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n'
ca root "Tideline Test Root CA"
ca int "Tideline Test Intermediate CA" root
ca rogue-root "Rogue Root CA"
ca rogue-int "Rogue Intermediate CA" rogue-root
leaf server tideline.test int "${SERVER}subjectAltName=DNS:tideline.test,DNS:localhost,IP:127.0.0.1,IP:::1\n"
leaf rr-test01 rr-test01 int "${CLIENT}subjectAltName=URI:urn:tideline:sensor:rr-test01\n"
leaf rr-other rr-other int "${CLIENT}subjectAltName=URI:urn:tideline:sensor:rr-other\n"
leaf rogue rr-test01 rogue-int "${CLIENT}subjectAltName=URI:urn:tideline:sensor:rr-test01\n"
leaf nourn nourn int "${CLIENT}subjectAltName=DNS:nourn.test\n"
leaf rsa rr-rsa int "${CLIENT}subjectAltName=URI:urn:tideline:sensor:rr-rsa\n" rsa
leaf rogue-server tideline.test rogue-int "${SERVER}subjectAltName=DNS:tideline.test,DNS:localhost,IP:127.0.0.1\n"
rm -f ./*.csr ./*.ext ./*.srl ./*.crt
chmod 600 ./*.key; chmod 644 ./*.pem
