#!/usr/bin/env python3
"""lo-sniff.py SECONDS IP[,IP...] PORT[,PORT...] -- count the packets a scan sends to the lab on loopback.

Used by `bench-run-recon.sh stop` (Outcrop 1.21): after a stopped run has exited, nothing may
still reach a lab service. Counted, toward any of the given addresses AND ports: TCP packets
that open a connection (SYN) or carry data, and UDP datagrams (DNS). Closing handshakes
(FIN/ACK without data) and the services' replies (to an ephemeral port) are not counted.
Prints one JSON object:
  {"seconds": N, "packets": N, "syn": N, "data": N, "udp": N, "first": [...a few samples...]}
Needs a raw packet socket (root or CAP_NET_RAW). Loopback only: it binds to "lo".
"""
import json
import socket
import struct
import sys
import time


def main():
    secs = float(sys.argv[1])
    ips = {socket.inet_aton(a) for a in sys.argv[2].split(",") if a}
    ports = {int(p) for p in sys.argv[3].split(",") if p}
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind(("lo", 0))
    s.settimeout(0.2)
    end = time.time() + secs
    out = {"seconds": secs, "packets": 0, "syn": 0, "data": 0, "udp": 0, "first": []}
    while time.time() < end:
        try:
            pkt, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        if addr[2] == socket.PACKET_OUTGOING:   # loopback shows each packet twice: count it once
            continue
        if len(pkt) < 34 or pkt[12:14] != b"\x08\x00":   # Ethernet + IPv4 only
            continue
        ip = pkt[14:]
        ihl = (ip[0] & 0x0F) * 4
        proto, dst = ip[9], ip[16:20]
        if dst not in ips:
            continue
        total = struct.unpack("!H", ip[2:4])[0]
        l4 = ip[ihl:]
        if proto == 6 and len(l4) >= 20:
            dport = struct.unpack("!H", l4[2:4])[0]
            if dport not in ports:
                continue
            flags = l4[13]
            doff = (l4[12] >> 4) * 4
            payload = total - ihl - doff
            syn = bool(flags & 0x02) and not flags & 0x10
            if not (syn or payload > 0):
                continue
            out["syn" if syn else "data"] += 1
            kind = "tcp-syn" if syn else "tcp-data"
        elif proto == 17 and len(l4) >= 8:
            dport = struct.unpack("!H", l4[2:4])[0]
            if dport not in ports:
                continue
            out["udp"] += 1
            kind = "udp"
        else:
            continue
        out["packets"] += 1
        if len(out["first"]) < 5:
            out["first"].append("%s %s:%d" % (kind, socket.inet_ntoa(dst), dport))
    print(json.dumps(out))


if __name__ == "__main__":
    main()
