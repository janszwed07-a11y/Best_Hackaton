#!/usr/bin/env python3
"""Generate synthetic .pcap files for testing pcapan.

Only the Python standard library is used (no scapy), so this runs anywhere.

    python3 tools/gen_samples.py samples/

Creates:
  normal.pcap        two minutes of ordinary web/DNS/SSH traffic (IPv4 + IPv6)
  attack.pcap        normal traffic plus a port scan, a SYN flood, a UDP
                     fan-out, DNS amplification, a slow receiver (zero window),
                     a lossy connection and a Telnet login
  malformed.pcap     broken headers and a file cut off mid-packet
  bigendian_ns.pcap  big-endian file, nanosecond timestamps, Linux SLL link type
"""
import ipaddress
import os
import random
import struct
import sys

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
MSS = 1448
T0 = 1_763_650_000.0          # capture start (Nov 2025), any epoch works


# ---------------------------------------------------------------- packets --

def ip_bytes(addr):
    return ipaddress.ip_address(addr).packed


def l4_tcp(sport, dport, seq, ack, flags, payload_len, window=64240):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xffffffff,
                      ack & 0xffffffff, 5 << 4, flags, window, 0, 0)
    return hdr + b"\x00" * payload_len


def l4_udp(sport, dport, payload_len):
    return struct.pack("!HHHH", sport, dport, 8 + payload_len, 0) + \
        b"\x00" * payload_len


def ip_packet(src, dst, proto, l4):
    s, d = ip_bytes(src), ip_bytes(dst)
    if len(s) == 4:
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0x4000,
                          64, proto, 0, s, d)
        return 0x0800, hdr + l4
    hdr = struct.pack("!IHBB16s16s", 6 << 28, len(l4), proto, 64, s, d)
    return 0x86DD, hdr + l4


class Capture:
    """Collects (time, frame) pairs and writes them as a pcap file."""

    def __init__(self, linktype=1):
        self.linktype = linktype
        self.pkts = []

    def add(self, t, src, dst, proto, l4):
        etype, ip = ip_packet(src, dst, proto, l4)
        if self.linktype == 1:              # Ethernet II
            frame = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + \
                struct.pack("!H", etype) + ip
        else:                               # Linux cooked capture (SLL)
            frame = struct.pack("!HHH8sH", 0, 1, 6, b"\x02" * 8, etype) + ip
        self.pkts.append((t, frame))

    def tcp(self, t, src, sport, dst, dport, seq, ack, flags, n=0, win=64240):
        self.add(t, src, dst, 6, l4_tcp(sport, dport, seq, ack, flags, n, win))

    def udp(self, t, src, sport, dst, dport, n):
        self.add(t, src, dst, 17, l4_udp(sport, dport, n))

    def write(self, path, big_endian=False, nsec=False, cut=0):
        e = ">" if big_endian else "<"
        magic = 0xA1B23C4D if nsec else 0xA1B2C3D4
        out = bytearray(struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 65535,
                                    self.linktype))
        for t, frame in sorted(self.pkts, key=lambda p: p[0]):
            sec = int(t)
            frac = int((t - sec) * (1e9 if nsec else 1e6))
            out += struct.pack(e + "IIII", sec, frac, len(frame), len(frame))
            out += frame
        if cut:
            out = out[:-cut]
        with open(path, "wb") as f:
            f.write(out)
        print(f"wrote {path}: {len(self.pkts)} packets, {len(out)} bytes")


# --------------------------------------------------------------- traffic --

def tcp_session(cap, t, cli, cport, srv, sport, exchanges, rtt=0.02,
                retrans=0.0, zero_window=0, close=True):
    """A complete TCP conversation: handshake, request/response pairs, close.
    exchanges is a list of (request_bytes, response_bytes)."""
    cs, ss = random.randrange(1 << 32), random.randrange(1 << 32)
    cap.tcp(t, cli, cport, srv, sport, cs, 0, SYN)
    cap.tcp(t + rtt / 2, srv, sport, cli, cport, ss, cs + 1, SYN | ACK)
    cap.tcp(t + rtt, cli, cport, srv, sport, cs + 1, ss + 1, ACK)
    cs, ss, t = cs + 1, ss + 1, t + rtt

    for req, resp in exchanges:
        t += random.uniform(0.05, 0.6)
        cap.tcp(t, cli, cport, srv, sport, cs, ss, PSH | ACK, req)
        cs += req
        t += rtt / 2
        sent, k = 0, 0
        while sent < resp:
            n = min(MSS, resp - sent)
            t += 0.0012
            cap.tcp(t, srv, sport, cli, cport, ss, cs, ACK, n)
            if random.random() < retrans:          # lost: send it again
                cap.tcp(t + 0.2, srv, sport, cli, cport, ss, cs, ACK, n)
            ss += n
            sent += n
            k += 1
            if k % 2 == 0:
                win = 0 if zero_window and k // 2 <= zero_window else 64240
                cap.tcp(t + rtt / 2, cli, cport, srv, sport, cs, ss, ACK, 0, win)
        if resp:
            cap.tcp(t + rtt / 2, cli, cport, srv, sport, cs, ss, ACK)
    if close:
        t += 0.1
        cap.tcp(t, cli, cport, srv, sport, cs, ss, FIN | ACK)
        cap.tcp(t + rtt / 2, srv, sport, cli, cport, ss, cs + 1, FIN | ACK)
        cap.tcp(t + rtt, cli, cport, srv, sport, cs + 1, ss + 1, ACK)
    return t


def normal_traffic(cap, duration=120):
    client, dns, v6c = "192.168.1.10", "192.168.1.1", "2001:db8::10"
    web = ["93.184.216.34", "142.250.74.46", "151.101.1.69", "104.16.132.229"]

    t = T0
    while t < T0 + duration - 5:               # browsing: a page every ~2 s
        srv = random.choice(web)
        port = random.randrange(40000, 60000)
        q = random.randrange(1024, 65535)
        cap.udp(t, client, q, dns, 53, 40)
        cap.udp(t + 0.01, dns, 53, client, q, 120)
        ex = [(random.randrange(300, 900), random.randrange(2000, 60000))
              for _ in range(random.randrange(1, 4))]
        tcp_session(cap, t + 0.02, client, port, srv, 443, ex, retrans=0.002)
        t += random.uniform(1.0, 3.0)

    # one longer download in the middle
    tcp_session(cap, T0 + 40, client, 51515, "151.101.1.69", 443,
                [(500, 2_500_000)])

    # interactive SSH session for the whole capture
    ex = [(random.randrange(40, 120), random.randrange(40, 400))
          for _ in range(int(duration / 0.45))]
    tcp_session(cap, T0 + 0.5, client, 50022, "10.0.0.5", 22, ex)

    # IPv6 HTTPS and NTP
    tcp_session(cap, T0 + 15, v6c, 45000, "2001:db8::1", 443,
                [(600, 30000), (700, 80000)])
    for i in range(0, duration, 30):
        cap.udp(T0 + i, client, 123, "162.159.200.1", 123, 48)
        cap.udp(T0 + i + 0.03, "162.159.200.1", 123, client, 123, 48)


def port_scan(cap, t, scanner="192.168.1.66", target="10.0.0.5"):
    open_ports = {22, 80, 443}
    for port in range(1, 301):
        sp, isn = random.randrange(30000, 60000), random.randrange(1 << 32)
        cap.tcp(t, scanner, sp, target, port, isn, 0, SYN, win=1024)
        if port in open_ports:          # open: SYN-ACK, scanner resets
            cap.tcp(t + 0.001, target, port, scanner, sp, 777, isn + 1, SYN | ACK)
            cap.tcp(t + 0.002, scanner, sp, target, port, isn + 1, 0, RST)
        else:                           # closed: RST-ACK
            cap.tcp(t + 0.001, target, port, scanner, sp, 0, isn + 1, RST | ACK)
        t += 0.004


def syn_flood(cap, t, target="10.0.0.5", port=80, count=3000, seconds=3.0):
    for i in range(count):
        src = f"{random.randrange(11, 223)}.{random.randrange(256)}." \
              f"{random.randrange(256)}.{random.randrange(1, 255)}"
        sp, ts = random.randrange(1024, 65535), t + i * seconds / count
        cap.tcp(ts, src, sp, target, port, random.randrange(1 << 32), 0, SYN)
        if i % 4 == 0:                  # server answers some, nobody ACKs
            cap.tcp(ts + 0.001, target, port, src, sp, 5, 1, SYN | ACK)


def udp_fanout(cap, t, src="192.168.1.77"):
    for i in range(80):
        cap.udp(t + i * 0.01, src, 40000 + i, f"10.0.1.{i + 1}", 161, 60)


def dns_amplification(cap, t, victim="192.168.1.10"):
    for i in range(400):                # big answers nobody asked for
        cap.udp(t + i * 0.005, "203.0.113.53", 53, victim, 33333, 1400)


def build_normal(path):
    cap = Capture()
    normal_traffic(cap)
    cap.write(path)


def build_attack(path):
    cap = Capture()
    normal_traffic(cap)
    port_scan(cap, T0 + 20)
    syn_flood(cap, T0 + 60)
    udp_fanout(cap, T0 + 80)
    dns_amplification(cap, T0 + 90)
    tcp_session(cap, T0 + 30, "192.168.1.20", 49800, "10.0.0.8", 445,
                [(200, 400_000)], zero_window=6)
    tcp_session(cap, T0 + 50, "192.168.1.30", 49900, "198.51.100.7", 443,
                [(400, 300_000)], retrans=0.3)
    tcp_session(cap, T0 + 70, "192.168.1.40", 49950, "10.0.0.9", 23,
                [(10, 80), (12, 40), (20, 300)])
    cap.write(path)


def build_malformed(path):
    cap = Capture()
    tcp_session(cap, T0, "10.1.1.1", 40000, "10.1.1.2", 80, [(100, 5000)])
    # IPv4 header claiming IHL=15 (60 bytes) in a 30-byte packet
    bad = bytearray(ip_packet("10.1.1.1", "10.1.1.2", 6, b"\x00" * 10)[1])
    bad[0] = 0x4F
    cap.pkts.append((T0 + 1, b"\x02" * 12 + b"\x08\x00" + bytes(bad)))
    # TCP header cut short: only 6 bytes of TCP
    etype, ip = ip_packet("10.1.1.1", "10.1.1.2", 6, b"\x00" * 6)
    cap.pkts.append((T0 + 2, b"\x02" * 12 + b"\x08\x00" + ip))
    # Ethernet frame shorter than its own header
    cap.pkts.append((T0 + 3, b"\x02" * 8))
    cap.write(path, cut=4)             # and the file ends mid-packet


def build_bigendian(path):
    cap = Capture(linktype=113)
    tcp_session(cap, T0, "172.16.0.2", 41000, "172.16.0.1", 8080,
                [(300, 20000), (300, 15000)])
    cap.udp(T0 + 2, "172.16.0.2", 5353, "224.0.0.251", 5353, 80)
    cap.write(path, big_endian=True, nsec=True)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "samples"
    os.makedirs(out, exist_ok=True)
    random.seed(42)                     # same files every run
    build_normal(os.path.join(out, "normal.pcap"))
    build_attack(os.path.join(out, "attack.pcap"))
    build_malformed(os.path.join(out, "malformed.pcap"))
    build_bigendian(os.path.join(out, "bigendian_ns.pcap"))


if __name__ == "__main__":
    main()
