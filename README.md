# pcapan: TCP/UDP traffic analyser for pcap files

`pcapan` is a command-line tool for Linux, written in C11. It reads a `.pcap` capture, rebuilds every TCP and UDP conversation, flags suspicious or unhealthy traffic, and writes:

- `report.pdf`: a multi-page report with a capture summary, findings ranked by severity, every chart, and the largest flows
- one PNG per chart: traffic over time, TCP connection attempts, protocol mix, top talkers, top services, packet sizes and connection durations

```
$ ./pcapan -o out samples/attack.pcap
samples/attack.pcap: 13,616 packets, 8.0 MB, 3504 flows, 3099 hosts
  [HIGH  ] TCP port scan: 192.168.1.66 probed 300 different TCP ports on 10.0.0.5 ...
  [HIGH  ] Possible SYN flood: 3001 connection attempts to 10.0.0.5:80 never completed ...
  [HIGH  ] Possible UDP amplification: 1 UDP flow(s) on DNS/NTP/SNMP/SSDP/memcached ports ...
  [MEDIUM] Connections with heavy retransmission: ...
  [MEDIUM] UDP fan-out: 192.168.1.77 sent UDP traffic to 80 different hosts ...
  [LOW   ] TCP zero-window events: ...
  [LOW   ] Traffic spike: ...
  [INFO  ] Unencrypted login protocol: 1 Telnet session(s) on TCP port 23 ...
Report written to out/report.pdf
```

An example report from `samples/attack.pcap` is in [`docs/example_report.pdf`](docs/example_report.pdf).

![TCP connection attempts](docs/tcp_handshakes.png)

## Building

The only dependency is **Cairo**, a lightweight 2D graphics library that every Linux distribution ships. It produces both the PNG charts and the PDF report. Its font configuration library, fontconfig, is installed along with it.

```sh
# Debian / Ubuntu
sudo apt install build-essential pkg-config libcairo2-dev
# Fedora
sudo dnf install gcc make pkgconf-pkg-config cairo-devel

make            # builds ./pcapan
```

The code compiles without warnings under `-std=c11 -Wall -Wextra -Wpedantic -Wshadow`.

## Usage

```
pcapan [-o DIR] [-q] FILE.pcap

  -o DIR   output directory (default: pcapan_out, created if missing)
  -q       quiet: do not print the summary to the terminal
  -h       help
  -V       version
```

Capture your own traffic with `sudo tcpdump -i any -w capture.pcap`. Files in pcapng format, Wireshark's default, are detected and rejected with a message. Convert them first with `editcap -F pcap in.pcapng out.pcap`.

## Testing

```sh
make samples   # generates 4 synthetic captures in samples/ (Python 3, stdlib only)
make test      # runs pcapan on each of them
make asan      # rebuilds with AddressSanitizer + UndefinedBehaviorSanitizer
```

| Sample | What it exercises |
|---|---|
| `normal.pcap` | two minutes of web, DNS, SSH and NTP traffic, IPv4 and IPv6 |
| `attack.pcap` | the same traffic plus a port scan, a SYN flood, a UDP fan-out, DNS amplification, a zero-window receiver, a lossy connection and a Telnet login |
| `malformed.pcap` | broken IP/TCP headers, a frame shorter than Ethernet, a file cut mid-packet |
| `bigendian_ns.pcap` | big-endian byte order, nanosecond timestamps, Linux cooked-capture link type |

The tool was checked with valgrind (no leaks or errors) and with ASan/UBSan on all samples. It was also run on empty, header-only, random and byte-fuzzed files. Bad input never crashes it: it exits with an error or analyses everything that could be read.

## Architecture

```
pcap.c  ->  decode.c  ->  analysis.c  ->  anomaly.c  ->  charts.c  ->  report.c
 read        parse         flows and       detection     PNG charts   PDF report
 records     headers       statistics      rules         (Cairo)      (Cairo)
```

| File | Responsibility |
|---|---|
| `pcap.c` | Reads the classic pcap format directly. It handles both byte orders and both µs and ns timestamps, and detects truncated files. |
| `decode.c` | Parses Ethernet (with VLAN tags), Linux SLL/SLL2, raw IP and BSD loopback, then IPv4 and IPv6 (including extension headers and fragments), then TCP and UDP. Every read is bounds-checked. |
| `analysis.c` | A flow table keyed by the 5-tuple, where both directions map to one flow. It also tracks a per-second timeline, a packet size histogram, TCP handshake state and retransmissions. After the last packet it aggregates hosts and services. |
| `anomaly.c` | Detection rules. Each one is a documented threshold at the top of the file. |
| `charts.c` | Seven charts. Each is a single function drawing on a `cairo_t`. |
| `report.c` | The PDF layout: text wrapping, pagination, severity tags, the flows table. |
| `main.c` | Command-line handling and the main pipeline. |

### Design decisions

- **No libpcap.** The file format is 24 bytes of file header plus 16 bytes per packet. Reading it directly removes a dependency and keeps the tool in full control of malformed input.
- **Streaming.** Packets are processed one at a time and never stored. Memory grows with the number of flows and the capture duration (one small record per second), not with file size.
- **One drawing path for PNG and PDF.** Every chart draws on a fixed 800×420 logical canvas. For PNG output the canvas is scaled 2× onto an image surface. For the report it is scaled down onto a PDF page and stays vector graphics, so the charts are sharp at any zoom.
- **Bidirectional flows.** The hash is computed on the two endpoints in sorted order, so A→B and B→A share a bucket. Side "a" of a flow is whoever sent the first packet, normally the client.
- **Aggregation by sorting.** Top hosts and top services are built by emitting one record per flow endpoint, sorting, and merging neighbours. This is simpler than additional hash tables, and fast enough because it runs once.
- **Explainable rules.** Every finding states the numbers that triggered it, so a reader can judge it rather than trust a score.

### Detection rules

| Finding | Rule | Severity |
|---|---|---|
| TCP port scan | one source sends SYNs to at least 15 distinct ports on one host, and none of those connections completes | high |
| Host sweep | one source tries the same port on at least 15 hosts without completing a connection | high |
| SYN flood | at least 100 incomplete handshakes to one service. The number of distinct sources is reported, and many sources suggest spoofing. | high |
| UDP amplification | a DNS, NTP, SNMP, SSDP, LDAP, chargen or memcached flow where the server sends at least 10× the bytes requested and at least 100 KB | high |
| High retransmission rate | 3% or more of TCP data segments are retransmitted | medium |
| Lossy connections | flows with at least 10 retransmissions that make up at least 10% of their packets | medium |
| UDP fan-out | one source sends UDP to at least 50 hosts | medium |
| Zero window | a receiver advertises a zero window 3 or more times | low |
| Many resets | at least 10 established connections, and over 20% of all of them, end with RST instead of FIN | low |
| Traffic spike | a second carrying more than 10× the median rate and more than mean + 4σ (needs at least 30 s of capture) | low |
| Unencrypted login | completed FTP, Telnet, POP3 or IMAP sessions | info |
| Capture problems | malformed packets or a truncated file | info |

A segment counts as a retransmission when its sequence range ends at or before the highest sequence number already seen in that direction. Serial-number arithmetic handles sequence-number wrap-around.

## Limitations

- Classic pcap only. pcapng is detected and must be converted first.
- No TCP stream reassembly or application-layer parsing. Analysis is based on headers.
- IP fragments after the first one are counted but not reassembled.
- Thresholds are fixed constants in `src/anomaly.c`. On very large or very small networks they may need tuning.
