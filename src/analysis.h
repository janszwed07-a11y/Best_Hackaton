/* analysis.h - everything we learn about a capture.
 *
 * Packets are fed in one at a time (streaming), so memory use depends on the
 * number of flows and the capture duration, never on the file size.
 */
#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <stddef.h>
#include <stdint.h>

#include "decode.h"
#include "pcap.h"

#define SIZE_BINS    16             /* packet size histogram: 100-byte bins */
#define MAX_SECONDS  (7 * 86400)    /* longest timeline we keep (7 days) */

/* Handshake progress bits, see analysis.c:update_tcp() */
#define HS_SYN     0x01   /* client sent SYN */
#define HS_SYNACK  0x02   /* server answered SYN-ACK */
#define HS_DONE    0x04   /* client sent the final ACK: established */
#define HS_MIDSTREAM 0x08 /* capture started after the handshake */

/* One conversation, identified by its 5-tuple. Side "a" is whoever sent the
 * first packet we saw (the client, in a normal capture). Index 0 of the
 * two-element arrays is a->b, index 1 is b->a. */
typedef struct flow {
    struct flow *next;         /* hash table chain */
    uint32_t hash;
    uint8_t  ipver, proto;
    uint8_t  a[16], b[16];
    uint16_t pa, pb;

    uint64_t pkts[2], bytes[2], payload[2];
    uint64_t first_us, last_us;

    /* TCP only */
    uint8_t  hs;               /* HS_* bits */
    uint32_t syn, rst, fin;
    uint32_t retrans, zero_win;
    uint32_t seq_end[2];       /* highest sequence number seen + 1 */
    uint8_t  seq_valid[2];
} flow_t;

typedef struct {
    uint64_t tcp_bytes, udp_bytes;
    uint32_t pkts, syn, synack;
} second_t;

typedef struct {
    int      ipver;
    uint8_t  addr[16];
    uint64_t bytes_out, bytes_in, pkts;
    uint32_t flows;
} host_stat_t;

typedef struct {
    uint8_t  proto;
    uint16_t port;
    uint64_t bytes;
    uint32_t flows;
} port_stat_t;

typedef enum { SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO } severity_t;

typedef struct {
    severity_t sev;
    char       title[96];
    char       detail[384];
    uint64_t   first_us, last_us;  /* 0 when not tied to a time range */
} anomaly_t;

typedef struct {
    const char *path;

    /* totals */
    uint64_t packets, bytes;
    uint64_t tcp_pkts, udp_pkts, other_pkts, malformed_pkts;
    uint64_t tcp_bytes, udp_bytes, other_bytes;
    uint64_t ipv4_pkts, ipv6_pkts;
    uint64_t syn_pkts, synack_pkts, rst_pkts, fin_pkts;
    uint64_t retrans_pkts, tcp_data_pkts;
    uint64_t first_us, last_us;
    int      truncated_file;
    uint32_t linktype;

    uint64_t size_hist[SIZE_BINS];

    /* per-second timeline, index = seconds since the first packet */
    second_t *sec;
    size_t    nsec, sec_cap;

    /* flow hash table */
    flow_t  **buckets;
    size_t    nbuckets, nflows;

    /* filled in by analysis_finish() */
    flow_t     **flows;          /* all flows, biggest first */
    host_stat_t *hosts;          /* biggest first */
    size_t       nhosts;
    port_stat_t *ports;          /* biggest first */
    size_t       nports;
    uint32_t     tcp_flows, udp_flows, established, failed_handshakes;

    anomaly_t   *anom;
    size_t       nanom, anom_cap;
} analysis_t;

void analysis_init(analysis_t *a, const char *path, uint32_t linktype);
void analysis_add(analysis_t *a, const packet_t *pkt);
void analysis_finish(analysis_t *a);        /* sorts, aggregates, detects */
void analysis_free(analysis_t *a);

/* The port that identifies the service (e.g. 443 for a web connection). */
uint16_t flow_service_port(const flow_t *f);

/* anomaly.c */
void detect_anomalies(analysis_t *a);
void add_anomaly(analysis_t *a, severity_t sev, uint64_t first_us,
                 uint64_t last_us, const char *title, const char *fmt, ...)
    __attribute__((format(printf, 6, 7)));
const char *severity_name(severity_t s);

#endif
