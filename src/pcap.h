/* pcap.h - minimal reader for the classic libpcap file format.
 *
 * Written from scratch on purpose: the format is tiny (one 24-byte file
 * header, then a 16-byte header before every packet), so we do not need
 * libpcap as a dependency just to read files.
 */
#ifndef PCAP_H
#define PCAP_H

#include <stdint.h>
#include <stdio.h>

/* Link-layer types we understand (values from tcpdump.org/linktypes.html). */
#define LINKTYPE_NULL      0    /* BSD loopback */
#define LINKTYPE_ETHERNET  1
#define LINKTYPE_RAW       101  /* raw IPv4/IPv6, no link header */
#define LINKTYPE_LINUX_SLL 113  /* "tcpdump -i any" on Linux */
#define LINKTYPE_LINUX_SLL2 276

typedef struct {
    FILE    *f;
    int      swap;       /* file was written with the other byte order */
    int      nsec;       /* timestamps are in nanoseconds, not microseconds */
    uint32_t linktype;
    uint32_t snaplen;
    uint8_t *buf;        /* reused buffer for packet data */
    uint32_t bufcap;
} pcap_file_t;

typedef struct {
    uint64_t       ts_us;    /* timestamp in microseconds since the epoch */
    uint32_t       caplen;   /* bytes stored in the file */
    uint32_t       wirelen;  /* bytes the packet really had on the wire */
    const uint8_t *data;     /* valid until the next pcap_next() call */
} packet_t;

/* Returns 0 on success, -1 on error (message written to err). */
int  pcap_open(pcap_file_t *p, const char *path, char *err, size_t errlen);

/* Returns 1 when a packet was read, 0 at a clean end of file,
 * -1 when the file is truncated or corrupt. */
int  pcap_next(pcap_file_t *p, packet_t *pkt);

void pcap_close(pcap_file_t *p);

#endif
