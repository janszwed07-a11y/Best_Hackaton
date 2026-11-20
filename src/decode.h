/* decode.h - turn raw packet bytes into the fields we analyse. */
#ifndef DECODE_H
#define DECODE_H

#include <stdint.h>

#define PROTO_TCP 6
#define PROTO_UDP 17

/* TCP flag bits */
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10

typedef enum {
    DEC_OK = 0,       /* IPv4/IPv6 + TCP/UDP, all fields filled in */
    DEC_OTHER,        /* valid, but not TCP/UDP over IP (ARP, ICMP, ...) */
    DEC_MALFORMED     /* truncated or inconsistent headers */
} dec_status_t;

typedef struct {
    int      ipver;          /* 4 or 6 (0 if not IP) */
    uint8_t  src[16];        /* IPv4 uses the first 4 bytes */
    uint8_t  dst[16];
    uint8_t  proto;          /* PROTO_TCP or PROTO_UDP */
    uint16_t sport, dport;
    uint32_t payload_len;    /* application bytes in this segment/datagram */

    /* TCP only */
    uint8_t  flags;
    uint32_t seq, ack;
    uint16_t window;
} decoded_t;

dec_status_t decode_packet(uint32_t linktype, const uint8_t *data,
                           uint32_t len, decoded_t *out);

#endif
