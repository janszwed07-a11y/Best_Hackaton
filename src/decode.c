#include "decode.h"
#include "pcap.h"

#include <string.h>

#define ETH_IPV4 0x0800
#define ETH_IPV6 0x86dd
#define ETH_VLAN 0x8100
#define ETH_QINQ 0x88a8

/* Network byte order (big-endian) readers. Every caller checks the
 * length first, so these never read past the buffer. */
static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | p[3];
}

/* Parse the transport header. l4len is how many bytes the IP header says
 * the transport segment has; cap is how many of those are in the capture. */
static dec_status_t decode_l4(const uint8_t *p, uint32_t cap, uint32_t l4len,
                              decoded_t *out)
{
    if (out->proto == PROTO_TCP) {
        if (cap < 20 || l4len < 20)
            return DEC_MALFORMED;
        uint32_t hlen = (uint32_t)(p[12] >> 4) * 4;  /* data offset */
        if (hlen < 20 || hlen > l4len)
            return DEC_MALFORMED;
        out->sport       = be16(p);
        out->dport       = be16(p + 2);
        out->seq         = be32(p + 4);
        out->ack         = be32(p + 8);
        out->flags       = p[13];
        out->window      = be16(p + 14);
        out->payload_len = l4len - hlen;
        return DEC_OK;
    }
    if (out->proto == PROTO_UDP) {
        if (cap < 8 || l4len < 8)
            return DEC_MALFORMED;
        out->sport       = be16(p);
        out->dport       = be16(p + 2);
        out->payload_len = l4len - 8;
        return DEC_OK;
    }
    return DEC_OTHER;
}

static dec_status_t decode_ipv4(const uint8_t *p, uint32_t len, decoded_t *out)
{
    if (len < 20 || (p[0] >> 4) != 4)
        return DEC_MALFORMED;
    uint32_t ihl   = (uint32_t)(p[0] & 0x0f) * 4;
    uint32_t total = be16(p + 2);
    if (ihl < 20 || ihl > len || total < ihl)
        return DEC_MALFORMED;

    out->ipver = 4;
    memcpy(out->src, p + 12, 4);
    memcpy(out->dst, p + 16, 4);
    out->proto = p[9];

    /* Fragments after the first one carry no TCP/UDP header. */
    if (be16(p + 6) & 0x1fff)
        return DEC_OTHER;

    /* Ethernet pads short frames, so trust the IP length, not the frame. */
    uint32_t cap = (len < total ? len : total) - ihl;
    return decode_l4(p + ihl, cap, total - ihl, out);
}

static dec_status_t decode_ipv6(const uint8_t *p, uint32_t len, decoded_t *out)
{
    if (len < 40 || (p[0] >> 4) != 6)
        return DEC_MALFORMED;
    uint32_t plen = be16(p + 4);
    uint8_t  next = p[6];

    out->ipver = 6;
    memcpy(out->src, p + 8, 16);
    memcpy(out->dst, p + 24, 16);

    uint32_t off = 40;
    uint32_t end = 40 + plen;
    uint32_t cap_end = len < end ? len : end;

    /* Walk the common extension headers until we reach TCP/UDP. */
    for (int guard = 0; guard < 8; guard++) {
        if (next == 0 || next == 43 || next == 60) {   /* hop, routing, dest */
            if (off + 8 > cap_end)
                return DEC_MALFORMED;
            uint32_t elen = ((uint32_t)p[off + 1] + 1) * 8;
            next = p[off];
            off += elen;
        } else if (next == 44) {                        /* fragment */
            if (off + 8 > cap_end)
                return DEC_MALFORMED;
            if (be16(p + off + 2) & 0xfff8)
                return DEC_OTHER;                       /* not the first piece */
            next = p[off];
            off += 8;
        } else {
            break;
        }
    }
    if (off > end)
        return DEC_MALFORMED;

    out->proto = next;
    return decode_l4(p + off, cap_end > off ? cap_end - off : 0, end - off, out);
}

static dec_status_t decode_l3(uint16_t ethertype, const uint8_t *p,
                              uint32_t len, decoded_t *out)
{
    if (ethertype == ETH_IPV4)
        return decode_ipv4(p, len, out);
    if (ethertype == ETH_IPV6)
        return decode_ipv6(p, len, out);
    return DEC_OTHER;
}

dec_status_t decode_packet(uint32_t linktype, const uint8_t *d, uint32_t len,
                           decoded_t *out)
{
    memset(out, 0, sizeof *out);

    switch (linktype) {
    case LINKTYPE_ETHERNET: {
        if (len < 14)
            return DEC_MALFORMED;
        uint32_t off = 12;
        uint16_t type = be16(d + off);
        while (type == ETH_VLAN || type == ETH_QINQ) {  /* skip VLAN tags */
            off += 4;
            if (off + 2 > len)
                return DEC_MALFORMED;
            type = be16(d + off);
        }
        off += 2;
        return decode_l3(type, d + off, len - off, out);
    }
    case LINKTYPE_LINUX_SLL:
        if (len < 16)
            return DEC_MALFORMED;
        return decode_l3(be16(d + 14), d + 16, len - 16, out);
    case LINKTYPE_LINUX_SLL2:
        if (len < 20)
            return DEC_MALFORMED;
        return decode_l3(be16(d), d + 20, len - 20, out);
    case LINKTYPE_RAW:
    case 12: /* some systems use 12 for raw IP */
        if (len < 1)
            return DEC_MALFORMED;
        return decode_l3((d[0] >> 4) == 6 ? ETH_IPV6 : ETH_IPV4, d, len, out);
    case LINKTYPE_NULL: {
        if (len < 4)
            return DEC_MALFORMED;
        /* 4-byte address family in the writer's byte order. */
        uint32_t fam = d[0] ? d[0] : d[3];
        if (fam == 2)
            return decode_l3(ETH_IPV4, d + 4, len - 4, out);
        if (fam == 24 || fam == 28 || fam == 30)
            return decode_l3(ETH_IPV6, d + 4, len - 4, out);
        return DEC_OTHER;
    }
    default:
        return DEC_OTHER;
    }
}
