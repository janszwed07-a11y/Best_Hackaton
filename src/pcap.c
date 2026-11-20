#include "pcap.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC_US      0xa1b2c3d4u  /* microsecond timestamps */
#define MAGIC_NS      0xa1b23c4du  /* nanosecond timestamps */
#define MAGIC_PCAPNG  0x0a0d0d0au  /* pcapng: not supported, but detect it */
#define MAX_PACKET    (256u * 1024u)

static uint32_t swap32(uint32_t v)
{
    return ((v & 0xffu) << 24) | ((v & 0xff00u) << 8) |
           ((v >> 8) & 0xff00u) | (v >> 24);
}

static uint32_t rd32(const pcap_file_t *p, const uint8_t *b)
{
    uint32_t v;
    memcpy(&v, b, 4);          /* memcpy avoids unaligned access */
    return p->swap ? swap32(v) : v;
}

int pcap_open(pcap_file_t *p, const char *path, char *err, size_t errlen)
{
    uint8_t hdr[24];
    uint32_t magic;

    memset(p, 0, sizeof *p);
    p->f = fopen(path, "rb");
    if (!p->f) {
        snprintf(err, errlen, "cannot open %s: %s", path, strerror(errno));
        return -1;
    }
    if (fread(hdr, 1, sizeof hdr, p->f) != sizeof hdr) {
        snprintf(err, errlen, "%s: file too short for a pcap header", path);
        goto fail;
    }

    memcpy(&magic, hdr, 4);
    if (magic == MAGIC_US || magic == MAGIC_NS) {
        p->swap = 0;
    } else if (swap32(magic) == MAGIC_US || swap32(magic) == MAGIC_NS) {
        p->swap = 1;
        magic = swap32(magic);
    } else if (magic == MAGIC_PCAPNG) {
        snprintf(err, errlen, "%s is pcapng; convert it first with: "
                 "editcap -F pcap in.pcapng out.pcap", path);
        goto fail;
    } else {
        snprintf(err, errlen, "%s: not a pcap file (bad magic 0x%08x)",
                 path, magic);
        goto fail;
    }

    p->nsec     = (magic == MAGIC_NS);
    p->snaplen  = rd32(p, hdr + 16);
    p->linktype = rd32(p, hdr + 20) & 0x0fffffffu; /* upper bits = FCS info */
    return 0;

fail:
    fclose(p->f);
    p->f = NULL;
    return -1;
}

int pcap_next(pcap_file_t *p, packet_t *pkt)
{
    uint8_t rh[16];
    size_t n = fread(rh, 1, sizeof rh, p->f);

    if (n == 0)
        return 0;               /* clean end of file */
    if (n != sizeof rh)
        return -1;              /* file cut in the middle of a header */

    uint32_t sec  = rd32(p, rh);
    uint32_t frac = rd32(p, rh + 4);
    uint32_t incl = rd32(p, rh + 8);
    uint32_t orig = rd32(p, rh + 12);

    if (incl > MAX_PACKET)
        return -1;              /* nonsense length: corrupt file */

    if (incl > p->bufcap) {
        uint8_t *nb = realloc(p->buf, incl);
        if (!nb)
            return -1;
        p->buf = nb;
        p->bufcap = incl;
    }
    if (incl && fread(p->buf, 1, incl, p->f) != incl)
        return -1;              /* file cut in the middle of a packet */

    pkt->ts_us   = (uint64_t)sec * 1000000u + (p->nsec ? frac / 1000u : frac);
    pkt->caplen  = incl;
    pkt->wirelen = orig < incl ? incl : orig;
    pkt->data    = p->buf;
    return 1;
}

void pcap_close(pcap_file_t *p)
{
    if (p->f)
        fclose(p->f);
    free(p->buf);
    memset(p, 0, sizeof *p);
}
