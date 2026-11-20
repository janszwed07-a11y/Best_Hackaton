#include "analysis.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

#define INITIAL_BUCKETS 4096

/* ---------- flow table ---------------------------------------------------- */

/* FNV-1a. We hash the two endpoints in a fixed order (smaller first), so
 * A->B and B->A packets land in the same bucket. */
static uint32_t fnv(uint32_t h, const void *data, size_t n)
{
    const uint8_t *p = data;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static int ep_cmp(const uint8_t *a1, uint16_t p1, const uint8_t *a2, uint16_t p2)
{
    int c = memcmp(a1, a2, 16);
    if (c)
        return c;
    return (int)p1 - (int)p2;
}

static uint32_t flow_hash(const decoded_t *d)
{
    uint32_t h = 2166136261u;
    h = fnv(h, &d->proto, 1);
    if (ep_cmp(d->src, d->sport, d->dst, d->dport) < 0) {
        h = fnv(h, d->src, 16); h = fnv(h, &d->sport, 2);
        h = fnv(h, d->dst, 16); h = fnv(h, &d->dport, 2);
    } else {
        h = fnv(h, d->dst, 16); h = fnv(h, &d->dport, 2);
        h = fnv(h, d->src, 16); h = fnv(h, &d->sport, 2);
    }
    return h;
}

static void grow_table(analysis_t *a)
{
    size_t nb = a->nbuckets * 2;
    flow_t **nt = xcalloc(nb, sizeof *nt);
    for (size_t i = 0; i < a->nbuckets; i++) {
        flow_t *f = a->buckets[i];
        while (f) {
            flow_t *next = f->next;
            size_t j = f->hash & (nb - 1);
            f->next = nt[j];
            nt[j] = f;
            f = next;
        }
    }
    free(a->buckets);
    a->buckets = nt;
    a->nbuckets = nb;
}

/* Find the flow for this packet (creating it if needed) and report which
 * direction the packet travels: 0 = a->b, 1 = b->a. */
static flow_t *flow_lookup(analysis_t *a, const decoded_t *d, int *dir)
{
    uint32_t h = flow_hash(d);
    flow_t *f;

    for (f = a->buckets[h & (a->nbuckets - 1)]; f; f = f->next) {
        if (f->hash != h || f->proto != d->proto || f->ipver != d->ipver)
            continue;
        if (f->pa == d->sport && f->pb == d->dport &&
            !memcmp(f->a, d->src, 16) && !memcmp(f->b, d->dst, 16)) {
            *dir = 0;
            return f;
        }
        if (f->pa == d->dport && f->pb == d->sport &&
            !memcmp(f->a, d->dst, 16) && !memcmp(f->b, d->src, 16)) {
            *dir = 1;
            return f;
        }
    }

    if (a->nflows >= a->nbuckets)
        grow_table(a);

    f = xcalloc(1, sizeof *f);
    f->hash  = h;
    f->ipver = (uint8_t)d->ipver;
    f->proto = d->proto;
    memcpy(f->a, d->src, 16);
    memcpy(f->b, d->dst, 16);
    f->pa = d->sport;
    f->pb = d->dport;

    size_t i = h & (a->nbuckets - 1);
    f->next = a->buckets[i];
    a->buckets[i] = f;
    a->nflows++;
    *dir = 0;
    return f;
}

/* ---------- per-packet updates ------------------------------------------- */

static void update_tcp(analysis_t *a, flow_t *f, int dir, const decoded_t *d)
{
    int syn = d->flags & TH_SYN, ack = d->flags & TH_ACK;

    /* First packet of the flow is not a SYN: we joined mid-conversation. */
    if (f->pkts[0] + f->pkts[1] == 1 && !syn)
        f->hs |= HS_MIDSTREAM;

    /* Handshake tracking: SYN (a->b), SYN-ACK (b->a), ACK (a->b). */
    if (syn && !ack) {
        a->syn_pkts++;
        if (dir == 0) {
            f->hs |= HS_SYN;
            f->syn++;
        }
    } else if (syn && ack) {
        a->synack_pkts++;
        if (dir == 1 && (f->hs & HS_SYN))
            f->hs |= HS_SYNACK;
    } else if (ack && !syn && dir == 0 && (f->hs & HS_SYNACK)) {
        f->hs |= HS_DONE;
    }

    if (d->flags & TH_RST) {
        f->rst++;
        a->rst_pkts++;
    }
    if (d->flags & TH_FIN) {
        f->fin++;
        a->fin_pkts++;
    }
    if (d->window == 0 && !(d->flags & (TH_RST | TH_SYN)))
        f->zero_win++;

    /* Retransmission: a data segment that ends at or before data we have
     * already seen in this direction. Serial-number arithmetic (the int32_t
     * cast) handles sequence-number wrap-around. */
    if (d->payload_len > 0) {
        uint32_t end = d->seq + d->payload_len;
        a->tcp_data_pkts++;
        if (f->seq_valid[dir] && (int32_t)(end - f->seq_end[dir]) <= 0) {
            f->retrans++;
            a->retrans_pkts++;
        } else {
            f->seq_end[dir] = end;
            f->seq_valid[dir] = 1;
        }
    }
}

static second_t *second_for(analysis_t *a, uint64_t ts)
{
    size_t idx = ts > a->first_us ? (size_t)((ts - a->first_us) / 1000000u) : 0;
    if (idx >= MAX_SECONDS)
        idx = MAX_SECONDS - 1;
    if (idx >= a->sec_cap) {
        size_t nc = a->sec_cap ? a->sec_cap : 64;
        while (nc <= idx)
            nc *= 2;
        a->sec = xrealloc(a->sec, nc * sizeof *a->sec);
        memset(a->sec + a->sec_cap, 0, (nc - a->sec_cap) * sizeof *a->sec);
        a->sec_cap = nc;
    }
    if (idx >= a->nsec)
        a->nsec = idx + 1;
    return &a->sec[idx];
}

void analysis_init(analysis_t *a, const char *path, uint32_t linktype)
{
    memset(a, 0, sizeof *a);
    a->path = path;
    a->linktype = linktype;
    a->nbuckets = INITIAL_BUCKETS;
    a->buckets = xcalloc(a->nbuckets, sizeof *a->buckets);
}

void analysis_add(analysis_t *a, const packet_t *pkt)
{
    decoded_t d;
    dec_status_t st = decode_packet(a->linktype, pkt->data, pkt->caplen, &d);
    uint64_t len = pkt->wirelen;

    if (a->packets == 0 || pkt->ts_us < a->first_us)
        a->first_us = pkt->ts_us;
    if (pkt->ts_us > a->last_us)
        a->last_us = pkt->ts_us;
    a->packets++;
    a->bytes += len;

    size_t bin = len / 100;
    a->size_hist[bin < SIZE_BINS ? bin : SIZE_BINS - 1]++;

    second_t *s = second_for(a, pkt->ts_us);
    s->pkts++;

    if (d.ipver == 4)
        a->ipv4_pkts++;
    else if (d.ipver == 6)
        a->ipv6_pkts++;

    if (st == DEC_MALFORMED) {
        a->malformed_pkts++;
        a->other_bytes += len;
        return;
    }
    if (st == DEC_OTHER) {
        a->other_pkts++;
        a->other_bytes += len;
        return;
    }

    int dir;
    flow_t *f = flow_lookup(a, &d, &dir);
    if (f->pkts[0] + f->pkts[1] == 0)
        f->first_us = pkt->ts_us;
    if (pkt->ts_us > f->last_us)
        f->last_us = pkt->ts_us;
    f->pkts[dir]++;
    f->bytes[dir] += len;
    f->payload[dir] += d.payload_len;

    if (d.proto == PROTO_TCP) {
        a->tcp_pkts++;
        a->tcp_bytes += len;
        s->tcp_bytes += len;
        if ((d.flags & (TH_SYN | TH_ACK)) == TH_SYN)
            s->syn++;
        else if ((d.flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
            s->synack++;
        update_tcp(a, f, dir, &d);
    } else {
        a->udp_pkts++;
        a->udp_bytes += len;
        s->udp_bytes += len;
    }
}

/* ---------- aggregation after the last packet --------------------------- */

uint16_t flow_service_port(const flow_t *f)
{
    if (f->hs & HS_SYN)
        return f->pb;               /* the side that received the SYN */
    return f->pa < f->pb ? f->pa : f->pb;  /* otherwise: lower port wins */
}

static int cmp_flow_bytes(const void *x, const void *y)
{
    const flow_t *a = *(flow_t *const *)x, *b = *(flow_t *const *)y;
    uint64_t ta = a->bytes[0] + a->bytes[1], tb = b->bytes[0] + b->bytes[1];
    return ta < tb ? 1 : ta > tb ? -1 : 0;
}

static int cmp_host_addr(const void *x, const void *y)
{
    const host_stat_t *a = x, *b = y;
    if (a->ipver != b->ipver)
        return a->ipver - b->ipver;
    return memcmp(a->addr, b->addr, 16);
}

static int cmp_host_bytes(const void *x, const void *y)
{
    const host_stat_t *a = x, *b = y;
    uint64_t ta = a->bytes_out + a->bytes_in, tb = b->bytes_out + b->bytes_in;
    return ta < tb ? 1 : ta > tb ? -1 : 0;
}

static int cmp_port_key(const void *x, const void *y)
{
    const port_stat_t *a = x, *b = y;
    if (a->proto != b->proto)
        return a->proto - b->proto;
    return (int)a->port - (int)b->port;
}

static int cmp_port_bytes(const void *x, const void *y)
{
    const port_stat_t *a = x, *b = y;
    return a->bytes < b->bytes ? 1 : a->bytes > b->bytes ? -1 : 0;
}

/* Hosts: emit one record per flow endpoint, sort by address, then merge
 * neighbours. Sorting is simpler than a second hash table and fast enough. */
static void aggregate_hosts(analysis_t *a)
{
    host_stat_t *h = xcalloc(a->nflows * 2, sizeof *h);
    size_t n = 0;

    for (size_t i = 0; i < a->nflows; i++) {
        const flow_t *f = a->flows[i];
        h[n].ipver = f->ipver;
        memcpy(h[n].addr, f->a, 16);
        h[n].bytes_out = f->bytes[0];
        h[n].bytes_in  = f->bytes[1];
        h[n].pkts      = f->pkts[0] + f->pkts[1];
        h[n].flows     = 1;
        n++;
        h[n].ipver = f->ipver;
        memcpy(h[n].addr, f->b, 16);
        h[n].bytes_out = f->bytes[1];
        h[n].bytes_in  = f->bytes[0];
        h[n].pkts      = f->pkts[0] + f->pkts[1];
        h[n].flows     = 1;
        n++;
    }
    qsort(h, n, sizeof *h, cmp_host_addr);

    size_t out = 0;
    for (size_t i = 0; i < n; i++) {
        if (out > 0 && cmp_host_addr(&h[out - 1], &h[i]) == 0) {
            h[out - 1].bytes_out += h[i].bytes_out;
            h[out - 1].bytes_in  += h[i].bytes_in;
            h[out - 1].pkts      += h[i].pkts;
            h[out - 1].flows     += h[i].flows;
        } else {
            h[out++] = h[i];
        }
    }
    qsort(h, out, sizeof *h, cmp_host_bytes);
    a->hosts = h;
    a->nhosts = out;
}

static void aggregate_ports(analysis_t *a)
{
    port_stat_t *p = xcalloc(a->nflows, sizeof *p);
    size_t n = 0, out = 0;

    for (size_t i = 0; i < a->nflows; i++) {
        const flow_t *f = a->flows[i];
        p[n].proto = f->proto;
        p[n].port  = flow_service_port(f);
        p[n].bytes = f->bytes[0] + f->bytes[1];
        p[n].flows = 1;
        n++;
    }
    qsort(p, n, sizeof *p, cmp_port_key);
    for (size_t i = 0; i < n; i++) {
        if (out > 0 && cmp_port_key(&p[out - 1], &p[i]) == 0) {
            p[out - 1].bytes += p[i].bytes;
            p[out - 1].flows += p[i].flows;
        } else {
            p[out++] = p[i];
        }
    }
    qsort(p, out, sizeof *p, cmp_port_bytes);
    a->ports = p;
    a->nports = out;
}

void analysis_finish(analysis_t *a)
{
    size_t n = 0;

    a->flows = xcalloc(a->nflows, sizeof *a->flows);
    for (size_t i = 0; i < a->nbuckets; i++)
        for (flow_t *f = a->buckets[i]; f; f = f->next)
            a->flows[n++] = f;
    qsort(a->flows, n, sizeof *a->flows, cmp_flow_bytes);

    for (size_t i = 0; i < n; i++) {
        const flow_t *f = a->flows[i];
        if (f->proto == PROTO_UDP) {
            a->udp_flows++;
            continue;
        }
        a->tcp_flows++;
        if (f->hs & HS_DONE)
            a->established++;
        else if (f->hs & HS_SYN)
            a->failed_handshakes++;
    }

    aggregate_hosts(a);
    aggregate_ports(a);
    detect_anomalies(a);
}

void analysis_free(analysis_t *a)
{
    for (size_t i = 0; i < a->nbuckets; i++) {
        flow_t *f = a->buckets[i];
        while (f) {
            flow_t *next = f->next;
            free(f);
            f = next;
        }
    }
    free(a->buckets);
    free(a->flows);
    free(a->hosts);
    free(a->ports);
    free(a->sec);
    free(a->anom);
    memset(a, 0, sizeof *a);
}
