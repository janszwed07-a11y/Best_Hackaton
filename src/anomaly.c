/* anomaly.c - heuristics that flag suspicious or unhealthy traffic.
 *
 * Every rule is a simple threshold that can be explained in one sentence.
 * That is deliberate: a reviewer (or an analyst reading the report) should be
 * able to see *why* something was flagged and decide whether it matters.
 */
#include "analysis.h"
#include "util.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Thresholds */
#define SCAN_MIN_PORTS     15    /* one source -> one target, distinct ports */
#define SWEEP_MIN_HOSTS    15    /* one source -> one port, distinct targets */
#define FLOOD_MIN_HALFOPEN 100   /* unanswered handshakes to one service */
#define RETRANS_GLOBAL_PCT 3.0   /* % of TCP data segments retransmitted */
#define RETRANS_FLOW_MIN   10
#define ZERO_WIN_MIN       3
#define UDP_FANOUT_HOSTS   50
#define AMP_RATIO          10.0  /* response bytes / request bytes */
#define AMP_MIN_BYTES      (100 * 1024)
#define SPIKE_FACTOR       10.0  /* x median bytes per second */
#define SPIKE_MIN_SECONDS  30    /* need this much timeline to judge spikes */
#define MAX_LISTED         3

const char *severity_name(severity_t s)
{
    switch (s) {
    case SEV_HIGH:   return "HIGH";
    case SEV_MEDIUM: return "MEDIUM";
    case SEV_LOW:    return "LOW";
    default:         return "INFO";
    }
}

void add_anomaly(analysis_t *a, severity_t sev, uint64_t first_us,
                 uint64_t last_us, const char *title, const char *fmt, ...)
{
    va_list ap;
    if (a->nanom == a->anom_cap) {
        a->anom_cap = a->anom_cap ? a->anom_cap * 2 : 16;
        a->anom = xrealloc(a->anom, a->anom_cap * sizeof *a->anom);
    }
    anomaly_t *x = &a->anom[a->nanom++];
    x->sev = sev;
    x->first_us = first_us;
    x->last_us = last_us;
    snprintf(x->title, sizeof x->title, "%s", title);
    va_start(ap, fmt);
    vsnprintf(x->detail, sizeof x->detail, fmt, ap);
    va_end(ap);
}

/* ---------- helpers ------------------------------------------------------- */

static int addr_cmp(const flow_t *x, const uint8_t *ax, const flow_t *y,
                    const uint8_t *ay)
{
    if (x->ipver != y->ipver)
        return x->ipver - y->ipver;
    return memcmp(ax, ay, 16);
}

/* Sort keys used to group flows. */
static int cmp_src_dst_port(const void *p, const void *q)
{
    const flow_t *x = *(flow_t *const *)p, *y = *(flow_t *const *)q;
    int c = addr_cmp(x, x->a, y, y->a);
    if (!c) c = addr_cmp(x, x->b, y, y->b);
    if (!c) c = (int)x->pb - (int)y->pb;
    return c;
}

static int cmp_src_port_dst(const void *p, const void *q)
{
    const flow_t *x = *(flow_t *const *)p, *y = *(flow_t *const *)q;
    int c = addr_cmp(x, x->a, y, y->a);
    if (!c) c = (int)x->pb - (int)y->pb;
    if (!c) c = addr_cmp(x, x->b, y, y->b);
    return c;
}

static int cmp_dst_port_src(const void *p, const void *q)
{
    const flow_t *x = *(flow_t *const *)p, *y = *(flow_t *const *)q;
    int c = addr_cmp(x, x->b, y, y->b);
    if (!c) c = (int)x->pb - (int)y->pb;
    if (!c) c = addr_cmp(x, x->a, y, y->a);
    return c;
}

static void span(const flow_t *f, uint64_t *first, uint64_t *last)
{
    if (*first == 0 || f->first_us < *first)
        *first = f->first_us;
    if (f->last_us > *last)
        *last = f->last_us;
}

static void flow_label(const flow_t *f, char *buf, size_t n)
{
    char sa[64], sb[64];
    fmt_addr(f->ipver, f->a, sa, sizeof sa);
    fmt_addr(f->ipver, f->b, sb, sizeof sb);
    snprintf(buf, n, "%s:%u -> %s:%u", sa, f->pa, sb, f->pb);
}

/* ---------- TCP handshake based rules ------------------------------------ */

/* Collect TCP flows where the client sent a SYN but never completed the
 * handshake: the raw material for scan and flood detection. */
static flow_t **failed_handshakes(const analysis_t *a, size_t *n)
{
    flow_t **v = xcalloc(a->nflows, sizeof *v);
    *n = 0;
    for (size_t i = 0; i < a->nflows; i++) {
        flow_t *f = a->flows[i];
        if (f->proto == PROTO_TCP && (f->hs & HS_SYN) && !(f->hs & HS_DONE))
            v[(*n)++] = f;
    }
    return v;
}

/* Vertical port scan: one source probes many ports on one target. */
static void detect_port_scans(analysis_t *a, flow_t **v, size_t n)
{
    qsort(v, n, sizeof *v, cmp_src_dst_port);
    for (size_t i = 0; i < n;) {
        size_t j = i, ports = 0, open = 0;
        char open_list[96] = "";
        uint64_t first = 0, last = 0;

        while (j < n && !addr_cmp(v[i], v[i]->a, v[j], v[j]->a) &&
               !addr_cmp(v[i], v[i]->b, v[j], v[j]->b)) {
            /* Flows are sorted by port: handle one run of equal ports. */
            size_t k = j;
            int answered = 0;
            while (k < n && v[k]->pb == v[j]->pb &&
                   !addr_cmp(v[j], v[j]->a, v[k], v[k]->a) &&
                   !addr_cmp(v[j], v[j]->b, v[k], v[k]->b)) {
                answered |= (v[k]->hs & HS_SYNACK) != 0;
                span(v[k], &first, &last);
                k++;
            }
            ports++;
            if (answered) {
                size_t l = strlen(open_list);
                if (open < 8)
                    snprintf(open_list + l, sizeof open_list - l, "%s%u",
                             open ? ", " : "", v[j]->pb);
                open++;
            }
            j = k;
        }
        if (ports >= SCAN_MIN_PORTS) {
            char src[64], dst[64];
            fmt_addr(v[i]->ipver, v[i]->a, src, sizeof src);
            fmt_addr(v[i]->ipver, v[i]->b, dst, sizeof dst);
            add_anomaly(a, SEV_HIGH, first, last, "TCP port scan",
                        "%s probed %zu different TCP ports on %s without "
                        "completing a connection. %zu port(s) answered as "
                        "open%s%s%s.", src, ports, dst, open,
                        open ? " (" : "", open_list, open ? ")" : "");
        }
        i = j;
    }
}

/* Horizontal sweep: one source tries the same port on many hosts. */
static void detect_sweeps(analysis_t *a, flow_t **v, size_t n)
{
    qsort(v, n, sizeof *v, cmp_src_port_dst);
    for (size_t i = 0; i < n;) {
        size_t j = i, hosts = 0;
        uint64_t first = 0, last = 0;
        while (j < n && !addr_cmp(v[i], v[i]->a, v[j], v[j]->a) &&
               v[j]->pb == v[i]->pb) {
            if (j == i || addr_cmp(v[j], v[j]->b, v[j - 1], v[j - 1]->b))
                hosts++;
            span(v[j], &first, &last);
            j++;
        }
        if (hosts >= SWEEP_MIN_HOSTS) {
            char src[64];
            fmt_addr(v[i]->ipver, v[i]->a, src, sizeof src);
            add_anomaly(a, SEV_HIGH, first, last, "Host sweep",
                        "%s tried TCP port %u on %zu different hosts without "
                        "completing a connection, which is typical of "
                        "network reconnaissance.", src, v[i]->pb, hosts);
        }
        i = j;
    }
}

/* SYN flood: very many half-open connections to a single service. */
static void detect_syn_floods(analysis_t *a, flow_t **v, size_t n)
{
    uint32_t peak = 0;
    for (size_t s = 0; s < a->nsec; s++)
        if (a->sec[s].syn > peak)
            peak = a->sec[s].syn;

    qsort(v, n, sizeof *v, cmp_dst_port_src);
    for (size_t i = 0; i < n;) {
        size_t j = i, sources = 0;
        uint64_t first = 0, last = 0;
        while (j < n && !addr_cmp(v[i], v[i]->b, v[j], v[j]->b) &&
               v[j]->pb == v[i]->pb) {
            if (j == i || addr_cmp(v[j], v[j]->a, v[j - 1], v[j - 1]->a))
                sources++;
            span(v[j], &first, &last);
            j++;
        }
        if (j - i >= FLOOD_MIN_HALFOPEN) {
            char dst[64];
            fmt_addr(v[i]->ipver, v[i]->b, dst, sizeof dst);
            add_anomaly(a, SEV_HIGH, first, last, "Possible SYN flood",
                        "%zu connection attempts to %s:%u never completed "
                        "the handshake. They came from %zu distinct source "
                        "address(es)%s. Peak rate: %u SYN/s.",
                        j - i, dst, v[i]->pb, sources,
                        sources > 50 ? ", which suggests spoofed addresses"
                                     : "", peak);
        }
        i = j;
    }
}

static void detect_retransmissions(analysis_t *a)
{
    if (a->tcp_data_pkts >= 100) {
        double pct = 100.0 * (double)a->retrans_pkts / (double)a->tcp_data_pkts;
        if (pct >= RETRANS_GLOBAL_PCT)
            add_anomaly(a, SEV_MEDIUM, 0, 0, "High TCP retransmission rate",
                        "%.1f%% of TCP data segments were retransmissions "
                        "(normal is well under 1%%). This points to packet "
                        "loss or congestion on the path.", pct);
    }

    /* Worst individual flows. a->flows is sorted by size, so collect the
     * qualifying ones and keep the ones with the most retransmissions. */
    const flow_t *worst[MAX_LISTED] = {0};
    size_t count = 0;
    for (size_t i = 0; i < a->nflows; i++) {
        const flow_t *f = a->flows[i];
        uint64_t pk = f->pkts[0] + f->pkts[1];
        if (f->proto != PROTO_TCP || f->retrans < RETRANS_FLOW_MIN ||
            f->retrans * 10 < pk)        /* at least 10% of packets */
            continue;
        count++;
        for (size_t k = 0; k < MAX_LISTED; k++) {
            if (!worst[k] || f->retrans > worst[k]->retrans) {
                memmove(&worst[k + 1], &worst[k],
                        (MAX_LISTED - k - 1) * sizeof *worst);
                worst[k] = f;
                break;
            }
        }
    }
    if (count) {
        char list[640] = "", lbl[192];
        for (size_t k = 0; k < MAX_LISTED && worst[k]; k++) {
            size_t l = strlen(list);
            flow_label(worst[k], lbl, sizeof lbl);
            snprintf(list + l, sizeof list - l, "%s%s (%u retransmissions)",
                     k ? "; " : "", lbl, worst[k]->retrans);
        }
        add_anomaly(a, SEV_MEDIUM, 0, 0, "Connections with heavy retransmission",
                    "%zu connection(s) retransmitted 10%% or more of their "
                    "packets. Worst: %s.", count, list);
    }
}

static void detect_zero_window(analysis_t *a)
{
    size_t count = 0;
    char list[640] = "", lbl[192];
    for (size_t i = 0; i < a->nflows; i++) {
        const flow_t *f = a->flows[i];
        if (f->proto != PROTO_TCP || f->zero_win < ZERO_WIN_MIN)
            continue;
        if (count < MAX_LISTED) {
            size_t l = strlen(list);
            flow_label(f, lbl, sizeof lbl);
            snprintf(list + l, sizeof list - l, "%s%s (%u times)",
                     count ? "; " : "", lbl, f->zero_win);
        }
        count++;
    }
    if (count)
        add_anomaly(a, SEV_LOW, 0, 0, "TCP zero-window events",
                    "In %zu connection(s) a receiver advertised a zero "
                    "window, meaning it could not keep up and the sender "
                    "had to stop. Examples: %s.", count, list);
}

static void detect_aborted(analysis_t *a)
{
    size_t aborted = 0;
    for (size_t i = 0; i < a->nflows; i++) {
        const flow_t *f = a->flows[i];
        if (f->proto == PROTO_TCP && (f->hs & HS_DONE) && f->rst && !f->fin)
            aborted++;
    }
    if (aborted >= 10 && aborted * 5 > a->established)
        add_anomaly(a, SEV_LOW, 0, 0, "Many connections reset",
                    "%zu of %u established TCP connections ended with a "
                    "reset (RST) instead of a normal close (FIN). This can "
                    "mean crashing applications, timeouts or a firewall "
                    "killing sessions.", aborted, a->established);
}

/* ---------- UDP rules ------------------------------------------------------ */

static void detect_udp_fanout(analysis_t *a)
{
    flow_t **v = xcalloc(a->nflows, sizeof *v);
    size_t n = 0;
    for (size_t i = 0; i < a->nflows; i++)
        if (a->flows[i]->proto == PROTO_UDP)
            v[n++] = a->flows[i];
    qsort(v, n, sizeof *v, cmp_src_dst_port);

    for (size_t i = 0; i < n;) {
        size_t j = i, hosts = 0;
        uint64_t first = 0, last = 0;
        while (j < n && !addr_cmp(v[i], v[i]->a, v[j], v[j]->a)) {
            if (j == i || addr_cmp(v[j], v[j]->b, v[j - 1], v[j - 1]->b))
                hosts++;
            span(v[j], &first, &last);
            j++;
        }
        if (hosts >= UDP_FANOUT_HOSTS) {
            char src[64];
            fmt_addr(v[i]->ipver, v[i]->a, src, sizeof src);
            add_anomaly(a, SEV_MEDIUM, first, last, "UDP fan-out",
                        "%s sent UDP traffic to %zu different hosts. This "
                        "can be a UDP scan, worm-like spreading or a "
                        "misbehaving service.", src, hosts);
        }
        i = j;
    }
    free(v);
}

static int amplification_port(uint16_t p)
{
    return p == 19 || p == 53 || p == 123 || p == 161 || p == 389 ||
           p == 1900 || p == 11211;
}

/* Reflection/amplification: a UDP service answers with far more data than
 * it was asked for (typical for spoofed DNS/NTP/memcached attacks). */
static void detect_amplification(analysis_t *a)
{
    size_t count = 0;
    uint64_t total = 0, first = 0, last = 0;
    const flow_t *top = NULL;

    for (size_t i = 0; i < a->nflows; i++) {
        const flow_t *f = a->flows[i];
        if (f->proto != PROTO_UDP)
            continue;
        int server_is_a;
        if (amplification_port(f->pa))
            server_is_a = 1;
        else if (amplification_port(f->pb))
            server_is_a = 0;
        else
            continue;
        uint64_t resp = server_is_a ? f->bytes[0] : f->bytes[1];
        uint64_t req  = server_is_a ? f->bytes[1] : f->bytes[0];
        if (resp < AMP_MIN_BYTES || (double)resp < AMP_RATIO * (double)req)
            continue;
        count++;
        total += resp;
        span(f, &first, &last);
        if (!top)
            top = f;   /* flows are sorted by size: first match is largest */
    }
    if (count) {
        char tb[32], lbl[192];
        fmt_bytes((double)total, tb, sizeof tb);
        flow_label(top, lbl, sizeof lbl);
        add_anomaly(a, SEV_HIGH, first, last, "Possible UDP amplification",
                    "%zu UDP flow(s) on DNS/NTP/SNMP/SSDP/memcached ports "
                    "returned at least %.0fx more data than was requested "
                    "(%s in total). Largest: %s.", count, AMP_RATIO, tb, lbl);
    }
}

/* ---------- volume and hygiene rules ------------------------------------- */

static int cmp_u64(const void *p, const void *q)
{
    uint64_t x = *(const uint64_t *)p, y = *(const uint64_t *)q;
    return x < y ? -1 : x > y;
}

static void detect_spikes(analysis_t *a)
{
    if (a->nsec < SPIKE_MIN_SECONDS)
        return;

    uint64_t *v = xmalloc(a->nsec * sizeof *v);
    double mean = 0, var = 0;
    for (size_t i = 0; i < a->nsec; i++) {
        v[i] = a->sec[i].tcp_bytes + a->sec[i].udp_bytes;
        mean += (double)v[i];
    }
    mean /= (double)a->nsec;
    for (size_t i = 0; i < a->nsec; i++)
        var += ((double)v[i] - mean) * ((double)v[i] - mean);
    double sd = sqrt(var / (double)a->nsec);
    qsort(v, a->nsec, sizeof *v, cmp_u64);
    double median = (double)v[a->nsec / 2];
    free(v);

    double limit = fmax(SPIKE_FACTOR * fmax(median, 1000.0), mean + 4 * sd);
    int reported = 0;
    for (size_t i = 0; i < a->nsec && reported < MAX_LISTED; i++) {
        double b = (double)(a->sec[i].tcp_bytes + a->sec[i].udp_bytes);
        if (b <= limit)
            continue;
        size_t j = i;                     /* merge consecutive seconds */
        double peak = b;
        while (j + 1 < a->nsec &&
               (double)(a->sec[j + 1].tcp_bytes + a->sec[j + 1].udp_bytes) > limit) {
            j++;
            peak = fmax(peak, (double)(a->sec[j].tcp_bytes + a->sec[j].udp_bytes));
        }
        char pb[32], mb[32];
        fmt_bytes(peak, pb, sizeof pb);
        fmt_bytes(median, mb, sizeof mb);
        add_anomaly(a, SEV_LOW, a->first_us + i * 1000000u,
                    a->first_us + (j + 1) * 1000000u, "Traffic spike",
                    "Traffic peaked at %s/s for %zu second(s), against a "
                    "typical (median) rate of %s/s.", pb, j - i + 1, mb);
        reported++;
        i = j;
    }
}

/* Only count real sessions (handshake completed, or joined mid-stream with
 * data), so a port scan touching port 23 is not reported as Telnet use. */
static void detect_plaintext(analysis_t *a)
{
    static const struct { uint16_t port; const char *name; } risky[] = {
        {21, "FTP"}, {23, "Telnet"}, {110, "POP3"}, {143, "IMAP"},
    };
    for (size_t r = 0; r < sizeof risky / sizeof risky[0]; r++) {
        size_t n = 0;
        for (size_t i = 0; i < a->nflows; i++) {
            const flow_t *f = a->flows[i];
            if (f->proto != PROTO_TCP || flow_service_port(f) != risky[r].port)
                continue;
            if ((f->hs & HS_DONE) ||
                ((f->hs & HS_MIDSTREAM) && f->payload[0] + f->payload[1] > 0))
                n++;
        }
        if (n)
            add_anomaly(a, SEV_INFO, 0, 0, "Unencrypted login protocol",
                        "%zu %s session(s) on TCP port %u. %s sends "
                        "credentials in clear text.", n, risky[r].name,
                        risky[r].port, risky[r].name);
    }
}

static void detect_capture_problems(analysis_t *a)
{
    if (a->malformed_pkts)
        add_anomaly(a, SEV_INFO, 0, 0, "Malformed packets",
                    "%llu packet(s) had truncated or inconsistent headers "
                    "and were skipped.",
                    (unsigned long long)a->malformed_pkts);
    if (a->truncated_file)
        add_anomaly(a, SEV_INFO, 0, 0, "Truncated capture file",
                    "The file ended in the middle of a packet. Everything "
                    "before that point was analysed.");
}

/* Stable sort by severity (small n, so insertion sort is fine). */
static void sort_by_severity(analysis_t *a)
{
    for (size_t i = 1; i < a->nanom; i++) {
        anomaly_t tmp = a->anom[i];
        size_t j = i;
        while (j > 0 && a->anom[j - 1].sev > tmp.sev) {
            a->anom[j] = a->anom[j - 1];
            j--;
        }
        a->anom[j] = tmp;
    }
}

void detect_anomalies(analysis_t *a)
{
    size_t n;
    flow_t **failed = failed_handshakes(a, &n);
    detect_port_scans(a, failed, n);
    detect_sweeps(a, failed, n);
    detect_syn_floods(a, failed, n);
    free(failed);

    detect_retransmissions(a);
    detect_zero_window(a);
    detect_aborted(a);
    detect_udp_fanout(a);
    detect_amplification(a);
    detect_spikes(a);
    detect_plaintext(a);
    detect_capture_problems(a);
    sort_by_severity(a);
}
