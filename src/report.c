#include "report.h"
#include "charts.h"
#include "util.h"

#include <cairo-pdf.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* A4 in PostScript points */
#define PAGE_W   595.0
#define PAGE_H   842.0
#define MARGIN   48.0
#define CONTENT_W (PAGE_W - 2 * MARGIN)
#define BOTTOM   (PAGE_H - 56.0)

#define FONT "DejaVu Sans"

#define C_TEXT   0x0b0b0b
#define C_TEXT2  0x52514e
#define C_MUTED  0x898781
#define C_RULE   0xe1e0d9

/* Status colours: reserved for severities, always shown with a label. */
#define C_CRITICAL 0xd03b3b
#define C_SERIOUS  0xec835a
#define C_WARNING  0xfab219
#define C_INFO     0xe1e0d9

typedef struct {
    cairo_t    *cr;
    double      y;        /* current vertical position */
    int         page;
    const char *file;     /* shown in the footer */
} doc_t;

static void rgb(cairo_t *cr, unsigned c)
{
    cairo_set_source_rgb(cr, ((c >> 16) & 0xff) / 255.0,
                         ((c >> 8) & 0xff) / 255.0, (c & 0xff) / 255.0);
}

static void font(cairo_t *cr, double size, int bold)
{
    cairo_select_font_face(cr, FONT, CAIRO_FONT_SLANT_NORMAL,
                           bold ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, size);
}

static double text_w(cairo_t *cr, const char *s)
{
    cairo_text_extents_t e;
    cairo_text_extents(cr, s, &e);
    return e.x_advance;
}

static void put(doc_t *d, double x, double y, const char *s, double size,
                unsigned color, int bold)
{
    font(d->cr, size, bold);
    rgb(d->cr, color);
    cairo_move_to(d->cr, x, y);
    cairo_show_text(d->cr, s);
}

static void footer(doc_t *d)
{
    char buf[512];
    snprintf(buf, sizeof buf, "pcapan report: %s", d->file);
    put(d, MARGIN, PAGE_H - 28, buf, 8, C_MUTED, 0);
    snprintf(buf, sizeof buf, "Page %d", d->page);
    font(d->cr, 8, 0);
    put(d, PAGE_W - MARGIN - text_w(d->cr, buf), PAGE_H - 28, buf, 8, C_MUTED, 0);
}

static void new_page(doc_t *d)
{
    footer(d);
    cairo_show_page(d->cr);
    d->page++;
    d->y = MARGIN;
}

/* Start a new page if the next block of height h does not fit. */
static void need(doc_t *d, double h)
{
    if (d->y + h > BOTTOM)
        new_page(d);
}

/* Word-wrapped paragraph. Returns nothing; advances d->y. */
static void para(doc_t *d, double x, double width, const char *s, double size,
                 unsigned color, int bold)
{
    char line[1024] = "", trial[1024];
    const char *p = s;
    double lh = size * 1.4;

    font(d->cr, size, bold);
    while (*p) {
        const char *sp = strchr(p, ' ');
        size_t wl = sp ? (size_t)(sp - p) : strlen(p);
        snprintf(trial, sizeof trial, "%s%s%.*s", line, *line ? " " : "",
                 (int)wl, p);
        if (*line && text_w(d->cr, trial) > width) {
            need(d, lh);
            put(d, x, d->y + size, line, size, color, bold);
            d->y += lh;
            snprintf(line, sizeof line, "%.*s", (int)wl, p);
        } else {
            snprintf(line, sizeof line, "%s", trial);
        }
        p += wl;
        while (*p == ' ')
            p++;
    }
    if (*line) {
        need(d, lh);
        put(d, x, d->y + size, line, size, color, bold);
        d->y += lh;
    }
}

static void heading(doc_t *d, const char *s)
{
    need(d, 60);
    d->y += 14;
    put(d, MARGIN, d->y + 15, s, 15, C_TEXT, 1);
    d->y += 22;
    rgb(d->cr, C_RULE);
    cairo_set_line_width(d->cr, 1);
    cairo_move_to(d->cr, MARGIN, d->y + 0.5);
    cairo_line_to(d->cr, PAGE_W - MARGIN, d->y + 0.5);
    cairo_stroke(d->cr);
    d->y += 12;
}

/* Two-column label/value row. */
static void kv(doc_t *d, const char *k, const char *v)
{
    need(d, 16);
    put(d, MARGIN, d->y + 10, k, 9.5, C_TEXT2, 0);
    put(d, MARGIN + 170, d->y + 10, v, 9.5, C_TEXT, 0);
    d->y += 16;
}

/* ---------- sections ------------------------------------------------------ */

static void title_block(doc_t *d, const analysis_t *a)
{
    char buf[512], now[64];
    fmt_time((uint64_t)time(NULL) * 1000000u, now, sizeof now);

    put(d, MARGIN, d->y + 24, "Network traffic analysis", 24, C_TEXT, 1);
    d->y += 38;
    snprintf(buf, sizeof buf, "Capture: %s", a->path);
    para(d, MARGIN, CONTENT_W, buf, 10, C_TEXT2, 0);
    snprintf(buf, sizeof buf, "Generated: %s", now);
    para(d, MARGIN, CONTENT_W, buf, 10, C_TEXT2, 0);
}

static const char *linktype_name(uint32_t t)
{
    switch (t) {
    case LINKTYPE_ETHERNET:   return "Ethernet";
    case LINKTYPE_LINUX_SLL:  return "Linux cooked capture (SLL)";
    case LINKTYPE_LINUX_SLL2: return "Linux cooked capture v2 (SLL2)";
    case LINKTYPE_RAW:        return "Raw IP";
    case LINKTYPE_NULL:       return "BSD loopback";
    default:                  return "Unsupported";
    }
}

static void summary(doc_t *d, const analysis_t *a)
{
    char b1[64], b2[64], b3[64], v[256];
    double dur = a->packets ? (double)(a->last_us - a->first_us) / 1e6 : 0;

    heading(d, "Capture summary");

    snprintf(v, sizeof v, "%s (%u)", linktype_name(a->linktype), a->linktype);
    kv(d, "Link type", v);
    if (a->packets) {
        fmt_time(a->first_us, b1, sizeof b1);
        kv(d, "First packet", b1);
        fmt_time(a->last_us, b1, sizeof b1);
        kv(d, "Last packet", b1);
    }
    fmt_dur(dur, b1, sizeof b1);
    kv(d, "Duration", b1);

    fmt_count(a->packets, b1, sizeof b1);
    fmt_bytes((double)a->bytes, b2, sizeof b2);
    snprintf(v, sizeof v, "%s packets, %s", b1, b2);
    kv(d, "Total traffic", v);

    if (dur > 0) {
        fmt_bytes((double)a->bytes / dur, b1, sizeof b1);
        snprintf(v, sizeof v, "%s/s (%.1f packets/s)", b1,
                 (double)a->packets / dur);
        kv(d, "Average rate", v);
    }
    if (a->packets) {
        snprintf(v, sizeof v, "%.0f bytes", (double)a->bytes / (double)a->packets);
        kv(d, "Average packet size", v);
    }

    fmt_count(a->tcp_pkts, b1, sizeof b1);
    fmt_count(a->udp_pkts, b2, sizeof b2);
    fmt_count(a->other_pkts, b3, sizeof b3);
    snprintf(v, sizeof v, "TCP %s, UDP %s, other %s", b1, b2, b3);
    kv(d, "Packets by protocol", v);

    fmt_count(a->ipv4_pkts, b1, sizeof b1);
    fmt_count(a->ipv6_pkts, b2, sizeof b2);
    snprintf(v, sizeof v, "IPv4 %s, IPv6 %s", b1, b2);
    kv(d, "Packets by IP version", v);

    snprintf(v, sizeof v, "%zu (TCP %u, UDP %u)", a->nflows, a->tcp_flows,
             a->udp_flows);
    kv(d, "Flows (5-tuples)", v);
    snprintf(v, sizeof v, "%zu", a->nhosts);
    kv(d, "Distinct hosts", v);

    snprintf(v, sizeof v, "%u completed, %u not completed", a->established,
             a->failed_handshakes);
    kv(d, "TCP handshakes", v);

    fmt_count(a->syn_pkts, b1, sizeof b1);
    fmt_count(a->rst_pkts, b2, sizeof b2);
    fmt_count(a->fin_pkts, b3, sizeof b3);
    snprintf(v, sizeof v, "SYN %s, RST %s, FIN %s", b1, b2, b3);
    kv(d, "TCP control packets", v);

    if (a->tcp_data_pkts) {
        fmt_count(a->retrans_pkts, b1, sizeof b1);
        snprintf(v, sizeof v, "%s (%.2f%% of data segments)", b1,
                 100.0 * (double)a->retrans_pkts / (double)a->tcp_data_pkts);
        kv(d, "TCP retransmissions", v);
    }
    if (a->malformed_pkts) {
        fmt_count(a->malformed_pkts, b1, sizeof b1);
        kv(d, "Malformed packets", b1);
    }
}

static void severity_tag(doc_t *d, double x, double y, severity_t s)
{
    static const unsigned bg[] = {C_CRITICAL, C_SERIOUS, C_WARNING, C_INFO};
    const char *label = severity_name(s);
    cairo_t *cr = d->cr;

    font(cr, 7.5, 1);
    double w = text_w(cr, label) + 12;
    rgb(cr, bg[s]);
    cairo_new_path(cr);
    cairo_arc(cr, x + 3, y + 3, 3, M_PI, 1.5 * M_PI);
    cairo_arc(cr, x + w - 3, y + 3, 3, 1.5 * M_PI, 2 * M_PI);
    cairo_arc(cr, x + w - 3, y + 11, 3, 0, 0.5 * M_PI);
    cairo_arc(cr, x + 3, y + 11, 3, 0.5 * M_PI, M_PI);
    cairo_close_path(cr);
    cairo_fill(cr);
    put(d, x + 6, y + 10.5, label, 7.5, s == SEV_HIGH ? 0xffffff : C_TEXT, 1);
}

static void findings(doc_t *d, const analysis_t *a)
{
    size_t count[4] = {0};
    char buf[256];

    heading(d, "Findings");
    for (size_t i = 0; i < a->nanom; i++)
        count[a->anom[i].sev]++;

    if (a->nanom == 0) {
        para(d, MARGIN, CONTENT_W, "No anomalies matched the detection rules.",
             10, C_TEXT, 0);
        return;
    }
    snprintf(buf, sizeof buf, "%zu finding(s): %zu high, %zu medium, %zu low, "
             "%zu informational.", a->nanom, count[SEV_HIGH], count[SEV_MEDIUM],
             count[SEV_LOW], count[SEV_INFO]);
    para(d, MARGIN, CONTENT_W, buf, 10, C_TEXT, 0);
    d->y += 6;

    for (size_t i = 0; i < a->nanom; i++) {
        const anomaly_t *x = &a->anom[i];
        need(d, 54);
        severity_tag(d, MARGIN, d->y, x->sev);
        put(d, MARGIN + 62, d->y + 10.5, x->title, 10.5, C_TEXT, 1);
        d->y += 18;
        if (x->first_us) {
            char t1[64], t2[64];
            fmt_time(x->first_us, t1, sizeof t1);
            fmt_dur((double)(x->last_us - x->first_us) / 1e6, t2, sizeof t2);
            snprintf(buf, sizeof buf, "From %s, lasting %s", t1, t2);
            para(d, MARGIN + 62, CONTENT_W - 62, buf, 8.5, C_MUTED, 0);
        }
        para(d, MARGIN + 62, CONTENT_W - 62, x->detail, 9.5, C_TEXT2, 0);
        d->y += 8;
    }
}

static void charts(doc_t *d, const analysis_t *a)
{
    double scale = CONTENT_W / CHART_W, h = CHART_H * scale;

    for (size_t i = 0; i < NCHARTS; i++) {
        if (i == 0)
            new_page(d);
        need(d, h + 44);
        cairo_save(d->cr);
        cairo_translate(d->cr, MARGIN, d->y);
        cairo_rectangle(d->cr, 0, 0, CONTENT_W, h);
        cairo_clip(d->cr);
        cairo_scale(d->cr, scale, scale);
        CHARTS[i].draw(d->cr, a);
        cairo_restore(d->cr);
        d->y += h + 6;
        para(d, MARGIN, CONTENT_W, CHARTS[i].caption, 8.5, C_MUTED, 0);
        d->y += 16;
    }
}

static void top_flows(doc_t *d, const analysis_t *a)
{
    static const double col[] = {0, 30, 158, 286, 334, 384};
    static const char *const hdr[] = {"Proto", "Client", "Server", "Packets",
                                      "Bytes", "Duration / state"};
    size_t n = a->nflows < 20 ? a->nflows : 20;

    new_page(d);
    heading(d, "Largest flows");
    if (n == 0) {
        para(d, MARGIN, CONTENT_W, "No TCP or UDP flows.", 10, C_TEXT, 0);
        return;
    }
    for (int c = 0; c < 6; c++)
        put(d, MARGIN + col[c], d->y + 9, hdr[c], 8, C_TEXT2, 1);
    d->y += 16;

    for (size_t i = 0; i < n; i++) {
        const flow_t *f = a->flows[i];
        char cli[96], srv[96], ad[64], pk[32], by[32], du[32], st[64];
        const char *state = "";

        fmt_addr(f->ipver, f->a, ad, sizeof ad);
        snprintf(cli, sizeof cli, "%.24s:%u", ad, f->pa);
        fmt_addr(f->ipver, f->b, ad, sizeof ad);
        snprintf(srv, sizeof srv, "%.24s:%u", ad, f->pb);
        fmt_count(f->pkts[0] + f->pkts[1], pk, sizeof pk);
        fmt_bytes((double)(f->bytes[0] + f->bytes[1]), by, sizeof by);
        fmt_dur((double)(f->last_us - f->first_us) / 1e6, du, sizeof du);
        if (f->proto == PROTO_TCP) {
            if (f->hs & HS_DONE)
                state = f->rst ? "reset" : f->fin ? "closed" : "open";
            else if (f->hs & HS_MIDSTREAM)
                state = "joined late";
            else
                state = "no handshake";
        }
        snprintf(st, sizeof st, "%s%s%s", du, *state ? ", " : "", state);

        need(d, 14);
        if (i % 2 == 0) {
            rgb(d->cr, 0xf3f2ee);
            cairo_rectangle(d->cr, MARGIN - 4, d->y - 1, CONTENT_W + 8, 14);
            cairo_fill(d->cr);
        }
        put(d, MARGIN + col[0], d->y + 9, f->proto == PROTO_TCP ? "TCP" : "UDP",
            8, C_TEXT, 0);
        put(d, MARGIN + col[1], d->y + 9, cli, 8, C_TEXT, 0);
        put(d, MARGIN + col[2], d->y + 9, srv, 8, C_TEXT, 0);
        put(d, MARGIN + col[3], d->y + 9, pk, 8, C_TEXT, 0);
        put(d, MARGIN + col[4], d->y + 9, by, 8, C_TEXT, 0);
        put(d, MARGIN + col[5], d->y + 9, st, 8, C_TEXT, 0);
        d->y += 14;
    }
}

int report_write_pdf(const analysis_t *a, const char *path)
{
    cairo_surface_t *s = cairo_pdf_surface_create(path, PAGE_W, PAGE_H);
    if (cairo_surface_status(s) != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(s);
        return -1;
    }
    cairo_pdf_surface_set_metadata(s, CAIRO_PDF_METADATA_TITLE,
                                   "Network traffic analysis");
    cairo_pdf_surface_set_metadata(s, CAIRO_PDF_METADATA_CREATOR, "pcapan");

    doc_t d = {cairo_create(s), MARGIN, 1, a->path};

    title_block(&d, a);
    summary(&d, a);
    findings(&d, a);
    charts(&d, a);
    top_flows(&d, a);
    footer(&d);

    cairo_destroy(d.cr);
    cairo_surface_finish(s);
    cairo_status_t st = cairo_surface_status(s);
    cairo_surface_destroy(s);
    return st == CAIRO_STATUS_SUCCESS ? 0 : -1;
}
