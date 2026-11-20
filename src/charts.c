#include "charts.h"
#include "util.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Palette: light surface, muted axes, two categorical series colours. */
#define C_SURFACE   0xfcfcfb
#define C_TEXT      0x0b0b0b
#define C_TEXT2     0x52514e
#define C_MUTED     0x898781
#define C_GRID      0xe1e0d9
#define C_SERIES1   0x2a78d6   /* blue */
#define C_SERIES2   0xeb6834   /* orange */

#define FONT "DejaVu Sans"

/* Plot area for x/y charts */
#define PL 84.0
#define PR (CHART_W - 24.0)
#define PT 112.0
#define PB (CHART_H - 52.0)

#define MAX_BARS 10

/* ---------- drawing primitives ------------------------------------------- */

static void rgb(cairo_t *cr, unsigned c)
{
    cairo_set_source_rgb(cr, ((c >> 16) & 0xff) / 255.0,
                         ((c >> 8) & 0xff) / 255.0, (c & 0xff) / 255.0);
}

enum { LEFT, CENTER, RIGHT };

static void text(cairo_t *cr, double x, double y, const char *s, double size,
                 unsigned color, int align, int bold)
{
    cairo_text_extents_t e;
    cairo_select_font_face(cr, FONT, CAIRO_FONT_SLANT_NORMAL,
                           bold ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, size);
    cairo_text_extents(cr, s, &e);
    if (align == CENTER)
        x -= e.x_advance / 2;
    else if (align == RIGHT)
        x -= e.x_advance;
    rgb(cr, color);
    cairo_move_to(cr, x, y);
    cairo_show_text(cr, s);
}

static void header(cairo_t *cr, const char *title, const char *subtitle)
{
    rgb(cr, C_SURFACE);
    cairo_rectangle(cr, 0, 0, CHART_W, CHART_H);
    cairo_fill(cr);
    text(cr, 24, 38, title, 19, C_TEXT, LEFT, 1);
    if (subtitle)
        text(cr, 24, 62, subtitle, 13, C_TEXT2, LEFT, 0);
}

static void no_data(cairo_t *cr)
{
    text(cr, CHART_W / 2, CHART_H / 2, "No data in this capture", 14,
         C_MUTED, CENTER, 0);
}

/* Bar with rounded corners on the end away from the baseline. */
static void bar_v(cairo_t *cr, double x, double w, double y0, double y1)
{
    double h = y0 - y1, r = fmin(4.0, fmin(w / 2, h));
    if (h <= 0)
        return;
    cairo_new_path(cr);
    cairo_move_to(cr, x, y0);
    cairo_line_to(cr, x, y1 + r);
    cairo_arc(cr, x + r, y1 + r, r, M_PI, 1.5 * M_PI);
    cairo_arc(cr, x + w - r, y1 + r, r, 1.5 * M_PI, 2 * M_PI);
    cairo_line_to(cr, x + w, y0);
    cairo_close_path(cr);
    cairo_fill(cr);
}

static void bar_h(cairo_t *cr, double x0, double x1, double y, double h)
{
    double w = x1 - x0, r = fmin(4.0, fmin(h / 2, w));
    if (w <= 0)
        return;
    cairo_new_path(cr);
    cairo_move_to(cr, x0, y);
    cairo_line_to(cr, x1 - r, y);
    cairo_arc(cr, x1 - r, y + r, r, -0.5 * M_PI, 0);
    cairo_arc(cr, x1 - r, y + h - r, r, 0, 0.5 * M_PI);
    cairo_line_to(cr, x0, y + h);
    cairo_close_path(cr);
    cairo_fill(cr);
}

/* Round the axis maximum up to 1, 2 or 5 x 10^n so ticks are readable. */
static double nice_step(double max, int ticks)
{
    double raw = max / ticks, mag = pow(10, floor(log10(raw))), n = raw / mag;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * mag;
}

static void fmt_si(double v, const char *unit, char *buf, size_t n)
{
    const char *p = "";
    if (v >= 1e9)      { v /= 1e9; p = "G"; }
    else if (v >= 1e6) { v /= 1e6; p = "M"; }
    else if (v >= 1e3) { v /= 1e3; p = "k"; }
    snprintf(buf, n, "%g%s%s%s", round(v * 10) / 10, *unit == 'B' ? " " : "",
             p, unit);
}

/* Horizontal grid lines and y labels; returns the axis maximum. */
static double y_axis(cairo_t *cr, double max, const char *unit)
{
    if (max <= 0)
        max = 1;
    double step = nice_step(max, 4), top = ceil(max / step) * step;
    char lbl[32];

    cairo_set_line_width(cr, 1);
    for (double v = 0; v <= top + step / 2; v += step) {
        double y = PB - (PB - PT) * v / top;
        rgb(cr, v == 0 ? C_MUTED : C_GRID);
        cairo_move_to(cr, PL, round(y) + 0.5);
        cairo_line_to(cr, PR, round(y) + 0.5);
        cairo_stroke(cr);
        fmt_si(v, unit, lbl, sizeof lbl);
        text(cr, PL - 10, y + 4, lbl, 11, C_MUTED, RIGHT, 0);
    }
    return top;
}

static void legend(cairo_t *cr, int n, const char *const *names,
                   const unsigned *colors)
{
    double x = PR;
    cairo_text_extents_t e;
    cairo_set_font_size(cr, 12);
    for (int i = n - 1; i >= 0; i--) {
        cairo_text_extents(cr, names[i], &e);
        x -= e.x_advance;
        text(cr, x, 90, names[i], 12, C_TEXT2, LEFT, 0);
        rgb(cr, colors[i]);
        cairo_set_line_width(cr, 3);
        cairo_move_to(cr, x - 22, 86);
        cairo_line_to(cr, x - 6, 86);
        cairo_stroke(cr);
        x -= 40;
    }
}

/* ---------- reusable chart types ----------------------------------------- */

/* Line chart over the capture timeline. vals[s][i] holds series s at
 * timeline point i; points are bin_sec seconds apart. */
static void line_chart(cairo_t *cr, const analysis_t *a, int ns,
                       double *const *vals, size_t n, double bin_sec,
                       const char *unit, const char *const *names,
                       const unsigned *colors)
{
    double max = 0;
    for (int s = 0; s < ns; s++)
        for (size_t i = 0; i < n; i++)
            max = fmax(max, vals[s][i]);
    double top = y_axis(cr, max, unit);

    /* x labels: five evenly spaced times since the start */
    double span = (double)n * bin_sec;
    for (int t = 0; t <= 4; t++) {
        char lbl[32];
        fmt_dur(span * t / 4, lbl, sizeof lbl);
        if (t == 0)
            snprintf(lbl, sizeof lbl, "0 s");
        text(cr, PL + (PR - PL) * t / 4, PB + 20, lbl, 11, C_MUTED,
             t == 0 ? LEFT : t == 4 ? RIGHT : CENTER, 0);
    }
    text(cr, (PL + PR) / 2, PB + 40, "time since first packet", 11, C_MUTED,
         CENTER, 0);

    cairo_set_line_width(cr, 2);
    cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
    for (int s = 0; s < ns; s++) {
        rgb(cr, colors[s]);
        for (size_t i = 0; i < n; i++) {
            double x = n > 1 ? PL + (PR - PL) * (double)i / (double)(n - 1)
                             : (PL + PR) / 2;
            double y = PB - (PB - PT) * vals[s][i] / top;
            if (i == 0)
                cairo_move_to(cr, x, y);
            else
                cairo_line_to(cr, x, y);
        }
        if (n == 1)
            cairo_rel_line_to(cr, 1, 0);
        cairo_stroke(cr);
    }
    legend(cr, ns, names, colors);
    (void)a;
}

/* Vertical bars with a category label under each one. */
static void column_chart(cairo_t *cr, size_t n, const double *v,
                         const char *const *labels, const char *unit,
                         const char *xtitle)
{
    double max = 0;
    for (size_t i = 0; i < n; i++)
        max = fmax(max, v[i]);
    if (max <= 0) {
        no_data(cr);
        return;
    }
    double top = y_axis(cr, max, unit);
    double slot = (PR - PL) / (double)n, w = slot - fmax(2.0, slot * 0.25);

    for (size_t i = 0; i < n; i++) {
        double x = PL + slot * (double)i + (slot - w) / 2;
        rgb(cr, C_SERIES1);
        bar_v(cr, x, w, PB, PB - (PB - PT) * v[i] / top);
        text(cr, x + w / 2, PB + 18, labels[i], 10.5, C_MUTED, CENTER, 0);
    }
    text(cr, (PL + PR) / 2, PB + 40, xtitle, 11, C_MUTED, CENTER, 0);
}

/* Horizontal ranked bars: label on the left, value text after the bar. */
static void ranked_bars(cairo_t *cr, size_t n, const double *v,
                        char labels[][64], char values[][48])
{
    const double lx = 220, rx = CHART_W - 150, top = 92, bottom = CHART_H - 20;
    if (n == 0 || v[0] <= 0) {
        no_data(cr);
        return;
    }
    double row = (bottom - top) / MAX_BARS, h = fmin(22, row - 6);

    for (size_t i = 0; i < n; i++) {
        double y = top + row * (double)i;
        double x1 = lx + (rx - lx) * v[i] / v[0];
        text(cr, lx - 12, y + h / 2 + 4, labels[i], 12, C_TEXT, RIGHT, 0);
        rgb(cr, C_SERIES1);
        bar_h(cr, lx, fmax(x1, lx + 2), y, h);
        text(cr, fmax(x1, lx + 2) + 8, y + h / 2 + 4, values[i], 11.5,
             C_TEXT2, LEFT, 0);
    }
    rgb(cr, C_MUTED);
    cairo_set_line_width(cr, 1);
    cairo_move_to(cr, lx + 0.5, top - 4);
    cairo_line_to(cr, lx + 0.5, top + row * (double)n - 2);
    cairo_stroke(cr);
}

/* ---------- the charts ---------------------------------------------------- */

/* Rebin the per-second timeline to at most max_pts points. */
static size_t timeline_bins(const analysis_t *a, size_t max_pts, size_t *per)
{
    *per = (a->nsec + max_pts - 1) / max_pts;
    if (*per < 1)
        *per = 1;
    return (a->nsec + *per - 1) / *per;
}

static void draw_traffic(cairo_t *cr, const analysis_t *a)
{
    header(cr, "Traffic over time", "Throughput per protocol (bytes per second)");
    if (a->nsec == 0) {
        no_data(cr);
        return;
    }
    size_t per, n = timeline_bins(a, 300, &per);
    double *tcp = xcalloc(n, sizeof *tcp), *udp = xcalloc(n, sizeof *udp);
    for (size_t i = 0; i < a->nsec; i++) {
        tcp[i / per] += (double)a->sec[i].tcp_bytes / (double)per;
        udp[i / per] += (double)a->sec[i].udp_bytes / (double)per;
    }
    double *vals[] = {tcp, udp};
    const char *names[] = {"TCP", "UDP"};
    const unsigned colors[] = {C_SERIES1, C_SERIES2};
    line_chart(cr, a, 2, vals, n, (double)per, "B/s", names, colors);
    free(tcp);
    free(udp);
}

static void draw_handshakes(cairo_t *cr, const analysis_t *a)
{
    header(cr, "TCP connection attempts",
           "SYN vs SYN-ACK per second: a widening gap means unanswered attempts");
    if (a->nsec == 0 || a->tcp_pkts == 0) {
        no_data(cr);
        return;
    }
    size_t per, n = timeline_bins(a, 300, &per);
    double *syn = xcalloc(n, sizeof *syn), *ack = xcalloc(n, sizeof *ack);
    for (size_t i = 0; i < a->nsec; i++) {
        syn[i / per] += (double)a->sec[i].syn / (double)per;
        ack[i / per] += (double)a->sec[i].synack / (double)per;
    }
    double *vals[] = {syn, ack};
    const char *names[] = {"SYN (attempts)", "SYN-ACK (accepted)"};
    const unsigned colors[] = {C_SERIES1, C_SERIES2};
    line_chart(cr, a, 2, vals, n, (double)per, "/s", names, colors);
    free(syn);
    free(ack);
}

static void draw_protocols(cairo_t *cr, const analysis_t *a)
{
    header(cr, "Protocol mix", "Share of captured bytes");
    static const char *const names[3] = {"TCP", "UDP", "Other / non-IP"};
    double v[3] = {(double)a->tcp_bytes, (double)a->udp_bytes,
                   (double)a->other_bytes};
    int order[3] = {0, 1, 2};
    double sorted[MAX_BARS];
    char labels[MAX_BARS][64], values[MAX_BARS][48];

    /* Rank largest first (3 items: a tiny bubble sort is enough). */
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 2 - i; j++)
            if (v[order[j]] < v[order[j + 1]]) {
                int t = order[j];
                order[j] = order[j + 1];
                order[j + 1] = t;
            }
    for (int i = 0; i < 3; i++) {
        int k = order[i];
        char bb[32];
        sorted[i] = v[k];
        fmt_bytes(v[k], bb, sizeof bb);
        snprintf(labels[i], sizeof labels[i], "%s", names[k]);
        snprintf(values[i], sizeof values[i], "%.1f%%  (%s)",
                 a->bytes ? 100.0 * v[k] / (double)a->bytes : 0.0, bb);
    }
    ranked_bars(cr, 3, sorted, labels, values);
}

static void draw_hosts(cairo_t *cr, const analysis_t *a)
{
    header(cr, "Top talkers", "Hosts by total bytes sent and received");
    size_t n = a->nhosts < MAX_BARS ? a->nhosts : MAX_BARS;
    double v[MAX_BARS];
    char labels[MAX_BARS][64], values[MAX_BARS][48];
    for (size_t i = 0; i < n; i++) {
        const host_stat_t *h = &a->hosts[i];
        v[i] = (double)(h->bytes_out + h->bytes_in);
        fmt_addr(h->ipver, h->addr, labels[i], sizeof labels[i]);
        if (strlen(labels[i]) > 26)                /* long IPv6 addresses */
            strcpy(labels[i] + 23, "...");
        fmt_bytes(v[i], values[i], sizeof values[i]);
    }
    ranked_bars(cr, n, v, labels, values);
}

static void draw_ports(cairo_t *cr, const analysis_t *a)
{
    header(cr, "Top services", "Server ports by total bytes");
    size_t n = a->nports < MAX_BARS ? a->nports : MAX_BARS;
    double v[MAX_BARS];
    char labels[MAX_BARS][64], values[MAX_BARS][48];
    for (size_t i = 0; i < n; i++) {
        const port_stat_t *p = &a->ports[i];
        const char *name = service_name(p->proto, p->port);
        char bb[32];
        v[i] = (double)p->bytes;
        snprintf(labels[i], sizeof labels[i], "%u/%s%s%s%s", p->port,
                 p->proto == PROTO_TCP ? "tcp" : "udp", name ? " (" : "",
                 name ? name : "", name ? ")" : "");
        fmt_bytes(v[i], bb, sizeof bb);
        snprintf(values[i], sizeof values[i], "%s, %u flow%s", bb, p->flows,
                 p->flows == 1 ? "" : "s");
    }
    ranked_bars(cr, n, v, labels, values);
}

static void draw_sizes(cairo_t *cr, const analysis_t *a)
{
    header(cr, "Packet sizes", "Number of packets by size on the wire");
    double v[SIZE_BINS];
    char buf[SIZE_BINS][12];
    const char *labels[SIZE_BINS];
    for (int i = 0; i < SIZE_BINS; i++) {
        v[i] = (double)a->size_hist[i];
        snprintf(buf[i], sizeof buf[i], i == SIZE_BINS - 1 ? "%d+" : "%d",
                 i * 100);
        labels[i] = buf[i];
    }
    column_chart(cr, SIZE_BINS, v, labels, "",
                 "packet size in bytes (bins of 100)");
}

static void draw_durations(cairo_t *cr, const analysis_t *a)
{
    static const double edge[] = {0.01, 0.1, 1, 10, 60, 600};
    static const char *const labels[] = {"< 10 ms", "10-100 ms", "0.1-1 s",
                                         "1-10 s", "10-60 s", "1-10 min",
                                         "> 10 min"};
    double v[7] = {0};
    header(cr, "Connection durations", "Number of flows (TCP and UDP) by lifetime");
    for (size_t i = 0; i < a->nflows; i++) {
        const flow_t *f = a->flows[i];
        double d = (double)(f->last_us - f->first_us) / 1e6;
        int b = 0;
        while (b < 6 && d >= edge[b])
            b++;
        v[b]++;
    }
    column_chart(cr, 7, v, labels, "", "flow duration");
}

const chart_def_t CHARTS[] = {
    {"traffic_over_time.png", "Traffic over time",
     "Bytes per second for TCP and UDP across the capture.", draw_traffic},
    {"tcp_handshakes.png", "TCP connection attempts",
     "New connection attempts (SYN) against accepted ones (SYN-ACK). Scans "
     "and SYN floods appear as SYN bursts with no matching SYN-ACKs.",
     draw_handshakes},
    {"protocol_mix.png", "Protocol mix",
     "How the captured bytes split between TCP, UDP and everything else.",
     draw_protocols},
    {"top_talkers.png", "Top talkers",
     "The hosts that moved the most data.", draw_hosts},
    {"top_services.png", "Top services",
     "Services identified by server port, ranked by bytes.", draw_ports},
    {"packet_sizes.png", "Packet sizes",
     "Small packets are mostly ACKs and control traffic; full-size "
     "packets (about 1500 bytes) are bulk transfers.", draw_sizes},
    {"flow_durations.png", "Connection durations",
     "Very short flows dominate during scans; long flows are sessions and "
     "transfers.", draw_durations},
};
const size_t NCHARTS = sizeof CHARTS / sizeof CHARTS[0];

int charts_write_png(const analysis_t *a, const char *dir)
{
    const double scale = 2.0;          /* 1600 x 840 pixels: sharp on HiDPI */
    int failures = 0;

    for (size_t i = 0; i < NCHARTS; i++) {
        char path[4096];
        cairo_surface_t *s = cairo_image_surface_create(
            CAIRO_FORMAT_ARGB32, (int)(CHART_W * scale), (int)(CHART_H * scale));
        cairo_t *cr = cairo_create(s);
        cairo_scale(cr, scale, scale);
        CHARTS[i].draw(cr, a);
        cairo_destroy(cr);

        snprintf(path, sizeof path, "%s/%s", dir, CHARTS[i].file);
        if (cairo_surface_write_to_png(s, path) != CAIRO_STATUS_SUCCESS) {
            fprintf(stderr, "pcapan: cannot write %s\n", path);
            failures++;
        }
        cairo_surface_destroy(s);
    }
    return failures;
}
