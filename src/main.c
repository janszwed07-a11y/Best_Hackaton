/* pcapan - TCP/UDP traffic analyser for .pcap files.
 *
 * Pipeline:  pcap.c (read) -> decode.c (parse headers)
 *            -> analysis.c (flows + statistics) -> anomaly.c (rules)
 *            -> charts.c (PNG) + report.c (PDF)
 */
#include "analysis.h"
#include "charts.h"
#include "pcap.h"
#include "report.h"
#include "util.h"

#include <cairo.h>
#include <errno.h>
#include <fontconfig/fontconfig.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define VERSION "1.0.0"

static void usage(FILE *out)
{
    fprintf(out,
            "Usage: pcapan [-o DIR] [-q] FILE.pcap\n"
            "\n"
            "Analyses TCP and UDP traffic in a pcap capture and writes:\n"
            "  DIR/report.pdf   full report (summary, findings, charts, flows)\n"
            "  DIR/*.png        one image per chart\n"
            "\n"
            "Options:\n"
            "  -o DIR   output directory (default: pcapan_out)\n"
            "  -q       quiet: do not print the summary to the terminal\n"
            "  -h       show this help\n"
            "  -V       show the version\n");
}

/* Like "mkdir -p": create every missing directory in the path. */
static int make_dir(const char *dir)
{
    char tmp[4096];
    struct stat st;

    if (snprintf(tmp, sizeof tmp, "%s", dir) >= (int)sizeof tmp) {
        fprintf(stderr, "pcapan: output path too long\n");
        return -1;
    }
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
            goto fail;
        *p = '/';
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        goto fail;
    if (stat(tmp, &st) == 0 && S_ISDIR(st.st_mode))
        return 0;
    errno = ENOTDIR;
fail:
    fprintf(stderr, "pcapan: cannot create directory %s: %s\n", dir,
            strerror(errno));
    return -1;
}

static void print_summary(const analysis_t *a, const char *dir)
{
    char b1[32], b2[32];
    fmt_count(a->packets, b1, sizeof b1);
    fmt_bytes((double)a->bytes, b2, sizeof b2);
    printf("%s: %s packets, %s, %zu flows, %zu hosts\n", a->path, b1, b2,
           a->nflows, a->nhosts);

    if (a->nanom == 0)
        printf("No anomalies found.\n");
    for (size_t i = 0; i < a->nanom; i++)
        printf("  [%-6s] %s: %s\n", severity_name(a->anom[i].sev),
               a->anom[i].title, a->anom[i].detail);
    printf("Report written to %s/report.pdf\n", dir);
}

int main(int argc, char **argv)
{
    const char *outdir = "pcapan_out";
    int quiet = 0, opt;

    while ((opt = getopt(argc, argv, "o:qhV")) != -1) {
        switch (opt) {
        case 'o': outdir = optarg; break;
        case 'q': quiet = 1; break;
        case 'h': usage(stdout); return 0;
        case 'V': printf("pcapan %s\n", VERSION); return 0;
        default:  usage(stderr); return 1;
        }
    }
    if (optind != argc - 1) {
        usage(stderr);
        return 1;
    }
    const char *path = argv[optind];

    pcap_file_t pf;
    char err[512];
    if (pcap_open(&pf, path, err, sizeof err) < 0) {
        fprintf(stderr, "pcapan: %s\n", err);
        return 1;
    }

    analysis_t a;
    analysis_init(&a, path, pf.linktype);

    packet_t pkt;
    int r;
    while ((r = pcap_next(&pf, &pkt)) == 1)
        analysis_add(&a, &pkt);
    if (r < 0) {
        a.truncated_file = 1;
        fprintf(stderr, "pcapan: warning: %s is truncated or corrupt after "
                "packet %llu; analysing what was read\n", path,
                (unsigned long long)a.packets);
    }
    pcap_close(&pf);

    analysis_finish(&a);

    int status = 0;
    if (make_dir(outdir) < 0) {
        status = 1;
    } else {
        char pdf[4096];
        if (charts_write_png(&a, outdir) > 0)
            status = 1;
        snprintf(pdf, sizeof pdf, "%s/report.pdf", outdir);
        if (report_write_pdf(&a, pdf) < 0) {
            fprintf(stderr, "pcapan: cannot write %s\n", pdf);
            status = 1;
        }
        if (!quiet && status == 0)
            print_summary(&a, outdir);
    }

    analysis_free(&a);

    /* Release Cairo's and fontconfig's global caches so leak checkers
     * (valgrind, ASan) only report problems in our own code. */
    cairo_debug_reset_static_data();
    FcFini();
    return status;
}
