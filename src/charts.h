/* charts.h - chart drawing with Cairo.
 *
 * Every chart draws into a cairo_t using a fixed logical canvas of
 * CHART_W x CHART_H units. The caller decides the target: a PNG image surface
 * (scaled up for sharpness) or a page of the PDF report (scaled down, and
 * still vector graphics). One drawing function, two outputs.
 */
#ifndef CHARTS_H
#define CHARTS_H

#include <cairo.h>

#include "analysis.h"

#define CHART_W 800.0
#define CHART_H 420.0

typedef void (*chart_fn)(cairo_t *cr, const analysis_t *a);

typedef struct {
    const char *file;      /* PNG file name */
    const char *title;
    const char *caption;   /* one sentence for the report */
    chart_fn    draw;
} chart_def_t;

extern const chart_def_t CHARTS[];
extern const size_t NCHARTS;

/* Writes every chart as <dir>/<file>. Returns the number of failures. */
int charts_write_png(const analysis_t *a, const char *dir);

#endif
