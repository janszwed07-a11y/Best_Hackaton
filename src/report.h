/* report.h - multi-page PDF report rendered with Cairo. */
#ifndef REPORT_H
#define REPORT_H

#include "analysis.h"

/* Returns 0 on success, -1 on failure. */
int report_write_pdf(const analysis_t *a, const char *path);

#endif
