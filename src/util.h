/* util.h - allocation and formatting helpers. */
#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>

void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t size);
void *xrealloc(void *p, size_t n);

void fmt_addr(int ipver, const uint8_t *addr, char *buf, size_t n);
void fmt_bytes(double v, char *buf, size_t n);     /* 1.5 MB */
void fmt_count(uint64_t v, char *buf, size_t n);   /* 1,234,567 */
void fmt_time(uint64_t us, char *buf, size_t n);   /* 2026-11-20 18:00:00 UTC */
void fmt_dur(double sec, char *buf, size_t n);     /* 250 ms, 4.2 s, 3m05s */
const char *service_name(uint8_t proto, uint16_t port);

#endif
