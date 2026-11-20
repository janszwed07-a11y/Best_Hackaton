#include "util.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void oom(void)
{
    fputs("pcapan: out of memory\n", stderr);
    exit(2);
}

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p)
        oom();
    return p;
}

void *xcalloc(size_t n, size_t size)
{
    void *p = calloc(n ? n : 1, size ? size : 1);
    if (!p)
        oom();
    return p;
}

void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q)
        oom();
    return q;
}

void fmt_addr(int ipver, const uint8_t *addr, char *buf, size_t n)
{
    int af = ipver == 6 ? AF_INET6 : AF_INET;
    if (!inet_ntop(af, addr, buf, (socklen_t)n))
        snprintf(buf, n, "?");
}

void fmt_bytes(double v, char *buf, size_t n)
{
    static const char *const unit[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    while (v >= 1024.0 && i < 4) {
        v /= 1024.0;
        i++;
    }
    if (i == 0)
        snprintf(buf, n, "%.0f B", v);
    else
        snprintf(buf, n, "%.1f %s", v, unit[i]);
}

void fmt_count(uint64_t v, char *buf, size_t n)
{
    char tmp[32];
    size_t len, o = 0;

    snprintf(tmp, sizeof tmp, "%llu", (unsigned long long)v);
    len = strlen(tmp);
    for (size_t i = 0; i < len && o + 1 < n; i++) {
        if (i > 0 && (len - i) % 3 == 0 && o + 2 < n)
            buf[o++] = ',';
        buf[o++] = tmp[i];
    }
    buf[o] = '\0';
}

void fmt_time(uint64_t us, char *buf, size_t n)
{
    time_t s = (time_t)(us / 1000000u);
    struct tm tm;
    if (!gmtime_r(&s, &tm) || !strftime(buf, n, "%Y-%m-%d %H:%M:%S UTC", &tm))
        snprintf(buf, n, "n/a");
}

void fmt_dur(double sec, char *buf, size_t n)
{
    if (sec < 1.0)
        snprintf(buf, n, "%.0f ms", sec * 1000.0);
    else if (sec < 60.0)
        snprintf(buf, n, "%.1f s", sec);
    else if (sec < 3600.0)
        snprintf(buf, n, "%dm%02ds", (int)sec / 60, (int)sec % 60);
    else
        snprintf(buf, n, "%dh%02dm", (int)sec / 3600, ((int)sec / 60) % 60);
}

const char *service_name(uint8_t proto, uint16_t port)
{
    static const struct {
        uint16_t port;
        uint8_t proto;        /* 0 = both TCP and UDP */
        const char *name;
    } tab[] = {
        {20, 6, "ftp-data"}, {21, 6, "ftp"},     {22, 6, "ssh"},
        {23, 6, "telnet"},   {25, 6, "smtp"},    {53, 0, "dns"},
        {67, 17, "dhcp"},    {68, 17, "dhcp"},   {80, 6, "http"},
        {110, 6, "pop3"},    {123, 17, "ntp"},   {143, 6, "imap"},
        {161, 17, "snmp"},   {443, 0, "https"},  {445, 6, "smb"},
        {465, 6, "smtps"},   {587, 6, "smtp"},   {993, 6, "imaps"},
        {1900, 17, "ssdp"},  {3306, 6, "mysql"}, {3389, 6, "rdp"},
        {5353, 17, "mdns"},  {5432, 6, "postgres"}, {6379, 6, "redis"},
        {8080, 6, "http-alt"}, {11211, 0, "memcached"},
    };
    for (size_t i = 0; i < sizeof tab / sizeof tab[0]; i++)
        if (tab[i].port == port && (tab[i].proto == 0 || tab[i].proto == proto))
            return tab[i].name;
    return NULL;
}
