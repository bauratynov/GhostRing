/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * GhostRing Hypervisor — Linux User-Mode Agent
 *
 * Author: Baurzhan Atynov <bauratynov@gmail.com>
 *
 * Console application that communicates with the GhostRing kernel module
 * via /dev/ghostring.  Supports status queries, integrity checks, DKOM
 * scans, and continuous alert monitoring.
 *
 * Usage: ghostring-agent [--status|--integrity|--dkom|--monitor]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <errno.h>

/* ---------------------------------------------------------------------------
 * Output mode — toggled by --json on the command line.  Text output is for
 * interactive use; JSON is for SIEM / log shippers (syslog-ng, filebeat).
 * ------------------------------------------------------------------------- */

static int json_mode = 0;

static void
iso8601_now(char *out, size_t n)
{
    time_t      t;
    struct tm   utc;
    time(&t);
    gmtime_r(&t, &utc);
    strftime(out, n, "%Y-%m-%dT%H:%M:%SZ", &utc);
}

static void
hostname_short(char *out, size_t n)
{
    struct utsname u;
    if (uname(&u) == 0)
        snprintf(out, n, "%s", u.nodename);
    else
        snprintf(out, n, "unknown");
}

/* ---------------------------------------------------------------------------
 * IOCTL codes — must match ghostring_chardev.h in the kernel module
 * ------------------------------------------------------------------------- */

#define GR_IOC_MAGIC            'G'
#define GR_IOC_STATUS           _IOR(GR_IOC_MAGIC, 0, struct gr_status_info)
#define GR_IOC_INTEGRITY_CHECK  _IO(GR_IOC_MAGIC, 1)
#define GR_IOC_DKOM_SCAN        _IO(GR_IOC_MAGIC, 2)

#define GR_DEVICE_PATH          "/dev/ghostring"

/* ---------------------------------------------------------------------------
 * Status structure — must match kernel module
 * ------------------------------------------------------------------------- */

struct gr_status_info {
    unsigned int active_cpu_count;
    unsigned int total_cpu_count;
    unsigned int cpu_vendor;      /* 1 = Intel, 2 = AMD */
    unsigned int loaded;
};

/* ---------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

static void
print_timestamp(void)
{
    time_t      now;
    struct tm   local;

    time(&now);
    localtime_r(&now, &local);
    printf("[%04d-%02d-%02d %02d:%02d:%02d] ",
           local.tm_year + 1900, local.tm_mon + 1, local.tm_mday,
           local.tm_hour, local.tm_min, local.tm_sec);
}

static int
open_ghostring(void)
{
    int fd = open(GR_DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Error: cannot open %s: %s\n",
                GR_DEVICE_PATH, strerror(errno));
        fprintf(stderr, "Is the GhostRing kernel module loaded?\n");
    }
    return fd;
}

/* ---------------------------------------------------------------------------
 * --status : query hypervisor status
 * ------------------------------------------------------------------------- */

static int
cmd_status(int fd)
{
    struct gr_status_info info;

    if (ioctl(fd, GR_IOC_STATUS, &info) < 0) {
        perror("ioctl GR_IOC_STATUS");
        return 1;
    }

    if (json_mode) {
        char ts[32], host[128];
        iso8601_now(ts, sizeof(ts));
        hostname_short(host, sizeof(host));
        const char *vendor = (info.cpu_vendor == 1) ? "intel"
                          : (info.cpu_vendor == 2) ? "amd"
                          : "unknown";
        printf("{\"ts\":\"%s\",\"host\":\"%s\",\"event\":\"status\","
               "\"loaded\":%s,\"active_cpus\":%u,\"total_cpus\":%u,"
               "\"cpu_vendor\":\"%s\"}\n",
               ts, host, info.loaded ? "true" : "false",
               info.active_cpu_count, info.total_cpu_count, vendor);
    } else {
        print_timestamp();
        printf("GhostRing Status\n");
        printf("  Loaded     : %s\n", info.loaded ? "YES" : "NO");
        printf("  Active CPUs: %u / %u\n", info.active_cpu_count,
               info.total_cpu_count);
        printf("  CPU Vendor : %s\n",
               (info.cpu_vendor == 1) ? "Intel" :
               (info.cpu_vendor == 2) ? "AMD" : "Unknown");
    }

    return 0;
}

/* ---------------------------------------------------------------------------
 * --integrity : trigger integrity check
 * ------------------------------------------------------------------------- */

static int
cmd_integrity(int fd)
{
    if (ioctl(fd, GR_IOC_INTEGRITY_CHECK) < 0) {
        perror("ioctl GR_IOC_INTEGRITY_CHECK");
        return 1;
    }

    print_timestamp();
    printf("Integrity check requested successfully.\n");
    return 0;
}

/* ---------------------------------------------------------------------------
 * --dkom : trigger DKOM scan
 * ------------------------------------------------------------------------- */

static int
cmd_dkom(int fd)
{
    if (ioctl(fd, GR_IOC_DKOM_SCAN) < 0) {
        perror("ioctl GR_IOC_DKOM_SCAN");
        return 1;
    }

    print_timestamp();
    printf("DKOM scan requested successfully.\n");
    return 0;
}

/* ---------------------------------------------------------------------------
 * --monitor : continuous alert polling via read()
 * ------------------------------------------------------------------------- */

static int
cmd_monitor(int fd)
{
    char    buf[512];
    ssize_t n;

    print_timestamp();
    printf("Monitoring GhostRing alerts (Ctrl+C to stop)...\n");

    for (;;) {
        n = read(fd, buf, sizeof(buf) - 1);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            perror("read");
            return 1;
        }

        if (n > 0) {
            buf[n] = '\0';
            /* Strip trailing newline if any — SIEM JSON expects one per line. */
            char *nl = strchr(buf, '\n');
            if (nl) *nl = '\0';

            if (json_mode) {
                char ts[32], host[128];
                iso8601_now(ts, sizeof(ts));
                hostname_short(host, sizeof(host));
                /* Minimal JSON-escape of the payload (just quotes + backslash). */
                printf("{\"ts\":\"%s\",\"host\":\"%s\",\"event\":\"alert\","
                       "\"raw\":\"", ts, host);
                for (char *p = buf; *p; p++) {
                    if (*p == '"' || *p == '\\') putchar('\\');
                    if (*p >= 0x20) putchar(*p);
                }
                printf("\"}\n");
                fflush(stdout);
            } else {
                print_timestamp();
                printf("Alert: %s\n", buf);
            }
        }
    }

    return 0;
}

/* ---------------------------------------------------------------------------
 * Usage
 * ------------------------------------------------------------------------- */

static void
print_usage(const char *argv0)
{
    printf("GhostRing Agent — Linux\n");
    printf("Usage: %s [--json] [--status|--integrity|--dkom|--monitor]\n\n",
           argv0);
    printf("  --status      Query hypervisor status\n");
    printf("  --integrity   Trigger EPT integrity check\n");
    printf("  --dkom        Trigger DKOM scan\n");
    printf("  --monitor     Poll for alerts (blocking read)\n");
    printf("  --json        Emit structured JSON (for SIEM / syslog)\n");
}

/* ---------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */

int
main(int argc, char *argv[])
{
    int fd, rc = 0;

    if (argc < 2) {
        print_usage(argv[0]);
        return 0;
    }

    /* Parse --json anywhere in argv, remove it. */
    const char *action = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0)
            json_mode = 1;
        else if (!action)
            action = argv[i];
    }
    if (!action) {
        print_usage(argv[0]);
        return 0;
    }

    fd = open_ghostring();
    if (fd < 0)
        return 1;

    if (strcmp(action, "--status") == 0)
        rc = cmd_status(fd);
    else if (strcmp(action, "--integrity") == 0)
        rc = cmd_integrity(fd);
    else if (strcmp(action, "--dkom") == 0)
        rc = cmd_dkom(fd);
    else if (strcmp(action, "--monitor") == 0)
        rc = cmd_monitor(fd);
    else {
        print_usage(argv[0]);
        rc = 1;
    }

    close(fd);
    return rc;
}
