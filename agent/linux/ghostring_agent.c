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

/* Expose POSIX extensions (gmtime_r, localtime_r) under -std=c99. */
#define _POSIX_C_SOURCE 200809L

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
 * IOCTL codes — must match loader/linux/ghostring_chardev.c
 * ------------------------------------------------------------------------- */

#define GR_IOC_MAGIC            'G'
#define GR_IOC_STATUS           _IOR(GR_IOC_MAGIC, 1, int)
#define GR_IOC_CPU_COUNT        _IOR(GR_IOC_MAGIC, 2, int)
#define GR_IOC_INTEGRITY_CHECK  _IO(GR_IOC_MAGIC, 3)

#define GR_DEVICE_PATH          "/dev/ghostring"

/* ---------------------------------------------------------------------------
 * Alert structure — must match gr_alert_t in the kernel module
 * ------------------------------------------------------------------------- */

struct gr_alert_wire {
    unsigned long long ts_ns;
    unsigned int       cpu_id;
    unsigned int       alert_type;
    unsigned long long info;
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
    int loaded = 0, cpus = 0;

    if (ioctl(fd, GR_IOC_STATUS, &loaded) < 0) {
        perror("ioctl GR_IOC_STATUS");
        return 1;
    }
    if (ioctl(fd, GR_IOC_CPU_COUNT, &cpus) < 0) {
        perror("ioctl GR_IOC_CPU_COUNT");
        return 1;
    }

    if (json_mode) {
        char ts[32], host[128];
        iso8601_now(ts, sizeof(ts));
        hostname_short(host, sizeof(host));
        printf("{\"ts\":\"%s\",\"host\":\"%s\",\"event\":\"status\","
               "\"loaded\":%s,\"online_cpus\":%d}\n",
               ts, host, loaded ? "true" : "false", cpus);
    } else {
        print_timestamp();
        printf("GhostRing Status\n");
        printf("  Loaded      : %s\n", loaded ? "YES" : "NO");
        printf("  Online CPUs : %d\n", cpus);
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
 * --monitor : continuous alert consumption via read()
 *
 * The kernel pushes struct gr_alert_wire records into a ring buffer;
 * read() returns one record per call (24 bytes) or blocks.
 * ------------------------------------------------------------------------- */

static const char *
alert_type_name(unsigned int t)
{
    switch (t) {
    case 0:  return "unknown";
    case 1:  return "msr_write";
    case 2:  return "ept_write_violation";
    case 3:  return "idt_hook";
    case 4:  return "ssdt_hook";
    case 5:  return "cr_write";
    case 6:  return "ransomware_canary";
    case 7:  return "rop_violation";
    case 8:  return "code_inject";
    case 9:  return "integrity_crc_mismatch";
    case 10: return "dkom_hidden_cr3";
    default: return "other";
    }
}

static int
cmd_monitor(int fd)
{
    struct gr_alert_wire a;
    ssize_t n;

    if (!json_mode) {
        print_timestamp();
        printf("Monitoring GhostRing alerts (Ctrl+C to stop)...\n");
    }

    for (;;) {
        n = read(fd, &a, sizeof(a));
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            perror("read");
            return 1;
        }
        if (n < (ssize_t)sizeof(a))
            continue;

        if (json_mode) {
            char ts[32], host[128];
            iso8601_now(ts, sizeof(ts));
            hostname_short(host, sizeof(host));
            printf("{\"ts\":\"%s\",\"host\":\"%s\",\"event\":\"alert\","
                   "\"cpu\":%u,\"type\":\"%s\",\"type_id\":%u,"
                   "\"info\":\"0x%llx\",\"kernel_ts_ns\":%llu}\n",
                   ts, host, a.cpu_id, alert_type_name(a.alert_type),
                   a.alert_type, a.info, a.ts_ns);
            fflush(stdout);
        } else {
            print_timestamp();
            printf("Alert: cpu=%u type=%s (%u) info=0x%llx kts=%llu\n",
                   a.cpu_id, alert_type_name(a.alert_type), a.alert_type,
                   a.info, a.ts_ns);
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
    printf("Usage: %s [--json] [--status|--integrity|--monitor]\n\n",
           argv0);
    printf("  --status      Query hypervisor status\n");
    printf("  --integrity   Trigger EPT integrity check\n");
    printf("  --monitor     Consume alert ring buffer (blocking read)\n");
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
    else if (strcmp(action, "--monitor") == 0)
        rc = cmd_monitor(fd);
    else {
        print_usage(argv[0]);
        rc = 1;
    }

    close(fd);
    return rc;
}
