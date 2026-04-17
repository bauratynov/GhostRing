/*
 * GhostRing Hypervisor — Linux User-Mode Agent
 *
 * Author: Baurzhan Atynov <bauratynov@gmail.com>
 * License: MIT
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
#include <errno.h>

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

    print_timestamp();
    printf("GhostRing Status\n");
    printf("  Loaded     : %s\n", info.loaded ? "YES" : "NO");
    printf("  Active CPUs: %u / %u\n", info.active_cpu_count,
           info.total_cpu_count);
    printf("  CPU Vendor : %s\n",
           (info.cpu_vendor == 1) ? "Intel" :
           (info.cpu_vendor == 2) ? "AMD" : "Unknown");

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
            print_timestamp();
            printf("Alert: %s\n", buf);
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
    printf("Usage: %s [--status|--integrity|--dkom|--monitor]\n\n", argv0);
    printf("  --status      Query hypervisor status\n");
    printf("  --integrity   Trigger EPT integrity check\n");
    printf("  --dkom        Trigger DKOM scan\n");
    printf("  --monitor     Poll for alerts (blocking read)\n");
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

    fd = open_ghostring();
    if (fd < 0)
        return 1;

    if (strcmp(argv[1], "--status") == 0)
        rc = cmd_status(fd);
    else if (strcmp(argv[1], "--integrity") == 0)
        rc = cmd_integrity(fd);
    else if (strcmp(argv[1], "--dkom") == 0)
        rc = cmd_dkom(fd);
    else if (strcmp(argv[1], "--monitor") == 0)
        rc = cmd_monitor(fd);
    else {
        print_usage(argv[0]);
        rc = 1;
    }

    close(fd);
    return rc;
}
