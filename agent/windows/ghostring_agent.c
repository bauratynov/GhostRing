/*++

GhostRing Hypervisor — Windows User-Mode Agent

Author:

    Baurzhan Atynov <bauratynov@gmail.com>

License:

    MIT

Module:

    ghostring_agent.c

Abstract:

    Console application that communicates with the GhostRing kernel driver
    via DeviceIoControl on \\.\GhostRing.  Supports status queries,
    integrity checks, DKOM scans, and continuous alert monitoring.

Usage:

    ghostring-agent.exe [--status|--integrity|--dkom|--monitor]

Environment:

    User mode, Windows x64.

--*/

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ---------------------------------------------------------------------------
 * IOCTL codes — must match ghostring_win.h
 * ------------------------------------------------------------------------- */

#define GR_IOCTL_TYPE               0x8000

#define IOCTL_GR_STATUS             CTL_CODE(GR_IOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GR_INTEGRITY_CHECK    CTL_CODE(GR_IOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GR_DKOM_SCAN          CTL_CODE(GR_IOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define GR_DEVICE_PATH              "\\\\.\\GhostRing"

/* ---------------------------------------------------------------------------
 * Status structure — must match kernel driver
 * ------------------------------------------------------------------------- */

typedef struct _GR_STATUS_INFO {
    ULONG   ActiveCpuCount;
    ULONG   TotalCpuCount;
    ULONG   CpuVendor;
    BOOL    Loaded;
} GR_STATUS_INFO;

/* ---------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

static void
PrintTimestamp(void)
{
    time_t      now;
    struct tm   local;

    time(&now);
    localtime_s(&local, &now);
    printf("[%04d-%02d-%02d %02d:%02d:%02d] ",
           local.tm_year + 1900, local.tm_mon + 1, local.tm_mday,
           local.tm_hour, local.tm_min, local.tm_sec);
}

static HANDLE
OpenGhostRing(void)
{
    HANDLE hDevice;

    hDevice = CreateFileA(GR_DEVICE_PATH,
                          GENERIC_READ | GENERIC_WRITE,
                          0,
                          NULL,
                          OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL,
                          NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "Error: cannot open %s (0x%08lX)\n",
                GR_DEVICE_PATH, GetLastError());
        fprintf(stderr, "Is the GhostRing driver loaded?\n");
    }
    return hDevice;
}

/* ---------------------------------------------------------------------------
 * --status : query hypervisor status
 * ------------------------------------------------------------------------- */

static int
CmdStatus(HANDLE hDevice)
{
    GR_STATUS_INFO  info;
    DWORD           bytesReturned;

    if (!DeviceIoControl(hDevice,
                         IOCTL_GR_STATUS,
                         NULL, 0,
                         &info, sizeof(info),
                         &bytesReturned,
                         NULL))
    {
        fprintf(stderr, "IOCTL_GR_STATUS failed (0x%08lX)\n", GetLastError());
        return 1;
    }

    PrintTimestamp();
    printf("GhostRing Status\n");
    printf("  Loaded     : %s\n", info.Loaded ? "YES" : "NO");
    printf("  Active CPUs: %lu / %lu\n", info.ActiveCpuCount, info.TotalCpuCount);
    printf("  CPU Vendor : %s\n",
           (info.CpuVendor == 1) ? "Intel" :
           (info.CpuVendor == 2) ? "AMD" : "Unknown");

    return 0;
}

/* ---------------------------------------------------------------------------
 * --integrity : trigger integrity check
 * ------------------------------------------------------------------------- */

static int
CmdIntegrity(HANDLE hDevice)
{
    DWORD bytesReturned;

    if (!DeviceIoControl(hDevice,
                         IOCTL_GR_INTEGRITY_CHECK,
                         NULL, 0,
                         NULL, 0,
                         &bytesReturned,
                         NULL))
    {
        fprintf(stderr, "IOCTL_GR_INTEGRITY_CHECK failed (0x%08lX)\n",
                GetLastError());
        return 1;
    }

    PrintTimestamp();
    printf("Integrity check requested successfully.\n");
    return 0;
}

/* ---------------------------------------------------------------------------
 * --dkom : trigger DKOM scan
 * ------------------------------------------------------------------------- */

static int
CmdDkom(HANDLE hDevice)
{
    DWORD bytesReturned;

    if (!DeviceIoControl(hDevice,
                         IOCTL_GR_DKOM_SCAN,
                         NULL, 0,
                         NULL, 0,
                         &bytesReturned,
                         NULL))
    {
        fprintf(stderr, "IOCTL_GR_DKOM_SCAN failed (0x%08lX)\n",
                GetLastError());
        return 1;
    }

    PrintTimestamp();
    printf("DKOM scan requested successfully.\n");
    return 0;
}

/* ---------------------------------------------------------------------------
 * --monitor : continuous alert polling via ReadFile
 * ------------------------------------------------------------------------- */

static int
CmdMonitor(HANDLE hDevice)
{
    BYTE    buf[512];
    DWORD   bytesRead;

    PrintTimestamp();
    printf("Monitoring GhostRing alerts (Ctrl+C to stop)...\n");

    for (;;)
    {
        if (!ReadFile(hDevice, buf, sizeof(buf), &bytesRead, NULL))
        {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS || err == ERROR_HANDLE_EOF)
            {
                Sleep(500);
                continue;
            }
            fprintf(stderr, "ReadFile failed (0x%08lX)\n", err);
            return 1;
        }

        if (bytesRead > 0)
        {
            PrintTimestamp();
            printf("Alert: %.*s\n", (int)bytesRead, (char *)buf);
        }
        else
        {
            Sleep(500);
        }
    }

    return 0;
}

/* ---------------------------------------------------------------------------
 * Usage
 * ------------------------------------------------------------------------- */

static void
PrintUsage(const char *argv0)
{
    printf("GhostRing Agent — Windows\n");
    printf("Usage: %s [--status|--integrity|--dkom|--monitor]\n\n", argv0);
    printf("  --status      Query hypervisor status\n");
    printf("  --integrity   Trigger EPT integrity check\n");
    printf("  --dkom        Trigger DKOM scan\n");
    printf("  --monitor     Poll for alerts (blocking)\n");
}

/* ---------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */

int
main(int argc, char *argv[])
{
    HANDLE  hDevice;
    int     rc = 0;

    if (argc < 2)
    {
        PrintUsage(argv[0]);
        return 0;
    }

    hDevice = OpenGhostRing();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return 1;
    }

    if (strcmp(argv[1], "--status") == 0)
    {
        rc = CmdStatus(hDevice);
    }
    else if (strcmp(argv[1], "--integrity") == 0)
    {
        rc = CmdIntegrity(hDevice);
    }
    else if (strcmp(argv[1], "--dkom") == 0)
    {
        rc = CmdDkom(hDevice);
    }
    else if (strcmp(argv[1], "--monitor") == 0)
    {
        rc = CmdMonitor(hDevice);
    }
    else
    {
        PrintUsage(argv[0]);
        rc = 1;
    }

    CloseHandle(hDevice);
    return rc;
}
