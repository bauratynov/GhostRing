/*++

GhostRing Hypervisor — Windows Kernel Driver Header

Author:

    Baurzhan Atynov <bauratynov@gmail.com>

License:

    MIT

Module:

    ghostring_win.h

Abstract:

    Windows-specific definitions for the GhostRing kernel driver,
    including IOCTL codes, device names, and DPC context structures.

Environment:

    Kernel mode only.

--*/

#pragma once

#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>

/* ---------------------------------------------------------------------------
 * Device names
 * ------------------------------------------------------------------------- */

#define GR_DEVICE_NAME      L"\\Device\\GhostRing"
#define GR_SYMLINK_NAME     L"\\DosDevices\\GhostRing"

/* ---------------------------------------------------------------------------
 * IOCTL codes — METHOD_BUFFERED, FILE_ANY_ACCESS
 * ------------------------------------------------------------------------- */

#define GR_IOCTL_TYPE       0x8000

#define IOCTL_GR_STATUS             CTL_CODE(GR_IOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GR_INTEGRITY_CHECK    CTL_CODE(GR_IOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GR_DKOM_SCAN          CTL_CODE(GR_IOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ---------------------------------------------------------------------------
 * CPU vendor constants
 * ------------------------------------------------------------------------- */

#define GR_CPUID_VENDOR_INTEL   0x01
#define GR_CPUID_VENDOR_AMD     0x02

/* ---------------------------------------------------------------------------
 * Magic CPUID leaf — intercepted by GhostRing vmexit handler to shut down
 * ------------------------------------------------------------------------- */

#define GR_CPUID_EXIT_LEAF      0x47520001  /* "GR\x00\x01" */

/* ---------------------------------------------------------------------------
 * Segment selector constants for post-DPC cleanup
 * ------------------------------------------------------------------------- */

#define KGDT64_R3_DATA      0x28
#define KGDT64_R3_CMTEB     0x50

/* ---------------------------------------------------------------------------
 * Per-CPU vCPU context (mirrors Linux gr_vcpu_t)
 * ------------------------------------------------------------------------- */

typedef struct _GR_VCPU {
    ULONG       CpuId;
    BOOLEAN     Active;
    PVOID       VmxonRegion;        /* page-aligned VMXON region            */
    PVOID       Vmcs;               /* page-aligned VMCS                    */
    PVOID       HostStack;          /* small stack for VM-exit handler      */
} GR_VCPU, *PGR_VCPU;

/* ---------------------------------------------------------------------------
 * DPC broadcast context (SimpleVisor pattern)
 * ------------------------------------------------------------------------- */

typedef void (*GR_CPU_CALLBACK)(PVOID Context);

typedef struct _GR_DPC_CONTEXT {
    GR_CPU_CALLBACK     Routine;
    PVOID               Context;
    volatile LONG       SuccessCount;
    volatile LONG       FailCount;
} GR_DPC_CONTEXT, *PGR_DPC_CONTEXT;

/* ---------------------------------------------------------------------------
 * Status response structure (returned via IOCTL_GR_STATUS)
 * ------------------------------------------------------------------------- */

typedef struct _GR_STATUS_INFO {
    ULONG   ActiveCpuCount;
    ULONG   TotalCpuCount;
    ULONG   CpuVendor;         /* GR_CPUID_VENDOR_INTEL or _AMD */
    BOOLEAN Loaded;
} GR_STATUS_INFO, *PGR_STATUS_INFO;

/* ---------------------------------------------------------------------------
 * External VMX core functions (linked from ../../src/vmx/)
 * ------------------------------------------------------------------------- */

extern int  gr_vmx_check_support(PGR_VCPU Vcpu);
extern void gr_vmx_mtrr_init(PGR_VCPU Vcpu);
extern int  gr_vmx_ept_init(PGR_VCPU Vcpu);
extern int  gr_vmx_enter_root(PGR_VCPU Vcpu);
extern int  gr_vmx_setup_vmcs(PGR_VCPU Vcpu);
extern int  gr_vmx_launch(PGR_VCPU Vcpu);

/* ---------------------------------------------------------------------------
 * ASM helpers (ghostring_winasm.asm)
 * ------------------------------------------------------------------------- */

extern void GrCaptureContext(PCONTEXT ContextRecord);
extern void GrRestoreContext(PCONTEXT ContextRecord);
extern void GrVmxCleanup(UINT16 DataSelector, UINT16 TebSelector);
extern void _str(PUINT16 TaskRegister);
extern void _sldt(PUINT16 Ldtr);
extern void __lgdt(PVOID GdtBase);
