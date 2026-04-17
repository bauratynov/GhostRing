/*++

GhostRing Hypervisor — Windows Kernel Driver Entry

Author:

    Baurzhan Atynov <bauratynov@gmail.com>

License:

    MIT

Module:

    ghostring_drv.c

Abstract:

    Windows KMDF kernel driver that loads the GhostRing hypervisor on all
    logical CPUs.  Follows the SimpleVisor DPC broadcast pattern for per-CPU
    initialization and provides a DeviceIoControl interface for the
    user-mode agent.

Environment:

    Kernel mode only.

--*/

#include "ghostring_win.h"

#pragma warning(disable:4221)
#pragma warning(disable:4204)

/* ---------------------------------------------------------------------------
 * Undocumented DPC broadcast APIs (exported by ntoskrnl, not in headers)
 * ------------------------------------------------------------------------- */

NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
    _In_ PKDEFERRED_ROUTINE Routine,
    _In_opt_ PVOID Context
    );

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
    _In_ PVOID SystemArgument1
    );

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
    _In_ PVOID SystemArgument2
    );

/* ---------------------------------------------------------------------------
 * Forward declarations
 * ------------------------------------------------------------------------- */

DRIVER_INITIALIZE   DriverEntry;
DRIVER_UNLOAD       GrDriverUnload;

static VOID GrDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2);

static VOID GrPowerCallback(
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2);

static NTSTATUS GrDeviceCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS GrDeviceClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS GrDeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* ---------------------------------------------------------------------------
 * Globals
 * ------------------------------------------------------------------------- */

static ULONG        g_CpuVendor;
static ULONG        g_CpuCount;
static PGR_VCPU    *g_Vcpus;                   /* per-CPU array              */
static PVOID        g_PowerCallbackRegistration;
static PDEVICE_OBJECT g_DeviceObject;

/* ---------------------------------------------------------------------------
 * CPU vendor detection via CPUID
 * ------------------------------------------------------------------------- */

static ULONG
GrDetectCpuVendor(
    VOID
    )
{
    int regs[4];   /* EAX, EBX, ECX, EDX */

    __cpuid(regs, 0);

    /* "GenuineIntel": EBX=0x756e6547  EDX=0x49656e69  ECX=0x6c65746e */
    if (regs[1] == 0x756e6547 &&
        regs[3] == 0x49656e69 &&
        regs[2] == 0x6c65746e)
    {
        return GR_CPUID_VENDOR_INTEL;
    }

    /* "AuthenticAMD": EBX=0x68747541  EDX=0x69746e65  ECX=0x444d4163 */
    if (regs[1] == 0x68747541 &&
        regs[3] == 0x69746e65 &&
        regs[2] == 0x444d4163)
    {
        return GR_CPUID_VENDOR_AMD;
    }

    return 0;
}

/* ---------------------------------------------------------------------------
 * Per-CPU VMX init callback (called from DPC context on each processor)
 * ------------------------------------------------------------------------- */

static VOID
GrPerCpuInit(
    _In_ PVOID Context
    )
{
    ULONG cpu;
    PGR_VCPU vcpu;
    PGR_DPC_CONTEXT dpcCtx = (PGR_DPC_CONTEXT)Context;
    int rc;

    UNREFERENCED_PARAMETER(Context);

    cpu = KeGetCurrentProcessorNumberEx(NULL);
    if (cpu >= g_CpuCount)
    {
        InterlockedIncrement(&dpcCtx->FailCount);
        return;
    }

    vcpu = g_Vcpus[cpu];
    if (vcpu == NULL)
    {
        InterlockedIncrement(&dpcCtx->FailCount);
        return;
    }

    vcpu->CpuId = cpu;

    rc = gr_vmx_enter_root(vcpu);
    if (rc != 0)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "GhostRing: CPU %lu — gr_vmx_enter_root failed (%d)\n",
                    cpu, rc);
        InterlockedIncrement(&dpcCtx->FailCount);
        return;
    }

    rc = gr_vmx_setup_vmcs(vcpu);
    if (rc != 0)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "GhostRing: CPU %lu — gr_vmx_setup_vmcs failed (%d)\n",
                    cpu, rc);
        InterlockedIncrement(&dpcCtx->FailCount);
        return;
    }

    rc = gr_vmx_launch(vcpu);
    if (rc != 0)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "GhostRing: CPU %lu — gr_vmx_launch failed (%d)\n",
                    cpu, rc);
        InterlockedIncrement(&dpcCtx->FailCount);
        return;
    }

    vcpu->Active = TRUE;
    InterlockedIncrement(&dpcCtx->SuccessCount);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "GhostRing: CPU %lu virtualized\n", cpu);
}

/* ---------------------------------------------------------------------------
 * Per-CPU teardown — issue magic CPUID to exit VMX root mode
 * ------------------------------------------------------------------------- */

static VOID
GrPerCpuExit(
    _In_ PVOID Context
    )
{
    ULONG cpu;
    PGR_VCPU vcpu;
    int regs[4];

    UNREFERENCED_PARAMETER(Context);

    cpu = KeGetCurrentProcessorNumberEx(NULL);
    if (cpu >= g_CpuCount)
    {
        return;
    }

    vcpu = g_Vcpus[cpu];
    if (vcpu != NULL && vcpu->Active)
    {
        __cpuidex(regs, GR_CPUID_EXIT_LEAF, 0);
        vcpu->Active = FALSE;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "GhostRing: CPU %lu devirtualized\n", cpu);
    }
}

/* ---------------------------------------------------------------------------
 * DPC routine — SimpleVisor broadcast pattern
 * Runs the per-CPU callback, fixes segment selectors, then synchronises.
 * ------------------------------------------------------------------------- */

static VOID
GrDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PGR_DPC_CONTEXT dpcContext = (PGR_DPC_CONTEXT)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    __analysis_assume(DeferredContext != NULL);
    __analysis_assume(SystemArgument1 != NULL);
    __analysis_assume(SystemArgument2 != NULL);

    /*
     * Execute the per-CPU callback.
     */
    dpcContext->Routine(dpcContext);

    /*
     * After VMX operations the processor clears RPL bits from segment
     * selectors.  Restore DS/ES/FS to prevent GPF in WoW64 threads
     * (see SimpleVisor ShvOsDpcRoutine for the full explanation).
     */
    GrVmxCleanup(KGDT64_R3_DATA | RPL_MASK, KGDT64_R3_CMTEB | RPL_MASK);

    /*
     * Synchronise all DPCs, then signal completion.
     */
    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

/* ---------------------------------------------------------------------------
 * Broadcast a callback to all processors via KeGenericCallDpc
 * ------------------------------------------------------------------------- */

static VOID
GrRunOnAllProcessors(
    _In_ GR_CPU_CALLBACK Routine
    )
{
    GR_DPC_CONTEXT dpcContext;

    RtlZeroMemory(&dpcContext, sizeof(dpcContext));
    dpcContext.Routine = Routine;
    dpcContext.Context = &dpcContext;
    dpcContext.SuccessCount = 0;
    dpcContext.FailCount = 0;

    KeGenericCallDpc(GrDpcRoutine, &dpcContext);
}

/* ---------------------------------------------------------------------------
 * Load — allocate per-CPU structures and virtualise every processor
 * ------------------------------------------------------------------------- */

static NTSTATUS
GrLoad(
    VOID
    )
{
    ULONG i;
    PHYSICAL_ADDRESS lowest, highest, boundary;
    GR_DPC_CONTEXT dpcContext;

    g_CpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    /*
     * Allocate pointer array for per-CPU vCPU structs.
     */
    g_Vcpus = (PGR_VCPU *)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                           g_CpuCount * sizeof(PGR_VCPU),
                                           'RhGr');
    if (g_Vcpus == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_Vcpus, g_CpuCount * sizeof(PGR_VCPU));

    lowest.QuadPart  = 0;
    highest.QuadPart = (ULONGLONG)-1;
    boundary.QuadPart = 0;

    for (i = 0; i < g_CpuCount; i++)
    {
        /*
         * Use MmAllocateContiguousMemory for page-aligned vCPU data
         * (VMXON region, VMCS, etc. require physical contiguity).
         */
        g_Vcpus[i] = (PGR_VCPU)MmAllocateContiguousNodeMemory(
                          sizeof(GR_VCPU),
                          lowest,
                          highest,
                          boundary,
                          PAGE_READWRITE,
                          KeGetCurrentNodeNumber());
        if (g_Vcpus[i] == NULL)
        {
            goto fail_free;
        }

        RtlZeroMemory(g_Vcpus[i], sizeof(GR_VCPU));
    }

    /*
     * Broadcast VMX init to all processors.
     */
    RtlZeroMemory(&dpcContext, sizeof(dpcContext));
    dpcContext.Routine = GrPerCpuInit;
    dpcContext.Context = &dpcContext;
    dpcContext.SuccessCount = 0;
    dpcContext.FailCount = 0;

    KeGenericCallDpc(GrDpcRoutine, &dpcContext);

    if (dpcContext.SuccessCount == 0)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "GhostRing: failed to virtualize any CPU\n");
        goto fail_free;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "GhostRing: loaded on %ld / %lu CPUs\n",
               dpcContext.SuccessCount, g_CpuCount);

    return STATUS_SUCCESS;

fail_free:
    for (i = 0; i < g_CpuCount; i++)
    {
        if (g_Vcpus[i] != NULL)
        {
            MmFreeContiguousMemory(g_Vcpus[i]);
        }
    }
    ExFreePoolWithTag(g_Vcpus, 'RhGr');
    g_Vcpus = NULL;
    return STATUS_UNSUCCESSFUL;
}

/* ---------------------------------------------------------------------------
 * Unload — devirtualise all processors and free resources
 * ------------------------------------------------------------------------- */

static VOID
GrUnload(
    VOID
    )
{
    ULONG i;

    if (g_Vcpus == NULL)
    {
        return;
    }

    GrRunOnAllProcessors(GrPerCpuExit);

    for (i = 0; i < g_CpuCount; i++)
    {
        if (g_Vcpus[i] != NULL)
        {
            MmFreeContiguousMemory(g_Vcpus[i]);
        }
    }

    ExFreePoolWithTag(g_Vcpus, 'RhGr');
    g_Vcpus = NULL;
}

/* ---------------------------------------------------------------------------
 * Power state callback — re-virtualise on S0 resume, unload on Sx entry
 * (SimpleVisor pattern)
 * ------------------------------------------------------------------------- */

static VOID
GrPowerCallback(
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    UNREFERENCED_PARAMETER(CallbackContext);

    if (Argument1 != (PVOID)PO_CB_SYSTEM_STATE_LOCK)
    {
        return;
    }

    if (ARGUMENT_PRESENT(Argument2))
    {
        /* Sx -> S0 : reload the hypervisor */
        GrLoad();
    }
    else
    {
        /* S0 -> Sx : unload the hypervisor */
        GrUnload();
    }
}

/* ---------------------------------------------------------------------------
 * IRP_MJ_CREATE handler
 * ------------------------------------------------------------------------- */

static NTSTATUS
GrDeviceCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------------------
 * IRP_MJ_CLOSE handler
 * ------------------------------------------------------------------------- */

static NTSTATUS
GrDeviceClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------------------
 * IRP_MJ_DEVICE_CONTROL handler — STATUS, INTEGRITY_CHECK, DKOM_SCAN
 * ------------------------------------------------------------------------- */

static NTSTATUS
GrDeviceIoControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    PIO_STACK_LOCATION  irpSp;
    NTSTATUS            status = STATUS_SUCCESS;
    ULONG               outLen = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_GR_STATUS:
    {
        GR_STATUS_INFO info;
        ULONG i, activeCount = 0;

        if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(info))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (g_Vcpus != NULL)
        {
            for (i = 0; i < g_CpuCount; i++)
            {
                if (g_Vcpus[i] != NULL && g_Vcpus[i]->Active)
                {
                    activeCount++;
                }
            }
        }

        info.ActiveCpuCount = activeCount;
        info.TotalCpuCount  = g_CpuCount;
        info.CpuVendor      = g_CpuVendor;
        info.Loaded         = (activeCount > 0) ? TRUE : FALSE;

        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &info, sizeof(info));
        outLen = sizeof(info);
        break;
    }

    case IOCTL_GR_INTEGRITY_CHECK:
        /*
         * Stub — in the full implementation this triggers an EPT-based
         * integrity scan of critical kernel structures.
         */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "GhostRing: integrity check requested\n");
        status = STATUS_SUCCESS;
        break;

    case IOCTL_GR_DKOM_SCAN:
        /*
         * Stub — in the full implementation this walks EPROCESS lists
         * and cross-references with the hypervisor's shadow view.
         */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "GhostRing: DKOM scan requested\n");
        status = STATUS_SUCCESS;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = outLen;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ---------------------------------------------------------------------------
 * DriverUnload
 * ------------------------------------------------------------------------- */

VOID
GrDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(GR_SYMLINK_NAME);

    UNREFERENCED_PARAMETER(DriverObject);

    /* Unregister power callback */
    if (g_PowerCallbackRegistration != NULL)
    {
        ExUnregisterCallback(g_PowerCallbackRegistration);
        g_PowerCallbackRegistration = NULL;
    }

    /* Devirtualise and free resources */
    GrUnload();

    /* Remove device object and symbolic link */
    IoDeleteSymbolicLink(&symLink);
    if (g_DeviceObject != NULL)
    {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "GhostRing: driver unloaded\n");
}

/* ---------------------------------------------------------------------------
 * DriverEntry
 * ------------------------------------------------------------------------- */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS            status;
    UNICODE_STRING      deviceName  = RTL_CONSTANT_STRING(GR_DEVICE_NAME);
    UNICODE_STRING      symLink     = RTL_CONSTANT_STRING(GR_SYMLINK_NAME);
    PCALLBACK_OBJECT    callbackObject;
    UNICODE_STRING      callbackName =
                            RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
    OBJECT_ATTRIBUTES   objectAttributes =
                            RTL_CONSTANT_OBJECT_ATTRIBUTES(
                                &callbackName,
                                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "GhostRing: driver loading\n");

    /* 1. Allow unload */
    DriverObject->DriverUnload = GrDriverUnload;

    /* 2. Detect CPU vendor */
    g_CpuVendor = GrDetectCpuVendor();
    if (g_CpuVendor == 0)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "GhostRing: unsupported CPU vendor\n");
        return STATUS_NOT_SUPPORTED;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "GhostRing: detected %s CPU\n",
               (g_CpuVendor == GR_CPUID_VENDOR_INTEL) ? "Intel" : "AMD");

    /* 3. Create the device object for agent communication */
    status = IoCreateDevice(DriverObject,
                            0,
                            &deviceName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &g_DeviceObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "GhostRing: IoCreateDevice failed (0x%08X)\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    /* 4. Set up IRP dispatch routines */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = GrDeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = GrDeviceClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = GrDeviceIoControl;

    /* 5. Register power state callback (SimpleVisor pattern) */
    status = ExCreateCallback(&callbackObject, &objectAttributes, FALSE, TRUE);
    if (!NT_SUCCESS(status))
    {
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    g_PowerCallbackRegistration = ExRegisterCallback(callbackObject,
                                                     GrPowerCallback,
                                                     NULL);
    ObDereferenceObject(callbackObject);

    if (g_PowerCallbackRegistration == NULL)
    {
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* 6. Load the hypervisor on all CPUs */
    status = GrLoad();
    if (!NT_SUCCESS(status))
    {
        ExUnregisterCallback(g_PowerCallbackRegistration);
        g_PowerCallbackRegistration = NULL;
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "GhostRing: driver loaded successfully\n");

    return STATUS_SUCCESS;
}
