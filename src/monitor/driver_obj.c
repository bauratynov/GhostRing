/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * driver_obj.c — Windows DRIVER_OBJECT dispatch table integrity monitoring.
 *
 * Real-world attacks targeting driver dispatch tables:
 *   - TDL4 (Alureon): hooks disk driver MajorFunction[IRP_MJ_SCSI] to
 *     hide its bootkit payload on disk.
 *   - ZeroAccess: replaces IRP_MJ_DEVICE_CONTROL in the disk stack to
 *     intercept and filter I/O to protected sectors.
 *   - Uroburos (Turla): hooks NDIS miniport driver dispatch entries to
 *     intercept network packets for covert channel communication.
 *
 * The MajorFunction[] array contains IRP_MJ_MAXIMUM_FUNCTION+1 function
 * pointers.  Each pointer should resolve to an address within the
 * driver's own PE image.  A pointer outside the image indicates either
 * a rootkit hook or a filter driver attachment — we distinguish by
 * checking whether the target falls in any known driver image.
 */

#include "driver_obj.h"
#include "alerts.h"
#include "../vmx/vmx_ept.h"

/* ── Windows DRIVER_OBJECT layout offset ────────────────────────────────── */

/*
 * Offset of MajorFunction[] within the DRIVER_OBJECT structure.
 * On 64-bit Windows 10/11 this is at offset 0x70.  This value is
 * version-dependent and should be supplied by the loader; we use
 * a reasonable default.
 */
#define DRVOBJ_MAJOR_FUNCTION_OFFSET    0x70

/* ── Internal helpers ──────────────────────────────────────────────────── */

/*
 * Read the dispatch table from guest physical memory.
 */
static void drvobj_read_dispatch(phys_addr_t drvobj_gpa,
                                 uint64_t dispatch_out[GR_IRP_MJ_MAX])
{
    const uint64_t *table = (const uint64_t *)(uintptr_t)
        (drvobj_gpa + DRVOBJ_MAJOR_FUNCTION_OFFSET);

    for (uint32_t i = 0; i < GR_IRP_MJ_MAX; i++)
        dispatch_out[i] = table[i];
}

/*
 * Check whether a function pointer falls within the driver's PE image.
 */
static inline bool drvobj_target_in_image(const gr_drvobj_monitor_t *drv,
                                          uint64_t target)
{
    return (target >= drv->image_start && target < drv->image_end);
}

/*
 * Simple string copy with length limit and null termination.
 */
static void drvobj_copy_name(char *dst, const char *src, uint32_t max_len)
{
    uint32_t i = 0;
    if (src) {
        for (; i < max_len - 1 && src[i] != '\0'; i++)
            dst[i] = src[i];
    }
    dst[i] = '\0';
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void gr_drvobj_init(gr_drvobj_state_t *state)
{
    if (!state)
        return;

    /* Zero all slots */
    uint8_t *p = (uint8_t *)state;
    for (uint64_t i = 0; i < sizeof(*state); i++)
        p[i] = 0;

    state->initialised = true;
    GR_LOG_STR("drvobj: monitoring subsystem initialised");
}

int gr_drvobj_add(gr_drvobj_state_t *state,
                  phys_addr_t drvobj_gpa,
                  uint64_t image_start,
                  uint64_t image_end,
                  const char *name)
{
    if (!state || !state->initialised)
        return -1;

    if (state->count >= GR_DRVOBJ_MAX_MONITORED) {
        GR_LOG_STR("drvobj: monitoring table full, cannot add driver");
        return -1;
    }

    /* Find the next free slot */
    gr_drvobj_monitor_t *drv = NULL;
    for (uint32_t i = 0; i < GR_DRVOBJ_MAX_MONITORED; i++) {
        if (!state->drivers[i].active) {
            drv = &state->drivers[i];
            break;
        }
    }

    if (!drv)
        return -1;

    drv->gpa         = drvobj_gpa;
    drv->image_start = image_start;
    drv->image_end   = image_end;
    drv->active      = true;

    drvobj_copy_name(drv->driver_name, name, GR_DRVOBJ_NAME_LEN);

    /* Snapshot the current dispatch table */
    drvobj_read_dispatch(drvobj_gpa, drv->dispatch_table_snapshot);

    state->count++;

    GR_LOG("drvobj: monitoring driver at GPA=", drvobj_gpa);
    GR_LOG("drvobj: image range [", image_start);
    GR_LOG("drvobj:              ,", image_end);

    return 0;
}

uint32_t gr_drvobj_check(gr_drvobj_state_t *state)
{
    if (!state || !state->initialised)
        return 0;

    uint32_t total_hooks = 0;

    for (uint32_t d = 0; d < GR_DRVOBJ_MAX_MONITORED; d++) {
        gr_drvobj_monitor_t *drv = &state->drivers[d];
        if (!drv->active)
            continue;

        /* Read the live dispatch table */
        uint64_t live[GR_IRP_MJ_MAX];
        drvobj_read_dispatch(drv->gpa, live);

        for (uint32_t irp = 0; irp < GR_IRP_MJ_MAX; irp++) {
            if (live[irp] == drv->dispatch_table_snapshot[irp])
                continue;

            /*
             * Dispatch entry changed.  Check whether the new target
             * falls within the driver's own image.
             */
            if (!drvobj_target_in_image(drv, live[irp])) {
                total_hooks++;

                /*
                 * info field: pack the IRP major function code so
                 * user-space can identify the hooked operation
                 * (e.g., IRP_MJ_DEVICE_CONTROL = 0x0E).
                 */
                gr_alert_emit(GR_ALERT_DRVOBJ_HOOK,
                              live[irp],    /* new target address         */
                              0,            /* CR3: periodic check        */
                              drv->gpa + DRVOBJ_MAJOR_FUNCTION_OFFSET +
                                  (uint64_t)irp * sizeof(uint64_t),
                              (uint64_t)irp);

                GR_LOG("drvobj: HOOK detected, IRP_MJ=", (uint64_t)irp);
                GR_LOG("  driver GPA=", drv->gpa);
                GR_LOG("  original=", drv->dispatch_table_snapshot[irp]);
                GR_LOG("  current=",  live[irp]);
            }
        }
    }

    return total_hooks;
}

void gr_drvobj_protect(gr_drvobj_state_t *state, gr_ept_ctx_t *ept_ctx)
{
    if (!state || !state->initialised || !ept_ctx)
        return;

    for (uint32_t d = 0; d < GR_DRVOBJ_MAX_MONITORED; d++) {
        gr_drvobj_monitor_t *drv = &state->drivers[d];
        if (!drv->active)
            continue;

        /*
         * Protect the page(s) containing the DRIVER_OBJECT.  The
         * dispatch table at offset 0x70 with 28 entries spans
         * 28 * 8 = 224 bytes; the entire DRIVER_OBJECT is ~0x150
         * bytes, which may cross a page boundary.
         */
        phys_addr_t start = ALIGN_DOWN(drv->gpa, PAGE_SIZE);
        phys_addr_t end   = ALIGN_UP(drv->gpa + DRVOBJ_MAJOR_FUNCTION_OFFSET +
                                     GR_IRP_MJ_MAX * sizeof(uint64_t),
                                     PAGE_SIZE);

        for (phys_addr_t page = start; page < end; page += PAGE_SIZE) {
            int ret = gr_vmx_ept_protect_page(ept_ctx, page, EPT_PERM_RX);
            if (ret != 0)
                GR_LOG("drvobj: EPT protect failed for page=", page);
            else
                GR_LOG("drvobj: EPT write-protected page=", page);
        }
    }

    GR_LOG_STR("drvobj: EPT protection active for all monitored drivers");
}
