/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * driver_obj.h — Windows DRIVER_OBJECT integrity monitoring.
 *
 * Every Windows kernel-mode driver has a DRIVER_OBJECT whose
 * MajorFunction[] dispatch table routes IRPs (I/O Request Packets)
 * to the driver's handlers.  Rootkits such as TDL4 and ZeroAccess
 * replace entries in this table to intercept disk I/O, network
 * traffic, and file system operations without modifying kernel code.
 *
 * Detection:
 *   - Snapshot the MajorFunction[IRP_MJ_MAXIMUM_FUNCTION+1] array at
 *     a known-good point.
 *   - Periodically compare each function pointer.  Any entry that has
 *     changed and now points outside the driver's own image range is
 *     flagged as hooked.
 *   - EPT-write-protect the DRIVER_OBJECT pages for real-time prevention.
 *
 * This technique is similar to Bitdefender HVMI's driver object
 * protection (see introcore/include/drivers.h in the reference).
 */

#ifndef GHOSTRING_MONITOR_DRIVER_OBJ_H
#define GHOSTRING_MONITOR_DRIVER_OBJ_H

#include "../common/ghostring.h"

/* ── Constants ──────────────────────────────────────────────────────────── */

/*
 * IRP_MJ_MAXIMUM_FUNCTION + 1 as defined in the Windows DDK.
 * The MajorFunction[] array in DRIVER_OBJECT has this many slots.
 */
#define GR_IRP_MJ_MAX               28

/*
 * Maximum driver name length for logging.
 */
#define GR_DRVOBJ_NAME_LEN          64

/*
 * Maximum number of driver objects we can monitor simultaneously.
 * Typical systems have 100–200 loaded drivers; we track the
 * security-critical subset.
 */
#define GR_DRVOBJ_MAX_MONITORED     32

/* ── Per-driver monitor state ───────────────────────────────────────────── */

typedef struct gr_drvobj_monitor {
    phys_addr_t gpa;                                /* GPA of the DRIVER_OBJECT  */
    uint64_t    dispatch_table_snapshot[GR_IRP_MJ_MAX]; /* Baseline MajorFunction[] */
    uint64_t    image_start;                        /* Driver image base GPA     */
    uint64_t    image_end;                          /* Driver image end GPA      */
    char        driver_name[GR_DRVOBJ_NAME_LEN];    /* Human-readable name       */
    bool        active;                             /* Slot in use               */
} gr_drvobj_monitor_t;

/* ── Aggregate state for all monitored drivers ──────────────────────────── */

typedef struct gr_drvobj_state {
    gr_drvobj_monitor_t drivers[GR_DRVOBJ_MAX_MONITORED];
    uint32_t            count;          /* Number of active entries          */
    bool                initialised;
} gr_drvobj_state_t;

/* ── Public API ─────────────────────────────────────────────────────────── */

/*
 * gr_drvobj_init — Initialise the driver object monitoring subsystem.
 *
 * @state : Aggregate state to zero-initialise.
 */
void gr_drvobj_init(gr_drvobj_state_t *state);

/*
 * gr_drvobj_add — Register a driver object for monitoring.
 *
 * Snapshots the MajorFunction[] dispatch table from guest memory.
 *
 * @state       : Aggregate state.
 * @drvobj_gpa  : Guest physical address of the DRIVER_OBJECT structure.
 * @image_start : Start GPA of the driver's PE image.
 * @image_end   : End GPA of the driver's PE image.
 * @name        : Null-terminated driver name for logging.
 *
 * Returns 0 on success, -1 if the table is full.
 */
int gr_drvobj_add(gr_drvobj_state_t *state,
                  phys_addr_t drvobj_gpa,
                  uint64_t image_start,
                  uint64_t image_end,
                  const char *name);

/*
 * gr_drvobj_check — Scan all monitored driver objects for hooks.
 *
 * For each driver, compares the live MajorFunction[] against the
 * snapshot.  Entries pointing outside the driver's image range are
 * reported as hooks.
 *
 * @state : Aggregate state.
 *
 * Returns total number of hooked dispatch entries across all drivers.
 * Emits GR_ALERT_DRVOBJ_HOOK for each detected hook.
 */
uint32_t gr_drvobj_check(gr_drvobj_state_t *state);

/*
 * gr_drvobj_protect — EPT-write-protect all monitored driver objects.
 *
 * @state   : Aggregate state.
 * @ept_ctx : EPT context for this vCPU.
 */
void gr_drvobj_protect(gr_drvobj_state_t *state, gr_ept_ctx_t *ept_ctx);

#endif /* GHOSTRING_MONITOR_DRIVER_OBJ_H */
