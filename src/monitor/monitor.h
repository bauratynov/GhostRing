/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * monitor.h — Unified security monitor orchestrator.
 *
 * This is the top-level coordination layer that ties together the
 * individual detection subsystems (integrity, MSR guard, DKOM, hooks).
 * VM-exit handlers call into the monitor; the monitor delegates to the
 * appropriate subsystem and aggregates results.
 *
 * Design rationale: keeping detection logic separate from the VMX exit
 * path makes each subsystem independently testable and allows us to
 * enable/disable checks at runtime without touching the hot exit path.
 */

#ifndef GHOSTRING_MONITOR_MONITOR_H
#define GHOSTRING_MONITOR_MONITOR_H

#include "../common/ghostring.h"
#include "alerts.h"
#include "integrity.h"
#include "msr_guard.h"
#include "dkom.h"
#include "hooks.h"
#include "ssdt.h"
#include "driver_obj.h"
#include "code_inject.h"
#include "ransomware.h"
#include "cr_guard.h"
#include "shadow_stack.h"

/* ── EPT violation access types ─────────────────────────────────────────── */

/*
 * Bits extracted from the EPT-violation exit qualification (Intel SDM
 * Vol. 3C, Table 27-7).  We define our own constants to decouple the
 * monitor from the VMX hardware encoding.
 */
#define GR_EPT_ACCESS_READ      BIT(0)
#define GR_EPT_ACCESS_WRITE     BIT(1)
#define GR_EPT_ACCESS_EXEC      BIT(2)

/* ── Per-vCPU monitor state ─────────────────────────────────────────────── */

/*
 * Aggregates all sub-monitor state for a single virtual CPU.  Embedded
 * in or pointed to from the vCPU structure.
 */
typedef struct gr_monitor_state {
    gr_msr_shadow_t      msr_shadow;
    gr_hooks_state_t     hooks;
    gr_cr3_set_t         cr3_set;
    gr_dkom_config_t     dkom_config;

    /* Phase 5 — Advanced detection subsystems */
    gr_ssdt_state_t          ssdt;
    gr_drvobj_state_t        drvobj;
    gr_code_inject_state_t   code_inject;
    gr_ransom_state_t        ransomware;
    gr_cr_guard_state_t      cr_guard;
    gr_shadow_stack_mgr_t    shadow_stack;

    /* Integrity regions are shared across all vCPUs */
    gr_integrity_region_t *integrity_regions;
    uint32_t              integrity_count;

    /* Counters for status reporting */
    uint64_t             total_alerts;
    uint64_t             total_ept_violations;
    uint32_t             protected_pages;

    bool                 armed;         /* True once all subsystems init'd */
} gr_monitor_state_t;

/* ── Public API ─────────────────────────────────────────────────────────── */

/*
 * gr_monitor_init — Initialise all detection subsystems for a vCPU.
 *
 * @mon         : Per-vCPU monitor state to populate.
 * @msr_bitmap  : Pointer to the vCPU's MSR bitmap (4KB).
 * @ept_ctx     : EPT context for this vCPU.
 * @ktext_start : Kernel text section start address.
 * @ktext_end   : Kernel text section end address.
 */
void gr_monitor_init(gr_monitor_state_t *mon,
                     uint8_t *msr_bitmap,
                     gr_ept_ctx_t *ept_ctx,
                     uint64_t ktext_start,
                     uint64_t ktext_end);

/*
 * gr_monitor_ept_violation — Handle an EPT violation VM-exit.
 *
 * Called from the VMX exit dispatcher when the guest triggers an EPT
 * violation.  Determines what was hit, emits the appropriate alert,
 * and decides whether to block (inject #GP) or log-and-allow.
 *
 * @mon           : Per-vCPU monitor state.
 * @gpa           : Faulting guest physical address.
 * @access_type   : Bitmask of GR_EPT_ACCESS_READ/WRITE/EXEC.
 * @guest_rip     : Guest RIP at the time of the violation.
 * @guest_cr3     : Guest CR3 at the time of the violation.
 *
 * Returns 0 to resume the guest, non-zero to inject a fault.
 */
int gr_monitor_ept_violation(gr_monitor_state_t *mon,
                             uint64_t gpa,
                             uint32_t access_type,
                             uint64_t guest_rip,
                             uint64_t guest_cr3);

/*
 * gr_monitor_periodic — Run all periodic checks.
 *
 * Executes integrity verification, DKOM scan, and IDT check.
 * Called from a timer VM-exit, preemption timer, or on-demand via
 * hypercall.
 *
 * @mon : Per-vCPU monitor state.
 *
 * Returns total number of anomalies detected across all checks.
 */
uint32_t gr_monitor_periodic(gr_monitor_state_t *mon);

/*
 * gr_monitor_msr_write — Handle a WRMSR VM-exit.
 *
 * Delegates to the MSR guard subsystem.
 *
 * @mon       : Per-vCPU monitor state.
 * @msr       : MSR index being written.
 * @value     : Value being written.
 * @guest_rip : Guest RIP for alert context.
 * @guest_cr3 : Guest CR3 for alert context.
 *
 * Returns true if the write is allowed, false if blocked.
 */
bool gr_monitor_msr_write(gr_monitor_state_t *mon,
                          uint32_t msr,
                          uint64_t value,
                          uint64_t guest_rip,
                          uint64_t guest_cr3);

/*
 * gr_monitor_cr3_update — Track a MOV-to-CR3 event for DKOM detection.
 *
 * Called from the CR-access VM-exit handler.
 *
 * @mon       : Per-vCPU monitor state.
 * @new_cr3   : The new CR3 value being loaded.
 */
void gr_monitor_cr3_update(gr_monitor_state_t *mon, uint64_t new_cr3);

/*
 * gr_monitor_cr0_write — Handle a guest MOV-to-CR0 exit.
 *
 * Delegates to the CR guard subsystem.  Returns true if allowed.
 */
bool gr_monitor_cr0_write(gr_monitor_state_t *mon,
                          uint64_t new_cr0,
                          uint64_t guest_rip,
                          uint64_t guest_cr3);

/*
 * gr_monitor_cr4_write — Handle a guest MOV-to-CR4 exit.
 *
 * Delegates to the CR guard subsystem.  Returns true if allowed.
 */
bool gr_monitor_cr4_write(gr_monitor_state_t *mon,
                          uint64_t new_cr4,
                          uint64_t guest_rip,
                          uint64_t guest_cr3);

#endif /* GHOSTRING_MONITOR_MONITOR_H */
