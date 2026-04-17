/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * msr_guard.h — Protection for security-critical Model-Specific Registers.
 *
 * Rootkits commonly overwrite LSTAR (the SYSCALL entry point) or
 * SYSENTER_EIP to redirect all system calls through attacker code.
 * Clearing the NXE bit in EFER re-enables execute-from-data attacks.
 *
 * We shadow these MSRs and intercept WRMSR via the MSR bitmap.  Any
 * write that would change a protected value is blocked and an alert is
 * emitted.  Legitimate kernel updates (e.g., during CPU hotplug) can
 * be whitelisted by updating the shadow.
 *
 * Reference: Intel SDM Vol. 3C, Section 24.6.9 (MSR-bitmap address).
 */

#ifndef GHOSTRING_MONITOR_MSR_GUARD_H
#define GHOSTRING_MONITOR_MSR_GUARD_H

#include "../common/ghostring.h"

/* ── MSR indices we protect ─────────────────────────────────────────────── */

/*
 * These are defined in vmx_defs.h but we redeclare locally so that
 * msr_guard.h is self-contained for documentation purposes.
 */
#ifndef MSR_IA32_LSTAR
#define MSR_IA32_LSTAR              0xC0000082
#endif

/* Existing defines from vmx_defs.h: MSR_IA32_SYSENTER_EIP (0x176),
 * MSR_IA32_SYSENTER_ESP (0x175), MSR_IA32_EFER (0xC0000080). */

/* ── EFER bit definitions ───────────────────────────────────────────────── */

#define EFER_SCE    BIT(0)      /* SYSCALL / SYSRET enable               */
#define EFER_LME    BIT(8)      /* Long Mode Enable                      */
#define EFER_LMA    BIT(10)     /* Long Mode Active (read-only)          */
#define EFER_NXE    BIT(11)     /* No-Execute Enable                     */

/* ── Shadow state ───────────────────────────────────────────────────────── */

/*
 * One instance per vCPU.  The shadow values represent the "known good"
 * state of each MSR, captured at hypervisor load time before any guest
 * code has had a chance to tamper.
 */
typedef struct gr_msr_shadow {
    uint64_t lstar;             /* IA32_LSTAR — SYSCALL entry point      */
    uint64_t sysenter_eip;      /* IA32_SYSENTER_EIP                     */
    uint64_t sysenter_esp;      /* IA32_SYSENTER_ESP                     */
    uint64_t efer;              /* IA32_EFER                             */
    bool     initialised;       /* Set after first init                  */
} gr_msr_shadow_t;

/* ── Public API ─────────────────────────────────────────────────────────── */

/*
 * gr_msr_guard_init — Read and shadow the current values of all protected
 *                     MSRs on this vCPU.  Must be called before the guest
 *                     executes so the shadow reflects the clean baseline.
 *
 * @shadow     : Per-vCPU shadow structure to populate.
 * @msr_bitmap : Pointer to the 4KB MSR bitmap for this vCPU; the
 *               function sets the write-intercept bits for the
 *               protected MSRs.
 */
void gr_msr_guard_init(gr_msr_shadow_t *shadow, uint8_t *msr_bitmap);

/*
 * gr_msr_guard_check_write — Evaluate a guest WRMSR and decide whether
 *                             to allow or deny it.
 *
 * @shadow    : Per-vCPU shadow state.
 * @msr_index : The MSR the guest is trying to write.
 * @new_value : The value the guest wants to write.
 * @guest_rip : Current guest RIP (for alert context).
 * @guest_cr3 : Current guest CR3 (for alert context).
 *
 * Returns true if the write is allowed, false if it was blocked.
 * On block the function emits a GR_ALERT_MSR_TAMPER alert.
 */
bool gr_msr_guard_check_write(gr_msr_shadow_t *shadow,
                              uint32_t msr_index,
                              uint64_t new_value,
                              uint64_t guest_rip,
                              uint64_t guest_cr3);

/*
 * gr_msr_bitmap_protect — Set the write-intercept bit for a single MSR
 *                          in the VMCS MSR bitmap.
 *
 * The MSR bitmap is a 4KB region laid out as:
 *   [0x000..0x3FF] Read bitmap for MSRs 0x00000000 – 0x00001FFF
 *   [0x400..0x7FF] Read bitmap for MSRs 0xC0000000 – 0xC0001FFF
 *   [0x800..0xBFF] Write bitmap for MSRs 0x00000000 – 0x00001FFF
 *   [0xC00..0xFFF] Write bitmap for MSRs 0xC0000000 – 0xC0001FFF
 *
 * See Intel SDM Vol. 3C, Section 24.6.9.
 */
void gr_msr_bitmap_protect(uint8_t *msr_bitmap, uint32_t msr_index);

#endif /* GHOSTRING_MONITOR_MSR_GUARD_H */
