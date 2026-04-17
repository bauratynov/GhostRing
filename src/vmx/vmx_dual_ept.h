/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * vmx_dual_ept.h — Dual-EPT system for stealth memory introspection.
 *
 * Two EPT views of the same physical memory:
 *   Primary:   R/W on all pages, no-execute on monitored code pages
 *   Secondary: execute-only shadow pages with hook trampolines
 *
 * When guest executes monitored code:
 *   1. EPT violation (no-X in primary) → switch EPTP to secondary
 *   2. VMRESUME → code runs from shadow page (contains hook)
 *   3. Hook executes, sets MTF (Monitor Trap Flag)
 *   4. MTF exit → switch EPTP back to primary
 *
 * Result: hooks invisible to memory scanners (they read via primary EPT
 * which shows clean, unmodified pages).
 *
 * Used by: DdiMon, HyperDbg, illusion-rs, matrix-rs.
 * Reference: secret.club/2025/06/02/hypervisors-for-memory-introspection
 */

#ifndef GHOSTRING_VMX_DUAL_EPT_H
#define GHOSTRING_VMX_DUAL_EPT_H

#include "vmx_defs.h"

#define GR_MAX_EPT_HOOKS  256

typedef struct {
    uint64_t target_gpa;        /* hooked guest page GPA */
    uint64_t shadow_hpa;        /* shadow page host physical address */
    uint8_t  original_byte;     /* first byte of original instruction */
    uint8_t  active;
} gr_ept_hook_t;

typedef struct gr_dual_ept {
    uint64_t primary_eptp;      /* normal view: R/W, no-X on hooked pages */
    uint64_t secondary_eptp;    /* shadow view: execute-only shadow pages */
    gr_ept_hook_t hooks[GR_MAX_EPT_HOOKS];
    uint32_t hook_count;
    bool     in_secondary;      /* currently executing in shadow view */
} gr_dual_ept_t;

void gr_dual_ept_init(gr_dual_ept_t *ctx, uint64_t primary_eptp);

/*
 * Install an EPT hook on a code page.
 * Creates a shadow copy of the page with a breakpoint at the target offset.
 */
int gr_dual_ept_add_hook(gr_dual_ept_t *ctx, uint64_t target_gpa);

/*
 * Handle EPT execute violation on a hooked page.
 * Switches to secondary EPTP and sets MTF for single-step return.
 */
void gr_dual_ept_handle_exec_violation(gr_dual_ept_t *ctx, uint64_t gpa);

/*
 * Handle MTF (Monitor Trap Flag) exit.
 * Switches back to primary EPTP after one instruction executed in shadow.
 */
void gr_dual_ept_handle_mtf(gr_dual_ept_t *ctx);

/* Check if a GPA is hooked */
bool gr_dual_ept_is_hooked(gr_dual_ept_t *ctx, uint64_t gpa);

#endif /* GHOSTRING_VMX_DUAL_EPT_H */
