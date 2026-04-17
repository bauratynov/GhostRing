/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * vmx_vmfunc.h — VMFUNC EPTP switching for exitless EPT view changes.
 *
 * VMFUNC (VM Function) allows the guest to invoke hypervisor-configured
 * functions without causing a VM-exit.  Function 0 = EPTP switching.
 *
 * The guest executes:
 *   MOV EAX, 0          ; function 0 = EPTP switch
 *   MOV ECX, <index>    ; EPTP list index (0-511)
 *   VMFUNC
 *
 * The CPU switches to EPTP[index] in ~134 cycles — 2.2× faster than
 * a full VM-exit round trip (~301 cycles).
 *
 * For GhostRing dual-EPT stealth monitoring:
 *   EPTP[0] = primary (R/W, no-X on hooked pages)
 *   EPTP[1] = secondary (execute-only shadow pages)
 *
 * When guest executes hooked code → EPT violation (no-X) → we inject
 * VMFUNC(0,1) via #VE handler → guest switches to shadow view at 134
 * cycles → executes hook → VMFUNC(0,0) back to primary.
 *
 * Total cost per hook hit: ~268 cycles (2× VMFUNC) vs ~602 cycles (2× exit).
 *
 * Requires: CPUID.7.0:ECX.VMFUNC[bit 13] and Secondary Controls bit 13.
 * Reference: Intel SDM Vol. 3C, Section 25.5.6.
 */

#ifndef GHOSTRING_VMX_VMFUNC_H
#define GHOSTRING_VMX_VMFUNC_H

#include "vmx_defs.h"

/* ── EPTP list (up to 512 entries, must be page-aligned) ──────────────── */

#define GR_EPTP_LIST_MAX    512

typedef struct gr_vmfunc_ctx {
    uint64_t eptp_list[GR_EPTP_LIST_MAX] GR_ALIGNED(PAGE_SIZE);
    uint32_t count;                 /* number of configured EPTPs */
    bool     supported;             /* CPU supports VMFUNC */
    bool     enabled;               /* VMFUNC active in VMCS */
} gr_vmfunc_ctx_t;

/* ── CPU support detection ─────────────────────────────────────────────── */

static inline bool gr_vmfunc_supported(void)
{
    uint32_t eax, ebx, ecx, edx;
    gr_cpuid(0x7, 0, &eax, &ebx, &ecx, &edx);
    return (ecx & BIT(13)) != 0;  /* CPUID.7.0:ECX.VMFUNC */
}

/* ── Initialization ────────────────────────────────────────────────────── */

static inline void gr_vmfunc_init(gr_vmfunc_ctx_t *ctx)
{
    ctx->count = 0;
    ctx->supported = gr_vmfunc_supported();
    ctx->enabled = false;

    /* Zero the EPTP list */
    for (uint32_t i = 0; i < GR_EPTP_LIST_MAX; i++)
        ctx->eptp_list[i] = 0;
}

/* ── Add an EPTP to the list ───────────────────────────────────────────── */

static inline int gr_vmfunc_add_eptp(gr_vmfunc_ctx_t *ctx, uint64_t eptp)
{
    if (ctx->count >= GR_EPTP_LIST_MAX)
        return -1;
    ctx->eptp_list[ctx->count] = eptp;
    return (int)ctx->count++;
}

/*
 * ── Enable VMFUNC in VMCS ─────────────────────────────────────────────
 *
 * Must be called after gr_vmx_setup_vmcs().  Sets:
 *   - Secondary Controls bit 13 (Enable VM functions)
 *   - VM_FUNCTION_CONTROL = 1 (EPTP switching enabled)
 *   - EPTP_LIST_ADDR = physical address of eptp_list
 *
 * The caller should also set SECONDARY_EXEC_ENABLE_VIRT_EXCEPTIONS
 * (bit 18) if using #VE for in-guest EPT violation handling.
 */
void gr_vmfunc_enable(gr_vmfunc_ctx_t *ctx);

/*
 * ── Guest-side VMFUNC invocation (inline asm) ─────────────────────────
 *
 * This would be used by an in-guest agent, NOT by the hypervisor itself.
 * Included here for reference and for the agent build.
 */
static inline void gr_guest_vmfunc_switch_eptp(uint32_t index)
{
    __asm__ volatile(
        "mov $0, %%eax\n\t"    /* function 0 = EPTP switch */
        "mov %0, %%ecx\n\t"    /* target EPTP index */
        ".byte 0x0f, 0x01, 0xd4\n\t"  /* VMFUNC (not all assemblers know it) */
        :
        : "r"(index)
        : "eax", "ecx", "memory"
    );
}

#endif /* GHOSTRING_VMX_VMFUNC_H */
