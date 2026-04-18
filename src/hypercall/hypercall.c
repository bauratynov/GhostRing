/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * hypercall.c — VMCALL dispatcher and individual hypercall handlers.
 *
 * The hypercall interface is the only sanctioned communication channel
 * between the guest kernel module and the hypervisor.  Every call is
 * validated for privilege level before dispatch — this prevents
 * unprivileged user-space code from triggering monitoring operations
 * or (critically) the unload path.
 */

#include "hypercall.h"

/* ── VMCS read helper (local) ───────────────────────────────────────────── */

static inline uint64_t hcall_vmread(uint64_t field)
{
    uint64_t value;
    __asm__ volatile("vmread %[field], %[val]"
                     : [val] "=r"(value)
                     : [field] "r"(field)
                     : "cc");
    return value;
}

/* ── Privilege validation ───────────────────────────────────────────────── */

/*
 * Check that the VMCALL was issued from ring 0.  The current privilege
 * level is encoded in bits [1:0] of the CS access-rights field in the
 * VMCS (the DPL field of the code segment descriptor).
 *
 * Intel SDM Vol. 3C, Section 24.4.1: "Guest-state area" — the
 * access-rights format mirrors the segment descriptor, with DPL at
 * bits [6:5].
 *
 * Returns true if the caller is ring 0.
 */
static bool caller_is_ring0(void)
{
    uint64_t cs_ar = hcall_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS);

    /*
     * Access-rights layout (Intel SDM Vol. 3C, Table 24-2):
     *   Bits [3:0]  : Segment type
     *   Bit  4      : S (descriptor type)
     *   Bits [6:5]  : DPL
     *   Bit  7      : P (present)
     *   ...
     * DPL 0 = ring 0 (kernel), DPL 3 = ring 3 (user).
     */
    uint32_t dpl = (uint32_t)((cs_ar >> 5) & 0x3);
    return dpl == 0;
}

/* ── Hypercall handlers ─────────────────────────────────────────────────── */

/*
 * PING — simple liveness check.
 *
 * The guest driver issues VMCALL(GR_HCALL_PING) during probe to verify
 * that GhostRing is loaded and intercepting.  Returns the magic value
 * "GhRi" (0x47685269) in RAX.
 */
static void hcall_ping(gr_vmx_guest_ctx_t *ctx)
{
    ctx->rax = GR_HCALL_MAGIC_REPLY;
    GR_LOG_STR("hcall: PING → GhRi");
}

/*
 * STATUS — return monitoring statistics.
 *
 * RAX = protected page count (low 32) | alert count (high 32)
 * The guest module can expose these via /proc or sysfs.
 */
static void hcall_status(gr_vmx_guest_ctx_t *ctx,
                         const gr_monitor_state_t *mon)
{
    if (!mon) {
        ctx->rax = 0;
        return;
    }

    uint64_t pages  = (uint64_t)mon->protected_pages & 0xFFFFFFFF;
    uint64_t alerts = mon->total_alerts & 0xFFFFFFFF;
    ctx->rax = (alerts << 32) | pages;

    GR_LOG("hcall: STATUS pages=",  pages);
    GR_LOG("hcall: STATUS alerts=", alerts);
}

/*
 * INTEGRITY — trigger an on-demand integrity check.
 *
 * Returns the number of mismatched regions in RAX.  The guest module
 * can use this after applying a kernel update to verify that only
 * expected regions changed.
 */
static void hcall_integrity(gr_vmx_guest_ctx_t *ctx,
                            gr_monitor_state_t *mon)
{
    if (!mon) {
        ctx->rax = 0;
        return;
    }

    uint32_t result = gr_monitor_periodic(mon);
    ctx->rax = (uint64_t)result;

    GR_LOG("hcall: INTEGRITY result=", (uint64_t)result);
}

/*
 * DKOM_SCAN — trigger an on-demand hidden process scan.
 *
 * Returns the number of hidden processes in RAX.
 */
static void hcall_dkom_scan(gr_vmx_guest_ctx_t *ctx,
                            gr_monitor_state_t *mon)
{
    if (!mon) {
        ctx->rax = 0;
        return;
    }

    uint32_t hidden = gr_dkom_scan(&mon->cr3_set, &mon->dkom_config);
    ctx->rax = (uint64_t)hidden;

    GR_LOG("hcall: DKOM_SCAN hidden=", (uint64_t)hidden);
}

/*
 * UNLOAD — request devirtualisation of this CPU.
 *
 * Sets the vCPU's exit flag so the main exit loop terminates after
 * this VM-exit and executes VMXOFF.  This is the clean shutdown path
 * invoked by the kernel module during rmmod.
 *
 * Security note: we still require ring 0 (validated by the caller),
 * so user-space cannot force an unload.
 */
static void hcall_unload(gr_vmx_guest_ctx_t *ctx, bool *exit_vm)
{
    if (exit_vm) {
        *exit_vm = true;
        GR_LOG_STR("hcall: UNLOAD — devirtualisation requested");
    }
    ctx->rax = 0;
}

/* ── Main dispatcher ────────────────────────────────────────────────────── */

void gr_hypercall_dispatch(gr_vmx_guest_ctx_t *ctx,
                           gr_monitor_state_t *mon,
                           bool *exit_vm)
{
    if (!ctx)
        return;

    /*
     * Reject calls from user-space.  A malicious or confused user-mode
     * program should not be able to trigger hypervisor operations.  We
     * return a distinctive error code so the guest module can detect
     * the condition (though a well-written module would never issue
     * VMCALL from ring 3).
     */
    if (!caller_is_ring0()) {
        GR_LOG("hcall: REJECTED — caller not ring 0, rax=", ctx->rax);
        ctx->rax = GR_HCALL_ERR_NOT_RING0;
        return;
    }

    uint64_t call_nr = ctx->rax;

    switch (call_nr) {
    case GR_HCALL_PING:
        hcall_ping(ctx);
        break;

    case GR_HCALL_STATUS:
        hcall_status(ctx, mon);
        break;

    case GR_HCALL_INTEGRITY:
        hcall_integrity(ctx, mon);
        break;

    case GR_HCALL_DKOM_SCAN:
        hcall_dkom_scan(ctx, mon);
        break;

    case GR_HCALL_UNLOAD:
        hcall_unload(ctx, exit_vm);
        break;

    default:
        /* Unknown hypercall — most commonly the guest kernel's Hyper-V
         * paravirt code hitting its 'hypercall page' under us.  Log
         * only the first few, then stay quiet to avoid a serial flood. */
        {
            static uint64_t unknown_count;
            if (unknown_count++ < 5)
                GR_LOG("hcall: unknown call number=", call_nr);
        }
        ctx->rax = (uint64_t)GR_HCALL_ERR_UNKNOWN;
        break;
    }
}
