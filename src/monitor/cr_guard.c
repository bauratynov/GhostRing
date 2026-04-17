/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * cr_guard.c — Control register protection for CR0 and CR4.
 *
 * Attack scenarios prevented:
 *
 *   CR0.WP bypass — Rootkits (e.g., certain variants of Necurs, Turla)
 *     temporarily clear CR0.WP to write to read-only pages without
 *     triggering #PF.  This allows patching kernel code or user-mode
 *     memory from ring-0 without copy-on-write overhead.
 *
 *   SMEP bypass — The Hacking Team kernel exploit (CVE-2015-2387) and
 *     multiple in-the-wild Windows exploits disable SMEP to execute
 *     shellcode placed in user-mode pages from kernel context.  This
 *     is the single most common exploitation primitive against modern
 *     Windows kernels.
 *
 *   SMAP bypass — Disabling SMAP allows ring-0 code to freely read
 *     user-mode memory, which facilitates KASLR bypass and data-only
 *     attacks.
 *
 *   CET disable — Intel CET provides hardware shadow stacks.  Clearing
 *     CR4.CET disables this protection, re-enabling ROP/JOP attacks.
 *
 * Implementation:
 *   The VMCS guest-host mask mechanism intercepts MOV-to-CR0/CR4 only
 *   for the bits we care about.  Other bits pass through without a
 *   VM-exit, keeping overhead near zero.  The read shadow ensures the
 *   guest sees its expected CR0/CR4 value on read.
 */

#include "cr_guard.h"
#include "alerts.h"
#include "../vmx/vmx_defs.h"   /* VMCS_GUEST_CR0, VMCS_CR0_GUEST_HOST_MASK */

/* ── VMCS read/write helpers (local declarations) ──────────────────────── */

static inline uint64_t gr_vmread_local(uint64_t field)
{
    uint64_t value;
    __asm__ volatile("vmread %[field], %[val]"
                     : [val] "=r"(value)
                     : [field] "r"(field)
                     : "cc");
    return value;
}

static inline void gr_vmwrite_local(uint64_t field, uint64_t value)
{
    __asm__ volatile("vmwrite %[val], %[field]"
                     :
                     : [field] "r"(field), [val] "r"(value)
                     : "cc");
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void gr_cr_guard_init(gr_cr_guard_state_t *state)
{
    if (!state)
        return;

    /*
     * Read the current guest CR0 and CR4 from the VMCS.  At init
     * time the guest has not yet had a chance to tamper, so these
     * values represent the clean baseline.
     */
    state->shadow_cr0 = gr_vmread_local(VMCS_GUEST_CR0);
    state->shadow_cr4 = gr_vmread_local(VMCS_GUEST_CR4);

    GR_LOG("cr_guard: shadow CR0=", state->shadow_cr0);
    GR_LOG("cr_guard: shadow CR4=", state->shadow_cr4);

    /*
     * Build the protection masks.  We intercept:
     *   CR0: WP and PG bits
     *   CR4: SMEP, SMAP, and CET bits
     *
     * Setting a bit in the mask means "exit on guest modification
     * of this bit".  The VMCS read shadow is set to the guest's
     * current value so that reads return what the guest expects.
     */
    state->cr0_mask = CR0_WP | CR0_PG;
    state->cr4_mask = CR4_SMEP | CR4_SMAP | CR4_CET;

    /*
     * Program the VMCS.  The guest-host mask tells the CPU which
     * bits are "owned" by the host.  The read shadow supplies the
     * guest-visible value for those bits on CR reads.
     */
    gr_vmwrite_local(VMCS_CR0_GUEST_HOST_MASK, state->cr0_mask);
    gr_vmwrite_local(VMCS_CR0_READ_SHADOW,     state->shadow_cr0);
    gr_vmwrite_local(VMCS_CR4_GUEST_HOST_MASK, state->cr4_mask);
    gr_vmwrite_local(VMCS_CR4_READ_SHADOW,     state->shadow_cr4);

    state->denied_count = 0;
    state->initialised  = true;

    GR_LOG("cr_guard: CR0 mask=", state->cr0_mask);
    GR_LOG("cr_guard: CR4 mask=", state->cr4_mask);
    GR_LOG_STR("cr_guard: armed — CR0.WP, CR0.PG, CR4.SMEP, CR4.SMAP, CR4.CET protected");
}

bool gr_cr_guard_check_cr0(gr_cr_guard_state_t *state,
                           uint64_t new_cr0,
                           uint64_t guest_rip,
                           uint64_t guest_cr3)
{
    if (!state || !state->initialised)
        return true;  /* Not armed — allow */

    bool deny = false;

    /*
     * Check CR0.WP — must remain set.  Clearing WP allows ring-0 to
     * write to read-only user pages, bypassing copy-on-write and
     * page-level write protection.
     */
    if ((state->shadow_cr0 & CR0_WP) && !(new_cr0 & CR0_WP)) {
        GR_LOG("cr_guard: DENIED — guest clearing CR0.WP, rip=", guest_rip);
        deny = true;
    }

    /*
     * Check CR0.PG — must remain set in long mode.  Clearing PG in
     * long mode causes #GP, but we intercept before the hardware
     * fault to log the attempt (possibly a confused driver or exploit
     * probing).
     */
    if ((state->shadow_cr0 & CR0_PG) && !(new_cr0 & CR0_PG)) {
        GR_LOG("cr_guard: DENIED — guest clearing CR0.PG, rip=", guest_rip);
        deny = true;
    }

    if (deny) {
        state->denied_count++;

        gr_alert_emit(GR_ALERT_CR_TAMPER,
                      guest_rip,
                      guest_cr3,
                      0,              /* GPA not applicable */
                      new_cr0);       /* info = attempted CR0 value */

        return false;
    }

    /*
     * The modification does not touch protected bits, or sets them
     * to the same value.  Allow the write.
     */
    return true;
}

bool gr_cr_guard_check_cr4(gr_cr_guard_state_t *state,
                           uint64_t new_cr4,
                           uint64_t guest_rip,
                           uint64_t guest_cr3)
{
    if (!state || !state->initialised)
        return true;  /* Not armed — allow */

    bool deny = false;

    /*
     * Check CR4.SMEP — clearing this is the most common exploitation
     * primitive for modern Windows kernel exploits.  An attacker who
     * achieves arbitrary kernel write can flip this bit and then
     * execute shellcode from user-mode pages.
     */
    if ((state->shadow_cr4 & CR4_SMEP) && !(new_cr4 & CR4_SMEP)) {
        GR_LOG("cr_guard: DENIED — guest clearing CR4.SMEP, rip=", guest_rip);
        deny = true;
    }

    /*
     * Check CR4.SMAP — prevents ring-0 from reading/writing user
     * pages.  Disabling this opens the door to KASLR bypass via
     * user-mode data reads from kernel context.
     */
    if ((state->shadow_cr4 & CR4_SMAP) && !(new_cr4 & CR4_SMAP)) {
        GR_LOG("cr_guard: DENIED — guest clearing CR4.SMAP, rip=", guest_rip);
        deny = true;
    }

    /*
     * Check CR4.CET — disabling CET removes hardware shadow stack
     * and indirect branch tracking protections.
     */
    if ((state->shadow_cr4 & CR4_CET) && !(new_cr4 & CR4_CET)) {
        GR_LOG("cr_guard: DENIED — guest clearing CR4.CET, rip=", guest_rip);
        deny = true;
    }

    if (deny) {
        state->denied_count++;

        gr_alert_emit(GR_ALERT_CR_TAMPER,
                      guest_rip,
                      guest_cr3,
                      0,              /* GPA not applicable */
                      new_cr4);       /* info = attempted CR4 value */

        return false;
    }

    return true;
}

void gr_cr_guard_get_masks(const gr_cr_guard_state_t *state,
                           uint64_t *cr0_mask,
                           uint64_t *cr4_mask)
{
    if (!state || !state->initialised) {
        if (cr0_mask) *cr0_mask = 0;
        if (cr4_mask) *cr4_mask = 0;
        return;
    }

    if (cr0_mask) *cr0_mask = state->cr0_mask;
    if (cr4_mask) *cr4_mask = state->cr4_mask;
}
