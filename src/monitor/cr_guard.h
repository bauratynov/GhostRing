/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * cr_guard.h — Control register protection (CR0 and CR4).
 *
 * Certain bits in CR0 and CR4 are critical for security enforcement:
 *
 *   CR0.WP (bit 16) — Write Protect: when set, prevents ring-0 code
 *     from writing to read-only user-mode pages.  Clearing this bit
 *     allows a rootkit to overwrite user-mode code pages (e.g., to
 *     patch ntdll.dll syscall stubs without triggering copy-on-write).
 *
 *   CR0.PG (bit 31) — Paging: disabling paging in long mode causes
 *     a #GP, but in legacy mode it can be used to bypass all page-level
 *     protections.
 *
 *   CR4.SMEP (bit 20) — Supervisor Mode Execution Prevention: prevents
 *     ring-0 from executing code in user-mode pages.  Clearing SMEP is
 *     a well-known exploitation primitive (e.g., used by Hacking Team's
 *     Windows kernel exploit).
 *
 *   CR4.SMAP (bit 21) — Supervisor Mode Access Prevention: prevents
 *     ring-0 from reading/writing user-mode pages unless EFLAGS.AC is
 *     set.  Clearing SMAP weakens KASLR bypass mitigations.
 *
 *   CR4.CET (bit 23) — Control-flow Enforcement Technology: enables
 *     hardware shadow stacks and indirect branch tracking.  Clearing
 *     this disables CFI protections.
 *
 * We use the VMCS guest-host mask to intercept MOV-to-CR0 and
 * MOV-to-CR4 that would modify these bits.  The read shadow presents
 * the guest's expected value while we silently enforce our policy.
 *
 * Reference: Intel SDM Vol. 3C, Section 24.6.6 (Guest/Host Masks and
 * Read Shadows for CR0 and CR4).
 */

#ifndef GHOSTRING_MONITOR_CR_GUARD_H
#define GHOSTRING_MONITOR_CR_GUARD_H

#include "../common/ghostring.h"

/* ── CR0 bit definitions ────────────────────────────────────────────────── */

#define CR0_PE      BIT(0)      /* Protected mode enable                   */
#define CR0_WP      BIT(16)     /* Write protect                           */
#define CR0_PG      BIT(31)     /* Paging                                  */

/* ── CR4 bit definitions ────────────────────────────────────────────────── */

#define CR4_SMEP    BIT(20)     /* Supervisor Mode Execution Prevention    */
#define CR4_SMAP    BIT(21)     /* Supervisor Mode Access Prevention       */
#define CR4_CET     BIT(23)     /* Control-flow Enforcement Technology     */

/* ── CR guard state ─────────────────────────────────────────────────────── */

typedef struct gr_cr_guard_state {
    /*
     * Shadow copies of CR0 and CR4 captured at init time.  These
     * represent the "known-good" configuration.
     */
    uint64_t shadow_cr0;
    uint64_t shadow_cr4;

    /*
     * Masks specifying which bits we protect.  A set bit in the mask
     * means "intercept MOV-to-CRx for this bit".
     */
    uint64_t cr0_mask;
    uint64_t cr4_mask;

    uint32_t denied_count;      /* Number of denied CR modifications     */
    bool     initialised;
} gr_cr_guard_state_t;

/* ── Public API ─────────────────────────────────────────────────────────── */

/*
 * gr_cr_guard_init — Capture current CR0 and CR4 values and configure
 *                    the guest-host masks in the VMCS.
 *
 * After this call, any guest attempt to clear the protected bits will
 * trigger a VM-exit, which is handled by gr_cr_guard_check_cr0/cr4.
 *
 * @state : CR guard state to initialise.
 */
void gr_cr_guard_init(gr_cr_guard_state_t *state);

/*
 * gr_cr_guard_check_cr0 — Evaluate a guest MOV-to-CR0.
 *
 * @state   : CR guard state.
 * @new_cr0 : Value the guest is trying to load into CR0.
 *
 * Returns true if the write is allowed, false if blocked.
 * On block emits GR_ALERT_CR_TAMPER.
 */
bool gr_cr_guard_check_cr0(gr_cr_guard_state_t *state,
                           uint64_t new_cr0,
                           uint64_t guest_rip,
                           uint64_t guest_cr3);

/*
 * gr_cr_guard_check_cr4 — Evaluate a guest MOV-to-CR4.
 *
 * @state   : CR guard state.
 * @new_cr4 : Value the guest is trying to load into CR4.
 *
 * Returns true if the write is allowed, false if blocked.
 * On block emits GR_ALERT_CR_TAMPER.
 */
bool gr_cr_guard_check_cr4(gr_cr_guard_state_t *state,
                           uint64_t new_cr4,
                           uint64_t guest_rip,
                           uint64_t guest_cr3);

/*
 * gr_cr_guard_get_masks — Return the CR0 and CR4 masks for VMCS
 *                          guest-host mask fields.
 *
 * The caller writes these into VMCS_CR0_GUEST_HOST_MASK and
 * VMCS_CR4_GUEST_HOST_MASK respectively.
 *
 * @state     : CR guard state.
 * @cr0_mask  : Output — mask for CR0.
 * @cr4_mask  : Output — mask for CR4.
 */
void gr_cr_guard_get_masks(const gr_cr_guard_state_t *state,
                           uint64_t *cr0_mask,
                           uint64_t *cr4_mask);

#endif /* GHOSTRING_MONITOR_CR_GUARD_H */
