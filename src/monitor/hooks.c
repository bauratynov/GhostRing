/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * hooks.c — IDT integrity checking and EPT-based write protection.
 *
 * The IDT is one of the most critical structures on x86: any interrupt
 * or exception dispatches through it.  A modified IDT entry can redirect
 * execution to attacker code for any vector — page faults (#PF),
 * breakpoints (#BP), double faults (#DF), or the legacy INT 0x80
 * system call path.
 *
 * Two defence layers:
 *   1. EPT write-protection — prevents modification in real time.
 *   2. Periodic snapshot comparison — catches any modification that
 *      somehow bypassed EPT (e.g., DMA, or if EPT protection was
 *      temporarily lifted for a legitimate reason).
 */

#include "hooks.h"
#include "alerts.h"
#include "../vmx/vmx_ept.h"

/* ── VMCS read helper (local declaration) ───────────────────────────────── */

/*
 * gr_vmread is defined as a static inline in vmx_vmcs.c.  We declare
 * it here as an extern to avoid pulling in the full VMCS compilation
 * unit.  The linker resolves it via LTO or via a non-static wrapper
 * provided by vmx_vmcs.c.
 */
static inline uint64_t gr_vmread_local(uint64_t field)
{
    uint64_t value;
    __asm__ volatile("vmread %[field], %[val]"
                     : [val] "=r"(value)
                     : [field] "r"(field)
                     : "cc");
    return value;
}

/* ── IDT gate address extraction ────────────────────────────────────────── */

/*
 * Reconstruct the full 64-bit handler address from the three fields
 * in the gate descriptor.
 */
static inline uint64_t gate_handler_addr(const gr_idt_gate_t *gate)
{
    return (uint64_t)gate->offset_low                  |
           ((uint64_t)gate->offset_mid  << 16)         |
           ((uint64_t)gate->offset_high << 32);
}

/*
 * Check whether a gate descriptor is "present" (P bit in type_attr).
 * Non-present gates are not active and should not trigger alerts.
 */
static inline bool gate_is_present(const gr_idt_gate_t *gate)
{
    return (gate->type_attr & 0x80) != 0;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void gr_hooks_init(gr_hooks_state_t *state,
                   uint64_t kernel_text_start,
                   uint64_t kernel_text_end)
{
    if (!state)
        return;

    /*
     * Read the IDTR from the VMCS.  VMCS_GUEST_IDTR_BASE gives the
     * guest-linear address of the IDT; VMCS_GUEST_IDTR_LIMIT gives
     * the byte limit.
     */
    state->idt_base_gva = gr_vmread_local(VMCS_GUEST_IDTR_BASE);
    uint64_t idt_limit  = gr_vmread_local(VMCS_GUEST_IDTR_LIMIT);

    GR_LOG("hooks: IDT base GVA=", state->idt_base_gva);
    GR_LOG("hooks: IDT limit=",    idt_limit);

    /*
     * Sanity check: the IDT should cover at least 256 entries.
     * If the limit is smaller, we only snapshot what is there.
     */
    uint32_t usable_entries = (uint32_t)((idt_limit + 1) / GR_IDT_ENTRY_SIZE);
    if (usable_entries > GR_IDT_ENTRIES)
        usable_entries = GR_IDT_ENTRIES;

    /*
     * Copy the IDT contents.  The IDT GVA is in the kernel's direct-map
     * region, which under our identity-mapped EPT is directly accessible.
     * In a production system this would go through a GVA-to-HVA
     * translation layer.
     */
    const gr_idt_gate_t *live_idt =
        (const gr_idt_gate_t *)(uintptr_t)state->idt_base_gva;

    for (uint32_t i = 0; i < usable_entries; i++)
        state->snapshot[i] = live_idt[i];

    /* Zero remaining entries if IDT is smaller than 256 */
    for (uint32_t i = usable_entries; i < GR_IDT_ENTRIES; i++) {
        gr_idt_gate_t *g = &state->snapshot[i];
        g->offset_low       = 0;
        g->segment_selector = 0;
        g->ist              = 0;
        g->type_attr        = 0;
        g->offset_mid       = 0;
        g->offset_high      = 0;
        g->reserved         = 0;
    }

    /*
     * Store the physical address for EPT protection.  Under the
     * identity-mapped EPT, the GVA of a kernel direct-map address
     * can be converted by masking off the direct-map base.  For
     * simplicity we assume the loader provides this or we derive
     * it from the host CR3 page walk.
     *
     * Placeholder: use the GVA as the physical address.  The caller
     * should set idt_phys correctly if the mapping is non-trivial.
     */
    state->idt_phys = (phys_addr_t)state->idt_base_gva;

    state->kernel_text_start = kernel_text_start;
    state->kernel_text_end   = kernel_text_end;
    state->initialised       = true;

    GR_LOG("hooks: IDT snapshot taken, entries=", (uint64_t)usable_entries);
}

uint32_t gr_hooks_check_idt(gr_hooks_state_t *state)
{
    if (!state || !state->initialised)
        return 0;

    const gr_idt_gate_t *live_idt =
        (const gr_idt_gate_t *)(uintptr_t)state->idt_base_gva;

    uint32_t modified = 0;

    for (uint32_t vec = 0; vec < GR_IDT_ENTRIES; vec++) {
        const gr_idt_gate_t *snap = &state->snapshot[vec];
        const gr_idt_gate_t *live = &live_idt[vec];

        /* Skip non-present entries — nothing to protect */
        if (!gate_is_present(snap) && !gate_is_present(live))
            continue;

        /* Compare the handler address — this is what rootkits change */
        uint64_t snap_addr = gate_handler_addr(snap);
        uint64_t live_addr = gate_handler_addr(live);

        if (snap_addr == live_addr)
            continue;

        modified++;

        /*
         * Classify severity: a handler pointing outside kernel text
         * is almost certainly malicious.  One pointing inside might
         * be a legitimate kernel update (e.g., perf event handler
         * replacement), though this is rare after boot.
         */
        bool outside_kernel = (live_addr < state->kernel_text_start) ||
                              (live_addr >= state->kernel_text_end);

        if (outside_kernel) {
            GR_LOG("hooks: IDT HOOK vec=", (uint64_t)vec);
            GR_LOG("  old_handler=", snap_addr);
            GR_LOG("  new_handler=", live_addr);

            gr_alert_emit(GR_ALERT_IDT_HOOK,
                          live_addr,    /* "RIP" = the malicious handler */
                          0,            /* CR3: not applicable */
                          state->idt_phys + (uint64_t)vec * GR_IDT_ENTRY_SIZE,
                          (uint64_t)vec);
        } else {
            /*
             * Handler moved but still within kernel text.  This could
             * be a legitimate kernel update.  Log but do not alert at
             * the highest severity.
             */
            GR_LOG("hooks: IDT entry changed (in-kernel) vec=", (uint64_t)vec);
            GR_LOG("  old=", snap_addr);
            GR_LOG("  new=", live_addr);
        }
    }

    return modified;
}

void gr_hooks_protect_idt(gr_hooks_state_t *state, gr_ept_ctx_t *ept_ctx)
{
    if (!state || !state->initialised || !ept_ctx)
        return;

    /*
     * The IDT is 4096 bytes, which may span 1 or 2 pages depending on
     * alignment.  Protect all pages that the IDT touches.
     */
    phys_addr_t idt_start = ALIGN_DOWN(state->idt_phys, PAGE_SIZE);
    phys_addr_t idt_end   = ALIGN_UP(state->idt_phys + GR_IDT_TOTAL_SIZE,
                                     PAGE_SIZE);

    for (phys_addr_t page = idt_start; page < idt_end; page += PAGE_SIZE) {
        /*
         * Set EPT permissions to read+execute only — any write attempt
         * will cause an EPT violation VM-exit.
         */
        int ret = gr_vmx_ept_protect_page(ept_ctx, page, EPT_PERM_RX);
        if (ret != 0) {
            GR_LOG("hooks: EPT protect failed for IDT page=", page);
        } else {
            GR_LOG("hooks: EPT write-protected IDT page=", page);
        }
    }

    GR_LOG_STR("hooks: IDT EPT protection active");
}
