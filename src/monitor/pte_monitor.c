/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

#include "pte_monitor.h"
#include "alerts.h"

void gr_pte_monitor_init(gr_pte_monitor_state_t *state,
                         uint64_t cr3,
                         uint64_t kernel_base,
                         uint64_t kernel_size)
{
    state->guest_cr3 = cr3;
    state->kernel_base = kernel_base;
    state->kernel_size = kernel_size;
    state->pt_page_count = 0;
    state->code_pfn_count = 0;
}

void gr_pte_monitor_add_pt_page(gr_pte_monitor_state_t *state, uint64_t pt_gpa)
{
    if (state->pt_page_count >= GR_MAX_PT_PAGES)
        return;
    state->pt_pages[state->pt_page_count++] = pt_gpa;
}

void gr_pte_monitor_add_code_pfn(gr_pte_monitor_state_t *state, uint64_t pfn)
{
    if (state->code_pfn_count >= 1024)
        return;
    state->code_pfns[state->code_pfn_count++] = pfn;
}

/*
 * Check if a PFN is a known kernel code page.
 */
static bool is_code_pfn(gr_pte_monitor_state_t *state, uint64_t pfn)
{
    for (uint32_t i = 0; i < state->code_pfn_count; i++)
        if (state->code_pfns[i] == pfn)
            return true;
    return false;
}

int gr_pte_monitor_check(gr_pte_monitor_state_t *state,
                         uint64_t old_pte, uint64_t new_pte)
{
    /* Only care about present entries */
    if (!(new_pte & GUEST_PTE_PRESENT))
        return PTE_VIOLATION_NONE;

    uint64_t new_pfn = (new_pte & GUEST_PTE_PFN_MASK) >> 12;
    bool is_user    = (new_pte & GUEST_PTE_USER) != 0;
    bool is_write   = (new_pte & GUEST_PTE_WRITE) != 0;
    bool is_exec    = (new_pte & GUEST_PTE_NX) == 0;  /* NX=0 means executable */
    bool was_user   = (old_pte & GUEST_PTE_USER) != 0;

    /*
     * SMEP bypass detection: a page transitions from user-mode to
     * kernel-executable.  SMEP prevents the kernel from executing
     * user pages, so attackers clear the User bit in the PTE.
     *
     * Classic exploit pattern: user-mode shellcode page, then clear
     * PTE.User bit → kernel can now execute it.
     */
    if (was_user && !is_user && is_exec) {
        GR_LOG("PTE: SMEP bypass — user→kernel exec at PFN ", new_pfn);
        return PTE_VIOLATION_SMEP_BYPASS;
    }

    /*
     * RWX kernel mapping: kernel pages should never be simultaneously
     * writable and executable.  W^X policy enforcement.
     */
    if (!is_user && is_write && is_exec) {
        /* Allow known code pages that are legitimately RX (not RWX) */
        if (!is_code_pfn(state, new_pfn)) {
            GR_LOG("PTE: RWX kernel mapping at PFN ", new_pfn);
            return PTE_VIOLATION_RWX_KERNEL;
        }
    }

    /*
     * Kernel code PFN remap: if a PTE that previously pointed to a
     * kernel code page now points somewhere else, it might be a code
     * redirection attack.
     */
    if (old_pte & GUEST_PTE_PRESENT) {
        uint64_t old_pfn = (old_pte & GUEST_PTE_PFN_MASK) >> 12;
        if (is_code_pfn(state, old_pfn) && new_pfn != old_pfn) {
            GR_LOG("PTE: kernel code PFN changed ", old_pfn);
            return PTE_VIOLATION_CODE_REMAP;
        }
    }

    return PTE_VIOLATION_NONE;
}

bool gr_pte_monitor_is_pt_page(gr_pte_monitor_state_t *state, uint64_t gpa)
{
    uint64_t page = gpa & PAGE_MASK;
    for (uint32_t i = 0; i < state->pt_page_count; i++)
        if (state->pt_pages[i] == page)
            return true;
    return false;
}
