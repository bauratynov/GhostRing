/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * pte_monitor.h — Page table entry manipulation detection (HVPT-style).
 *
 * Exploits overwrite PTEs to bypass SMEP/SMAP:
 *   - Map user pages as kernel-executable (SMEP bypass)
 *   - Create RWX mappings in kernel space
 *   - Redirect kernel code via PFN swap
 *
 * Microsoft ships HVPT in Windows 11 24H2 for exactly this purpose.
 * GhostRing implements the same concept as an open-source alternative.
 *
 * Detection: EPT write-protect guest page table pages.  On PTE write,
 * validate the new mapping against security policy.
 *
 * Reference: Microsoft HVPT blog (2024), Intel VT-rp HLAT (2023).
 */

#ifndef GHOSTRING_MONITOR_PTE_MONITOR_H
#define GHOSTRING_MONITOR_PTE_MONITOR_H

#include "../common/ghostring.h"

/* x86-64 PTE bit definitions for guest page tables */
#define GUEST_PTE_PRESENT   BIT(0)
#define GUEST_PTE_WRITE     BIT(1)
#define GUEST_PTE_USER      BIT(2)
#define GUEST_PTE_PS        BIT(7)   /* large page */
#define GUEST_PTE_NX        BIT(63)  /* no-execute */
#define GUEST_PTE_PFN_MASK  0x000FFFFFFFFFF000ULL

/* Policy violation types */
#define PTE_VIOLATION_NONE          0
#define PTE_VIOLATION_SMEP_BYPASS   1  /* user page becomes kernel-executable */
#define PTE_VIOLATION_RWX_KERNEL    2  /* kernel mapping becomes RWX */
#define PTE_VIOLATION_CODE_REMAP    3  /* kernel code PFN changed */

#define GR_MAX_PT_PAGES  4096

typedef struct {
    uint64_t guest_cr3;
    uint64_t kernel_base;
    uint64_t kernel_size;

    /* Tracked page table page GPAs */
    uint64_t pt_pages[GR_MAX_PT_PAGES];
    uint32_t pt_page_count;

    /* Known-good PFNs for kernel code pages */
    uint64_t code_pfns[1024];
    uint32_t code_pfn_count;
} gr_pte_monitor_state_t;

void gr_pte_monitor_init(gr_pte_monitor_state_t *state,
                         uint64_t cr3,
                         uint64_t kernel_base,
                         uint64_t kernel_size);

/* Track a new page table page for EPT protection */
void gr_pte_monitor_add_pt_page(gr_pte_monitor_state_t *state, uint64_t pt_gpa);

/* Register a known-good kernel code PFN */
void gr_pte_monitor_add_code_pfn(gr_pte_monitor_state_t *state, uint64_t pfn);

/*
 * Validate a PTE write.
 * @old_pte : original PTE value
 * @new_pte : value being written
 *
 * Returns PTE_VIOLATION_NONE if ok, or a violation type code.
 */
int gr_pte_monitor_check(gr_pte_monitor_state_t *state,
                         uint64_t old_pte, uint64_t new_pte);

/* Check if a GPA is a tracked page table page */
bool gr_pte_monitor_is_pt_page(gr_pte_monitor_state_t *state, uint64_t gpa);

#endif /* GHOSTRING_MONITOR_PTE_MONITOR_H */
