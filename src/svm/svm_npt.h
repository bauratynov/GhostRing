/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * svm_npt.h — Nested Page Table (NPT) management interface for the
 *              GhostRing SVM backend.
 *
 * Provides MTRR enumeration, identity-mapped NPT construction with 2MB
 * large pages, per-page permission adjustment (with 2MB-to-4KB splitting),
 * and TLB flush helpers.
 *
 * NPT uses the standard AMD64 page table format (Present/R-W/User/NX),
 * NOT EPT-style R/W/X bits.  This is the key architectural difference
 * from Intel's Extended Page Tables.
 *
 * Reference: AMD APM Vol. 2, Section 15.25 ("Nested Paging").
 */

#ifndef GHOSTRING_SVM_NPT_H
#define GHOSTRING_SVM_NPT_H

#include "svm_defs.h"

/* -- MTRR range descriptor ------------------------------------------------ */

typedef struct gr_svm_mtrr_range {
    uint64_t phys_base;     /* Start of the range (page-aligned)           */
    uint64_t phys_end;      /* Last byte covered (inclusive)                */
    uint32_t type;          /* SVM_MTRR_TYPE_* constant                    */
    uint32_t enabled;       /* Non-zero when the variable MTRR is active   */
} gr_svm_mtrr_range_t;

/* -- Per-vCPU NPT context ------------------------------------------------- */

/*
 * Every virtual processor owns an independent NPT hierarchy so that page
 * permissions can be adjusted without cross-CPU synchronisation on the
 * fast path.
 *
 * Layout:
 *   pml4[512]               -- single PML4 page
 *   pdpt[512]               -- single PDPT page
 *   pde[512][512]           -- one PDE page per PDPT entry (2MB leaves)
 *
 * When a 2MB entry must be split, the split page tables are allocated from
 * the hypervisor page pool and linked in place.
 */
typedef struct gr_npt_ctx {
    /* NPT page tables -- must be page-aligned */
    npt_pml4e_t   pml4[NPT_PML4E_COUNT]  GR_ALIGNED(PAGE_SIZE);
    npt_pdpte_t   pdpt[NPT_PDPTE_COUNT]  GR_ALIGNED(PAGE_SIZE);
    npt_pde_2mb_t pde[NPT_PDPTE_COUNT][NPT_PDE_COUNT] GR_ALIGNED(PAGE_SIZE);

    /* MTRR snapshot taken during init */
    gr_svm_mtrr_range_t mtrr[SVM_MTRR_MAX_VARIABLE_RANGES];
    uint32_t            mtrr_count;

    /* Physical address of PML4 root for nCR3 in VMCB */
    phys_addr_t         ncr3;
} gr_npt_ctx_t;

/* -- Public API ----------------------------------------------------------- */

/*
 * gr_svm_mtrr_init -- Enumerate variable MTRR ranges from hardware and
 *                      store them in npt_ctx->mtrr[].
 * See APM Vol. 2, Section 7.8.
 */
void gr_svm_mtrr_init(gr_npt_ctx_t *ctx);

/*
 * gr_svm_mtrr_adjust -- For a given 2MB large-page base address, check
 *                        whether any variable MTRR overrides the candidate
 *                        memory type.
 * Returns the effective memory type for the NPT entry PAT/PWT/PCD bits.
 */
uint32_t gr_svm_mtrr_adjust(const gr_npt_ctx_t *ctx,
                             uint64_t large_page_addr,
                             uint32_t candidate_type);

/*
 * gr_svm_npt_init -- Build a full identity-mapped NPT (4-level, 2MB pages)
 *                     covering the first 512 GB of physical memory.
 * Must be called after gr_svm_mtrr_init().
 */
void gr_svm_npt_init(gr_npt_ctx_t *ctx);

/*
 * gr_svm_npt_protect_page -- Change NPT permissions for a single 4KB guest
 *                             physical page.  If the page sits inside a 2MB
 *                             entry the function transparently splits it
 *                             into a full 4KB page table first.
 * @gpa   : Guest physical address (any alignment, page-aligned internally).
 * @perms : Bitmask of NPT_PERM_READ / WRITE / EXEC.
 *
 * Returns 0 on success, -1 if the split allocation fails.
 */
int gr_svm_npt_protect_page(gr_npt_ctx_t *ctx,
                            phys_addr_t gpa,
                            uint32_t perms);

#endif /* GHOSTRING_SVM_NPT_H */
