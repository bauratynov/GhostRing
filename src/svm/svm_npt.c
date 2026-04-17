/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * svm_npt.c — Nested Page Table construction and manipulation for the
 *              GhostRing SVM backend.
 *
 * Builds an identity-mapped NPT using 2MB large pages.  NPT entries use
 * the standard AMD64 page table format (Present / R-W / User / NX), not
 * EPT-style R/W/X bits.
 *
 * Reference: AMD APM Vol. 2, Section 15.25 ("Nested Paging").
 */

#include "svm_npt.h"

/* -- Intrinsics ----------------------------------------------------------- */

static inline uint64_t gr_rdmsr_npt(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline phys_addr_t virt_to_phys_npt(const void *va)
{
    return (phys_addr_t)(uintptr_t)va;
}

/* -- Helpers -------------------------------------------------------------- */

/*
 * Zero a page-sized region.
 */
static void
zero_page(void *page)
{
    uint64_t *p = (uint64_t *)page;
    for (uint32_t i = 0; i < PAGE_SIZE / sizeof(uint64_t); i++)
        p[i] = 0;
}

/* =========================================================================
 * gr_svm_mtrr_init — Enumerate variable MTRRs
 * See APM Vol. 2, Section 7.8.
 * ========================================================================= */

void
gr_svm_mtrr_init(gr_npt_ctx_t *ctx)
{
    /*
     * Read IA32_MTRRCAP to determine the number of variable-range MTRRs.
     * Bits 7:0 contain the count.
     */
    uint64_t mtrr_cap = gr_rdmsr_npt(SVM_MTRR_MSR_CAPABILITIES);
    uint32_t var_count = (uint32_t)(mtrr_cap & 0xFF);

    if (var_count > SVM_MTRR_MAX_VARIABLE_RANGES)
        var_count = SVM_MTRR_MAX_VARIABLE_RANGES;

    ctx->mtrr_count = 0;

    for (uint32_t i = 0; i < var_count; i++) {
        uint64_t base_msr = gr_rdmsr_npt(SVM_MTRR_MSR_VARIABLE_BASE + i * 2);
        uint64_t mask_msr = gr_rdmsr_npt(SVM_MTRR_MSR_VARIABLE_MASK + i * 2);

        /* Bit 11 of the mask MSR indicates the range is enabled */
        if (!(mask_msr & BIT(11)))
            continue;

        gr_svm_mtrr_range_t *range = &ctx->mtrr[ctx->mtrr_count];
        range->type      = (uint32_t)(base_msr & 0xFF);
        range->enabled   = 1;

        /*
         * Physical base = bits 51:12 of base MSR, shifted left by 12.
         * Physical mask = bits 51:12 of mask MSR, shifted left by 12.
         * Range: base ... base | ~mask.
         */
        uint64_t phys_base = base_msr & 0x000FFFFFFFFFF000ULL;
        uint64_t phys_mask = mask_msr & 0x000FFFFFFFFFF000ULL;

        range->phys_base = phys_base;
        range->phys_end  = phys_base | (~phys_mask & 0x000FFFFFFFFFULL);

        ctx->mtrr_count++;
    }
}

/* =========================================================================
 * gr_svm_mtrr_adjust — Resolve MTRR type for a 2MB region
 * ========================================================================= */

uint32_t
gr_svm_mtrr_adjust(const gr_npt_ctx_t *ctx,
                    uint64_t large_page_addr,
                    uint32_t candidate_type)
{
    uint64_t region_end = large_page_addr + _2MB - 1;

    for (uint32_t i = 0; i < ctx->mtrr_count; i++) {
        const gr_svm_mtrr_range_t *r = &ctx->mtrr[i];
        if (!r->enabled)
            continue;

        /* Check for overlap */
        if (large_page_addr <= r->phys_end && region_end >= r->phys_base) {
            /*
             * MTRR precedence: UC beats all, then WT beats WB.
             * See APM Vol. 2, Section 7.8.2.
             */
            if (r->type == SVM_MTRR_TYPE_UC)
                return SVM_MTRR_TYPE_UC;
            if (candidate_type == SVM_MTRR_TYPE_WB && r->type == SVM_MTRR_TYPE_WT)
                candidate_type = SVM_MTRR_TYPE_WT;
            else if (r->type < candidate_type)
                candidate_type = r->type;
        }
    }

    return candidate_type;
}

/* =========================================================================
 * gr_svm_npt_init — Build identity-mapped NPT with 2MB large pages
 * See APM Vol. 2, Section 15.25.5.
 * ========================================================================= */

void
gr_svm_npt_init(gr_npt_ctx_t *ctx)
{
    /*
     * Zero all page table memory before use.  In a freestanding
     * environment the pool allocator does this, but we are defensive.
     */
    zero_page(ctx->pml4);
    zero_page(ctx->pdpt);

    /* -- PML4 entries --
     *
     * We populate only PML4[0] to cover the first 512 GB.  Each PML4 entry
     * maps 512 GB = 512 PDPT entries.
     */
    npt_pml4e_t pml4e = {0};
    pml4e.present = 1;
    pml4e.write   = 1;
    pml4e.user    = 1;     /* Needed for nested paging user-mode access */
    pml4e.pfn     = virt_to_phys_npt(ctx->pdpt) >> PAGE_SHIFT;
    ctx->pml4[0]  = pml4e;

    /* -- PDPT entries --
     *
     * Each PDPT entry points to a page directory (512 PDEs = 1 GB).
     */
    for (uint32_t i = 0; i < NPT_PDPTE_COUNT; i++) {
        npt_pdpte_t pdpte = {0};
        pdpte.present = 1;
        pdpte.write   = 1;
        pdpte.user    = 1;
        pdpte.pfn     = virt_to_phys_npt(&ctx->pde[i][0]) >> PAGE_SHIFT;
        ctx->pdpt[i]  = pdpte;
    }

    /* -- PDE entries (2MB large pages) --
     *
     * Identity map: GPA == HPA for each 2MB region.
     * Memory type defaults to WB, adjusted by MTRR.
     */
    for (uint32_t i = 0; i < NPT_PDPTE_COUNT; i++) {
        for (uint32_t j = 0; j < NPT_PDE_COUNT; j++) {
            uint64_t phys_addr = ((uint64_t)i * _1GB) + ((uint64_t)j * _2MB);

            /* Resolve effective memory type via MTRR */
            uint32_t mem_type = gr_svm_mtrr_adjust(ctx, phys_addr,
                                                    SVM_MTRR_TYPE_WB);

            npt_pde_2mb_t pde = {0};
            pde.present = 1;
            pde.write   = 1;
            pde.user    = 1;
            pde.large   = 1;       /* 2MB page */
            pde.pfn     = (uint32_t)(phys_addr >> 21);

            /*
             * NPT uses standard PAT/PWT/PCD encoding for memory types,
             * unlike EPT which has explicit mem_type bits.
             *
             * WB  = PAT=0, PWT=0, PCD=0 (default)
             * UC  = PAT=0, PWT=0, PCD=1
             * WC  = PAT=0, PWT=1, PCD=0
             * WT  = PAT=0, PWT=1, PCD=1
             *
             * See APM Vol. 2, Section 7.8.
             */
            switch (mem_type) {
            case SVM_MTRR_TYPE_UC:
                pde.pcd = 1;
                break;
            case SVM_MTRR_TYPE_WC:
                pde.pwt = 1;
                break;
            case SVM_MTRR_TYPE_WT:
                pde.pwt = 1;
                pde.pcd = 1;
                break;
            case SVM_MTRR_TYPE_WB:
            default:
                /* PAT=0, PWT=0, PCD=0 for WB */
                break;
            }

            ctx->pde[i][j] = pde;
        }
    }

    /* Store the physical address of PML4 for the VMCB nCR3 field */
    ctx->ncr3 = virt_to_phys_npt(ctx->pml4);
}

/* =========================================================================
 * gr_svm_npt_protect_page — Change permissions for a single 4KB page
 *
 * NPT uses standard page table permission bits:
 *   - Present bit  = page is accessible (read implied by present)
 *   - Write bit    = page is writable
 *   - NX bit       = page is NOT executable (inverted from EXEC)
 *
 * If the target page is inside a 2MB large page, this function splits
 * the 2MB entry into 512 individual 4KB PTEs first.
 * ========================================================================= */

int
gr_svm_npt_protect_page(gr_npt_ctx_t *ctx,
                        phys_addr_t gpa,
                        uint32_t perms)
{
    /* Decompose GPA into table indices */
    uint64_t aligned_gpa = ALIGN_DOWN(gpa, PAGE_SIZE);
    uint32_t pml4_idx = (uint32_t)((aligned_gpa >> 39) & 0x1FF);
    uint32_t pdpt_idx = (uint32_t)((aligned_gpa >> 30) & 0x1FF);
    uint32_t pde_idx  = (uint32_t)((aligned_gpa >> 21) & 0x1FF);
    uint32_t pte_idx  = (uint32_t)((aligned_gpa >> 12) & 0x1FF);

    /* We only map PML4[0] — reject addresses beyond 512 GB */
    if (pml4_idx != 0)
        return -1;

    /*
     * Check if the target PDE is a 2MB large page.  If so, we must split
     * it into a 4KB page table first.
     */
    npt_pde_2mb_t *large_pde = &ctx->pde[pdpt_idx][pde_idx];

    if (large_pde->large) {
        /*
         * Allocate a page table page from the pool.  In a freestanding
         * environment we use gr_alloc_page().  The caller must ensure the
         * pool is initialised.
         */
        extern void *gr_alloc_page(gr_page_pool_t *pool);
        extern gr_page_pool_t gr_hv_pool;

        npt_pte_t *pt = (npt_pte_t *)gr_alloc_page(&gr_hv_pool);
        if (!pt)
            return -1;

        /* Populate the 512 4KB PTEs to reproduce the 2MB mapping */
        uint64_t base_2mb = (uint64_t)large_pde->pfn << 21;
        for (uint32_t k = 0; k < NPT_PTE_COUNT; k++) {
            npt_pte_t pte = {0};
            pte.present = large_pde->present;
            pte.write   = large_pde->write;
            pte.user    = large_pde->user;
            pte.pwt     = large_pde->pwt;
            pte.pcd     = large_pde->pcd;
            pte.pfn     = (base_2mb + k * PAGE_SIZE) >> PAGE_SHIFT;
            /* NX inherits from large page (which defaults to 0 = executable) */
            pt[k] = pte;
        }

        /* Replace the 2MB PDE with a non-leaf PDE pointing to the PT */
        npt_pde_t new_pde = {0};
        new_pde.present = 1;
        new_pde.write   = 1;
        new_pde.user    = 1;
        new_pde.pfn     = virt_to_phys_npt(pt) >> PAGE_SHIFT;
        /* large = 0 (non-leaf) */

        /* Write the new PDE — alias through a pointer cast since the union
         * layouts overlap at the same offset. */
        *(npt_pde_t *)large_pde = new_pde;
    }

    /*
     * At this point the PDE is non-leaf and points to a 4KB page table.
     * Read the PFN from the PDE to locate the page table.
     */
    npt_pde_t *pde_ptr = (npt_pde_t *)large_pde;
    npt_pte_t *pt = (npt_pte_t *)(uintptr_t)(pde_ptr->pfn << PAGE_SHIFT);
    npt_pte_t *target_pte = &pt[pte_idx];

    /*
     * Apply permissions using standard page table encoding:
     *   - Present = readable (if read permission is granted)
     *   - Write   = writable
     *   - NX      = NOT executable (inverted logic)
     */
    if (perms == NPT_PERM_NONE) {
        target_pte->present = 0;
        target_pte->write   = 0;
        target_pte->nx      = 1;
    } else {
        target_pte->present = (perms & NPT_PERM_READ)  ? 1 : 0;
        target_pte->write   = (perms & NPT_PERM_WRITE) ? 1 : 0;
        target_pte->nx      = (perms & NPT_PERM_EXEC)  ? 0 : 1;
    }

    return 0;
}
