/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * vmx_ept.c — Extended Page Table construction and management.
 *
 * Builds an identity-mapped EPT hierarchy with 2MB large pages and
 * MTRR-adjusted memory types.  Supports per-page permission changes
 * with automatic 2MB-to-4KB splitting.
 *
 * Reference: Intel SDM Vol. 3C, Chapter 28.
 */

#include "vmx_ept.h"

/* ── Intrinsics (GCC/Clang inline assembly) ────────────────────────────── */

/* Use gr_rdmsr from common/cpu.h — no local duplicate */

/*
 * Bit-scan-forward for 64-bit values.  Returns the index of the lowest
 * set bit, or -1 if the value is zero.
 */
static inline int gr_bsf64(uint64_t val)
{
    if (val == 0)
        return -1;
    uint64_t idx;
    __asm__ volatile("bsfq %1, %0" : "=r"(idx) : "rm"(val));
    return (int)idx;
}

/*
 * Obtain the physical address of a kernel-virtual pointer.
 * In a freestanding hypervisor running with an identity-mapped page table
 * the virtual address equals the physical address.  If the platform layer
 * provides a different mapping, override this with a proper implementation.
 */
/* Use gr_virt_to_phys from platform.h — no hardcoded identity mapping */
#define virt_to_phys(va) gr_virt_to_phys((void *)(va))

/* ═══════════════════════════════════════════════════════════════════════════
 * MTRR Enumeration — See SDM Vol. 3A, Section 11.11
 * ═══════════════════════════════════════════════════════════════════════════ */

void
gr_vmx_mtrr_init(gr_ept_ctx_t *ctx)
{
    mtrr_cap_t cap;
    cap.raw = gr_rdmsr(MTRR_MSR_CAPABILITIES);

    uint32_t count = (uint32_t)cap.var_cnt;
    if (count > MTRR_MAX_VARIABLE_RANGES)
        count = MTRR_MAX_VARIABLE_RANGES;

    ctx->mtrr_count = count;

    for (uint32_t i = 0; i < count; i++) {
        mtrr_var_base_t base;
        mtrr_var_mask_t mask;

        base.raw = gr_rdmsr(MTRR_MSR_VARIABLE_BASE + i * 2);
        mask.raw = gr_rdmsr(MTRR_MSR_VARIABLE_BASE + 1 + i * 2);

        ctx->mtrr[i].type    = (uint32_t)base.type;
        ctx->mtrr[i].enabled = (uint32_t)mask.enabled;

        if (ctx->mtrr[i].enabled) {
            /*
             * The range base is bits 35:0 of phys_base shifted left by 12.
             * The range length is derived from the lowest set bit in the
             * physical mask field (also shifted left by 12).
             */
            ctx->mtrr[i].phys_base = base.phys_base * MTRR_PAGE_SIZE;

            int bit = gr_bsf64(mask.phys_mask * MTRR_PAGE_SIZE);
            if (bit >= 0) {
                ctx->mtrr[i].phys_end = ctx->mtrr[i].phys_base +
                                        (1ULL << bit) - 1;
            }
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MTRR type adjustment for 2MB pages
 * ═══════════════════════════════════════════════════════════════════════════ */

uint32_t
gr_vmx_mtrr_adjust(const gr_ept_ctx_t *ctx,
                    uint64_t large_page_addr,
                    uint32_t candidate_type)
{
    /*
     * If any 4KB sub-page of this 2MB region falls inside an active MTRR
     * range, the MTRR type overrides the candidate.  This is a conservative
     * approach: the entire 2MB page inherits the MTRR type.
     * See SDM Vol. 3A, Section 11.11.4.1.
     */
    for (uint32_t i = 0; i < ctx->mtrr_count; i++) {
        if (!ctx->mtrr[i].enabled)
            continue;

        uint64_t page_end = large_page_addr + _2MB - 1;
        if (page_end >= ctx->mtrr[i].phys_base &&
            large_page_addr <= ctx->mtrr[i].phys_end) {
            candidate_type = ctx->mtrr[i].type;
        }
    }

    return candidate_type;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * EPT identity-map construction — See SDM Vol. 3C, Section 28.2.2
 * ═══════════════════════════════════════════════════════════════════════════ */

void
gr_vmx_ept_init(gr_ept_ctx_t *ctx)
{
    /*
     * Step 1: PML4[0] — single entry covering the first 512 GB.
     * Points to the PDPT table.
     */
    ctx->pml4[0].raw      = 0;
    ctx->pml4[0].read     = 1;
    ctx->pml4[0].write    = 1;
    ctx->pml4[0].execute  = 1;
    ctx->pml4[0].pfn      = virt_to_phys(&ctx->pdpt[0]) >> PAGE_SHIFT;

    /*
     * Step 2: Fill PDPT entries — each covers 1 GB and points to its
     * own page directory (array of 512 x 2MB entries).
     */
    for (uint32_t i = 0; i < PDPTE_COUNT; i++) {
        ctx->pdpt[i].raw     = 0;
        ctx->pdpt[i].read    = 1;
        ctx->pdpt[i].write   = 1;
        ctx->pdpt[i].execute = 1;
        ctx->pdpt[i].pfn     = virt_to_phys(&ctx->pde[i][0]) >> PAGE_SHIFT;
    }

    /*
     * Step 3: Fill PDE entries — each is a 2MB large-page leaf entry
     * with an identity mapping (GPA == HPA) and MTRR-adjusted type.
     */
    for (uint32_t i = 0; i < PDPTE_COUNT; i++) {
        for (uint32_t j = 0; j < PDE_COUNT; j++) {
            uint64_t page_pfn  = (uint64_t)(i * PDE_COUNT + j);
            uint64_t page_addr = page_pfn * _2MB;

            ctx->pde[i][j].raw      = 0;
            ctx->pde[i][j].read     = 1;
            ctx->pde[i][j].write    = 1;
            ctx->pde[i][j].execute  = 1;
            ctx->pde[i][j].large    = 1;
            ctx->pde[i][j].pfn      = (uint32_t)page_pfn;
            ctx->pde[i][j].mem_type = gr_vmx_mtrr_adjust(ctx, page_addr,
                                                          MTRR_TYPE_WB);
        }
    }

    /*
     * Step 4: Construct EPTP — WB memory type, 4-level walk (length=3),
     * PML4 physical address.  See SDM Vol. 3C, Section 24.6.11.
     */
    ctx->eptp.raw         = 0;
    ctx->eptp.mem_type    = MTRR_TYPE_WB;
    ctx->eptp.walk_length = 3;  /* 4-level walk minus 1 */
    ctx->eptp.pfn         = virt_to_phys(&ctx->pml4[0]) >> PAGE_SHIFT;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * EPT page protection — split 2MB pages and adjust permissions
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Use the platform allocator from platform.h for contiguous page alloc.
 * Simple wrapper since this file needs a single zeroed page.
 */
#include "../common/platform.h"

static inline void *gr_ept_alloc_page(void)
{
    return gr_platform_alloc_pages(1);
}

int
gr_vmx_ept_protect_page(gr_ept_ctx_t *ctx,
                         phys_addr_t gpa,
                         uint32_t perms)
{
    /* Decompose GPA into EPT table indices */
    uint64_t aligned      = ALIGN_DOWN(gpa, PAGE_SIZE);
    uint32_t pdpt_idx     = (uint32_t)((aligned >> 30) & 0x1FF);
    uint32_t pde_idx      = (uint32_t)((aligned >> 21) & 0x1FF);
    uint32_t pte_idx      = (uint32_t)((aligned >> 12) & 0x1FF);

    ept_pde_2mb_t *pde    = &ctx->pde[pdpt_idx][pde_idx];

    /*
     * If the PDE is still a 2MB large page we need to split it into a
     * full 4KB page table before adjusting a single page.
     */
    if (pde->large) {
        ept_pte_t *pt = (ept_pte_t *)gr_ept_alloc_page();
        if (!pt)
            return -1;

        /* Populate all 512 PTEs to preserve the identity mapping */
        uint64_t base_pfn = (uint64_t)pde->pfn << 9;  /* 2MB PFN -> 4KB PFN */
        uint32_t mem_type = (uint32_t)pde->mem_type;

        for (uint32_t k = 0; k < PTE_COUNT; k++) {
            pt[k].raw      = 0;
            pt[k].read     = 1;
            pt[k].write    = 1;
            pt[k].execute  = 1;
            pt[k].pfn      = base_pfn + k;
            pt[k].mem_type = mem_type;
        }

        /*
         * Convert the PDE from a large-page leaf to a non-leaf entry
         * pointing to our new page table.  We rewrite via a raw ept_pde_t
         * overlay to avoid large-page bit-field confusion.
         */
        ept_pde_t new_pde;
        new_pde.raw     = 0;
        new_pde.read    = 1;
        new_pde.write   = 1;
        new_pde.execute = 1;
        new_pde.pfn     = virt_to_phys(pt) >> PAGE_SHIFT;

        /* Atomic-width store: a single 64-bit write is atomic on x86-64 */
        *(volatile uint64_t *)pde = new_pde.raw;
    }

    /*
     * The PDE is now a non-leaf pointer to a 4KB page table.
     * Read the PFN and locate the PTE.
     */
    ept_pde_t *pde_nonleaf = (ept_pde_t *)pde;
    ept_pte_t *pt = (ept_pte_t *)((uintptr_t)(pde_nonleaf->pfn << PAGE_SHIFT));
    ept_pte_t *pte = &pt[pte_idx];

    /* Apply the requested permissions */
    pte->read    = (perms & EPT_PERM_READ)  ? 1 : 0;
    pte->write   = (perms & EPT_PERM_WRITE) ? 1 : 0;
    pte->execute = (perms & EPT_PERM_EXEC)  ? 1 : 0;

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * INVEPT helper — See SDM Vol. 3C, Section 30.3
 * ═══════════════════════════════════════════════════════════════════════════ */

void
gr_vmx_invept(uint32_t type, uint64_t eptp)
{
    invept_desc_t desc;
    desc.eptp     = eptp;
    desc.reserved = 0;

    /*
     * INVEPT — Invalidate EPT-derived translations.
     * Encoding: 66 0F 38 80 /r   (operand is memory, type is register).
     */
    __asm__ volatile(
        "invept %[desc], %[type]"
        :
        : [desc] "m"(desc), [type] "r"((uint64_t)type)
        : "memory", "cc"
    );
}
