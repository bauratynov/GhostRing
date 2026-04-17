/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * vmx_ept.h — Extended Page Table (EPT) management interface.
 *
 * Provides MTRR enumeration, identity-mapped EPT construction with 2MB
 * large pages, per-page permission adjustment (with 2MB-to-4KB splitting),
 * and INVEPT helpers.
 *
 * Reference: Intel SDM Vol. 3C, Chapter 28 ("VMX Support for Address
 * Translation").
 */

#ifndef GHOSTRING_VMX_EPT_H
#define GHOSTRING_VMX_EPT_H

#include "vmx_defs.h"

/* ── MTRR range descriptor ─────────────────────────────────────────────── */

typedef struct gr_mtrr_range {
    uint64_t phys_base;     /* Start of the range (page-aligned)           */
    uint64_t phys_end;      /* Last byte covered (inclusive)                */
    uint32_t type;          /* MTRR_TYPE_* constant                        */
    uint32_t enabled;       /* Non-zero when the variable MTRR is active   */
} gr_mtrr_range_t;

/* ── Per-vCPU EPT context ──────────────────────────────────────────────── */

/*
 * Every virtual processor owns an independent EPT hierarchy so that page
 * permissions can be adjusted without cross-CPU synchronisation on the
 * fast path.
 *
 * Layout:
 *   pml4[512]               — single PML4 page
 *   pdpt[512]               — single PDPT page
 *   pde[512][512]           — one PDE page per PDPT entry (2MB leaves)
 *
 * When a 2MB entry must be split, the split page tables are allocated from
 * the hypervisor page pool and linked in place.
 */
typedef struct gr_ept_ctx {
    /* EPT page tables — must be page-aligned */
    ept_pml4e_t   pml4[PML4E_COUNT]  GR_ALIGNED(PAGE_SIZE);
    ept_pdpte_t   pdpt[PDPTE_COUNT]  GR_ALIGNED(PAGE_SIZE);
    ept_pde_2mb_t pde[PDPTE_COUNT][PDE_COUNT] GR_ALIGNED(PAGE_SIZE);

    /* MTRR snapshot taken during init */
    gr_mtrr_range_t mtrr[MTRR_MAX_VARIABLE_RANGES];
    uint32_t        mtrr_count;

    /* Constructed EPTP value ready for VMCS */
    vmx_eptp_t      eptp;
} gr_ept_ctx_t;

/* ── Public API ────────────────────────────────────────────────────────── */

/*
 * gr_vmx_mtrr_init — Enumerate variable MTRR ranges from hardware and
 *                     store them in ept_ctx->mtrr[].
 * See SDM Vol. 3A, Section 11.11.2.
 */
void gr_vmx_mtrr_init(gr_ept_ctx_t *ctx);

/*
 * gr_vmx_mtrr_adjust — For a given 2MB large-page base address, check
 *                       whether any variable MTRR overrides the candidate
 *                       memory type.
 * Returns the effective EPT memory type.
 */
uint32_t gr_vmx_mtrr_adjust(const gr_ept_ctx_t *ctx,
                             uint64_t large_page_addr,
                             uint32_t candidate_type);

/*
 * gr_vmx_ept_init — Build a full identity-mapped EPT (4-level, 2MB pages)
 *                    covering the first 512 GB of physical memory.
 * Must be called after gr_vmx_mtrr_init().
 */
void gr_vmx_ept_init(gr_ept_ctx_t *ctx);

/*
 * gr_vmx_ept_protect_page — Change EPT permissions for a single 4KB guest
 *                            physical page.  If the page sits inside a 2MB
 *                            entry the function transparently splits it
 *                            into a full 4KB page table first.
 * @gpa   : Guest physical address (any alignment, page-aligned internally).
 * @perms : Bitmask of EPT_PERM_READ / WRITE / EXEC.
 *
 * Returns 0 on success, -1 if the split allocation fails.
 */
int gr_vmx_ept_protect_page(gr_ept_ctx_t *ctx,
                            phys_addr_t gpa,
                            uint32_t perms);

/*
 * gr_vmx_invept — Execute INVEPT for the given context type.
 * @type : INVEPT_SINGLE_CONTEXT or INVEPT_ALL_CONTEXT.
 */
void gr_vmx_invept(uint32_t type, uint64_t eptp);

#endif /* GHOSTRING_VMX_EPT_H */
