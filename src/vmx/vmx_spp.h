/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * vmx_spp.h — Intel Sub-Page Permissions (SPP) for 128-byte monitoring.
 *
 * Standard EPT provides 4KB page granularity for write permissions.
 * SPP extends this to 128-byte sub-page granularity: each 4KB page
 * gets a 32-bit permission bitmap where each bit controls write access
 * to one 128-byte region.
 *
 * Architecture:
 *   4KB page = 32 × 128-byte sub-pages
 *   Each sub-page: 1 = write-allowed, 0 = write-trapped
 *   Bitmap stored in a 4-level Sub-Page Permission Table (SPPT)
 *
 * Use cases for GhostRing:
 *   - Monitor Token field in EPROCESS (~8 bytes at offset 0x4B8)
 *     without trapping on all other EPROCESS writes
 *   - Monitor specific callback pointers (8 bytes each)
 *   - Monitor SSDT entry (8 bytes) without trapping whole page
 *
 * Without SPP: EPT write-protect entire 4KB → every write to any
 * of the ~150 fields in EPROCESS causes a VM-exit.
 * With SPP: only writes to the 128-byte region containing Token
 * cause a VM-exit.  ~30× fewer false-positive exits.
 *
 * Activation: Secondary VM-Execution Controls bit 23 (Enable SPP).
 * Reference: Intel SDM Vol. 3C, Section 28.3.4 ("Sub-Page Permissions").
 */

#ifndef GHOSTRING_VMX_SPP_H
#define GHOSTRING_VMX_SPP_H

#include "vmx_defs.h"

/* ── Constants ─────────────────────────────────────────────────────────── */

#define SPP_SUBPAGE_SIZE    128     /* bytes per sub-page */
#define SPP_SUBPAGES_PER_PAGE 32   /* 4096 / 128 */
#define SPP_BITMAP_ALL_ALLOW  0xFFFFFFFFU  /* all sub-pages writable */
#define SPP_BITMAP_ALL_DENY   0x00000000U  /* all sub-pages trapped */

/* ── SPPT entry (mirrors EPT structure, 4-level) ──────────────────────── */

/*
 * The SPPT maps GPA → 32-bit sub-page permission bitmap.
 * Level structure is identical to EPT (PML4→PDPT→PD→PT) but the
 * leaf entry contains a 32-bit bitmap instead of a PFN.
 *
 * SPPT pointer is stored in VMCS at a dedicated field.
 */

typedef struct gr_spp_ctx {
    phys_addr_t sppt_root;      /* SPPT PML4 physical address */
    bool        supported;
    bool        enabled;
} gr_spp_ctx_t;

/* ── Detection ─────────────────────────────────────────────────────────── */

static inline bool gr_spp_supported(void)
{
    /*
     * SPP support indicated by IA32_VMX_PROCBASED_CTLS2 allowing bit 23.
     * Also requires EPT A/D bits to be enabled.
     *
     * NOTE: SPP was in development but deprioritized by Intel.  Available
     * on some Xeon models (Ice Lake server) but not on consumer chips.
     * Always check at runtime via adjust_controls.
     */
    return false;  /* Conservative: detected during VMCS setup */
}

/* ── API ───────────────────────────────────────────────────────────────── */

/*
 * Initialize SPP for a vCPU.
 * Allocates SPPT hierarchy from page pool.
 */
void gr_spp_init(gr_spp_ctx_t *ctx);

/*
 * Set sub-page permissions for a specific GPA.
 * @gpa    : target guest physical address (4KB-aligned)
 * @bitmap : 32-bit permission mask (bit N = sub-page N, 1=allow, 0=trap)
 *
 * Example: to trap writes to bytes 0x480-0x4FF (sub-page 9) only:
 *   bitmap = 0xFFFFFFFF & ~BIT(9) = 0xFFFFFDFF
 */
void gr_spp_set_permissions(gr_spp_ctx_t *ctx, uint64_t gpa, uint32_t bitmap);

/*
 * Compute which sub-page index a GPA offset falls into.
 * @offset : byte offset within the 4KB page (0-4095)
 * Returns: sub-page index (0-31)
 */
static inline uint32_t gr_spp_subpage_index(uint32_t offset)
{
    return offset / SPP_SUBPAGE_SIZE;
}

/*
 * Create a bitmap that traps writes to a specific byte range.
 * @offset : start offset within page
 * @size   : number of bytes to protect
 * Returns: 32-bit bitmap with 0-bits for protected sub-pages
 */
static inline uint32_t gr_spp_protect_range(uint32_t offset, uint32_t size)
{
    uint32_t bitmap = SPP_BITMAP_ALL_ALLOW;
    uint32_t first = offset / SPP_SUBPAGE_SIZE;
    uint32_t last = (offset + size - 1) / SPP_SUBPAGE_SIZE;

    for (uint32_t i = first; i <= last && i < SPP_SUBPAGES_PER_PAGE; i++)
        bitmap &= ~BIT(i);

    return bitmap;
}

#endif /* GHOSTRING_VMX_SPP_H */
