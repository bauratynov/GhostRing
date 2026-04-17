/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * vmx_hlat.h — Hypervisor-Managed Linear Address Translation (Intel VT-rp).
 *
 * HLAT provides hardware-enforced page table integrity without EPT
 * write-protection on guest page tables.  The hypervisor maintains a
 * separate "HLAT paging structure" (HLATP) that the CPU uses in parallel
 * with the guest's own page tables.  If the guest PTE disagrees with
 * the HLAT PTE, the access fails.
 *
 * Key bits (in EPT entries):
 *   - PW (Paging Write, bit 57): allows CPU to set A/D bits in HLAT
 *     pages while keeping them read-only to the guest
 *   - GPV (Guest Paging Verification, bit 58): verifies that address
 *     translation used HLAT tables, not attacker-modified CR3 tables
 *
 * Available: Intel 12th gen (Alder Lake) with vPro / Intel 4th gen Xeon
 *
 * Benefits for GhostRing:
 *   - Our pte_monitor.c currently EPT write-protects guest PT pages,
 *     causing a VM-exit on every PTE write (~301 cycles each)
 *   - With HLAT, the CPU enforces the same policy in hardware at
 *     zero exit cost — the hypervisor just sets up the HLAT structure
 *   - Fallback: if HLAT not available, use pte_monitor.c EPT approach
 *
 * Reference: Intel SDM Vol. 3C, Section 26.5 ("HLAT Paging")
 *            Satoshi Tandasat: tandasat.github.io/blog/2023/07/05/intel-vt-rp-part-1
 */

#ifndef GHOSTRING_VMX_HLAT_H
#define GHOSTRING_VMX_HLAT_H

#include "vmx_defs.h"

/* ── CPUID detection ───────────────────────────────────────────────────── */

/*
 * HLAT is indicated by:
 *   CPUID.7.1:EAX[bit 26] — HLAT support
 *   IA32_VMX_PROCBASED_CTLS3[bit 1] — HLAT paging control
 */
static inline bool gr_hlat_supported(void)
{
    uint32_t eax, ebx, ecx, edx;
    gr_cpuid(0x7, 1, &eax, &ebx, &ecx, &edx);
    return (eax & BIT(26)) != 0;
}

/* ── HLAT Prefix Size (from VMCS) ─────────────────────────────────────── */

/*
 * HLAT_PREFIX_SIZE (VMCS field): number of upper bits of linear address
 * used to select between kernel (HLAT) and user (guest) paging.
 * Typical: 1 (bit 63 selects kernel vs user, matching canonical form).
 */
#define VMCS_HLAT_PREFIX_SIZE   0x00000006  /* 16-bit VMCS field */

/* ── EPT PW and GPV bits ───────────────────────────────────────────────── */

#define EPT_PW_BIT      BIT(57)  /* Paging Write — allow CPU A/D updates */
#define EPT_GPV_BIT     BIT(58)  /* Guest Paging Verification */

/* ── HLAT context ──────────────────────────────────────────────────────── */

typedef struct gr_hlat_ctx {
    uint64_t hlatp;         /* HLAT PML4 physical address */
    bool     supported;     /* CPU + VMCS support HLAT */
    bool     enabled;       /* HLAT active for this vCPU */
} gr_hlat_ctx_t;

/* ── API ───────────────────────────────────────────────────────────────── */

/*
 * Initialize HLAT: detect support, allocate HLAT paging structure.
 * The HLAT tables mirror the guest's page tables but with the
 * hypervisor's security policy applied (no user→kernel exec, W^X, etc.).
 */
void gr_hlat_init(gr_hlat_ctx_t *ctx);

/*
 * Enable HLAT for a vCPU.  Sets VMCS fields:
 *   - Tertiary VM-Execution Control bit 1
 *   - HLATP VMCS field = physical address of HLAT PML4
 *   - HLAT_PREFIX_SIZE = 1 (bit 63 = kernel/user split)
 *
 * Also sets EPT PW+GPV bits on kernel page table pages.
 */
void gr_hlat_enable(gr_hlat_ctx_t *ctx);

/*
 * Update HLAT tables when the guest modifies its page tables.
 * Called from the CR3-switch handler and periodic sync.
 *
 * The HLAT tables enforce:
 *   - No user→kernel execute (SMEP equivalent)
 *   - No RWX kernel mappings (W^X enforcement)
 *   - No PFN changes for kernel code pages
 */
void gr_hlat_sync(gr_hlat_ctx_t *ctx, uint64_t guest_cr3);

#endif /* GHOSTRING_VMX_HLAT_H */
