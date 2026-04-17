/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * vmx_vmcs.h — VMCS setup interface: feature probing, VMXON, and full
 *              VMCS field configuration for the GhostRing VMX backend.
 *
 * Reference: Intel SDM Vol. 3C, Chapter 24 ("Virtual Machine Control
 * Structures").
 */

#ifndef GHOSTRING_VMX_VMCS_H
#define GHOSTRING_VMX_VMCS_H

#include "vmx_defs.h"
#include "vmx_ept.h"

/* ── Saved special registers snapshot ──────────────────────────────────── */

typedef struct gr_special_regs {
    uint64_t cr0;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t dr7;
    uint64_t debug_ctl;         /* IA32_DEBUGCTL MSR */
    uint64_t efer;              /* IA32_EFER MSR */
    uint64_t pat;               /* IA32_PAT MSR */
    uint64_t gs_base;           /* IA32_GS_BASE MSR */
    uint64_t kernel_gs_base;    /* IA32_KERNEL_GS_BASE MSR */
    uint64_t sysenter_cs;
    uint64_t sysenter_esp;
    uint64_t sysenter_eip;

    /* GDT / IDT */
    struct {
        uint16_t limit;
        uint64_t base;
    } GR_PACKED gdtr, idtr;

    uint16_t tr;
    uint16_t ldtr;

    /* Segment selectors */
    uint16_t cs, ss, ds, es, fs, gs;

    /* RFLAGS */
    uint64_t rflags;
} gr_special_regs_t;

/* ── Per-vCPU VMX state ────────────────────────────────────────────────── */

/*
 * gr_vmx_vcpu aggregates everything a single logical processor needs to
 * enter and operate in VMX non-root mode.
 */
typedef struct gr_vmx_vcpu {
    /* VMXON region — must be page-aligned, page-sized */
    vmx_vmcs_t  vmxon_region  GR_ALIGNED(PAGE_SIZE);

    /* VMCS region — must be page-aligned, page-sized */
    vmx_vmcs_t  vmcs_region   GR_ALIGNED(PAGE_SIZE);

    /* MSR bitmap — all bits zero = no MSR interception */
    uint8_t     msr_bitmap[PAGE_SIZE] GR_ALIGNED(PAGE_SIZE);

    /* EPT context */
    gr_ept_ctx_t ept;

    /* Physical addresses (cached after virt_to_phys) */
    phys_addr_t vmxon_phys;
    phys_addr_t vmcs_phys;
    phys_addr_t msr_bitmap_phys;

    /* Capability MSRs snapshot (indices match MSR_IA32_VMX_BASIC + i) */
    uint64_t    vmx_msr[17];

    /* Secondary execution controls (EPT + VPID flags) */
    uint32_t    ept_controls;

    /* Saved host register state */
    gr_special_regs_t host_regs;

    /* System CR3 (kernel page table) for HOST_CR3 */
    phys_addr_t system_cr3;

    /* Hypervisor stack base and size */
    uintptr_t   hv_stack;
    uint64_t    hv_stack_size;

    /* Monitor state — allocated separately, pointed to from here and
     * from the unified gr_vcpu_t.  NULL until gr_monitor_init(). */
    struct gr_monitor_state *monitor;
} gr_vmx_vcpu_t;

/* ── Public API ────────────────────────────────────────────────────────── */

/*
 * gr_vmx_check_support — Probe CPUID leaf 1 (ECX.VMX), IA32_FEATURE_CONTROL,
 *                         and EPT/VPID capabilities.
 * Returns true if this processor supports VMX with the features GhostRing
 * requires, false otherwise.
 */
bool gr_vmx_check_support(void);

/*
 * gr_vmx_adjust_controls — Compute the effective value for a VM-execution
 *                           control field by applying the "allowed 0" and
 *                           "allowed 1" rules from the true capability MSR.
 * @msr_value : Raw value of the relevant IA32_VMX_TRUE_*_CTLS MSR.
 * @desired   : Bits the caller wants enabled.
 *
 * Returns the adjusted control value with mandatory bits set/cleared.
 * See SDM Vol. 3C, Appendix A.3-A.5.
 */
uint32_t gr_vmx_adjust_controls(uint64_t msr_value, uint32_t desired);

/*
 * gr_vmx_enter_root — Execute the full VMXON sequence:
 *   1. Validate VMCS size, memory type, true-MSR support.
 *   2. Adjust CR0/CR4 per VMX fixed bits.
 *   3. VMXON.
 *   4. VMCLEAR + VMPTRLD.
 *
 * Returns true on success.  On failure the processor is not in VMX root
 * mode and no cleanup is necessary.
 */
bool gr_vmx_enter_root(gr_vmx_vcpu_t *vcpu);

/*
 * gr_vmx_setup_vmcs — Write every required field into the active VMCS:
 *   - Link pointer, EPT pointer, VPID, MSR bitmap.
 *   - Pin / CPU / Secondary / Exit / Entry controls.
 *   - All guest and host segment registers.
 *   - CR0 / CR3 / CR4 with shadows.
 *   - GDTR / IDTR.
 *   - Guest RIP/RSP, Host RIP/RSP.
 *
 * Must be called after gr_vmx_enter_root().
 */
void gr_vmx_setup_vmcs(gr_vmx_vcpu_t *vcpu);

#endif /* GHOSTRING_VMX_VMCS_H */
