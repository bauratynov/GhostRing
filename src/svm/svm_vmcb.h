/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * svm_vmcb.h — VMCB setup interface: SVM feature probing, EFER.SVME
 *               activation, and complete VMCB field configuration for
 *               the GhostRing SVM backend.
 *
 * Reference: AMD APM Vol. 2, Chapter 15 ("Secure Virtual Machine").
 */

#ifndef GHOSTRING_SVM_VMCB_H
#define GHOSTRING_SVM_VMCB_H

#include "svm_defs.h"
#include "svm_npt.h"

/* -- Saved host register state -------------------------------------------- */

/*
 * SVM does not save/restore host state automatically (unlike VMX).
 * VMSAVE/VMLOAD handle FS, GS, TR, LDTR, KERNEL_GS_BASE, STAR, LSTAR,
 * CSTAR, SFMASK, and SYSENTER_* MSRs.  Everything else the hypervisor
 * must save and restore manually.
 */
typedef struct gr_svm_host_state {
    uint64_t cr0;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t efer;
    uint64_t dr7;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t rip;

    /* GDT / IDT */
    struct {
        uint16_t limit;
        uint64_t base;
    } GR_PACKED gdtr, idtr;

    uint16_t tr;
    uint16_t ldtr;

    /* Segment selectors */
    uint16_t cs, ss, ds, es, fs, gs;

    /* Segment bases */
    uint64_t fs_base;
    uint64_t gs_base;
    uint64_t kernel_gs_base;

    /* SYSCALL/SYSENTER MSRs */
    uint64_t star;
    uint64_t lstar;
    uint64_t cstar;
    uint64_t sfmask;
    uint64_t sysenter_cs;
    uint64_t sysenter_esp;
    uint64_t sysenter_eip;

    /* PAT */
    uint64_t pat;
    uint64_t debug_ctl;
} gr_svm_host_state_t;

/* -- Per-vCPU SVM state --------------------------------------------------- */

/*
 * gr_svm_vcpu_t aggregates everything a single logical processor needs
 * to enter and operate in guest mode via AMD SVM.
 */
typedef struct gr_svm_vcpu {
    /*
     * VMCB — Virtual Machine Control Block.
     * Must be page-aligned; occupies two pages (control area + state save).
     * See APM Vol. 2, Section 15.5.1.
     */
    uint8_t         vmcb[VMCB_SIZE] GR_ALIGNED(PAGE_SIZE);

    /*
     * Host Save Area — VMRUN saves select host state here automatically.
     * One page, page-aligned.  Address stored in MSR_VM_HSAVE_PA.
     * See APM Vol. 2, Section 15.5.4.
     */
    uint8_t         hsave[PAGE_SIZE] GR_ALIGNED(PAGE_SIZE);

    /*
     * MSR Permission Map — intercept specific MSR reads/writes.
     * Two pages (8 KiB), page-aligned.
     * See APM Vol. 2, Section 15.11.
     */
    uint8_t         msrpm[SVM_MSRPM_SIZE] GR_ALIGNED(PAGE_SIZE);

    /* NPT context */
    gr_npt_ctx_t    npt;

    /* Physical addresses (cached after virt_to_phys) */
    phys_addr_t     vmcb_phys;
    phys_addr_t     hsave_phys;
    phys_addr_t     msrpm_phys;

    /* Manually saved/restored host state */
    gr_svm_host_state_t host_state;

    /* Hypervisor stack base and size */
    uintptr_t       hv_stack;
    uint64_t        hv_stack_size;
} gr_svm_vcpu_t;

/* -- Public API ----------------------------------------------------------- */

/*
 * gr_svm_check_support — Probe CPUID leaf 0x80000001 ECX bit 2 (SVM) and
 *                          verify MSR_VM_CR.SVMDIS is clear.
 * Returns true if this processor supports SVM with the features GhostRing
 * requires, false otherwise.
 */
bool gr_svm_check_support(void);

/*
 * gr_svm_enter_root — Enable EFER.SVME, configure VM_HSAVE_PA, and
 *                      prepare the VMCB for the first VMRUN.
 * Returns true on success.
 */
bool gr_svm_enter_root(gr_svm_vcpu_t *vcpu);

/*
 * gr_svm_setup_vmcb — Populate every VMCB field:
 *   - Control area: intercepts, MSRPM, guest ASID, NPT enable, nCR3.
 *   - State save: all segment registers, control registers, EFER,
 *     RIP, RSP, RFLAGS.
 *   - Clean bits = 0 (force full reload on first VMRUN).
 *
 * Must be called after gr_svm_enter_root().
 */
void gr_svm_setup_vmcb(gr_svm_vcpu_t *vcpu);

#endif /* GHOSTRING_SVM_VMCB_H */
