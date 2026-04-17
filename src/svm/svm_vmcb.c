/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * svm_vmcb.c — SVM capability probing, EFER.SVME activation, and complete
 *               VMCB field setup for the GhostRing hypervisor.
 *
 * Reference: AMD APM Vol. 2, Chapter 15 ("Secure Virtual Machine").
 */

#include "svm_vmcb.h"

/* -- Intrinsics ----------------------------------------------------------- */

static inline uint64_t gr_rdmsr_vmcb(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void gr_wrmsr_vmcb(uint32_t msr, uint64_t val)
{
    uint32_t lo = (uint32_t)val;
    uint32_t hi = (uint32_t)(val >> 32);
    __asm__ volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

static inline void gr_cpuid_vmcb(uint32_t leaf,
                                  uint32_t *eax, uint32_t *ebx,
                                  uint32_t *ecx, uint32_t *edx)
{
    __asm__ volatile("cpuid"
                     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                     : "a"(leaf), "c"(0));
}

static inline uint64_t gr_read_cr0_vmcb(void)
{
    uint64_t v;
    __asm__ volatile("mov %%cr0, %0" : "=r"(v));
    return v;
}

static inline uint64_t gr_read_cr3_vmcb(void)
{
    uint64_t v;
    __asm__ volatile("mov %%cr3, %0" : "=r"(v));
    return v;
}

static inline uint64_t gr_read_cr4_vmcb(void)
{
    uint64_t v;
    __asm__ volatile("mov %%cr4, %0" : "=r"(v));
    return v;
}

static inline uint64_t gr_read_dr7_vmcb(void)
{
    uint64_t v;
    __asm__ volatile("mov %%dr7, %0" : "=r"(v));
    return v;
}

static inline uint64_t gr_read_rflags_vmcb(void)
{
    uint64_t f;
    __asm__ volatile("pushfq; popq %0" : "=r"(f) :: "memory");
    return f;
}

static inline phys_addr_t virt_to_phys_vmcb(const void *va)
{
    return (phys_addr_t)(uintptr_t)va;
}

/* -- Segment descriptor helpers ------------------------------------------- */

/*
 * Read a GDT entry and produce SVM-format segment attributes (16-bit).
 * SVM stores attributes in a compressed form: bits 7:0 = type+S+DPL+P,
 * bits 11:8 = AVL+L+D/B+G.
 * See APM Vol. 2, Section 15.5.1 ("VMCB State Save Area").
 */
typedef struct {
    uint16_t selector;
    uint16_t attrib;
    uint32_t limit;
    uint64_t base;
} svm_seg_t;

static void
gdt_to_svm_seg(uint64_t gdt_base, uint16_t selector, svm_seg_t *out)
{
    uint16_t idx = selector & ~0x07;    /* Strip RPL + TI */

    if (idx == 0) {
        out->selector = selector;
        out->attrib   = 0;
        out->limit    = 0;
        out->base     = 0;
        return;
    }

    typedef struct {
        uint16_t limit_low;
        uint16_t base_low;
        uint8_t  base_mid;
        uint8_t  flags1;        /* Type[4] + S + DPL[2] + P */
        uint8_t  flags2;        /* Limit_hi[4] + AVL + L + D/B + G */
        uint8_t  base_hi;
        uint32_t base_upper;    /* For 16-byte system descriptors in long mode */
        uint32_t reserved;
    } GR_PACKED raw_gdt64_t;

    const raw_gdt64_t *entry = (const raw_gdt64_t *)(gdt_base + idx);

    out->selector = selector;

    /* Reconstruct base */
    out->base = (uint64_t)entry->base_low |
                ((uint64_t)entry->base_mid << 16) |
                ((uint64_t)entry->base_hi  << 24);

    /* System segments (S=0) are 16 bytes and carry upper base */
    if ((entry->flags1 & 0x10) == 0)
        out->base |= ((uint64_t)entry->base_upper << 32);

    /* Reconstruct limit */
    out->limit = (uint32_t)entry->limit_low |
                 (((uint32_t)entry->flags2 & 0x0F) << 16);

    /*
     * SVM segment attribute format (APM Vol. 2, Table 15-2):
     *   Bits  3:0  = Type
     *   Bit   4    = S
     *   Bits  6:5  = DPL
     *   Bit   7    = P
     *   Bit   8    = AVL
     *   Bit   9    = L (long mode)
     *   Bit  10    = D/B
     *   Bit  11    = G (granularity)
     */
    out->attrib = ((uint16_t)entry->flags1 & 0xFF) |
                  (((uint16_t)entry->flags2 & 0xF0) << 4);
}

/* -- Descriptor table register helpers ------------------------------------ */

typedef struct GR_PACKED {
    uint16_t limit;
    uint64_t base;
} svm_desc_table_reg_t;

static inline void svm_sgdt(svm_desc_table_reg_t *gdtr)
{
    __asm__ volatile("sgdt %0" : "=m"(*gdtr));
}

static inline void svm_sidt(svm_desc_table_reg_t *idtr)
{
    __asm__ volatile("sidt %0" : "=m"(*idtr));
}

static inline uint16_t svm_str(void)
{
    uint16_t tr;
    __asm__ volatile("str %0" : "=r"(tr));
    return tr;
}

static inline uint16_t svm_sldt(void)
{
    uint16_t ldt;
    __asm__ volatile("sldt %0" : "=r"(ldt));
    return ldt;
}

#define SVM_READ_SEG(name)                                      \
    static inline uint16_t svm_read_##name(void)                \
    {                                                           \
        uint16_t v;                                             \
        __asm__ volatile("mov %%" #name ", %0" : "=r"(v));     \
        return v;                                               \
    }

SVM_READ_SEG(cs)
SVM_READ_SEG(ds)
SVM_READ_SEG(es)
SVM_READ_SEG(fs)
SVM_READ_SEG(gs)
SVM_READ_SEG(ss)

#undef SVM_READ_SEG

/* -- Zero helper ---------------------------------------------------------- */

static void
zero_region(void *ptr, uint64_t size)
{
    uint64_t *p = (uint64_t *)ptr;
    for (uint64_t i = 0; i < size / sizeof(uint64_t); i++)
        p[i] = 0;
}

/* -- Forward declarations for assembly entry points ----------------------- */

extern void gr_svm_vmrun(void);            /* VMRUN loop (asm)             */
extern void gr_svm_restore_guest(void);    /* Guest restore after launch   */

/* =========================================================================
 * gr_svm_check_support — See APM Vol. 2, Section 15.4
 * ========================================================================= */

bool
gr_svm_check_support(void)
{
    uint32_t eax, ebx, ecx, edx;

    /*
     * Step 1: Check CPUID leaf 0x80000001, ECX bit 2 (SVM feature flag).
     * See APM Vol. 2, Section 15.4 ("Enabling SVM").
     */
    gr_cpuid_vmcb(0x80000001, &eax, &ebx, &ecx, &edx);
    if ((ecx & BIT(2)) == 0)
        return false;

    /*
     * Step 2: Read MSR_VM_CR and check SVMDIS (bit 4).
     * If SVMDIS=1, the BIOS has disabled SVM and it cannot be enabled.
     * See APM Vol. 2, Section 15.4.
     */
    uint64_t vm_cr = gr_rdmsr_vmcb(MSR_VM_CR);
    if (vm_cr & VM_CR_SVMDIS)
        return false;

    /*
     * Step 3: Verify Nested Paging support via CPUID leaf 0x8000000A.
     * EDX bit 0 = NP (Nested Paging).
     * See APM Vol. 2, Section 15.4.
     */
    gr_cpuid_vmcb(0x8000000A, &eax, &ebx, &ecx, &edx);
    if ((edx & BIT(0)) == 0)
        return false;

    /* Step 4: Verify NRIP save support — EDX bit 3 */
    if ((edx & BIT(3)) == 0)
        return false;

    return true;
}

/* =========================================================================
 * gr_svm_setup_msrpm — Configure MSR Permission Map
 * See APM Vol. 2, Section 15.11.
 *
 * The MSRPM is a 2-page bitmap.  Each MSR is represented by 2 bits:
 *   bit 0 = intercept RDMSR, bit 1 = intercept WRMSR.
 *
 * MSR ranges and their offsets in the bitmap:
 *   0x0000_0000 - 0x0000_1FFF: offset 0x000 - 0x7FF
 *   0xC000_0000 - 0xC000_1FFF: offset 0x800 - 0xFFF
 *   0xC001_0000 - 0xC001_1FFF: offset 0x1000 - 0x17FF
 * ========================================================================= */

static void
set_msrpm_bit(uint8_t *msrpm, uint32_t msr, bool read, bool write)
{
    uint32_t offset;
    uint32_t msr_index;

    if (msr <= 0x1FFF) {
        offset    = 0x000;
        msr_index = msr;
    } else if (msr >= 0xC0000000 && msr <= 0xC0001FFF) {
        offset    = 0x800;
        msr_index = msr - 0xC0000000;
    } else if (msr >= 0xC0010000 && msr <= 0xC0011FFF) {
        offset    = 0x1000;
        msr_index = msr - 0xC0010000;
    } else {
        return;     /* MSR not covered by MSRPM */
    }

    /* Each MSR uses 2 bits; 4 MSRs per byte */
    uint32_t byte_offset = offset + (msr_index / 4);
    uint32_t bit_offset  = (msr_index % 4) * 2;

    if (read)
        msrpm[byte_offset] |= (1 << bit_offset);
    if (write)
        msrpm[byte_offset] |= (1 << (bit_offset + 1));
}

static void
gr_svm_setup_msrpm(gr_svm_vcpu_t *vcpu)
{
    /* Start with all MSRs passed through (zeroed bitmap) */
    zero_region(vcpu->msrpm, SVM_MSRPM_SIZE);

    /*
     * Intercept writes to key syscall MSRs so we can track them.
     * This mirrors the VMX backend's MSR bitmap approach.
     */
    set_msrpm_bit(vcpu->msrpm, MSR_LSTAR,    false, true);
    set_msrpm_bit(vcpu->msrpm, MSR_STAR,     false, true);
    set_msrpm_bit(vcpu->msrpm, MSR_CSTAR,    false, true);
    set_msrpm_bit(vcpu->msrpm, MSR_SFMASK,   false, true);

    /* Intercept SYSENTER writes */
    set_msrpm_bit(vcpu->msrpm, MSR_SYSENTER_CS,  false, true);
    set_msrpm_bit(vcpu->msrpm, MSR_SYSENTER_ESP, false, true);
    set_msrpm_bit(vcpu->msrpm, MSR_SYSENTER_EIP, false, true);

    /* Intercept EFER writes to track SVME changes */
    set_msrpm_bit(vcpu->msrpm, MSR_EFER, false, true);
}

/* =========================================================================
 * gr_svm_enter_root — Enable SVM, set HSAVE area
 * See APM Vol. 2, Section 15.4 ("Enabling SVM").
 * ========================================================================= */

bool
gr_svm_enter_root(gr_svm_vcpu_t *vcpu)
{
    /*
     * Step 1: Enable EFER.SVME (bit 12).
     * This is required before executing any SVM instruction.
     * See APM Vol. 2, Section 15.4.
     */
    uint64_t efer = gr_rdmsr_vmcb(MSR_EFER);
    if (!(efer & EFER_SVME)) {
        efer |= EFER_SVME;
        gr_wrmsr_vmcb(MSR_EFER, efer);
    }

    /*
     * Step 2: Zero the VMCB and host save area.
     */
    zero_region(vcpu->vmcb, VMCB_SIZE);
    zero_region(vcpu->hsave, PAGE_SIZE);

    /*
     * Step 3: Cache physical addresses.
     */
    vcpu->vmcb_phys  = virt_to_phys_vmcb(vcpu->vmcb);
    vcpu->hsave_phys = virt_to_phys_vmcb(vcpu->hsave);
    vcpu->msrpm_phys = virt_to_phys_vmcb(vcpu->msrpm);

    /*
     * Step 4: Write the host save area physical address to VM_HSAVE_PA MSR.
     * The processor saves a subset of host state here on every VMRUN.
     * See APM Vol. 2, Section 15.5.4.
     */
    gr_wrmsr_vmcb(MSR_VM_HSAVE_PA, vcpu->hsave_phys);

    /*
     * Step 5: Save current host register state for manual restore after
     * #VMEXIT.  SVM only auto-restores a minimal set of registers via
     * the host save area.
     */
    vcpu->host_state.cr0   = gr_read_cr0_vmcb();
    vcpu->host_state.cr3   = gr_read_cr3_vmcb();
    vcpu->host_state.cr4   = gr_read_cr4_vmcb();
    vcpu->host_state.efer  = gr_rdmsr_vmcb(MSR_EFER);
    vcpu->host_state.dr7   = gr_read_dr7_vmcb();
    vcpu->host_state.rflags = gr_read_rflags_vmcb();

    /* Segment selectors */
    vcpu->host_state.cs = svm_read_cs();
    vcpu->host_state.ss = svm_read_ss();
    vcpu->host_state.ds = svm_read_ds();
    vcpu->host_state.es = svm_read_es();
    vcpu->host_state.fs = svm_read_fs();
    vcpu->host_state.gs = svm_read_gs();
    vcpu->host_state.tr   = svm_str();
    vcpu->host_state.ldtr = svm_sldt();

    /* Descriptor table registers */
    svm_sgdt((svm_desc_table_reg_t *)&vcpu->host_state.gdtr);
    svm_sidt((svm_desc_table_reg_t *)&vcpu->host_state.idtr);

    /* Segment bases */
    vcpu->host_state.fs_base         = gr_rdmsr_vmcb(MSR_FS_BASE);
    vcpu->host_state.gs_base         = gr_rdmsr_vmcb(MSR_GS_BASE);
    vcpu->host_state.kernel_gs_base  = gr_rdmsr_vmcb(MSR_KERNEL_GS_BASE);

    /* SYSCALL/SYSENTER MSRs */
    vcpu->host_state.star         = gr_rdmsr_vmcb(MSR_STAR);
    vcpu->host_state.lstar        = gr_rdmsr_vmcb(MSR_LSTAR);
    vcpu->host_state.cstar        = gr_rdmsr_vmcb(MSR_CSTAR);
    vcpu->host_state.sfmask       = gr_rdmsr_vmcb(MSR_SFMASK);
    vcpu->host_state.sysenter_cs  = gr_rdmsr_vmcb(MSR_SYSENTER_CS);
    vcpu->host_state.sysenter_esp = gr_rdmsr_vmcb(MSR_SYSENTER_ESP);
    vcpu->host_state.sysenter_eip = gr_rdmsr_vmcb(MSR_SYSENTER_EIP);

    /* PAT and debug control */
    vcpu->host_state.pat       = gr_rdmsr_vmcb(MSR_PAT);
    vcpu->host_state.debug_ctl = gr_rdmsr_vmcb(MSR_DEBUG_CTL);

    /*
     * Step 6: Initialise the NPT (nested page tables).
     */
    gr_svm_mtrr_init(&vcpu->npt);
    gr_svm_npt_init(&vcpu->npt);

    /*
     * Step 7: Set up the MSRPM.
     */
    gr_svm_setup_msrpm(vcpu);

    return true;
}

/* =========================================================================
 * gr_svm_setup_vmcb — Populate the VMCB control and state-save areas
 * See APM Vol. 2, Section 15.5.1.
 * ========================================================================= */

void
gr_svm_setup_vmcb(gr_svm_vcpu_t *vcpu)
{
    uint8_t *vmcb = vcpu->vmcb;
    const gr_svm_host_state_t *host = &vcpu->host_state;

    /* ==== Control Area ==== */

    /*
     * Intercepts — See APM Vol. 2, Table 15-7.
     *
     * We intercept:
     *   - CPUID (to inject hypervisor presence)
     *   - MSR read/write (via MSRPM for specific MSRs)
     *   - VMRUN (required — always intercept VMRUN per APM 15.9)
     *   - VMLOAD / VMSAVE (block nested SVM)
     *   - VMMCALL (hypercall interface)
     *   - INVD (replace with WBINVD for cache coherence)
     */

    /* Intercept CR0 writes for selective monitoring */
    gr_vmcb_write16(vmcb, VMCB_CTRL_INTERCEPT_CR_WRITE, BIT(0));

    /* Intercept MISC1: CPUID + MSR protection + INVD */
    gr_vmcb_write32(vmcb, VMCB_CTRL_INTERCEPT_MISC1,
                    SVM_INTERCEPT_MISC1_CPUID   |
                    SVM_INTERCEPT_MISC1_MSR_PROT |
                    SVM_INTERCEPT_MISC1_INVD);

    /*
     * Intercept MISC2: VMRUN (mandatory), VMMCALL, VMLOAD, VMSAVE.
     * See APM Vol. 2, Section 15.9 — VMRUN always requires intercept.
     */
    gr_vmcb_write32(vmcb, VMCB_CTRL_INTERCEPT_MISC2,
                    SVM_INTERCEPT_MISC2_VMRUN   |
                    SVM_INTERCEPT_MISC2_VMMCALL |
                    SVM_INTERCEPT_MISC2_VMLOAD  |
                    SVM_INTERCEPT_MISC2_VMSAVE);

    /* No exception intercepts — let all exceptions pass to guest */
    gr_vmcb_write32(vmcb, VMCB_CTRL_INTERCEPT_EXCEPTIONS, 0);

    /* MSRPM physical address */
    gr_vmcb_write64(vmcb, VMCB_CTRL_MSRPM_BASE_PA, vcpu->msrpm_phys);

    /* TSC offset = 0 (no time adjustment) */
    gr_vmcb_write64(vmcb, VMCB_CTRL_TSC_OFFSET, 0);

    /*
     * Guest ASID — must be non-zero.
     * See APM Vol. 2, Section 15.16.
     */
    gr_vmcb_write32(vmcb, VMCB_CTRL_GUEST_ASID, 1);

    /* TLB control: flush all on first entry */
    gr_vmcb_write32(vmcb, VMCB_CTRL_TLB_CONTROL, SVM_TLB_CONTROL_FLUSH_ALL);

    /*
     * Enable Nested Paging.
     * See APM Vol. 2, Section 15.25.
     */
    gr_vmcb_write64(vmcb, VMCB_CTRL_NP_ENABLE, 1);

    /* Set nCR3 to the NPT PML4 physical address */
    gr_vmcb_write64(vmcb, VMCB_CTRL_NCR3, vcpu->npt.ncr3);

    /*
     * VMCB clean bits = 0 — force the processor to reload everything
     * from the VMCB on the first VMRUN.
     * See APM Vol. 2, Section 15.15.4.
     */
    gr_vmcb_write64(vmcb, VMCB_CTRL_VMCB_CLEAN_BITS, 0);

    /* No event injection on first entry */
    gr_vmcb_write64(vmcb, VMCB_CTRL_EVENT_INJECTION, 0);

    /* ==== State Save Area ==== */

    /*
     * Populate segment registers from current host state.
     * The guest starts with the same segments as the host.
     */
    svm_seg_t seg;

    /* ES */
    gdt_to_svm_seg(host->gdtr.base, host->es, &seg);
    gr_vmcb_write16(vmcb, VMCB_STATE_ES_SELECTOR, seg.selector);
    gr_vmcb_write16(vmcb, VMCB_STATE_ES_ATTRIB,   seg.attrib);
    gr_vmcb_write32(vmcb, VMCB_STATE_ES_LIMIT,    seg.limit);
    gr_vmcb_write64(vmcb, VMCB_STATE_ES_BASE,     seg.base);

    /* CS */
    gdt_to_svm_seg(host->gdtr.base, host->cs, &seg);
    gr_vmcb_write16(vmcb, VMCB_STATE_CS_SELECTOR, seg.selector);
    gr_vmcb_write16(vmcb, VMCB_STATE_CS_ATTRIB,   seg.attrib);
    gr_vmcb_write32(vmcb, VMCB_STATE_CS_LIMIT,    seg.limit);
    gr_vmcb_write64(vmcb, VMCB_STATE_CS_BASE,     seg.base);

    /* SS */
    gdt_to_svm_seg(host->gdtr.base, host->ss, &seg);
    gr_vmcb_write16(vmcb, VMCB_STATE_SS_SELECTOR, seg.selector);
    gr_vmcb_write16(vmcb, VMCB_STATE_SS_ATTRIB,   seg.attrib);
    gr_vmcb_write32(vmcb, VMCB_STATE_SS_LIMIT,    seg.limit);
    gr_vmcb_write64(vmcb, VMCB_STATE_SS_BASE,     seg.base);

    /* DS */
    gdt_to_svm_seg(host->gdtr.base, host->ds, &seg);
    gr_vmcb_write16(vmcb, VMCB_STATE_DS_SELECTOR, seg.selector);
    gr_vmcb_write16(vmcb, VMCB_STATE_DS_ATTRIB,   seg.attrib);
    gr_vmcb_write32(vmcb, VMCB_STATE_DS_LIMIT,    seg.limit);
    gr_vmcb_write64(vmcb, VMCB_STATE_DS_BASE,     seg.base);

    /* FS */
    gdt_to_svm_seg(host->gdtr.base, host->fs, &seg);
    gr_vmcb_write16(vmcb, VMCB_STATE_FS_SELECTOR, seg.selector);
    gr_vmcb_write16(vmcb, VMCB_STATE_FS_ATTRIB,   seg.attrib);
    gr_vmcb_write32(vmcb, VMCB_STATE_FS_LIMIT,    seg.limit);
    gr_vmcb_write64(vmcb, VMCB_STATE_FS_BASE,     host->fs_base);

    /* GS — base from MSR, not GDT, in long mode */
    gdt_to_svm_seg(host->gdtr.base, host->gs, &seg);
    gr_vmcb_write16(vmcb, VMCB_STATE_GS_SELECTOR, seg.selector);
    gr_vmcb_write16(vmcb, VMCB_STATE_GS_ATTRIB,   seg.attrib);
    gr_vmcb_write32(vmcb, VMCB_STATE_GS_LIMIT,    seg.limit);
    gr_vmcb_write64(vmcb, VMCB_STATE_GS_BASE,     host->gs_base);

    /* GDTR */
    gr_vmcb_write16(vmcb, VMCB_STATE_GDTR_SELECTOR, 0);
    gr_vmcb_write16(vmcb, VMCB_STATE_GDTR_ATTRIB,   0);
    gr_vmcb_write32(vmcb, VMCB_STATE_GDTR_LIMIT,    host->gdtr.limit);
    gr_vmcb_write64(vmcb, VMCB_STATE_GDTR_BASE,     host->gdtr.base);

    /* IDTR */
    gr_vmcb_write16(vmcb, VMCB_STATE_IDTR_SELECTOR, 0);
    gr_vmcb_write16(vmcb, VMCB_STATE_IDTR_ATTRIB,   0);
    gr_vmcb_write32(vmcb, VMCB_STATE_IDTR_LIMIT,    host->idtr.limit);
    gr_vmcb_write64(vmcb, VMCB_STATE_IDTR_BASE,     host->idtr.base);

    /* TR */
    gdt_to_svm_seg(host->gdtr.base, host->tr, &seg);
    gr_vmcb_write16(vmcb, VMCB_STATE_TR_SELECTOR, seg.selector);
    gr_vmcb_write16(vmcb, VMCB_STATE_TR_ATTRIB,   seg.attrib);
    gr_vmcb_write32(vmcb, VMCB_STATE_TR_LIMIT,    seg.limit);
    gr_vmcb_write64(vmcb, VMCB_STATE_TR_BASE,     seg.base);

    /* LDTR */
    gdt_to_svm_seg(host->gdtr.base, host->ldtr, &seg);
    gr_vmcb_write16(vmcb, VMCB_STATE_LDTR_SELECTOR, seg.selector);
    gr_vmcb_write16(vmcb, VMCB_STATE_LDTR_ATTRIB,   seg.attrib);
    gr_vmcb_write32(vmcb, VMCB_STATE_LDTR_LIMIT,    seg.limit);
    gr_vmcb_write64(vmcb, VMCB_STATE_LDTR_BASE,     seg.base);

    /* Control registers */
    gr_vmcb_write64(vmcb, VMCB_STATE_CR0, host->cr0);
    gr_vmcb_write64(vmcb, VMCB_STATE_CR3, host->cr3);
    gr_vmcb_write64(vmcb, VMCB_STATE_CR4, host->cr4);
    gr_vmcb_write64(vmcb, VMCB_STATE_CR2, 0);

    /* EFER — guest starts with host EFER (SVME is set) */
    gr_vmcb_write64(vmcb, VMCB_STATE_EFER, host->efer);

    /* Debug registers */
    gr_vmcb_write64(vmcb, VMCB_STATE_DR7, host->dr7);
    gr_vmcb_write64(vmcb, VMCB_STATE_DR6, 0xFFFF0FF0ULL);

    /* RFLAGS */
    gr_vmcb_write64(vmcb, VMCB_STATE_RFLAGS, host->rflags);

    /*
     * Guest RIP — points to the restore function that runs when VMRUN
     * transfers control to the guest for the first time.
     */
    gr_vmcb_write64(vmcb, VMCB_STATE_RIP, (uintptr_t)gr_svm_restore_guest);

    /* Guest RSP — matches the hypervisor stack so the restore function
     * sees a valid stack frame. */
    gr_vmcb_write64(vmcb, VMCB_STATE_RSP, vcpu->hv_stack + vcpu->hv_stack_size);

    /* Guest RAX — initial value is unimportant, zero it */
    gr_vmcb_write64(vmcb, VMCB_STATE_RAX, 0);

    /* CPL = 0 (Ring 0) */
    gr_vmcb_write8(vmcb, VMCB_STATE_CPL, 0);

    /* SYSCALL MSRs */
    gr_vmcb_write64(vmcb, VMCB_STATE_STAR,          host->star);
    gr_vmcb_write64(vmcb, VMCB_STATE_LSTAR,         host->lstar);
    gr_vmcb_write64(vmcb, VMCB_STATE_CSTAR,         host->cstar);
    gr_vmcb_write64(vmcb, VMCB_STATE_SFMASK,        host->sfmask);
    gr_vmcb_write64(vmcb, VMCB_STATE_KERNEL_GS_BASE, host->kernel_gs_base);

    /* SYSENTER MSRs */
    gr_vmcb_write64(vmcb, VMCB_STATE_SYSENTER_CS,  host->sysenter_cs);
    gr_vmcb_write64(vmcb, VMCB_STATE_SYSENTER_ESP, host->sysenter_esp);
    gr_vmcb_write64(vmcb, VMCB_STATE_SYSENTER_EIP, host->sysenter_eip);

    /* PAT */
    gr_vmcb_write64(vmcb, VMCB_STATE_PAT, host->pat);

    /* Debug control */
    gr_vmcb_write64(vmcb, VMCB_STATE_DEBUG_CTL, host->debug_ctl);
}
