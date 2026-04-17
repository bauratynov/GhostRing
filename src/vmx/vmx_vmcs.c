/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * vmx_vmcs.c — VMX capability probing, VMXON sequence, and complete VMCS
 *              field setup for the GhostRing hypervisor.
 *
 * Reference: Intel SDM Vol. 3C, Chapters 23-24.
 */

#include "vmx_vmcs.h"

/* ── Intrinsics ────────────────────────────────────────────────────────── */

/*
 * Use common/cpu.h intrinsics where possible.  Only define local aliases
 * for brevity within this file to avoid polluting the namespace.
 */
#define gr_rdmsr_vmcs(msr)       gr_rdmsr(msr)
#define gr_wrcr0(val)            gr_write_cr0(val)
#define gr_wrcr4(val)            gr_write_cr4(val)
#define gr_rdcr4()               gr_read_cr4()

/* Local CPUID wrapper — avoids dependency on common/cpu.h's 5-arg version */
static inline void gr_cpuid_local(uint32_t leaf,
                                   uint32_t *eax, uint32_t *ebx,
                                   uint32_t *ecx, uint32_t *edx)
{
    __asm__ volatile("cpuid"
                     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                     : "a"(leaf), "c"(0));
}

/*
 * VMXON / VMCLEAR / VMPTRLD / VMWRITE wrappers.
 * Each returns 0 on success, non-zero on failure (CF=1 or ZF=1).
 */
static inline int gr_vmxon(phys_addr_t *pa)
{
    uint8_t err;
    __asm__ volatile(
        "vmxon %[pa]; setna %[err]"
        : [err] "=rm"(err)
        : [pa]  "m"(*pa)
        : "memory", "cc"
    );
    return (int)err;
}

static inline int gr_vmclear(phys_addr_t *pa)
{
    uint8_t err;
    __asm__ volatile(
        "vmclear %[pa]; setna %[err]"
        : [err] "=rm"(err)
        : [pa]  "m"(*pa)
        : "memory", "cc"
    );
    return (int)err;
}

static inline int gr_vmptrld(phys_addr_t *pa)
{
    uint8_t err;
    __asm__ volatile(
        "vmptrld %[pa]; setna %[err]"
        : [err] "=rm"(err)
        : [pa]  "m"(*pa)
        : "memory", "cc"
    );
    return (int)err;
}

static inline void gr_vmwrite(uint64_t field, uint64_t value)
{
    __asm__ volatile("vmwrite %[val], %[field]"
                     :
                     : [field] "r"(field), [val] "rm"(value)
                     : "cc", "memory");
}

static inline void gr_vmxoff(void)
{
    __asm__ volatile("vmxoff" ::: "cc", "memory");
}

/*
 * Convert virtual address to physical via the platform abstraction layer.
 * The loader registers its OS-specific implementation at init time
 * (Linux: virt_to_phys, Windows: MmGetPhysicalAddress, UEFI: identity).
 */
static inline phys_addr_t virt_to_phys_vmcs(const void *va)
{
    return gr_virt_to_phys((void *)va);
}

/* ── Forward declarations for assembly entry points ───────────────────── */

extern void gr_vmx_entry(void);             /* VM-exit entry point (asm)   */
extern void gr_vmx_restore_guest(void);     /* Guest restore after launch  */

/* ═══════════════════════════════════════════════════════════════════════════
 * GDT entry conversion — decode a 64-bit GDT entry into VMCS access-rights
 * format.  See SDM Vol. 3C, Section 24.4.1 ("Guest Register State").
 * ═══════════════════════════════════════════════════════════════════════════ */

static void
gdt_to_vmx_entry(uint64_t gdt_base, uint16_t selector, vmx_gdt_entry_t *out)
{
    /* Strip RPL and table indicator for the lookup */
    uint16_t idx = selector & ~(RPL_MASK | SELECTOR_TABLE_INDEX);

    /*
     * A null selector results in a segment marked "unusable" in VMCS
     * parlance.  The processor ignores all other fields for unusable
     * segments.  See SDM Vol. 3C, Section 26.3.1.2.
     */
    if (idx == 0) {
        out->base          = 0;
        out->limit         = 0;
        out->access_rights = 0;
        out->bits.unusable = 1;
        out->selector      = selector;
        return;
    }

    /*
     * Each GDT descriptor is 8 bytes for code/data or 16 bytes for
     * system (TSS, LDT) segments in long mode.
     */
    typedef struct {
        uint16_t limit_low;
        uint16_t base_low;
        uint8_t  base_mid;
        uint8_t  flags1;        /* Type[4] + S + DPL[2] + P */
        uint8_t  flags2;        /* Limit_hi[4] + AVL + L + D/B + G */
        uint8_t  base_hi;
        uint32_t base_upper;    /* Only valid for 16-byte system descriptors */
        uint32_t reserved;
    } GR_PACKED raw_gdt64_t;

    const raw_gdt64_t *entry = (const raw_gdt64_t *)(gdt_base + idx);

    /* Reconstruct base address */
    out->base = (uint64_t)entry->base_low |
                ((uint64_t)entry->base_mid << 16) |
                ((uint64_t)entry->base_hi  << 24);

    /* System segments (type < 16 with S=0) are 16 bytes and carry upper base */
    uint8_t type = entry->flags1 & 0x1F;   /* Type[4:0] + S bit */
    if ((type & 0x10) == 0) {
        /* S bit is 0 — this is a system descriptor (TSS / LDT) */
        out->base |= ((uint64_t)entry->base_upper << 32);
    }

    /* Reconstruct limit */
    out->limit = (uint32_t)entry->limit_low |
                 (((uint32_t)entry->flags2 & 0x0F) << 16);

    /*
     * VMCS access-rights format (SDM Table 24-2):
     *   Bits  3:0  — Segment type
     *   Bit   4    — S (descriptor type)
     *   Bits  6:5  — DPL
     *   Bit   7    — P (present)
     *   Bits 11:8  — Reserved (0)
     *   Bit  12    — AVL
     *   Bit  13    — L (64-bit code)
     *   Bit  14    — D/B
     *   Bit  15    — G (granularity)
     *   Bit  16    — Unusable
     */
    out->access_rights = ((uint32_t)entry->flags1 & 0xFF) |
                         (((uint32_t)entry->flags2 & 0xF0) << 4);

    out->selector = selector;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * gr_vmx_check_support — See SDM Vol. 3C, Section 23.6
 * ═══════════════════════════════════════════════════════════════════════════ */

bool
gr_vmx_check_support(void)
{
    uint32_t eax, ebx, ecx, edx;

    /* Check if another hypervisor is already present.
     * CPUID.1:ECX bit 31 = hypervisor present.  Normally we refuse to
     * layer on top of another hypervisor, but when the host exposes
     * nested VT-x (VirtualBox / KVM / Hyper-V / VMware with nesting)
     * VMXON from inside the guest is legal and useful for development.
     * g_allow_nested is a module-parameter-controlled override.
     * See SDM Vol. 2A, Table 3-8 (Feature Information). */
    extern int g_allow_nested;
    gr_cpuid_local(1, &eax, &ebx, &ecx, &edx);

    if ((ecx & BIT(31)) && !g_allow_nested) {
        GR_LOG_STR("vmx: another hypervisor already present, aborting "
                   "(set allow_nested=1 to force nested VT-x)");
        return false;
    }
    if ((ecx & BIT(31)) && g_allow_nested) {
        GR_LOG_STR("vmx: outer hypervisor detected, proceeding (nested VT-x)");
    }

    /* CPUID.1:ECX.VMX (bit 5) must be set */
    if ((ecx & BIT(5)) == 0)
        return false;

    /* IA32_FEATURE_CONTROL must be locked with VMXON-outside-SMX enabled */
    uint64_t feat = gr_rdmsr_vmcs(MSR_IA32_FEATURE_CONTROL);
    if (!(feat & FEATURE_CONTROL_LOCKED))
        return false;
    if (!(feat & FEATURE_CONTROL_VMXON_OUTSIDE_SMX))
        return false;

    /*
     * Optionally verify EPT + 2MB pages + WB EPTP support.
     * We read IA32_VMX_EPT_VPID_CAP (only valid when secondary controls
     * allow EPT).  Failure here is non-fatal — we can run without EPT,
     * but GhostRing's monitor relies on it.
     */
    uint64_t ept_cap = gr_rdmsr_vmcs(MSR_IA32_VMX_EPT_VPID_CAP);
    if (!(ept_cap & VMX_EPT_PAGE_WALK_4_BIT) ||
        !(ept_cap & VMX_EPTP_WB_BIT) ||
        !(ept_cap & VMX_EPT_2MB_PAGE_BIT)) {
        return false;
    }

    return true;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * gr_vmx_adjust_controls — See SDM Vol. 3C, Appendix A.3-A.5
 * ═══════════════════════════════════════════════════════════════════════════ */

uint32_t
gr_vmx_adjust_controls(uint64_t msr_value, uint32_t desired)
{
    /*
     * Low 32 bits  = "allowed 0-settings" — bits that MUST be 1.
     * High 32 bits = "allowed 1-settings" — bits that MAY be 1.
     *
     * Result = (desired OR must-be-1) AND may-be-1.
     */
    uint32_t must_be_one  = (uint32_t)(msr_value & 0xFFFFFFFF);
    uint32_t may_be_one   = (uint32_t)(msr_value >> 32);

    desired |= must_be_one;
    desired &= may_be_one;
    return desired;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * gr_vmx_enter_root — VMXON + VMCLEAR + VMPTRLD
 * See SDM Vol. 3C, Section 23.7 ("Enabling and Entering VMX Operation").
 * ═══════════════════════════════════════════════════════════════════════════ */

bool
gr_vmx_enter_root(gr_vmx_vcpu_t *vcpu)
{
    /*
     * Step 0: Read all VMX capability MSRs (indices 0..16 correspond to
     * MSR_IA32_VMX_BASIC through MSR_IA32_VMX_TRUE_ENTRY_CTLS).
     */
    for (uint32_t i = 0; i < ARRAY_SIZE(vcpu->vmx_msr); i++)
        vcpu->vmx_msr[i] = gr_rdmsr_vmcs(MSR_IA32_VMX_BASIC + i);

    uint64_t vmx_basic = vcpu->vmx_msr[0];

    /*
     * Step 1: Validate VMCS region size fits in one page.
     * See SDM Vol. 3C, Section 24.2.
     */
    uint64_t vmcs_size = (vmx_basic & VMX_BASIC_VMCS_SIZE_MASK) >> 32;
    if (vmcs_size > PAGE_SIZE) {
        GR_LOG("vmx: enter_root fail step1 (VMCS size) sz=", vmcs_size);
        return false;
    }

    /* Step 2: VMCS memory type must be write-back. */
    uint64_t vmcs_mem_type = (vmx_basic & VMX_BASIC_MEMORY_TYPE_MASK) >> 50;
    if (vmcs_mem_type != MTRR_TYPE_WB) {
        GR_LOG("vmx: enter_root fail step2 (VMCS memtype!=WB) mt=", vmcs_mem_type);
        return false;
    }

    /* Step 3: True MSR controls must be supported (bit 55). */
    if (!(vmx_basic & VMX_BASIC_DEFAULT1_ZERO)) {
        GR_LOG("vmx: enter_root fail step3 (no true-ctls) basic=", vmx_basic);
        return false;
    }

    /*
     * Step 4: Determine EPT + VPID support from IA32_VMX_EPT_VPID_CAP.
     * Index 12 = MSR_IA32_VMX_EPT_VPID_CAP (0x48C - 0x480 = 12).
     */
    uint64_t ept_cap = vcpu->vmx_msr[12];
    vcpu->ept_controls = 0;
    if ((ept_cap & VMX_EPT_PAGE_WALK_4_BIT) &&
        (ept_cap & VMX_EPTP_WB_BIT) &&
        (ept_cap & VMX_EPT_2MB_PAGE_BIT)) {
        vcpu->ept_controls = SECONDARY_EXEC_ENABLE_EPT |
                             SECONDARY_EXEC_ENABLE_VPID;
    }

    /*
     * Step 5: Write VMCS revision IDs.
     * See SDM Vol. 3C, Section 24.2.
     */
    uint32_t revision = (uint32_t)(vmx_basic & VMX_BASIC_REVISION_MASK);
    vcpu->vmxon_region.revision_id = revision;
    vcpu->vmcs_region.revision_id  = revision;

    /* Step 6: Cache physical addresses. */
    vcpu->vmxon_phys      = virt_to_phys_vmcs(&vcpu->vmxon_region);
    vcpu->vmcs_phys       = virt_to_phys_vmcs(&vcpu->vmcs_region);
    vcpu->msr_bitmap_phys = virt_to_phys_vmcs(&vcpu->msr_bitmap);

    /*
     * Step 7: Adjust CR0 and CR4 per VMX fixed-bit requirements.
     * Index 6/7 = IA32_VMX_CR0_FIXED0/1, 8/9 = IA32_VMX_CR4_FIXED0/1.
     * See SDM Vol. 3C, Section 23.8.
     */
    uint64_t cr0 = vcpu->host_regs.cr0;
    cr0 |= (uint32_t)(vcpu->vmx_msr[6]);          /* CR0_FIXED0: must-be-1 */
    cr0 &= (uint32_t)(vcpu->vmx_msr[7]);          /* CR0_FIXED1: must-be-0 */
    gr_wrcr0(cr0);
    vcpu->host_regs.cr0 = cr0;

    uint64_t cr4 = vcpu->host_regs.cr4;
    cr4 |= (uint32_t)(vcpu->vmx_msr[8]);          /* CR4_FIXED0: must-be-1 */
    cr4 &= (uint32_t)(vcpu->vmx_msr[9]);          /* CR4_FIXED1: must-be-0 */
    cr4 |= BIT(13);    /* CR4.VMXE — required before VMXON */
    gr_wrcr4(cr4);
    vcpu->host_regs.cr4 = cr4;

    /*
     * Step 8: Enter VMX root operation.
     * See SDM Vol. 3C, Section 23.7.
     */
    GR_LOG("vmx: attempting VMXON, region phys=", vcpu->vmxon_phys);
    GR_LOG("vmx: VMCS revision=", (uint64_t)revision);
    GR_LOG("vmx: CR4 after VMXE bit=", cr4);
    if (gr_vmxon(&vcpu->vmxon_phys)) {
        GR_LOG_STR("vmx: VMXON instruction faulted (CF=1)");
        return false;
    }
    GR_LOG_STR("vmx: VMXON succeeded, now in VMX root");

    /*
     * Step 9: Clear the VMCS (set to "clear" launch state), then load it
     * as the current VMCS on this logical processor.
     */
    if (gr_vmclear(&vcpu->vmcs_phys)) {
        GR_LOG_STR("vmx: VMCLEAR failed");
        gr_vmxoff();
        return false;
    }

    if (gr_vmptrld(&vcpu->vmcs_phys)) {
        GR_LOG_STR("vmx: VMPTRLD failed");
        gr_vmxoff();
        return false;
    }

    GR_LOG_STR("vmx: enter_root complete (VMXON + VMCLEAR + VMPTRLD OK)");
    return true;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * gr_vmx_setup_vmcs — Populate every VMCS field
 * See SDM Vol. 3C, Sections 24.4 – 24.9.
 * ═══════════════════════════════════════════════════════════════════════════ */

void
gr_vmx_setup_vmcs(gr_vmx_vcpu_t *vcpu)
{
    const gr_special_regs_t *regs = &vcpu->host_regs;
    vmx_gdt_entry_t seg;

    /* ── VMCS link pointer (required for shadow VMCS, set to ~0) ─────── */
    gr_vmwrite(VMCS_LINK_POINTER, ~0ULL);

    /* ── EPT pointer + VPID ──────────────────────────────────────────── */
    if (vcpu->ept_controls != 0) {
        gr_vmwrite(VMCS_EPT_POINTER, vcpu->ept.eptp.raw);
        gr_vmwrite(VMCS_VIRTUAL_PROCESSOR_ID, 1);
    }

    /* ── MSR bitmap (all zeroes = pass-through all MSRs) ─────────────── */
    gr_vmwrite(VMCS_MSR_BITMAP, vcpu->msr_bitmap_phys);

    /*
     * ── VM-execution controls ──────────────────────────────────────────
     *
     * MSR indices for the "true" capability MSRs:
     *   13 = IA32_VMX_TRUE_PINBASED_CTLS    (0x48D)
     *   14 = IA32_VMX_TRUE_PROCBASED_CTLS   (0x48E)
     *   15 = IA32_VMX_TRUE_EXIT_CTLS        (0x48F)
     *   16 = IA32_VMX_TRUE_ENTRY_CTLS       (0x490)
     *   11 = IA32_VMX_PROCBASED_CTLS2       (0x48B)
     */

    /* Secondary processor-based controls — enable RDTSCP, INVPCID,
     * XSAVES, and EPT/VPID if supported.  See SDM Sec 24.6.2. */
    gr_vmwrite(VMCS_SECONDARY_EXEC_CTRL,
               gr_vmx_adjust_controls(
                   vcpu->vmx_msr[11],
                   SECONDARY_EXEC_ENABLE_RDTSCP  |
                   SECONDARY_EXEC_ENABLE_INVPCID |
                   SECONDARY_EXEC_XSAVES         |
                   vcpu->ept_controls));

    /* Pin-based controls — no additional bits requested. */
    gr_vmwrite(VMCS_PIN_BASED_EXEC_CTRL,
               gr_vmx_adjust_controls(vcpu->vmx_msr[13], 0));

    /* Primary processor-based controls — activate MSR bitmap and
     * secondary controls.  See SDM Sec 24.6.2. */
    gr_vmwrite(VMCS_CPU_BASED_EXEC_CTRL,
               gr_vmx_adjust_controls(
                   vcpu->vmx_msr[14],
                   CPU_BASED_ACTIVATE_MSR_BITMAP |
                   CPU_BASED_ACTIVATE_SECONDARY_CTLS));

    /* VM-exit controls — long-mode host.  See SDM Sec 24.7.1. */
    gr_vmwrite(VMCS_EXIT_CONTROLS,
               gr_vmx_adjust_controls(vcpu->vmx_msr[15],
                                       VM_EXIT_IA32E_MODE));

    /* VM-entry controls — long-mode guest.  See SDM Sec 24.8.1. */
    gr_vmwrite(VMCS_ENTRY_CONTROLS,
               gr_vmx_adjust_controls(vcpu->vmx_msr[16],
                                       VM_ENTRY_IA32E_MODE));

    /* No exception bitmap — let all exceptions through to guest */
    gr_vmwrite(VMCS_EXCEPTION_BITMAP, 0);
    gr_vmwrite(VMCS_PF_ERROR_CODE_MASK, 0);
    gr_vmwrite(VMCS_PF_ERROR_CODE_MATCH, 0);
    gr_vmwrite(VMCS_CR3_TARGET_COUNT, 0);
    gr_vmwrite(VMCS_EXIT_MSR_STORE_COUNT, 0);
    gr_vmwrite(VMCS_EXIT_MSR_LOAD_COUNT, 0);
    gr_vmwrite(VMCS_ENTRY_MSR_LOAD_COUNT, 0);

    /* ── Guest segment registers ────────────────────────────────────── */

    /* CS — Ring 0 code */
    gdt_to_vmx_entry(regs->gdtr.base, regs->cs, &seg);
    gr_vmwrite(VMCS_GUEST_CS_SEL,           seg.selector);
    gr_vmwrite(VMCS_GUEST_CS_LIMIT,         seg.limit);
    gr_vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, seg.access_rights);
    gr_vmwrite(VMCS_GUEST_CS_BASE,          seg.base);
    gr_vmwrite(VMCS_HOST_CS_SEL,            regs->cs & ~RPL_MASK);

    /* SS — Ring 0 stack */
    gdt_to_vmx_entry(regs->gdtr.base, regs->ss, &seg);
    gr_vmwrite(VMCS_GUEST_SS_SEL,           seg.selector);
    gr_vmwrite(VMCS_GUEST_SS_LIMIT,         seg.limit);
    gr_vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, seg.access_rights);
    gr_vmwrite(VMCS_GUEST_SS_BASE,          seg.base);
    gr_vmwrite(VMCS_HOST_SS_SEL,            regs->ss & ~RPL_MASK);

    /* DS */
    gdt_to_vmx_entry(regs->gdtr.base, regs->ds, &seg);
    gr_vmwrite(VMCS_GUEST_DS_SEL,           seg.selector);
    gr_vmwrite(VMCS_GUEST_DS_LIMIT,         seg.limit);
    gr_vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, seg.access_rights);
    gr_vmwrite(VMCS_GUEST_DS_BASE,          seg.base);
    gr_vmwrite(VMCS_HOST_DS_SEL,            regs->ds & ~RPL_MASK);

    /* ES */
    gdt_to_vmx_entry(regs->gdtr.base, regs->es, &seg);
    gr_vmwrite(VMCS_GUEST_ES_SEL,           seg.selector);
    gr_vmwrite(VMCS_GUEST_ES_LIMIT,         seg.limit);
    gr_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, seg.access_rights);
    gr_vmwrite(VMCS_GUEST_ES_BASE,          seg.base);
    gr_vmwrite(VMCS_HOST_ES_SEL,            regs->es & ~RPL_MASK);

    /* FS */
    gdt_to_vmx_entry(regs->gdtr.base, regs->fs, &seg);
    gr_vmwrite(VMCS_GUEST_FS_SEL,           seg.selector);
    gr_vmwrite(VMCS_GUEST_FS_LIMIT,         seg.limit);
    gr_vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, seg.access_rights);
    gr_vmwrite(VMCS_GUEST_FS_BASE,          seg.base);
    gr_vmwrite(VMCS_HOST_FS_BASE,           seg.base);
    gr_vmwrite(VMCS_HOST_FS_SEL,            regs->fs & ~RPL_MASK);

    /* GS — base comes from MSR, not GDT, in long mode */
    gdt_to_vmx_entry(regs->gdtr.base, regs->gs, &seg);
    gr_vmwrite(VMCS_GUEST_GS_SEL,           seg.selector);
    gr_vmwrite(VMCS_GUEST_GS_LIMIT,         seg.limit);
    gr_vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, seg.access_rights);
    gr_vmwrite(VMCS_GUEST_GS_BASE,          regs->gs_base);
    gr_vmwrite(VMCS_HOST_GS_BASE,           regs->gs_base);
    gr_vmwrite(VMCS_HOST_GS_SEL,            regs->gs & ~RPL_MASK);

    /* TR — Task State Segment */
    gdt_to_vmx_entry(regs->gdtr.base, regs->tr, &seg);
    gr_vmwrite(VMCS_GUEST_TR_SEL,           seg.selector);
    gr_vmwrite(VMCS_GUEST_TR_LIMIT,         seg.limit);
    gr_vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, seg.access_rights);
    gr_vmwrite(VMCS_GUEST_TR_BASE,          seg.base);
    gr_vmwrite(VMCS_HOST_TR_BASE,           seg.base);
    gr_vmwrite(VMCS_HOST_TR_SEL,            regs->tr & ~RPL_MASK);

    /* LDTR */
    gdt_to_vmx_entry(regs->gdtr.base, regs->ldtr, &seg);
    gr_vmwrite(VMCS_GUEST_LDTR_SEL,           seg.selector);
    gr_vmwrite(VMCS_GUEST_LDTR_LIMIT,         seg.limit);
    gr_vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, seg.access_rights);
    gr_vmwrite(VMCS_GUEST_LDTR_BASE,          seg.base);

    /* ── GDTR / IDTR ────────────────────────────────────────────────── */
    gr_vmwrite(VMCS_GUEST_GDTR_BASE,  regs->gdtr.base);
    gr_vmwrite(VMCS_GUEST_GDTR_LIMIT, regs->gdtr.limit);
    gr_vmwrite(VMCS_HOST_GDTR_BASE,   regs->gdtr.base);

    gr_vmwrite(VMCS_GUEST_IDTR_BASE,  regs->idtr.base);
    gr_vmwrite(VMCS_GUEST_IDTR_LIMIT, regs->idtr.limit);
    gr_vmwrite(VMCS_HOST_IDTR_BASE,   regs->idtr.base);

    /* ── Control registers ──────────────────────────────────────────── */

    /* CR0 — host and guest start identical; shadow = real value */
    gr_vmwrite(VMCS_HOST_CR0,          regs->cr0);
    gr_vmwrite(VMCS_GUEST_CR0,         regs->cr0);
    gr_vmwrite(VMCS_CR0_READ_SHADOW,   regs->cr0);
    gr_vmwrite(VMCS_CR0_GUEST_HOST_MASK, 0);

    /*
     * CR3 — Use the system (kernel) page table for the host, not whatever
     * user-mode process we might be running in at DPC time.
     */
    gr_vmwrite(VMCS_HOST_CR3,  vcpu->system_cr3);
    gr_vmwrite(VMCS_GUEST_CR3, regs->cr3);

    /* CR4 — mirror guest and host; shadow = real value */
    gr_vmwrite(VMCS_HOST_CR4,          regs->cr4);
    gr_vmwrite(VMCS_GUEST_CR4,         regs->cr4);
    gr_vmwrite(VMCS_CR4_READ_SHADOW,   regs->cr4);
    gr_vmwrite(VMCS_CR4_GUEST_HOST_MASK, 0);

    /* ── Debug state ────────────────────────────────────────────────── */
    gr_vmwrite(VMCS_GUEST_IA32_DEBUGCTL, regs->debug_ctl);
    gr_vmwrite(VMCS_GUEST_DR7,           regs->dr7);

    /* ── SYSENTER state ─────────────────────────────────────────────── */
    gr_vmwrite(VMCS_GUEST_SYSENTER_CS,  regs->sysenter_cs);
    gr_vmwrite(VMCS_GUEST_SYSENTER_ESP, regs->sysenter_esp);
    gr_vmwrite(VMCS_GUEST_SYSENTER_EIP, regs->sysenter_eip);
    gr_vmwrite(VMCS_HOST_SYSENTER_CS,   regs->sysenter_cs);
    gr_vmwrite(VMCS_HOST_SYSENTER_ESP,  regs->sysenter_esp);
    gr_vmwrite(VMCS_HOST_SYSENTER_EIP,  regs->sysenter_eip);

    /* ── Activity & interruptibility ────────────────────────────────── */
    gr_vmwrite(VMCS_GUEST_ACTIVITY_STATE,        GUEST_ACTIVITY_ACTIVE);
    gr_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_INFO, 0);
    gr_vmwrite(VMCS_GUEST_PENDING_DBG_EXCEPTIONS, 0);

    /*
     * ── Guest RIP / RSP ────────────────────────────────────────────────
     *
     * Guest RIP points to the restore function that runs when VMLAUNCH
     * succeeds.  Guest RSP matches the hypervisor stack so that the
     * restore function sees a valid stack frame.
     */
    gr_vmwrite(VMCS_GUEST_RIP,    (uintptr_t)gr_vmx_restore_guest);
    gr_vmwrite(VMCS_GUEST_RSP,    vcpu->hv_stack + vcpu->hv_stack_size);
    gr_vmwrite(VMCS_GUEST_RFLAGS, regs->rflags);

    /*
     * ── Host RIP / RSP ─────────────────────────────────────────────────
     *
     * Host RIP = VM-exit entry point (assembly stub that saves GPRs).
     * Host RSP = top of hypervisor stack, aligned for the ABI.  The
     * assembly stub will push a register context structure onto this
     * stack before calling into C.
     */
    gr_vmwrite(VMCS_HOST_RIP, (uintptr_t)gr_vmx_entry);
    gr_vmwrite(VMCS_HOST_RSP, vcpu->hv_stack + vcpu->hv_stack_size);
}
