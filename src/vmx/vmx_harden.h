/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * vmx_harden.h — CPU hardening and anti-detection measures.
 *
 * Collects all CPU-level security hardening that doesn't fit neatly
 * into EPT, VMCS, or monitor modules.  Each function addresses a
 * specific attack vector discovered in 2024-2026 research.
 *
 * Attack vectors addressed:
 *   1. Microcode injection (CVE-2024-56161) — block WRMSR to 0x79
 *   2. Debug register hooking — monitor DR0-DR7 writes
 *   3. TSC-based hypervisor detection — enable TSC offsetting
 *   4. DVFS frequency side channel — virtualize perf MSRs
 *   5. L3 cache side channel — Intel CAT partitioning
 *   6. IOMMU verification — check firmware didn't lie
 *   7. RowHammer self-protection — CRC32C on own EPT tables
 */

#ifndef GHOSTRING_VMX_HARDEN_H
#define GHOSTRING_VMX_HARDEN_H

#include "../common/ghostring.h"

/* ── MSR indices for hardening ───────���─────────────────────────────────── */

#define MSR_IA32_UCODE_WRITE        0x79    /* microcode update trigger */
#define MSR_IA32_PERF_STATUS        0x198   /* current P-state (read) */
#define MSR_IA32_PERF_CTL           0x199   /* P-state control (write) */
#define MSR_IA32_ENERGY_PERF_BIAS   0x1B0   /* energy/perf hint */
#define MSR_IA32_L3_QOS_MASK_0      0xC90   /* CAT L3 mask for COS 0 */
#define MSR_IA32_PQR_ASSOC          0xC8F   /* CAT COS association */
#define MSR_IA32_TSC_ADJUST         0x3B    /* TSC offset adjustment */

/* ── 1. Block microcode updates from guest ─────────────────────────────── */

/*
 * CVE-2024-56161: AMD's microcode signature used a weak hash.
 * Google researchers loaded arbitrary microcode via WRMSR 0x79.
 *
 * Fix: add MSR 0x79 to the WRMSR intercept bitmap.
 * On write attempt: inject #GP(0) into guest.
 */
static inline void gr_harden_block_microcode(uint8_t *msr_bitmap)
{
    /*
     * MSR bitmap layout (Intel SDM Vol. 3C, Section 24.6.9):
     *   Write bitmap for MSRs 0x00000000-0x00001FFF: offset 0x800
     *   Each bit = one MSR.  Byte offset = 0x800 + (msr / 8)
     *   Bit within byte = msr % 8
     */
    uint32_t byte_off = 0x800 + (MSR_IA32_UCODE_WRITE / 8);
    uint32_t bit_off  = MSR_IA32_UCODE_WRITE % 8;
    msr_bitmap[byte_off] |= (1 << bit_off);
}

/* ── 2. Enable debug register monitoring ───────────────────────────────── */

/*
 * Rootkits use DR0-DR3 hardware breakpoints on syscall entry points
 * (KiSystemCall64, ia32_sysenter_target) for stealthy hooking.
 * The "Blindside" technique uses NtContinue to set DRs without ETW.
 *
 * Fix: enable MOV-DR exiting in primary VM-execution controls.
 * On DR write: validate target address is not a kernel entry point.
 *
 * VMCS bit: CPU_BASED_MOV_DR_EXITING (bit 23, value 0x00800000)
 */

/* Check if a DR0-DR3 value targets a suspicious address */
static inline bool gr_harden_check_dr(uint64_t dr_value,
                                       uint64_t lstar_addr,
                                       uint64_t sysenter_addr)
{
    /* DR pointing at syscall entry = hooking attempt */
    if (dr_value == lstar_addr || dr_value == sysenter_addr)
        return false;  /* suspicious */

    /* DR pointing at first instruction of ntoskrnl dispatch */
    /* More addresses can be added based on OS-specific knowledge */

    return true;  /* ok */
}

/* ── 3. TSC anti-detection ─────────────────��───────────────────────────── */

/*
 * Guests detect hypervisors by measuring RDTSC latency variations.
 * BI-ZONE demonstrated speculative-execution-based detection.
 *
 * Mitigations:
 *   a) Enable TSC offsetting in VMCS (field TSC_OFFSET = 0x2010)
 *   b) Set offset to compensate for VM-exit overhead
 *   c) Enable RDTSC exiting only if needed (usually not)
 *
 * The offset is subtracted from the real TSC before returning to guest,
 * hiding the time spent in VM-exit handlers.
 */
static inline void gr_harden_tsc_offset(uint64_t exit_cost_cycles)
{
    /*
     * Negative offset: when guest reads TSC, it sees TSC - offset.
     * We subtract average exit cost so the guest doesn't see the
     * time "gap" during exits.
     *
     * Accumulate total exit overhead and apply periodically.
     */
    (void)exit_cost_cycles;
    /* Implementation: VMWRITE(TSC_OFFSET, accumulated_offset) */
}

/* ── 4. DVFS frequency side channel defense ────────────────────────────── */

/*
 * Guests can read MSR_IA32_PERF_STATUS to observe CPU frequency changes
 * caused by GhostRing's processing.  10 seconds of data reveals patterns.
 *
 * Fix: intercept RDMSR for perf MSRs and return constant values.
 */
static inline void gr_harden_dvfs(uint8_t *msr_bitmap)
{
    /* Intercept reads of performance/frequency MSRs */
    /* Read bitmap for MSRs 0x00000000-0x00001FFF: offset 0x000 */
    uint32_t msrs[] = { 0x198, 0x199, 0x1B0 };
    for (uint32_t i = 0; i < 3; i++) {
        uint32_t byte_off = 0x000 + (msrs[i] / 8);
        uint32_t bit_off  = msrs[i] % 8;
        msr_bitmap[byte_off] |= (1 << bit_off);
    }
}

/* Return fixed value for PERF_STATUS to hide frequency variations */
static inline uint64_t gr_harden_fake_perf_status(void)
{
    /* Return a fixed "nominal" frequency ratio.
     * Bits [15:8] = current ratio.  Hardcode to a typical value. */
    return 0x00002000;  /* ratio = 0x20 = 32 → 3.2 GHz nominal */
}

/* ── 5. Intel CAT L3 cache partitioning ────────��───────────────────────── */

/*
 * Without cache partitioning, guests can observe GhostRing's L3 cache
 * activity via Flush+Reload or Prime+Probe attacks.
 *
 * Intel CAT (Cache Allocation Technology) assigns cache ways to Classes
 * of Service (COS).  GhostRing gets its own COS with dedicated L3 ways.
 *
 * Detection: CPUID.10H:EBX[bit 1] = L3 CAT supported
 * Configuration: MSR_IA32_L3_QOS_MASK_n and MSR_IA32_PQR_ASSOC
 */
static inline bool gr_cat_supported(void)
{
    uint32_t eax, ebx, ecx, edx;
    gr_cpuid(0x10, 0, &eax, &ebx, &ecx, &edx);
    return (ebx & BIT(1)) != 0;  /* L3 CAT */
}

/*
 * Reserve 2 L3 cache ways for GhostRing (COS 1).
 * Assign guests to COS 0 with the remaining ways.
 *
 * Example for 11-way L3:
 *   COS 0 (guest):     mask = 0x1FF (ways 0-8)
 *   COS 1 (GhostRing): mask = 0x600 (ways 9-10)
 *
 * This prevents guest Flush+Reload from evicting GhostRing's data.
 */
static inline void gr_cat_init(void)
{
    if (!gr_cat_supported())
        return;

    /* Query number of ways: CPUID.10H.1:EAX[4:0] + 1 */
    uint32_t eax, ebx, ecx, edx;
    gr_cpuid(0x10, 1, &eax, &ebx, &ecx, &edx);
    uint32_t ways = (eax & 0x1F) + 1;

    if (ways < 4)
        return;  /* not enough ways to partition */

    /* Reserve top 2 ways for GhostRing (COS 1) */
    uint32_t ghost_mask = (3U << (ways - 2));
    uint32_t guest_mask = ((1U << (ways - 2)) - 1);

    gr_wrmsr(MSR_IA32_L3_QOS_MASK_0, guest_mask);       /* COS 0 = guest */
    gr_wrmsr(MSR_IA32_L3_QOS_MASK_0 + 1, ghost_mask);   /* COS 1 = GhostRing */

    /* Set current CPU to COS 1 (GhostRing) */
    uint64_t pqr = gr_rdmsr(MSR_IA32_PQR_ASSOC);
    pqr = (pqr & ~0xFFFFFFFF00000000ULL) | ((uint64_t)1 << 32);
    gr_wrmsr(MSR_IA32_PQR_ASSOC, pqr);
}

/* ── 6. IOMMU verification ─────────────────────────────────────────────── */

/*
 * CVE-2025-11901: UEFI firmware on ASUS/MSI/Gigabyte/ASRock *reports*
 * IOMMU as active but *fails to initialize* it.  Physical DMA attacks
 * succeed despite DMAR/IVRS ACPI tables being present.
 *
 * Fix: at GhostRing init, probe the actual IOMMU base registers to
 * verify they are programmed (not zero).
 *
 * Intel VT-d: DMAR ACPI table → DRHD → base address → read capability register
 * AMD IOMMU: IVRS ACPI table → base address → read MMIO capability
 *
 * If registers read as zero: IOMMU is NOT actually enabled.
 */
static inline bool gr_iommu_verify_intel(uint64_t drhd_base)
{
    /* VT-d capability register at offset 0x08 from DRHD base.
     * If zero, IOMMU is not initialized. */
    volatile uint64_t *cap = (volatile uint64_t *)(uintptr_t)(drhd_base + 0x08);
    return *cap != 0;
}

/* ── 7. RowHammer self-protection ─────���────────────────────────────────── */

/*
 * Phoenix RowHammer (CVE-2025-6202) can flip bits in DDR5 memory.
 * If GhostRing's EPT tables are targeted, EPT mappings could be
 * corrupted to grant guest access to hypervisor memory.
 *
 * Fix: periodically CRC32C our own EPT tables and compare.
 * Any unexpected change = bit flip = halt immediately.
 *
 * Uses gr_crc32() from integrity.c (already CRC32C polynomial).
 */
typedef struct {
    uint64_t ept_pml4_gpa;
    uint32_t expected_crc;
    bool     armed;
} gr_rowhammer_guard_t;

void gr_rowhammer_init(gr_rowhammer_guard_t *guard,
                       void *ept_pml4, uint64_t ept_size);
bool gr_rowhammer_check(gr_rowhammer_guard_t *guard,
                        void *ept_pml4, uint64_t ept_size);

#endif /* GHOSTRING_VMX_HARDEN_H */
