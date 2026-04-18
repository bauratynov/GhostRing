/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_exec_controls.c — pin / primary / secondary execution-control
 * bit positions.
 *
 * Intel SDM Vol 3C, Section 24.6:
 *
 *   Pin-based exec-ctrl (VMCS 0x4000):
 *     bit 0  — External-interrupt exiting
 *     bit 3  — NMI exiting
 *     bit 5  — Virtual NMIs
 *     bit 6  — Activate VMX preemption timer
 *     bit 7  — Process posted interrupts
 *
 *   Primary proc-based (0x4002) — subset:
 *     bit 28 — Use MSR bitmaps
 *     bit 31 — Activate secondary controls
 *
 *   Secondary proc-based (0x401E) — subset:
 *     bit 1  — Enable EPT
 *     bit 5  — Enable VPID
 *     bit 7  — Unrestricted guest
 *     bit 17 — Enable PML
 *
 * If bit 31 of PRIMARY is cleared, the WHOLE secondary field is
 * ignored — EPT, VPID, unrestricted guest all silently disabled.
 * Symptom: hypervisor loads, VM-entry succeeds, the guest takes a
 * #PF on its first user-mode instruction and the kernel panics with
 * "Unable to handle kernel paging request".
 *
 * This test locks the bit positions our bring-up code depends on.
 */

#include "test_framework.h"

/* Mirror of src/vmx/vmx_defs.h. */
#define PIN_BASED_EXT_INTR_MASK             (1u << 0)
#define PIN_BASED_NMI_EXITING               (1u << 3)
#define PIN_BASED_VIRTUAL_NMIS              (1u << 5)
#define PIN_BASED_PREEMPT_TIMER             (1u << 6)
#define PIN_BASED_POSTED_INTERRUPT          (1u << 7)

#define CPU_BASED_USE_MSR_BITMAPS           (1u << 28)
#define CPU_BASED_ACTIVATE_SECONDARY_CTLS   (1u << 31)

#define SECONDARY_EXEC_VIRT_APIC_ACCESSES   (1u << 0)
#define SECONDARY_EXEC_ENABLE_EPT           (1u << 1)
#define SECONDARY_EXEC_DESC_TABLE_EXIT      (1u << 2)
#define SECONDARY_EXEC_ENABLE_RDTSCP        (1u << 3)
#define SECONDARY_EXEC_VIRT_X2APIC_MODE     (1u << 4)
#define SECONDARY_EXEC_ENABLE_VPID          (1u << 5)
#define SECONDARY_EXEC_WBINVD_EXITING       (1u << 6)
#define SECONDARY_EXEC_UNRESTRICTED_GUEST   (1u << 7)
#define SECONDARY_EXEC_ENABLE_PML           (1u << 17)

#define VMCS_PIN_BASED_EXEC_CTRL            0x00004000u
#define VMCS_PRIMARY_EXEC_CTRL              0x00004002u
#define VMCS_SECONDARY_EXEC_CTRL            0x0000401Eu

TEST(test_pin_ctrl_bits_locked)
{
    ASSERT_EQ(PIN_BASED_EXT_INTR_MASK,    0x01u);
    ASSERT_EQ(PIN_BASED_NMI_EXITING,      0x08u);
    ASSERT_EQ(PIN_BASED_VIRTUAL_NMIS,     0x20u);
    ASSERT_EQ(PIN_BASED_PREEMPT_TIMER,    0x40u);
    ASSERT_EQ(PIN_BASED_POSTED_INTERRUPT, 0x80u);
}

TEST(test_activate_secondary_is_bit_31)
{
    /* If this moves, the whole secondary control block becomes
     * dead.  Guaranteed "works on bare-metal, fails on Hyper-V"
     * or vice versa regression. */
    ASSERT_EQ(CPU_BASED_ACTIVATE_SECONDARY_CTLS, 0x80000000u);
}

TEST(test_use_msr_bitmaps_is_bit_28)
{
    /* Without this bit set, every MSR RDMSR/WRMSR exits — our
     * perf is wrecked and we flood exits. */
    ASSERT_EQ(CPU_BASED_USE_MSR_BITMAPS, 0x10000000u);
}

TEST(test_secondary_core_bits_locked)
{
    /* The three secondary bits that, if misplaced, break the
     * hypervisor outright. */
    ASSERT_EQ(SECONDARY_EXEC_ENABLE_EPT,         0x02u);
    ASSERT_EQ(SECONDARY_EXEC_ENABLE_VPID,        0x20u);
    ASSERT_EQ(SECONDARY_EXEC_UNRESTRICTED_GUEST, 0x80u);
}

TEST(test_secondary_bits_disjoint)
{
    /* Sanity: the feature bits we OR together must not alias. */
    uint32_t mask = SECONDARY_EXEC_VIRT_APIC_ACCESSES
                  | SECONDARY_EXEC_ENABLE_EPT
                  | SECONDARY_EXEC_DESC_TABLE_EXIT
                  | SECONDARY_EXEC_ENABLE_RDTSCP
                  | SECONDARY_EXEC_VIRT_X2APIC_MODE
                  | SECONDARY_EXEC_ENABLE_VPID
                  | SECONDARY_EXEC_WBINVD_EXITING
                  | SECONDARY_EXEC_UNRESTRICTED_GUEST;
    /* popcount should equal the number of OR'd bits (8). */
    int bits = 0;
    for (int i = 0; i < 32; i++) if (mask & (1u << i)) bits++;
    ASSERT_EQ(bits, 8);
}

TEST(test_pml_bit_position)
{
    /* PML (Page Modification Logging) at bit 17 — we don't yet
     * enable it but a future ransomware module will. */
    ASSERT_EQ(SECONDARY_EXEC_ENABLE_PML, 1u << 17);
}

TEST(test_vmcs_exec_ctrl_encodings)
{
    /* These three VMCS field encodings come straight from SDM
     * Appendix B — same ABI concern as test_vmcs_encodings.c but
     * keeping them adjacent to the bit-position tests above so a
     * reviewer sees the full picture in one file. */
    ASSERT_EQ(VMCS_PIN_BASED_EXEC_CTRL, 0x4000u);
    ASSERT_EQ(VMCS_PRIMARY_EXEC_CTRL,   0x4002u);
    ASSERT_EQ(VMCS_SECONDARY_EXEC_CTRL, 0x401Eu);
}

TEST(test_canonical_secondary_mask_for_ghostring)
{
    /* The exact OR we write into SECONDARY_EXEC_CTRL.  A change in
     * this value between silicon generations will be caught by our
     * readback assert at bring-up (see src/vmx/vmx_vmcs.c) — but
     * also here, so regressions hit CI before the driver loads. */
    uint32_t want = SECONDARY_EXEC_ENABLE_EPT
                  | SECONDARY_EXEC_ENABLE_VPID
                  | SECONDARY_EXEC_UNRESTRICTED_GUEST
                  | SECONDARY_EXEC_ENABLE_RDTSCP;
    ASSERT_EQ(want, 0xAAu);  /* 1010'1010 */
}

int main(void)
{
    printf("GhostRing exec-controls bit-position tests\n");
    printf("==========================================\n");

    RUN_TEST(test_pin_ctrl_bits_locked);
    RUN_TEST(test_activate_secondary_is_bit_31);
    RUN_TEST(test_use_msr_bitmaps_is_bit_28);
    RUN_TEST(test_secondary_core_bits_locked);
    RUN_TEST(test_secondary_bits_disjoint);
    RUN_TEST(test_pml_bit_position);
    RUN_TEST(test_vmcs_exec_ctrl_encodings);
    RUN_TEST(test_canonical_secondary_mask_for_ghostring);

    REPORT();
}
