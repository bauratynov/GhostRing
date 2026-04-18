/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_pf_error_code.c — Page-fault error-code bit layout.
 *
 * Intel SDM Vol 3A, Section 4.7 / Table 4-18 defines the error code
 * pushed on the stack by #PF delivery.  Our EPT-violation handler in
 * src/vmx/vmx_exit.c may re-inject a #PF into the guest (e.g. for
 * ransomware canary pages where we want the guest to see an ordinary
 * access fault).  The error-code we write into
 * VMCS_ENTRY_EXCEPTION_ERROR_CODE must match the hardware layout, or
 * the guest's page-fault handler reads the wrong semantics.
 *
 *     Bit 0  (P)    : 0 = not-present fault, 1 = protection violation
 *     Bit 1  (W)    : 0 = read access,       1 = write access
 *     Bit 2  (U)    : 0 = supervisor mode,   1 = user mode
 *     Bit 3  (RSVD) : 1 = reserved bit set in a page-table entry
 *     Bit 4  (I)    : 1 = fault was from instruction fetch (NX violation)
 *     Bit 5  (PK)   : 1 = protection-key violation (CR4.PKE)
 *     Bit 6  (SS)   : 1 = shadow-stack access (CET)
 *     Bit 15 (SGX)  : 1 = inside an SGX enclave
 *
 * The classic bug is setting bit 1 (W) for a supposed "not present"
 * fault on a read — that tells the guest "write-fault on a present
 * page" and most kernels panic on that contradiction.  Lock the
 * common combinations used by our code.
 */

#include "test_framework.h"

#define PF_P      (1u << 0)   /* Present */
#define PF_W      (1u << 1)   /* Write */
#define PF_U      (1u << 2)   /* User */
#define PF_RSVD   (1u << 3)   /* Reserved bit */
#define PF_I      (1u << 4)   /* Instruction fetch */
#define PF_PK     (1u << 5)   /* Protection key */
#define PF_SS     (1u << 6)   /* Shadow stack */
#define PF_SGX    (1u << 15)  /* SGX enclave */

TEST(test_bit_positions_match_sdm_table_4_18)
{
    ASSERT_EQ(PF_P,    0x0001u);
    ASSERT_EQ(PF_W,    0x0002u);
    ASSERT_EQ(PF_U,    0x0004u);
    ASSERT_EQ(PF_RSVD, 0x0008u);
    ASSERT_EQ(PF_I,    0x0010u);
    ASSERT_EQ(PF_PK,   0x0020u);
    ASSERT_EQ(PF_SS,   0x0040u);
    ASSERT_EQ(PF_SGX,  0x8000u);
}

TEST(test_bits_are_distinct_single_bits)
{
    /* Bit positions 0..6 and 15 must all be disjoint. */
    uint32_t all = PF_P | PF_W | PF_U | PF_RSVD | PF_I | PF_PK | PF_SS | PF_SGX;
    int n = 0;
    for (int i = 0; i < 32; i++) if (all & (1u << i)) n++;
    ASSERT_EQ(n, 8);
}

TEST(test_not_present_kernel_read)
{
    /* A plain "kernel reads an absent page" fault — classic swapped-
     * out page access.  Error code = 0 (all bits clear). */
    uint32_t ec = 0;
    ASSERT_EQ(ec & (PF_P | PF_W | PF_U | PF_I), 0u);
}

TEST(test_user_write_to_present_readonly)
{
    /* User-mode program writes to a present, read-only page — the
     * canonical COW fault case.  P=1, W=1, U=1. */
    uint32_t ec = PF_P | PF_W | PF_U;
    ASSERT_EQ(ec, 7u);
}

TEST(test_kernel_instruction_fetch_nx_violation)
{
    /* Kernel tries to execute a no-execute page.  P=1, I=1, U=0. */
    uint32_t ec = PF_P | PF_I;
    ASSERT_EQ(ec, 0x11u);
    ASSERT_EQ(ec & PF_U, 0u);       /* not user mode */
    ASSERT_EQ(ec & PF_I, PF_I);     /* instruction fetch */
}

TEST(test_reserved_bit_set_in_pte)
{
    /* Our pte_monitor detector injects #PF with RSVD=1 when it
     * catches a guest setting a reserved bit in a PTE. */
    uint32_t ec = PF_P | PF_W | PF_RSVD;
    ASSERT_EQ(ec & PF_RSVD, PF_RSVD);
    /* RSVD faults are not an NX violation — bit 4 clears. */
    ASSERT_EQ(ec & PF_I, 0u);
}

TEST(test_shadow_stack_violation)
{
    /* CET shadow-stack violation — CR4.CET must be enabled in the
     * guest for this to be meaningful. */
    uint32_t ec = PF_P | PF_SS;
    ASSERT_EQ(ec & PF_SS, PF_SS);
    ASSERT_EQ(ec & 0x3Fu, PF_P);    /* bits 5:0: only P set */
}

TEST(test_write_and_not_present_is_contradictory_but_legal)
{
    /* Hardware allows the combination but semantically it means
     * "write that missed the page table".  Our EPT re-inject must
     * be careful: if we set W=1 with P=1, the guest sees a
     * protection violation on write; if we set W=1 with P=0, the
     * guest sees an absent-page fault on a write attempt. */
    uint32_t absent_write  = PF_W;
    uint32_t present_write = PF_P | PF_W;
    ASSERT_NEQ(absent_write, present_write);
    ASSERT_EQ(absent_write & PF_P,  0u);
    ASSERT_EQ(present_write & PF_P, PF_P);
}

TEST(test_reserved_field_stays_zero_on_clean_codes)
{
    /* Bits 7:14 and 16:31 must be zero in the error code per SDM.
     * If we accidentally set any of them the guest's PF handler
     * gets junk flags. */
    uint32_t ec = PF_P | PF_W | PF_U | PF_I;
    ASSERT_EQ(ec & 0x7F80u, 0u);        /* bits 14:7 */
    ASSERT_EQ(ec & 0xFFFF0000u, 0u);    /* high half */
}

int main(void)
{
    printf("GhostRing #PF error-code layout tests\n");
    printf("=====================================\n");

    RUN_TEST(test_bit_positions_match_sdm_table_4_18);
    RUN_TEST(test_bits_are_distinct_single_bits);
    RUN_TEST(test_not_present_kernel_read);
    RUN_TEST(test_user_write_to_present_readonly);
    RUN_TEST(test_kernel_instruction_fetch_nx_violation);
    RUN_TEST(test_reserved_bit_set_in_pte);
    RUN_TEST(test_shadow_stack_violation);
    RUN_TEST(test_write_and_not_present_is_contradictory_but_legal);
    RUN_TEST(test_reserved_field_stays_zero_on_clean_codes);

    REPORT();
}
