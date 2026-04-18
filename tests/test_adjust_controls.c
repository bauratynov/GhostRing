/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_adjust_controls.c — Law for VMX capability-MSR adjustment.
 *
 * Intel SDM Vol 3C, Appendix A.3-A.5:
 *
 *   IA32_VMX_TRUE_*_CTLS MSR encoding (64 bits):
 *     Low  32 bits = "allowed-0 settings" — bits that MUST be 1
 *                     in the control field
 *     High 32 bits = "allowed-1 settings" — bits that MAY  be 1
 *                     in the control field
 *
 *   Effective control value = (desired OR must_be_1) AND may_be_1
 *
 * Getting this rule wrong is a classic hypervisor bug.  Our
 * implementation in src/vmx/vmx_vmcs.c is:
 *
 *     desired |= (uint32_t)msr_value;          // must-be-1
 *     return  desired & (uint32_t)(msr_value >> 32);  // may-be-1
 *
 * Tests reproduce the function here and lock key invariants.
 */

#include "test_framework.h"

static uint32_t adjust(uint64_t msr, uint32_t desired)
{
    uint32_t must_one = (uint32_t)(msr & 0xFFFFFFFFu);
    uint32_t may_one  = (uint32_t)(msr >> 32);
    desired |= must_one;
    return desired & may_one;
}

TEST(test_must_be_one_bits_are_forced)
{
    /* MSR says bits 0-3 must be 1, all bits may be 1. */
    uint64_t msr = 0xFFFFFFFFULL << 32 | 0x0000000Fu;
    /* Desired = 0 — result must still have bits 0-3 set. */
    ASSERT_EQ(adjust(msr, 0), 0x0000000Fu);
}

TEST(test_may_not_be_one_bits_are_cleared)
{
    /* MSR says no bit may be 1, no bit must be 1. */
    uint64_t msr = 0ULL;  /* low=0, high=0 */
    ASSERT_EQ(adjust(msr, 0xFFFFFFFFu), 0);
}

TEST(test_desired_bits_preserved_when_allowed)
{
    /* MSR: no must-be-1, all may-be-1.  Desired passes through. */
    uint64_t msr = 0xFFFFFFFFULL << 32;
    ASSERT_EQ(adjust(msr, 0x12345678u), 0x12345678u);
}

TEST(test_combined_mandatory_and_forbidden)
{
    /* must-be-1: bit 0.  may-be-1: bits 0-7 only. */
    uint64_t msr = (0x000000FFULL << 32) | 0x00000001u;
    /* Desired: bits 5 + 10.  Result: bits 0 (forced) + 5 (allowed),
     * bit 10 must be cleared (not in may-be-1). */
    uint32_t got = adjust(msr, (1u << 5) | (1u << 10));
    ASSERT_EQ(got, 0x01u | (1u << 5));
}

TEST(test_vm_entry_ia32e_mode_bit_9)
{
    /* Sanity using a realistic MSR value observed on Hyper-V nested
     * VT-x: TRUE_ENTRY_CTLS = 0xd3ff000011fb.
     * must-be-1 bits = 0x11fb
     * may-be-1  bits = 0xd3ff
     * We want to set bit 9 (IA32e mode) and bit 15 (LOAD_GUEST_EFER). */
    uint64_t msr = 0x0000d3ff000011fbULL;
    uint32_t got = adjust(msr, (1u << 9) | (1u << 15));

    /* Must include must-be-1 bits (0x11fb) */
    ASSERT_EQ(got & 0x11fbu, 0x11fbu);
    /* Must include bits 9 and 15 we requested */
    ASSERT(got & (1u << 9));
    ASSERT(got & (1u << 15));
    /* Must not contain bits outside may-be-1 */
    ASSERT_EQ(got & ~0xd3ffu, 0);
}

TEST(test_msr_value_not_mutated)
{
    /* adjust() takes msr by value; just document the intent. */
    uint64_t msr = 0xCAFEBABEFEEDFACE;
    uint64_t snapshot = msr;
    adjust(msr, 0);
    ASSERT_EQ(msr, snapshot);
}

int main(void)
{
    printf("GhostRing gr_vmx_adjust_controls law tests\n");
    printf("==========================================\n");

    RUN_TEST(test_must_be_one_bits_are_forced);
    RUN_TEST(test_may_not_be_one_bits_are_cleared);
    RUN_TEST(test_desired_bits_preserved_when_allowed);
    RUN_TEST(test_combined_mandatory_and_forbidden);
    RUN_TEST(test_vm_entry_ia32e_mode_bit_9);
    RUN_TEST(test_msr_value_not_mutated);

    REPORT();
}
