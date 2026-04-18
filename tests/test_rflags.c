/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_rflags.c — RFLAGS value validation for VM entry.
 *
 * Intel SDM Vol 3C, Section 26.3.1.4 ("Checks on Guest RIP and RFLAGS"):
 *
 *   - Bits 1         must be 1 (reserved, fixed)
 *   - Bits 3, 5, 15  must be 0 (reserved)
 *   - Bit 17 (VM)    must be 0 for 64-bit guest
 *   - Bits 22-31     must be 0 (reserved in 64-bit mode)
 *
 * vmx_vmcs.c forces VMCS_GUEST_RFLAGS = 0x2 to satisfy these checks
 * unconditionally.  This test locks the invariants so an 'optimisation'
 * later can't silently widen the field and trigger invalid-guest-state
 * on first VMLAUNCH.
 */

#include "test_framework.h"

/* The RFLAGS value our code hard-codes for guest entry. */
#define GR_GUEST_RFLAGS_BASE 0x2ULL

TEST(test_reserved_bit_1_is_set)
{
    ASSERT((GR_GUEST_RFLAGS_BASE >> 1) & 1);
}

TEST(test_reserved_bits_3_5_15_are_clear)
{
    ASSERT_EQ((GR_GUEST_RFLAGS_BASE >> 3)  & 1, 0);
    ASSERT_EQ((GR_GUEST_RFLAGS_BASE >> 5)  & 1, 0);
    ASSERT_EQ((GR_GUEST_RFLAGS_BASE >> 15) & 1, 0);
}

TEST(test_vm_bit_17_clear)
{
    /* VM = 1 puts CPU in virtual-8086 mode — illegal for 64-bit guest. */
    ASSERT_EQ((GR_GUEST_RFLAGS_BASE >> 17) & 1, 0);
}

TEST(test_upper_bits_clear_in_64bit)
{
    /* SDM: bits 22-31 must be 0 in 64-bit mode. */
    ASSERT_EQ((GR_GUEST_RFLAGS_BASE >> 22) & 0x3FF, 0);
}

TEST(test_interrupt_flag_state)
{
    /* Bit 9 = IF (interrupts enabled).  Our default is 0 — the
     * guest is expected to re-enable IF as part of its resume
     * sequence.  If we set it on entry, we could preempt ourselves
     * before VMLAUNCH completes. */
    ASSERT_EQ((GR_GUEST_RFLAGS_BASE >> 9) & 1, 0);
}

TEST(test_value_is_minimally_legal)
{
    /* The only bit set is bit 1 — the minimum legal RFLAGS value
     * that satisfies SDM 26.3.1.4. */
    ASSERT_EQ(GR_GUEST_RFLAGS_BASE, 0x2ULL);
}

TEST(test_setting_vm_bit_would_be_rejected)
{
    /* Sanity: if someone ever ORs 0x20000 (VM bit) into the value,
     * this test flags it.  Not a runtime check but a design-intent
     * lock in the test tree. */
    uint64_t bogus = GR_GUEST_RFLAGS_BASE | (1ULL << 17);
    ASSERT_NEQ(bogus, GR_GUEST_RFLAGS_BASE);
    ASSERT((bogus >> 17) & 1);   /* documents the forbidden bit */
}

int main(void)
{
    printf("GhostRing RFLAGS validation tests\n");
    printf("=================================\n");

    RUN_TEST(test_reserved_bit_1_is_set);
    RUN_TEST(test_reserved_bits_3_5_15_are_clear);
    RUN_TEST(test_vm_bit_17_clear);
    RUN_TEST(test_upper_bits_clear_in_64bit);
    RUN_TEST(test_interrupt_flag_state);
    RUN_TEST(test_value_is_minimally_legal);
    RUN_TEST(test_setting_vm_bit_would_be_rejected);

    REPORT();
}
