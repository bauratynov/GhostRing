/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_cr_fixed_bits.c — CR0/CR4 fixed-bit adjustment law.
 *
 * Intel SDM Vol 3C, Section 23.8 ("Restrictions on VMX Operation"):
 *
 *   IA32_VMX_CR0_FIXED0 — bits that MUST be 1 in CR0 during VMX op
 *   IA32_VMX_CR0_FIXED1 — bits that MAY  be 1 in CR0 during VMX op
 *   IA32_VMX_CR4_FIXED0 — bits that MUST be 1 in CR4 during VMX op
 *   IA32_VMX_CR4_FIXED1 — bits that MAY  be 1 in CR4 during VMX op
 *
 *   Effective CRx = (current_CRx | FIXED0) & FIXED1
 *
 * Note the subtle difference from the control-field MSRs:
 *   - Control MSRs  : low32 = must_be_1, high32 = may_be_1
 *   - CR fixed MSRs : the whole 64-bit MSR is one field
 *
 * Mixing up these two layouts is a classic bring-up bug.  Symptom:
 * VMXON throws #GP or VMLAUNCH fails with invalid-host-state, and
 * bisecting it takes hours because the bit that was accidentally
 * dropped is often the PG (31) or NE (5) bit — both usually 1 on
 * any running system.
 */

#include "test_framework.h"

/* Mirror of the helper used in src/vmx/vmx_harden.h / vmx_vmcs.c. */
static uint64_t adjust_cr(uint64_t cr, uint64_t fixed0, uint64_t fixed1)
{
    return (cr | fixed0) & fixed1;
}

/* Real fixed-bit values observed under Hyper-V nested VT-x on our
 * test host.  From /dev/cpu/0/msr dump, hex-decoded:
 *   IA32_VMX_CR0_FIXED0 = 0x0000000080000021  (PE|NE|PG must be 1)
 *   IA32_VMX_CR0_FIXED1 = 0xFFFFFFFFFFFFFFFF  (all bits allowed)
 *   IA32_VMX_CR4_FIXED0 = 0x0000000000002000  (VMXE must be 1)
 *   IA32_VMX_CR4_FIXED1 = 0x00000000007FF8FF  (actual silicon limit)
 */
#define CR0_FIXED0_REAL   0x0000000080000021ULL
#define CR0_FIXED1_REAL   0xFFFFFFFFFFFFFFFFULL
#define CR4_FIXED0_REAL   0x0000000000002000ULL
#define CR4_FIXED1_REAL   0x00000000007FF8FFULL

#define CR0_PE            (1ULL << 0)
#define CR0_NE            (1ULL << 5)
#define CR0_PG            (1ULL << 31)
#define CR4_VMXE          (1ULL << 13)
#define CR4_SMEP          (1ULL << 20)
#define CR4_SMAP          (1ULL << 21)
#define CR4_PCIDE         (1ULL << 17)

TEST(test_cr0_must_have_pe_ne_pg)
{
    /* CR0 starts as all zeros — after adjustment it must have the
     * mandatory bits set, even if the caller "forgot" to set them. */
    uint64_t got = adjust_cr(0, CR0_FIXED0_REAL, CR0_FIXED1_REAL);
    ASSERT(got & CR0_PE);   /* protected mode */
    ASSERT(got & CR0_NE);   /* native FPU error reporting */
    ASSERT(got & CR0_PG);   /* paging */
}

TEST(test_cr0_preserves_allowed_bits)
{
    /* With all-ones FIXED1, every desired bit passes through. */
    uint64_t cr0 = 0x80000011ULL;  /* PE | ET | PG */
    uint64_t got = adjust_cr(cr0, CR0_FIXED0_REAL, CR0_FIXED1_REAL);
    /* Every bit in cr0 must still be present. */
    ASSERT_EQ(got & cr0, cr0);
}

TEST(test_cr4_vmxe_forced)
{
    /* VMX operation requires CR4.VMXE=1.  If a caller forgets to
     * set it, the adjustment must add it. */
    uint64_t got = adjust_cr(0, CR4_FIXED0_REAL, CR4_FIXED1_REAL);
    ASSERT(got & CR4_VMXE);
}

TEST(test_cr4_forbidden_bits_dropped)
{
    /* Bits above 0x7FF8FF in FIXED1 are NOT allowed on this silicon.
     * Any stray high bit in the input CR4 must be masked out. */
    uint64_t cr4 = 0xFFFFFFFFFFFFFFFFULL;   /* nonsense all-ones */
    uint64_t got = adjust_cr(cr4, CR4_FIXED0_REAL, CR4_FIXED1_REAL);
    /* Only bits inside FIXED1 survive. */
    ASSERT_EQ(got & ~CR4_FIXED1_REAL, 0);
}

TEST(test_cr4_keeps_smep_smap_pcide_when_allowed)
{
    /* SMEP, SMAP, PCIDE are all within 0x7FF8FF — should pass. */
    uint64_t cr4 = CR4_SMEP | CR4_SMAP | CR4_PCIDE;
    uint64_t got = adjust_cr(cr4, CR4_FIXED0_REAL, CR4_FIXED1_REAL);
    ASSERT(got & CR4_SMEP);
    ASSERT(got & CR4_SMAP);
    ASSERT(got & CR4_PCIDE);
    ASSERT(got & CR4_VMXE);   /* and VMXE forced */
}

TEST(test_adjust_is_idempotent)
{
    /* Applying the rule twice produces the same result.  If it
     * didn't, something is wrong with the bit-logic. */
    uint64_t cr0 = 0x80000021ULL;
    uint64_t once  = adjust_cr(cr0,  CR0_FIXED0_REAL, CR0_FIXED1_REAL);
    uint64_t twice = adjust_cr(once, CR0_FIXED0_REAL, CR0_FIXED1_REAL);
    ASSERT_EQ(once, twice);
}

TEST(test_not_confused_with_control_msr_layout)
{
    /* CLASSIC BUG: someone copies adjust_controls() for CRs and
     * writes `(cr | (uint32_t)msr) & (uint32_t)(msr >> 32)` — this
     * truncates the 64-bit CR to 32 bits AND uses the wrong half.
     * Verify that the correct formula uses full 64-bit width. */
    uint64_t cr0 = 0x80000000ULL;  /* bit 31 set (PG, a 32-bit bit) */
    uint64_t got = adjust_cr(cr0, CR0_FIXED0_REAL, CR0_FIXED1_REAL);
    /* Bit 31 (PG) must survive. */
    ASSERT(got & (1ULL << 31));
    /* And the upper 32 bits must remain addressable.  With the
     * buggy formula the upper half would be silently lost. */
    uint64_t high = adjust_cr(0x1ULL << 40, CR0_FIXED0_REAL, CR0_FIXED1_REAL);
    /* FIXED1 is all-ones, so bit 40 must survive. */
    ASSERT(high & (1ULL << 40));
}

TEST(test_fixed0_is_superset_of_zero)
{
    /* FIXED0 bits are always a subset of FIXED1 — you can't be
     * required to set a bit you're not allowed to set.  Sanity. */
    ASSERT_EQ(CR0_FIXED0_REAL & ~CR0_FIXED1_REAL, 0);
    ASSERT_EQ(CR4_FIXED0_REAL & ~CR4_FIXED1_REAL, 0);
}

int main(void)
{
    printf("GhostRing CR0/CR4 fixed-bit adjustment tests\n");
    printf("============================================\n");

    RUN_TEST(test_cr0_must_have_pe_ne_pg);
    RUN_TEST(test_cr0_preserves_allowed_bits);
    RUN_TEST(test_cr4_vmxe_forced);
    RUN_TEST(test_cr4_forbidden_bits_dropped);
    RUN_TEST(test_cr4_keeps_smep_smap_pcide_when_allowed);
    RUN_TEST(test_adjust_is_idempotent);
    RUN_TEST(test_not_confused_with_control_msr_layout);
    RUN_TEST(test_fixed0_is_superset_of_zero);

    REPORT();
}
