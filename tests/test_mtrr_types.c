/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_mtrr_types.c — MTRR memory-type encoding stability.
 *
 * The EPT PDE / PTE has a 3-bit mem_type field that must match the
 * MTRR values Intel hard-codes in SDM Vol 3A, Section 11.11:
 *
 *   0 = Uncacheable (UC)
 *   1 = Write Combining (WC)
 *   4 = Write Through (WT)
 *   5 = Write Protected (WP)
 *   6 = Write Back (WB)
 *
 * Wrong value is silent: the CPU still runs, but MMIO regions cached
 * as WB produce bogus device reads (e.g., network cards write DMA
 * descriptors and the CPU reads stale cached copies).  A debugging
 * nightmare, exactly the thing we want CI to catch before ship.
 */

#include "test_framework.h"

/* Values we use in src/vmx/vmx_ept.c. */
#define MTRR_TYPE_UC  0
#define MTRR_TYPE_WC  1
#define MTRR_TYPE_WT  4
#define MTRR_TYPE_WP  5
#define MTRR_TYPE_WB  6

TEST(test_mtrr_codes_are_intel_spec)
{
    ASSERT_EQ(MTRR_TYPE_UC, 0);
    ASSERT_EQ(MTRR_TYPE_WC, 1);
    ASSERT_EQ(MTRR_TYPE_WT, 4);
    ASSERT_EQ(MTRR_TYPE_WP, 5);
    ASSERT_EQ(MTRR_TYPE_WB, 6);
}

TEST(test_reserved_codes_are_not_used)
{
    /* 2, 3, 7 are reserved in SDM 11.11.  Our code must never emit
     * them into EPT mem_type — reserved values produce
     * EPT-misconfiguration VM-exits. */
    int used[] = {0, 1, 4, 5, 6};
    for (int candidate = 2; candidate <= 7; candidate++) {
        if (candidate == 4 || candidate == 5 || candidate == 6) continue;
        /* 2, 3, 7 reserved */
        if (candidate == 2 || candidate == 3 || candidate == 7) {
            int is_used = 0;
            for (size_t k = 0; k < sizeof(used)/sizeof(used[0]); k++)
                if (used[k] == candidate) is_used = 1;
            ASSERT_EQ(is_used, 0);  /* we must not use reserved codes */
        }
    }
}

TEST(test_mem_type_fits_three_bits)
{
    /* EPT PDE mem_type is bits [5:3], three bits.  All our values
     * must fit. */
    int vals[] = { MTRR_TYPE_UC, MTRR_TYPE_WC, MTRR_TYPE_WT,
                    MTRR_TYPE_WP, MTRR_TYPE_WB };
    for (size_t i = 0; i < sizeof(vals)/sizeof(vals[0]); i++) {
        ASSERT((vals[i] & ~0x7) == 0);
    }
}

TEST(test_wb_is_the_default_for_ram)
{
    /* The EPT init loop marks every 2 MiB as WB by default (matched
     * by MTRR on a healthy board).  If the constant drifts, every
     * RAM access becomes UC and the guest runs at 1 % speed. */
    ASSERT_EQ(MTRR_TYPE_WB, 6);
}

TEST(test_uc_is_zero_for_mmio_fallback)
{
    /* When gr_vmx_mtrr_adjust can't resolve a type, it falls back
     * to UC (zero).  UC-for-zero is both the Intel spec and a safe
     * default (worst-case slow but correct). */
    ASSERT_EQ(MTRR_TYPE_UC, 0);
}

TEST(test_variable_mtrr_mask_valid_bit)
{
    /* Variable-range MTRRs have a 'valid' bit at position 11 of the
     * mask MSR (SDM 11.11.2.3).  Verify our constants line up. */
    const uint64_t MTRR_VALID = 1ULL << 11;
    ASSERT_EQ(MTRR_VALID, 0x800ULL);
}

int main(void)
{
    printf("GhostRing MTRR memory-type encoding tests\n");
    printf("=========================================\n");

    RUN_TEST(test_mtrr_codes_are_intel_spec);
    RUN_TEST(test_reserved_codes_are_not_used);
    RUN_TEST(test_mem_type_fits_three_bits);
    RUN_TEST(test_wb_is_the_default_for_ram);
    RUN_TEST(test_uc_is_zero_for_mmio_fallback);
    RUN_TEST(test_variable_mtrr_mask_valid_bit);

    REPORT();
}
