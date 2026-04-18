/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_ept_indices.c — GPA → (PDPT, PDE, PTE) index decomposition.
 *
 * Mirrors the rule used in src/vmx/vmx_ept.c:gr_vmx_ept_protect_page.
 * Off-by-one in a shift = protect the wrong page = silent detection
 * miss — the operator sees no alert when the attacker rewrites IDT.
 * These tests pin each shift and mask.
 */

#include "test_framework.h"

#define PAGE_SIZE      0x1000ULL
#define PAGE_SHIFT     12

/* Same decomposition as gr_vmx_ept_protect_page:
 *   pdpt_idx = (aligned >> 30) & 0x1FF   (1 GiB granularity)
 *   pde_idx  = (aligned >> 21) & 0x1FF   (2 MiB granularity)
 *   pte_idx  = (aligned >> 12) & 0x1FF   (4 KiB granularity)
 */
static inline uint32_t pdpt_idx(uint64_t gpa)
{
    uint64_t aligned = gpa & ~(PAGE_SIZE - 1);
    return (uint32_t)((aligned >> 30) & 0x1FF);
}
static inline uint32_t pde_idx(uint64_t gpa)
{
    uint64_t aligned = gpa & ~(PAGE_SIZE - 1);
    return (uint32_t)((aligned >> 21) & 0x1FF);
}
static inline uint32_t pte_idx(uint64_t gpa)
{
    uint64_t aligned = gpa & ~(PAGE_SIZE - 1);
    return (uint32_t)((aligned >> 12) & 0x1FF);
}

TEST(test_zero_gpa_all_zero)
{
    ASSERT_EQ(pdpt_idx(0), 0);
    ASSERT_EQ(pde_idx(0),  0);
    ASSERT_EQ(pte_idx(0),  0);
}

TEST(test_sub_page_alignment_irrelevant)
{
    /* Bits below 12 must be masked out — any GPA inside the same
     * 4 KiB page maps to the same PTE. */
    ASSERT_EQ(pte_idx(0x1000), pte_idx(0x1FFF));
    ASSERT_EQ(pte_idx(0x1000), pte_idx(0x1000 + 0x7AB));
}

TEST(test_first_page_indices)
{
    /* GPA 0x1000 is the second 4 KiB page.  pte_idx = 1. */
    ASSERT_EQ(pte_idx(0x1000), 1);
    ASSERT_EQ(pde_idx(0x1000),  0);
    ASSERT_EQ(pdpt_idx(0x1000), 0);
}

TEST(test_2mb_boundary)
{
    /* 0x200000 (2 MiB) is the first PDE boundary. */
    ASSERT_EQ(pde_idx(0x200000),  1);
    ASSERT_EQ(pte_idx(0x200000),  0);
    ASSERT_EQ(pdpt_idx(0x200000), 0);
}

TEST(test_1gb_boundary)
{
    /* 0x40000000 (1 GiB) is the first PDPT boundary. */
    ASSERT_EQ(pdpt_idx(0x40000000), 1);
    ASSERT_EQ(pde_idx(0x40000000),  0);
    ASSERT_EQ(pte_idx(0x40000000),  0);
}

TEST(test_apic_mmio_0xfee00000)
{
    /* The local APIC MMIO base is 0xFEE00000 — a GPA that must
     * resolve to a specific (pdpt=3, pde=503, pte=0) triplet.
     * Widely used address so regressing its decode would break
     * many detectors at once. */
    ASSERT_EQ(pdpt_idx(0xFEE00000), 3);
    ASSERT_EQ(pde_idx(0xFEE00000),  503);
    ASSERT_EQ(pte_idx(0xFEE00000),  0);
}

TEST(test_max_512gb_boundary)
{
    /* 0x7FFFFF000 is the very last 4 KiB page of the 512 GiB range
     * our identity EPT covers.  All three indices must be 511. */
    ASSERT_EQ(pdpt_idx(0x7FFFFF000ULL), 511);
    ASSERT_EQ(pde_idx(0x7FFFFF000ULL),  511);
    ASSERT_EQ(pte_idx(0x7FFFFF000ULL),  511);
}

TEST(test_linux_idt_fixmap_gpa)
{
    /* Linux 6.12 maps the IDT at GVA 0xfffffe0000000000 but the
     * backing physical page is typically in low memory.  Example
     * GPA 0x12000: pdpt=0, pde=0, pte=18 (0x12). */
    ASSERT_EQ(pdpt_idx(0x12000), 0);
    ASSERT_EQ(pde_idx(0x12000),  0);
    ASSERT_EQ(pte_idx(0x12000),  0x12);
}

TEST(test_no_index_exceeds_511)
{
    /* Regression: the & 0x1FF mask must be present on every index.
     * If someone removed it, large GPAs would produce >511 indices
     * and we'd index out of bounds into the next table. */
    uint64_t gpas[] = {
        0x123456789ABCDEF0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x8000000000000000ULL,
    };
    for (int i = 0; i < 3; i++) {
        ASSERT(pdpt_idx(gpas[i]) <= 511);
        ASSERT(pde_idx(gpas[i])  <= 511);
        ASSERT(pte_idx(gpas[i])  <= 511);
    }
}

int main(void)
{
    printf("GhostRing EPT index decomposition tests\n");
    printf("=======================================\n");

    RUN_TEST(test_zero_gpa_all_zero);
    RUN_TEST(test_sub_page_alignment_irrelevant);
    RUN_TEST(test_first_page_indices);
    RUN_TEST(test_2mb_boundary);
    RUN_TEST(test_1gb_boundary);
    RUN_TEST(test_apic_mmio_0xfee00000);
    RUN_TEST(test_max_512gb_boundary);
    RUN_TEST(test_linux_idt_fixmap_gpa);
    RUN_TEST(test_no_index_exceeds_511);

    REPORT();
}
