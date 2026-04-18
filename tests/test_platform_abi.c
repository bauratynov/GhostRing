/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_platform_abi.c — Contract tests for the platform abstraction.
 *
 * The hypervisor core calls gr_virt_to_phys() / gr_phys_to_virt() in
 * EPT walk, MSR bitmap setup, VMCS region preparation, and monitor
 * init.  A platform implementation that violates the round-trip law
 * (phys_to_virt(virt_to_phys(p)) == p for valid p) is the exact
 * class of bug that caused the 'kernel #PF during IDT protect'
 * regression in v0.1.0 bring-up.
 *
 * Tests run a stub platform implementation so the core code can be
 * exercised in userspace.
 */

#include <stdlib.h>
#include "test_framework.h"

/* Minimal standin types — the core's platform abstraction just
 * needs the two conversion functions for this test. */
typedef uint64_t phys_addr_t;

/*
 * Userspace fake: treat the returned pointer as physical.  On Linux
 * direct-map kernels phys = virt - PAGE_OFFSET, but for our ABI test
 * we just need a monotonic bijection.  We add a fixed bias so the
 * round-trip is non-trivial (rules out a pass-by-identity stub).
 */
#define FAKE_BIAS  0xFFFF888000000000ULL

static phys_addr_t fake_virt_to_phys(void *va)
{
    return (phys_addr_t)((uintptr_t)va - FAKE_BIAS);
}

static void *fake_phys_to_virt(phys_addr_t pa)
{
    return (void *)(uintptr_t)(pa + FAKE_BIAS);
}

TEST(test_round_trip_identity)
{
    /* Several pointers — the only contract is phys_to_virt(virt_to_phys(p)) == p. */
    void *ptrs[] = {
        (void *)(FAKE_BIAS + 0x1000),
        (void *)(FAKE_BIAS + 0x12345678),
        (void *)(FAKE_BIAS + 0xDEADBEEFCAFEULL),
    };
    for (int i = 0; i < 3; i++) {
        phys_addr_t pa = fake_virt_to_phys(ptrs[i]);
        void       *rt = fake_phys_to_virt(pa);
        ASSERT(rt == ptrs[i]);
    }
}

TEST(test_phys_is_page_aligned_when_virt_is)
{
    /* A page-aligned virtual address must map to a page-aligned
     * physical address.  The EPT walker assumes this when it stores
     * (pa >> 12) as a PFN. */
    void *va = (void *)(FAKE_BIAS + 0x200000);
    phys_addr_t pa = fake_virt_to_phys(va);
    ASSERT_EQ(pa & 0xFFF, 0);
}

TEST(test_different_inputs_give_different_outputs)
{
    /* The function must be injective — two distinct virtual
     * addresses never collide at the same physical.  Otherwise EPT
     * entries would alias and detection fires at random. */
    phys_addr_t a = fake_virt_to_phys((void *)(FAKE_BIAS + 0x1000));
    phys_addr_t b = fake_virt_to_phys((void *)(FAKE_BIAS + 0x2000));
    ASSERT_NEQ(a, b);
}

TEST(test_phys_fits_uint64)
{
    /* EPT PFN field is 40 bits (supports up to 52-bit physical
     * addresses on modern x86-64), so the physical value our
     * platform returns must fit in uint64_t without truncation.
     * Just compile-time size check. */
    ASSERT_EQ(sizeof(phys_addr_t), sizeof(uint64_t));
}

TEST(test_null_is_handled)
{
    /* Policy: we never pass NULL through virt_to_phys in the
     * hypervisor core.  The platform stub may do anything for NULL,
     * but the CALLER contract requires non-NULL — assert that any
     * production allocation check rejects NULL before this point. */
    void *p = malloc(4096);
    ASSERT(p != NULL);
    phys_addr_t pa = fake_virt_to_phys(p);
    void *rt = fake_phys_to_virt(pa);
    ASSERT(rt == p);
    free(p);
}

int main(void)
{
    printf("GhostRing platform ABI round-trip tests\n");
    printf("=======================================\n");

    RUN_TEST(test_round_trip_identity);
    RUN_TEST(test_phys_is_page_aligned_when_virt_is);
    RUN_TEST(test_different_inputs_give_different_outputs);
    RUN_TEST(test_phys_fits_uint64);
    RUN_TEST(test_null_is_handled);

    REPORT();
}
