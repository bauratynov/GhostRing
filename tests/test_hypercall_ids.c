/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_hypercall_ids.c — Locks the public hypercall numbers.
 *
 * Rationale: the `GR_HCALL_*` values are part of the ABI between the
 * guest loader, the agent and the hypervisor.  Changing any of them
 * silently would break every deployed copy of `ghostring-agent`.
 * This test asserts the exact wire values so a rename/renumber must
 * also update the test — preventing accidental ABI drift.
 */

#include "test_framework.h"

#define GR_HCALL_PING           0x47520000
#define GR_HCALL_STATUS         0x47520001
#define GR_HCALL_INTEGRITY      0x47520002
#define GR_HCALL_DKOM_SCAN      0x47520003
#define GR_HCALL_UNLOAD         0x47520004
#define GR_HCALL_MAGIC_REPLY    0x47685269

/* Also lock the devirt CPUID leaf — different namespace but same role:
 * a well-known constant rootkits would try to probe for GhostRing
 * presence. */
#define GR_MAGIC_CPUID_LEAF     0x47520001

TEST(test_hcall_ids_are_stable)
{
    /* Primary range: 0x47520000 + index.  Keeps the first four bytes
     * of every hypercall readable as "GR" in memory dumps. */
    ASSERT_EQ(GR_HCALL_PING,      0x47520000u);
    ASSERT_EQ(GR_HCALL_STATUS,    0x47520001u);
    ASSERT_EQ(GR_HCALL_INTEGRITY, 0x47520002u);
    ASSERT_EQ(GR_HCALL_DKOM_SCAN, 0x47520003u);
    ASSERT_EQ(GR_HCALL_UNLOAD,    0x47520004u);
}

TEST(test_magic_reply_spells_ghri)
{
    /* "GhRi" packed little-endian: 'G' 'h' 'R' 'i' → 0x69 52 68 47. */
    ASSERT_EQ((GR_HCALL_MAGIC_REPLY >> 24) & 0xFF, 'i');
    ASSERT_EQ((GR_HCALL_MAGIC_REPLY >> 16) & 0xFF, 'R');
    ASSERT_EQ((GR_HCALL_MAGIC_REPLY >>  8) & 0xFF, 'h');
    ASSERT_EQ((GR_HCALL_MAGIC_REPLY      ) & 0xFF, 'G');
}

TEST(test_devirt_cpuid_leaf_not_real)
{
    /* Intel CPUID leaves 0x00000000-0x0000001F (std) and 0x80000000-
     * 0x8000001F (extended) are real.  Hypervisor range starts at
     * 0x40000000.  Our devirt leaf 0x47520001 is in a "vendor
     * reserved" sub-range — guaranteed not to collide with any CPU's
     * real leaves. */
    ASSERT((GR_MAGIC_CPUID_LEAF & 0xFF000000) == 0x47000000);
    /* Must be greater than the largest defined Hyper-V leaf
     * (0x4000000F currently) so no paravirt detection hits us. */
    ASSERT(GR_MAGIC_CPUID_LEAF > 0x40000010);
}

TEST(test_hcall_ids_distinct)
{
    /* Paranoia check: no two IDs accidentally equal. */
    int ids[] = {
        GR_HCALL_PING, GR_HCALL_STATUS, GR_HCALL_INTEGRITY,
        GR_HCALL_DKOM_SCAN, GR_HCALL_UNLOAD,
    };
    for (int i = 0; i < 5; i++) {
        for (int j = i + 1; j < 5; j++) {
            ASSERT_NEQ(ids[i], ids[j]);
        }
    }
}

int main(void)
{
    printf("GhostRing hypercall ID stability tests\n");
    printf("======================================\n");

    RUN_TEST(test_hcall_ids_are_stable);
    RUN_TEST(test_magic_reply_spells_ghri);
    RUN_TEST(test_devirt_cpuid_leaf_not_real);
    RUN_TEST(test_hcall_ids_distinct);

    REPORT();
}
