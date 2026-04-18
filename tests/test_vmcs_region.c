/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_vmcs_region.c — VMCS / VMXON region header and revision-ID
 * extraction law.
 *
 * Intel SDM Vol 3C, Section 24.2 & 24.11.5:
 *
 *   A VMCS / VMXON region is a 4096-byte page with:
 *     offset 0-3  : revision_id     (bits 30:0 from IA32_VMX_BASIC)
 *     offset 4-7  : abort_indicator
 *     offset 8+   : architecture-defined data
 *
 *   The revision_id MUST:
 *     - Match bits 30:0 of IA32_VMX_BASIC.low32 on the current CPU.
 *     - Have bit 31 clear.  In VMX_BASIC, bit 31 of the low half is
 *       a reserved/memory-type-ish signal and MUST NOT be copied
 *       into the revision field.
 *
 * Classic bring-up pitfall: writing the whole 32-bit low half of
 * IA32_VMX_BASIC into the VMCS header carries bit 31 along.  The
 * subsequent VMPTRLD fails with "VMCS revision mismatch" (error 5)
 * and the entire hypervisor refuses to start.  Happened to us in
 * a prior iteration — lock the extraction rule.
 */

#include <stddef.h>
#include "test_framework.h"

#define PAGE_SIZE            4096
#define VMX_BASIC_REV_MASK   0x7FFFFFFFu  /* bits 30:0 */

/* Rule: revision_id = IA32_VMX_BASIC[30:0]. */
static uint32_t extract_revision(uint64_t vmx_basic_msr)
{
    return (uint32_t)(vmx_basic_msr & VMX_BASIC_REV_MASK);
}

/* Mirror of vmx_vmcs_t from src/vmx/vmx_defs.h. */
typedef struct __attribute__((packed)) {
    uint32_t revision_id;
    uint32_t abort_indicator;
    uint8_t  data[PAGE_SIZE - 8];
} vmcs_region_t;

TEST(test_region_is_one_page)
{
    /* Hardware requires the region size to equal the native page
     * size reported by IA32_VMX_BASIC[44:32].  On x86_64 that is
     * always 4096.  If this struct grows or shrinks, VMPTRLD hands
     * back "VM instruction failed". */
    ASSERT_EQ(sizeof(vmcs_region_t), PAGE_SIZE);
}

TEST(test_revision_at_offset_zero)
{
    /* SDM is explicit: revision_id sits at the very start of the
     * region.  Any leading padding is a bug. */
    ASSERT_EQ(offsetof(vmcs_region_t, revision_id),     0);
    ASSERT_EQ(offsetof(vmcs_region_t, abort_indicator), 4);
    ASSERT_EQ(offsetof(vmcs_region_t, data),            8);
}

TEST(test_revision_extraction_masks_bit_31)
{
    /* Typical observed IA32_VMX_BASIC low half: 0x8000000B (bit 31
     * set, revision 0x0B).  Copy-the-whole-word bug would land
     * 0x8000000B into revision_id.  Correct extraction gives 0x0B. */
    uint64_t vmx_basic = 0x8000000BULL;
    uint32_t rev = extract_revision(vmx_basic);
    ASSERT_EQ(rev, 0x0Bu);
    ASSERT_EQ(rev & 0x80000000u, 0u);
}

TEST(test_revision_preserves_bits_30_to_0)
{
    /* Silicon on this class of chip reports revision 0x1A1.  Do not
     * truncate.  Do not drop.  Keep bits 30:0 intact. */
    uint64_t vmx_basic = 0x800001A1ULL;
    ASSERT_EQ(extract_revision(vmx_basic), 0x1A1u);
}

TEST(test_revision_with_bit_31_clear_unchanged)
{
    /* Some Hyper-V nested configurations report bit 31 clear.
     * Extraction must be idempotent regardless. */
    uint64_t vmx_basic = 0x00000042ULL;
    ASSERT_EQ(extract_revision(vmx_basic), 0x42u);
}

TEST(test_revision_extraction_handles_high_half_correctly)
{
    /* IA32_VMX_BASIC has capability flags in bits 63:32 that MUST
     * NOT leak into revision_id.  Stuff junk in high half. */
    uint64_t vmx_basic = 0xAAAAAAAA0000000BULL;
    ASSERT_EQ(extract_revision(vmx_basic), 0x0Bu);
}

TEST(test_freshly_zeroed_region_has_zero_abort)
{
    /* After kzalloc-equivalent, abort_indicator must be 0.  A
     * non-zero abort after VMXON / VMCLEAR means the CPU saw a
     * "VMX-abort" condition and refused to load the region. */
    vmcs_region_t r;
    memset(&r, 0, sizeof(r));
    ASSERT_EQ(r.abort_indicator, 0);
}

TEST(test_canonical_assembly)
{
    /* Simulate the full assembly: extract revision from the MSR,
     * write it, zero the abort slot.  This is literally the three
     * lines of C we execute in gr_vmx_alloc_region(). */
    uint64_t vmx_basic = 0x800001A1ULL;
    vmcs_region_t r;
    memset(&r, 0, sizeof(r));
    r.revision_id     = extract_revision(vmx_basic);
    r.abort_indicator = 0;

    ASSERT_EQ(r.revision_id, 0x1A1u);
    /* Bit 31 of the header word is specifically reserved and must
     * never be set. */
    ASSERT_EQ(r.revision_id & 0x80000000u, 0u);
}

int main(void)
{
    printf("GhostRing VMCS region header / revision-ID tests\n");
    printf("================================================\n");

    RUN_TEST(test_region_is_one_page);
    RUN_TEST(test_revision_at_offset_zero);
    RUN_TEST(test_revision_extraction_masks_bit_31);
    RUN_TEST(test_revision_preserves_bits_30_to_0);
    RUN_TEST(test_revision_with_bit_31_clear_unchanged);
    RUN_TEST(test_revision_extraction_handles_high_half_correctly);
    RUN_TEST(test_freshly_zeroed_region_has_zero_abort);
    RUN_TEST(test_canonical_assembly);

    REPORT();
}
