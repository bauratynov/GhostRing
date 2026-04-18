/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_msr_bitmap.c — Bit-in-page arithmetic for the VMX MSR bitmap.
 *
 * The bitmap layout (Intel SDM Vol 3C 24.6.9):
 *   Bytes [0x000..0x3FF]: Read bitmap,  MSRs 0x00000000 – 0x00001FFF
 *   Bytes [0x400..0x7FF]: Read bitmap,  MSRs 0xC0000000 – 0xC0001FFF
 *   Bytes [0x800..0xBFF]: Write bitmap, MSRs 0x00000000 – 0x00001FFF
 *   Bytes [0xC00..0xFFF]: Write bitmap, MSRs 0xC0000000 – 0xC0001FFF
 *
 * A one-off in the byte offset silently disables protection for a
 * whole MSR range — this is a detection miss the operator never
 * sees.  These tests pin the arithmetic.
 */

#include <string.h>
#include "test_framework.h"

/* Local copy of the protection helper — same rule as
 * src/monitor/msr_guard.c:gr_msr_bitmap_protect */
static void
bitmap_protect_write(uint8_t *b, uint32_t msr)
{
    uint32_t off, bit;
    if (msr < 0x2000) {
        off = 0x800 + (msr >> 3);
    } else if (msr >= 0xC0000000 && msr < 0xC0002000) {
        off = 0xC00 + ((msr - 0xC0000000) >> 3);
    } else {
        return;  /* outside protectable ranges */
    }
    bit = msr & 0x7;
    b[off] |= (uint8_t)(1U << bit);
}

static int bit_is_set(const uint8_t *b, uint32_t off, uint32_t bit)
{
    return (b[off] >> bit) & 1;
}

TEST(test_bitmap_starts_zero)
{
    uint8_t b[4096];
    memset(b, 0, sizeof(b));
    for (int i = 0; i < 4096; i++)
        ASSERT_EQ(b[i], 0);
}

TEST(test_msr_sysenter_eip_lands_at_correct_offset)
{
    /* MSR 0x176 = SYSENTER_EIP.  Write bitmap for low range starts
     * at 0x800.  Byte offset = 0x800 + (0x176 >> 3) = 0x800 + 0x2E =
     * 0x82E.  Bit index = 0x176 & 7 = 6. */
    uint8_t b[4096];
    memset(b, 0, sizeof(b));
    bitmap_protect_write(b, 0x176);
    ASSERT_EQ(b[0x82E], 1U << 6);
    ASSERT(bit_is_set(b, 0x82E, 6));
}

TEST(test_msr_lstar_lands_at_correct_offset)
{
    /* MSR 0xC0000082 = LSTAR.  High-range write bitmap starts at
     * 0xC00.  Offset = 0xC00 + ((0xC0000082 - 0xC0000000) >> 3)
     *                = 0xC00 + 0x10 = 0xC10.  Bit = 0x82 & 7 = 2. */
    uint8_t b[4096];
    memset(b, 0, sizeof(b));
    bitmap_protect_write(b, 0xC0000082);
    ASSERT_EQ(b[0xC10], 1U << 2);
}

TEST(test_msr_efer_lands_at_correct_offset)
{
    /* MSR 0xC0000080 = EFER.  Offset = 0xC00 + 0x10 = 0xC10.
     * Bit = 0x80 & 7 = 0. */
    uint8_t b[4096];
    memset(b, 0, sizeof(b));
    bitmap_protect_write(b, 0xC0000080);
    ASSERT_EQ(b[0xC10], 1U << 0);
}

TEST(test_msr_outside_range_is_noop)
{
    /* MSR 0x40000000 is Hyper-V paravirt — not in either protected
     * range.  The helper should leave the bitmap untouched. */
    uint8_t b[4096];
    memset(b, 0, sizeof(b));
    bitmap_protect_write(b, 0x40000000);
    for (int i = 0; i < 4096; i++)
        ASSERT_EQ(b[i], 0);
}

TEST(test_msrs_dont_overlap_when_close)
{
    /* LSTAR (0xC0000082) and SYSENTER_ESP (0x175) must NOT collide
     * — they live in different halves of the bitmap by design. */
    uint8_t b[4096];
    memset(b, 0, sizeof(b));
    bitmap_protect_write(b, 0xC0000082);
    bitmap_protect_write(b, 0x175);
    /* LSTAR byte */
    ASSERT_EQ(b[0xC10], 1U << 2);
    /* SYSENTER_ESP = 0x175: offset 0x800 + 0x2E = 0x82E, bit 5 */
    ASSERT_EQ(b[0x82E], 1U << 5);
    /* No cross-contamination */
    ASSERT((b[0xC10] & (1U << 5)) == 0);
    ASSERT((b[0x82E] & (1U << 2)) == 0);
}

TEST(test_boundary_msr_0x1fff)
{
    /* Last MSR in the low range.  Byte offset = 0x800 + 0x3FF =
     * 0xBFF (last byte of the low-range write bitmap). */
    uint8_t b[4096];
    memset(b, 0, sizeof(b));
    bitmap_protect_write(b, 0x1FFF);
    ASSERT_EQ(b[0xBFF], 1U << 7);
}

TEST(test_boundary_msr_0xc0001fff)
{
    /* Last MSR in the high range.  Byte offset = 0xC00 + 0x3FF =
     * 0xFFF (last byte of the whole 4KB bitmap). */
    uint8_t b[4096];
    memset(b, 0, sizeof(b));
    bitmap_protect_write(b, 0xC0001FFF);
    ASSERT_EQ(b[0xFFF], 1U << 7);
}

int main(void)
{
    printf("GhostRing MSR bitmap arithmetic tests\n");
    printf("=====================================\n");

    RUN_TEST(test_bitmap_starts_zero);
    RUN_TEST(test_msr_sysenter_eip_lands_at_correct_offset);
    RUN_TEST(test_msr_lstar_lands_at_correct_offset);
    RUN_TEST(test_msr_efer_lands_at_correct_offset);
    RUN_TEST(test_msr_outside_range_is_noop);
    RUN_TEST(test_msrs_dont_overlap_when_close);
    RUN_TEST(test_boundary_msr_0x1fff);
    RUN_TEST(test_boundary_msr_0xc0001fff);

    REPORT();
}
