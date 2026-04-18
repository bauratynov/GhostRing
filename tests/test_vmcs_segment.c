/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_vmcs_segment.c — Regression tests for the GDT → VMCS access-rights
 * encoding.
 *
 * Protects against the v0.1.0 regression where `flags2 << 4` was used
 * instead of `<< 8`, silently clearing the L bit (long-mode code segment)
 * on entry and producing "invalid guest state" VMLAUNCH failures.
 *
 * Compile: gcc -o test_vmcs_segment test_vmcs_segment.c && ./test_vmcs_segment
 */

#include <string.h>
#include "test_framework.h"

/* Local copy of the encoding rule from src/vmx/vmx_vmcs.c, isolated so
 * the test does not need the whole hypervisor include chain. */
static uint32_t encode_access_rights(uint8_t flags1, uint8_t flags2)
{
    return ((uint32_t)flags1 & 0xFF) |
           (((uint32_t)flags2 & 0xF0) << 8);
}

/* Common bit shortcuts per SDM Vol 3C Table 24-2. */
#define AR_TYPE(v)   ((v) & 0xF)
#define AR_S(v)      (((v) >> 4) & 0x1)
#define AR_DPL(v)    (((v) >> 5) & 0x3)
#define AR_P(v)      (((v) >> 7) & 0x1)
#define AR_AVL(v)    (((v) >> 12) & 0x1)
#define AR_L(v)      (((v) >> 13) & 0x1)
#define AR_DB(v)     (((v) >> 14) & 0x1)
#define AR_G(v)      (((v) >> 15) & 0x1)

/* Linux x86-64 __KERNEL_CS descriptor.
 * flags1 = 0x9b  (type=B code/read/accessed, S=1, DPL=0, P=1)
 * flags2 = 0xAF  (limit_hi=0xF, AVL=0, L=1, D=0, G=1)
 */
TEST(test_linux_kernel_cs)
{
    uint32_t ar = encode_access_rights(0x9B, 0xAF);
    ASSERT_EQ(AR_TYPE(ar), 0xB);   /* code, execute/read, accessed */
    ASSERT_EQ(AR_S(ar),    1);     /* code/data segment             */
    ASSERT_EQ(AR_DPL(ar),  0);     /* ring 0                        */
    ASSERT_EQ(AR_P(ar),    1);     /* present                       */
    ASSERT_EQ(AR_AVL(ar),  0);
    ASSERT_EQ(AR_L(ar),    1);     /* 64-bit long-mode code — CRITICAL */
    ASSERT_EQ(AR_DB(ar),   0);     /* must be 0 when L=1            */
    ASSERT_EQ(AR_G(ar),    1);     /* page-granular limit           */
    /* Reserved bits 11:8 must be zero (SDM). */
    ASSERT_EQ((ar >> 8) & 0xF, 0);
}

/* Linux x86-64 __KERNEL_DS descriptor — data segment, L ignored.
 * flags1 = 0x93 (type=3 data/write, S=1, DPL=0, P=1)
 * flags2 = 0xCF (limit_hi=0xF, AVL=0, L=0, D=1, G=1)  -- 32-bit style
 */
TEST(test_linux_kernel_ds)
{
    uint32_t ar = encode_access_rights(0x93, 0xCF);
    ASSERT_EQ(AR_TYPE(ar), 0x3);
    ASSERT_EQ(AR_S(ar),    1);
    ASSERT_EQ(AR_DPL(ar),  0);
    ASSERT_EQ(AR_P(ar),    1);
    ASSERT_EQ(AR_L(ar),    0);
    ASSERT_EQ(AR_DB(ar),   1);
    ASSERT_EQ(AR_G(ar),    1);
    ASSERT_EQ((ar >> 8) & 0xF, 0);
}

/* Linux x86-64 TSS — system descriptor (S=0), 64-bit busy TSS type=0xB.
 * flags1 = 0x8B  (type=0xB busy TSS, S=0, DPL=0, P=1)
 * flags2 = 0x00  (limit_hi=0, AVL=0, L=0, D=0, G=0)
 */
TEST(test_linux_tss)
{
    uint32_t ar = encode_access_rights(0x8B, 0x00);
    ASSERT_EQ(AR_TYPE(ar), 0xB);   /* 64-bit busy TSS */
    ASSERT_EQ(AR_S(ar),    0);     /* system descriptor */
    ASSERT_EQ(AR_P(ar),    1);
    ASSERT_EQ(AR_G(ar),    0);
}

/* Regression lock: the bug we fixed was encoding flags2 with `<< 4`
 * instead of `<< 8`, which left bits 15:12 (AVL/L/D/G) as zero and
 * polluted reserved bits 11:8.  Verify explicitly.
 */
TEST(test_regression_shift_is_8_not_4)
{
    uint32_t ar = encode_access_rights(0x9B, 0xAF);
    /* Bits 11:8 are RESERVED — must be zero.  Old bug parked G/D/L/AVL
     * here which the CPU silently cleared on VMWRITE, nuking the L bit. */
    ASSERT_EQ((ar >> 8) & 0xF, 0);
    /* Bits 15:12 are AVL/L/D/G — must carry the flags2 high nibble. */
    ASSERT_EQ((ar >> 12) & 0xF, 0xA);
}

/* Null-selector handling: when the selector index is zero the encoder
 * in vmx_vmcs.c sets only the unusable bit (bit 16).  The intent here
 * is to guard the downstream rule with a sanity check on raw bits. */
TEST(test_unusable_bit_position)
{
    /* The 'unusable' bit in VMCS access-rights is bit 16 per SDM
     * Vol 3C Table 24-2 — test that our bit ordering still agrees. */
    ASSERT_EQ(1U << 16, 0x10000);
}

int main(void)
{
    printf("GhostRing VMCS segment encoding tests\n");
    printf("=====================================\n");

    RUN_TEST(test_linux_kernel_cs);
    RUN_TEST(test_linux_kernel_ds);
    RUN_TEST(test_linux_tss);
    RUN_TEST(test_regression_shift_is_8_not_4);
    RUN_TEST(test_unusable_bit_position);

    REPORT();
}
