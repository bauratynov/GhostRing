/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_ept_encoding.c — EPT permission bits, EPTP field layout, and
 * INVEPT type codes.
 *
 * Three unrelated-looking constants all live in vmx_defs.h and all
 * must agree with hardware.  They were grouped here because a bug in
 * any one of them fails in the same way: VM-entry succeeds, the first
 * guest instruction faults, the kernel prints "EPT misconfig".
 *
 *   1. Permission bits 0/1/2 map to read/write/execute in EPT entries.
 *   2. EPTP (Intel SDM 24.6.11) has 3-bit mem-type at [2:0], 3-bit
 *      walk-length-minus-one at [5:3], AD-bit at [6], PFN at [51:12].
 *   3. INVEPT types: 1 = single-context, 2 = all-contexts.
 *
 * If the permission bits are swapped, executable pages would end up
 * writable and vice-versa — a silent downgrade of every EPT
 * protection we rely on.  If the EPTP layout drifts, VMLAUNCH fails
 * with "invalid-EPTP" and the whole hypervisor refuses to boot.
 */

#include "test_framework.h"

/* Mirror of vmx_defs.h constants. */
#define EPT_PERM_READ        (1u << 0)
#define EPT_PERM_WRITE       (1u << 1)
#define EPT_PERM_EXEC        (1u << 2)
#define EPT_PERM_RWX         (EPT_PERM_READ | EPT_PERM_WRITE | EPT_PERM_EXEC)
#define EPT_PERM_RW          (EPT_PERM_READ | EPT_PERM_WRITE)
#define EPT_PERM_RX          (EPT_PERM_READ | EPT_PERM_EXEC)
#define EPT_PERM_NONE        0u

#define INVEPT_SINGLE_CONTEXT 1
#define INVEPT_ALL_CONTEXT    2

#define MTRR_TYPE_UC          0
#define MTRR_TYPE_WB          6

/* EPTP layout — union form, same as src/vmx/vmx_defs.h vmx_eptp_t. */
typedef union {
    struct {
        uint64_t mem_type    : 3;
        uint64_t walk_length : 3;
        uint64_t ad_enabled  : 1;
        uint64_t reserved0   : 5;
        uint64_t pfn         : 36;
        uint64_t reserved1   : 16;
    };
    uint64_t raw;
} eptp_t;

TEST(test_perm_bits_in_correct_positions)
{
    /* Bit 0 = read, bit 1 = write, bit 2 = execute.  If any swap,
     * page protections become inverted. */
    ASSERT_EQ(EPT_PERM_READ,  0x1u);
    ASSERT_EQ(EPT_PERM_WRITE, 0x2u);
    ASSERT_EQ(EPT_PERM_EXEC,  0x4u);
}

TEST(test_perm_combos_are_unions)
{
    ASSERT_EQ(EPT_PERM_RWX, 0x7u);
    ASSERT_EQ(EPT_PERM_RW,  0x3u);
    ASSERT_EQ(EPT_PERM_RX,  0x5u);
    ASSERT_EQ(EPT_PERM_NONE, 0u);
}

TEST(test_perms_are_disjoint_single_bits)
{
    /* R, W, X must each be a single distinct bit — no overlap. */
    ASSERT_EQ(EPT_PERM_READ  & EPT_PERM_WRITE, 0);
    ASSERT_EQ(EPT_PERM_READ  & EPT_PERM_EXEC,  0);
    ASSERT_EQ(EPT_PERM_WRITE & EPT_PERM_EXEC,  0);
}

TEST(test_eptp_struct_size_is_8)
{
    /* EPTP is stored in a 64-bit VMCS field. */
    ASSERT_EQ(sizeof(eptp_t), 8);
}

TEST(test_eptp_writeback_4_level_encoding)
{
    /* Standard GhostRing EPTP: WB memory type, 4-level walk
     * (walk_length = 4 - 1 = 3), AD disabled, PML4 at some PFN. */
    eptp_t e = { .raw = 0 };
    e.mem_type    = MTRR_TYPE_WB;     /* 6 */
    e.walk_length = 3;                /* 4 levels - 1 */
    e.ad_enabled  = 0;
    e.pfn         = 0x12345;          /* arbitrary PML4 frame */

    /* Bottom byte: mem_type (3 bits) = 110b, walk_length (3 bits) =
     * 011b, ad_enabled (1 bit) = 0, bit 7 reserved = 0.
     *   result: 0011'1110 = 0x1E. */
    ASSERT_EQ(e.raw & 0xFFu, 0x1Eu);
    /* PFN is at bit 12 (because the struct packs pfn into bits
     * [51:12] via the preceding fields occupying bits [11:0]). */
    ASSERT_EQ((e.raw >> 12) & 0xFFFFFFFFFFull, 0x12345ull);
}

TEST(test_eptp_uc_type_for_sanity)
{
    /* UC memory type (0) also valid per SDM.  Encoding check. */
    eptp_t e = { .raw = 0 };
    e.mem_type    = MTRR_TYPE_UC;
    e.walk_length = 3;
    ASSERT_EQ(e.raw & 0xFFu, 0x18u);  /* 0011'1000 */
}

TEST(test_eptp_reserved_bits_stay_clear_in_canonical_value)
{
    /* Our code never sets the reserved fields.  A stray write would
     * fail VMLAUNCH with "invalid EPTP" (exit reason 33). */
    eptp_t e = { .raw = 0 };
    e.mem_type    = MTRR_TYPE_WB;
    e.walk_length = 3;
    e.pfn         = 0xABCDE;
    /* Bits 11:7 (reserved0) must be zero. */
    ASSERT_EQ((e.raw >> 7) & 0x1Full, 0);
    /* Bits 63:48 (reserved1) must be zero for 48-bit PA machines. */
    ASSERT_EQ((e.raw >> 48) & 0xFFFFull, 0);
}

TEST(test_invept_types_match_sdm)
{
    /* Intel SDM 30.3: INVEPT descriptor type 1 = single-context,
     * type 2 = all-contexts.  Type 0 is reserved, type 3 is
     * reserved.  Using the wrong type causes #UD on the INVEPT
     * instruction. */
    ASSERT_EQ(INVEPT_SINGLE_CONTEXT, 1);
    ASSERT_EQ(INVEPT_ALL_CONTEXT,    2);
}

TEST(test_invept_descriptor_size_and_layout)
{
    /* INVEPT descriptor: 128 bits = {EPTP, 64 reserved}. */
    struct invept_desc {
        uint64_t eptp;
        uint64_t reserved;
    } d = { .eptp = 0, .reserved = 0 };
    ASSERT_EQ(sizeof(d), 16);
    /* The reserved half must always be written as zero — a non-zero
     * value causes INVEPT to fail with VMX error. */
    ASSERT_EQ(d.reserved, 0);
}

TEST(test_ept_entry_bit_layout)
{
    /* Lowest 3 bits of an EPT entry = R/W/X.  Bit 6 (if AD enabled)
     * = accessed.  Bit 9 = dirty (PTE only).  These are disjoint
     * from the PFN at [51:12].  We simulate the layout by building
     * a value and verifying. */
    uint64_t entry = 0;
    entry |= EPT_PERM_RWX;          /* perms */
    entry |= (0x12345ull) << 12;    /* PFN */

    ASSERT_EQ(entry & 0x7ull, 7ull);                /* RWX */
    ASSERT_EQ((entry >> 12) & 0xFFFFFFFFFFull, 0x12345ull);
    /* Accessed and dirty bits untouched. */
    ASSERT_EQ((entry >> 8) & 0x1ull, 0);
    ASSERT_EQ((entry >> 9) & 0x1ull, 0);
}

int main(void)
{
    printf("GhostRing EPT permission / EPTP / INVEPT encoding tests\n");
    printf("=======================================================\n");

    RUN_TEST(test_perm_bits_in_correct_positions);
    RUN_TEST(test_perm_combos_are_unions);
    RUN_TEST(test_perms_are_disjoint_single_bits);
    RUN_TEST(test_eptp_struct_size_is_8);
    RUN_TEST(test_eptp_writeback_4_level_encoding);
    RUN_TEST(test_eptp_uc_type_for_sanity);
    RUN_TEST(test_eptp_reserved_bits_stay_clear_in_canonical_value);
    RUN_TEST(test_invept_types_match_sdm);
    RUN_TEST(test_invept_descriptor_size_and_layout);
    RUN_TEST(test_ept_entry_bit_layout);

    REPORT();
}
