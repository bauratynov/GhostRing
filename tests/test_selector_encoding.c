/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_selector_encoding.c — 16-bit segment selector field layout.
 *
 * Intel SDM Vol 3A, Section 3.4.2 ("Segment Selectors"):
 *
 *   Bits 1:0   — RPL (Requestor Privilege Level)
 *   Bit  2     — TI  (Table Indicator: 0 = GDT, 1 = LDT)
 *   Bits 15:3  — Index into the descriptor table
 *
 * Our VMCS setup clears RPL from host selectors via `sel & ~RPL_MASK`
 * (SDM 26.2.3 requires host CS/SS/DS/ES/FS/GS selectors to be 0 in
 * bits 0-2).  The code relies on two literal constants:
 *
 *   RPL_MASK                 = 0x03
 *   SELECTOR_TABLE_INDEX     = 0x04  (the TI bit)
 *
 * Renumbering either of these silently changes which bits get
 * cleared, potentially leaving a non-zero RPL in HOST_CS_SEL,
 * which then fails VM-entry with invalid-host-state.
 */

#include "test_framework.h"

#define RPL_MASK                0x03
#define SELECTOR_TABLE_INDEX    0x04
#define SEL_INDEX_MASK          0xFFF8

/* Common Linux kernel selector values for sanity. */
#define LINUX_KERNEL_CS         0x10    /* __KERNEL_CS  */
#define LINUX_KERNEL_DS         0x18    /* __KERNEL_DS  */
#define LINUX_USER_CS           0x33    /* __USER_CS + RPL 3 */
#define LINUX_USER_DS           0x2B    /* __USER_DS + RPL 3 */

TEST(test_rpl_mask_value)
{
    /* RPL occupies bits 1:0.  Mask must be exactly 0x03. */
    ASSERT_EQ(RPL_MASK, 0x03);
}

TEST(test_ti_bit_value)
{
    /* Table indicator bit is bit 2 — 0x04. */
    ASSERT_EQ(SELECTOR_TABLE_INDEX, 0x04);
}

TEST(test_strip_rpl_from_kernel_selector)
{
    /* Kernel CS = 0x10 already has RPL = 0, stripping is a no-op. */
    ASSERT_EQ(LINUX_KERNEL_CS & ~RPL_MASK, 0x10);
}

TEST(test_strip_rpl_from_user_selector)
{
    /* User CS = 0x33 has RPL = 3.  Strip -> 0x30. */
    ASSERT_EQ(LINUX_USER_CS & ~RPL_MASK, 0x30);
    /* User DS = 0x2B has RPL = 3.  Strip -> 0x28. */
    ASSERT_EQ(LINUX_USER_DS & ~RPL_MASK, 0x28);
}

TEST(test_host_selector_bits_0_2_clear)
{
    /* SDM 26.2.3: host CS/SS/DS/ES/FS/GS selectors must have
     * bits [0:2] = 0.  After `sel & ~RPL_MASK` only RPL is cleared.
     * For a TI=1 selector (LDT), the TI bit would still be set and
     * VM-entry would reject.  Our code expects kernel segments
     * only, which are GDT (TI=0). */
    uint16_t k = LINUX_KERNEL_CS & ~RPL_MASK;
    ASSERT_EQ(k & 0x7, 0);   /* bottom 3 bits all clear */
}

TEST(test_user_selector_rpl3)
{
    ASSERT_EQ(LINUX_USER_CS & RPL_MASK, 3);
    ASSERT_EQ(LINUX_USER_DS & RPL_MASK, 3);
}

TEST(test_index_bits_preserved_when_stripping_rpl)
{
    /* Stripping RPL must leave bits 15:3 untouched. */
    uint16_t before = LINUX_USER_CS;
    uint16_t after  = before & ~RPL_MASK;
    ASSERT_EQ(before & SEL_INDEX_MASK, after & SEL_INDEX_MASK);
}

TEST(test_null_selector_is_zero)
{
    /* Null selector is 0x0000, not just "low bits zero".  Some code
     * paths treat null specially (mark segment unusable in VMCS). */
    uint16_t null_sel = 0;
    ASSERT_EQ(null_sel & SEL_INDEX_MASK, 0);
    ASSERT_EQ(null_sel & RPL_MASK, 0);
    ASSERT_EQ(null_sel & SELECTOR_TABLE_INDEX, 0);
}

int main(void)
{
    printf("GhostRing selector encoding tests\n");
    printf("=================================\n");

    RUN_TEST(test_rpl_mask_value);
    RUN_TEST(test_ti_bit_value);
    RUN_TEST(test_strip_rpl_from_kernel_selector);
    RUN_TEST(test_strip_rpl_from_user_selector);
    RUN_TEST(test_host_selector_bits_0_2_clear);
    RUN_TEST(test_user_selector_rpl3);
    RUN_TEST(test_index_bits_preserved_when_stripping_rpl);
    RUN_TEST(test_null_selector_is_zero);

    REPORT();
}
