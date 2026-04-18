/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_vm_entry_intr_info.c — VM-entry interruption-information field.
 *
 * Intel SDM Vol 3C, Section 26.6 & Table 26-3.  On VM-entry, a 32-bit
 * field at VMCS_VM_ENTRY_INTR_INFO (0x4016) requests that a specific
 * event be delivered to the guest.  Layout:
 *
 *     Bits [ 7:0]  — Vector       (0-255)
 *     Bits [10:8]  — Type         (0=ExtINT, 2=NMI, 3=HWexc, 4=SWint,
 *                                   5=priv SWexc, 6=SWexc, 7=other)
 *     Bit  [11]    — DeliverErrCode (must agree with the vector)
 *     Bits [30:12] — Reserved, must be zero
 *     Bit  [31]    — Valid
 *
 * Wrong bit placement has the ugliest failure mode in the whole
 * hypervisor: the guest receives the WRONG interrupt vector.  If our
 * handler meant to re-inject vector 2 (NMI) but the valid bit landed
 * at bit 30 instead of 31, VM-entry rejects the request silently and
 * the NMI disappears.  If the type field is shifted by one bit, NMI
 * (type 2) becomes NMI-with-error-code-delivery — rejected.
 *
 * Lock the layout.  Losing an NMI once is losing the ability to
 * recover the guest on a watchdog timeout.
 */

#include "test_framework.h"

#define INTR_TYPE_EXT_INT       0
#define INTR_TYPE_NMI           2
#define INTR_TYPE_HW_EXCEPTION  3
#define INTR_TYPE_SW_INT        4
#define INTR_TYPE_PRIV_SW_EXC   5
#define INTR_TYPE_SW_EXCEPTION  6
#define INTR_TYPE_OTHER         7

#define INTR_VALID              (1u << 31)
#define INTR_DELIVER_ERRCODE    (1u << 11)

/* Build a VM-entry interruption-information value. */
static uint32_t build_intr_info(uint8_t vector, uint8_t type,
                                int deliver_errcode, int valid)
{
    uint32_t v = (uint32_t)vector;
    v |= ((uint32_t)type & 0x7) << 8;
    if (deliver_errcode) v |= INTR_DELIVER_ERRCODE;
    if (valid)           v |= INTR_VALID;
    return v;
}

/* Vector constants — Intel SDM Vol 3A Table 6-1. */
#define VEC_DE      0   /* #DE Divide Error */
#define VEC_NMI     2   /* NMI */
#define VEC_BP      3   /* #BP Breakpoint */
#define VEC_UD      6   /* #UD Invalid Opcode */
#define VEC_DF      8   /* #DF Double Fault (has error code) */
#define VEC_GP     13   /* #GP General Protection */
#define VEC_PF     14   /* #PF Page Fault */

TEST(test_valid_bit_is_bit_31)
{
    uint32_t v = INTR_VALID;
    ASSERT_EQ(v, 0x80000000u);
}

TEST(test_deliver_errcode_bit_is_11)
{
    ASSERT_EQ(INTR_DELIVER_ERRCODE, 0x800u);
}

TEST(test_vector_fits_in_low_byte)
{
    /* Max vector = 255.  Should fit in bits 7:0 without spilling. */
    uint32_t v = build_intr_info(0xFF, INTR_TYPE_HW_EXCEPTION, 0, 1);
    ASSERT_EQ(v & 0xFFu, 0xFFu);
    /* Type 3 (hw exc) sits at bits 10:8 = 011b = 0x300. */
    ASSERT_EQ(v & 0x700u, 0x300u);
}

TEST(test_type_field_at_bits_10_8)
{
    /* Each of 8 type values must land in the right 3 bits. */
    for (uint8_t t = 0; t <= 7; t++) {
        uint32_t v = build_intr_info(0, t, 0, 1);
        ASSERT_EQ((v >> 8) & 0x7u, (uint32_t)t);
        /* Must not spill into bits 11 or 7. */
        ASSERT_EQ(v & 0x7FFu, (uint32_t)t << 8);
    }
}

TEST(test_nmi_reinject_canonical_value)
{
    /* Classical NMI re-inject: vector=2, type=NMI(2), no err, valid.
     *   0x80000202 = 1000'0000'0000'0000'0000'0010'0000'0010
     *                ^valid            ^type=2 at bit 8
     *                                         ^vector=2
     */
    uint32_t v = build_intr_info(VEC_NMI, INTR_TYPE_NMI, 0, 1);
    ASSERT_EQ(v, 0x80000202u);
}

TEST(test_page_fault_reinject_with_errcode)
{
    /* #PF re-inject: vector=14, type=HW exc (3), err code present. */
    uint32_t v = build_intr_info(VEC_PF, INTR_TYPE_HW_EXCEPTION, 1, 1);
    /* valid(31) | errcode(11) | type=3 at 8 | vector=14
     *   = 0x80000B0E */
    ASSERT_EQ(v, 0x80000B0Eu);
    ASSERT(v & INTR_VALID);
    ASSERT(v & INTR_DELIVER_ERRCODE);
}

TEST(test_breakpoint_is_software_exception_not_hw)
{
    /* #BP (vector 3) must be type 6 (SWexc), NOT type 3 (HWexc).
     * Getting this wrong causes VM-entry to push the wrong IP. */
    uint32_t v = build_intr_info(VEC_BP, INTR_TYPE_SW_EXCEPTION, 0, 1);
    ASSERT_EQ((v >> 8) & 0x7, INTR_TYPE_SW_EXCEPTION);
}

TEST(test_reserved_bits_12_to_30_stay_zero)
{
    /* Bits 30:12 reserved.  Must be 0.  A stray bit in that range
     * makes VM-entry fail invalid-control-field. */
    uint32_t v = build_intr_info(VEC_GP, INTR_TYPE_HW_EXCEPTION, 1, 1);
    ASSERT_EQ((v >> 12) & 0x7FFFFu, 0u);
}

TEST(test_invalid_flag_disables_whole_field)
{
    /* With valid=0, the rest of the field MUST still be zero — else
     * a stale vector could sneak through. */
    uint32_t v = build_intr_info(0, 0, 0, 0);
    ASSERT_EQ(v, 0u);
}

TEST(test_double_fault_requires_errcode)
{
    /* #DF always delivers a (zero) error code.  Our re-inject logic
     * must set bit 11. */
    uint32_t v = build_intr_info(VEC_DF, INTR_TYPE_HW_EXCEPTION, 1, 1);
    ASSERT(v & INTR_DELIVER_ERRCODE);
    ASSERT_EQ(v & 0xFFu, VEC_DF);
}

int main(void)
{
    printf("GhostRing VM-entry interruption-information field tests\n");
    printf("=======================================================\n");

    RUN_TEST(test_valid_bit_is_bit_31);
    RUN_TEST(test_deliver_errcode_bit_is_11);
    RUN_TEST(test_vector_fits_in_low_byte);
    RUN_TEST(test_type_field_at_bits_10_8);
    RUN_TEST(test_nmi_reinject_canonical_value);
    RUN_TEST(test_page_fault_reinject_with_errcode);
    RUN_TEST(test_breakpoint_is_software_exception_not_hw);
    RUN_TEST(test_reserved_bits_12_to_30_stay_zero);
    RUN_TEST(test_invalid_flag_disables_whole_field);
    RUN_TEST(test_double_fault_requires_errcode);

    REPORT();
}
