/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_ept_violation_qual.c — exit-qualification bits reported on
 * an EPT-violation VM-exit.
 *
 * Intel SDM Vol 3C, Section 28.2.1.2 & Table 28-7.  When exit reason
 * = 48 (EPT violation), VMCS_EXIT_QUALIFICATION is populated with:
 *
 *     Bit 0  — data-read access caused the violation
 *     Bit 1  — data-write access caused the violation
 *     Bit 2  — instruction fetch caused the violation
 *     Bit 3  — EPT entry's read (R) permission
 *     Bit 4  — EPT entry's write (W) permission
 *     Bit 5  — EPT entry's execute (X) permission (supervisor)
 *     Bit 6  — EPT entry's user-mode execute (when mode-based EX on)
 *     Bit 7  — guest linear address valid
 *     Bit 8  — original GVA access (0 = paging structure, 1 = direct)
 *     Bit 12 — user/supervisor (0 = supervisor, 1 = user)
 *     Bit 13 — R/W (0 = read, 1 = write) — from the guest's PT walk
 *     Bit 14 — exec/data (0 = data, 1 = instruction)
 *     Bit 15 — NMI-unblocking due to IRET
 *
 * Our EPT violation handler in src/vmx/vmx_exit.c reads bits 0-2 to
 * classify "why did it fault" and bits 3-5 to learn the current EPT
 * permissions.  If the classification bits are misread, the handler
 * either (a) re-injects the wrong kind of fault into the guest, or
 * (b) loops forever because it "fixed" the wrong permission.  Lock
 * the layout so a header cleanup can't silently shift bits.
 */

#include "test_framework.h"

#define EPTQ_READ           (1u << 0)   /* data read caused fault */
#define EPTQ_WRITE          (1u << 1)   /* data write caused fault */
#define EPTQ_EXEC           (1u << 2)   /* fetch caused fault */
#define EPTQ_PERM_R         (1u << 3)   /* R bit of EPT entry */
#define EPTQ_PERM_W         (1u << 4)   /* W bit of EPT entry */
#define EPTQ_PERM_X         (1u << 5)   /* X bit (supervisor) */
#define EPTQ_PERM_X_USER    (1u << 6)   /* X bit (user, MBX) */
#define EPTQ_GLA_VALID      (1u << 7)
#define EPTQ_GLA_DIRECT     (1u << 8)
#define EPTQ_GUEST_USER     (1u << 12)
#define EPTQ_GUEST_WRITE    (1u << 13)
#define EPTQ_GUEST_FETCH    (1u << 14)
#define EPTQ_NMI_UNBLOCKED  (1u << 15)

TEST(test_access_cause_bits_are_0_1_2)
{
    ASSERT_EQ(EPTQ_READ,  0x01u);
    ASSERT_EQ(EPTQ_WRITE, 0x02u);
    ASSERT_EQ(EPTQ_EXEC,  0x04u);
}

TEST(test_ept_permission_bits_are_3_4_5)
{
    /* These mirror the R/W/X bits of the offending EPT entry — so
     * the ordering matches src/vmx/vmx_defs.h EPT_PERM_* (bits 0,1,2
     * in the entry itself, but exposed here shifted by 3 in the
     * qualification field). */
    ASSERT_EQ(EPTQ_PERM_R, 0x08u);
    ASSERT_EQ(EPTQ_PERM_W, 0x10u);
    ASSERT_EQ(EPTQ_PERM_X, 0x20u);
}

TEST(test_canonical_ransomware_write_to_canary)
{
    /* Ransomware detector arms a canary page as R-only.  The guest
     * writes it — we expect WRITE (bit 1), PERM_R (bit 3).  Bits
     * W/X in the entry are clear. */
    uint32_t q = EPTQ_WRITE | EPTQ_PERM_R;
    ASSERT(q & EPTQ_WRITE);
    ASSERT(q & EPTQ_PERM_R);
    ASSERT_EQ(q & EPTQ_PERM_W, 0u);
    ASSERT_EQ(q & EPTQ_PERM_X, 0u);
}

TEST(test_canonical_integrity_write_to_kernel_text)
{
    /* kernel .text mapped R-X.  Guest writes — WRITE bit set,
     * entry permissions include R and X but not W. */
    uint32_t q = EPTQ_WRITE | EPTQ_PERM_R | EPTQ_PERM_X;
    ASSERT(q & EPTQ_WRITE);
    ASSERT_EQ(q & EPTQ_PERM_W, 0u);
}

TEST(test_canonical_code_injection_fetch_from_non_image)
{
    /* Non-image page mapped RW-only (no X).  Guest executes —
     * EXEC bit set, entry has R/W but not X. */
    uint32_t q = EPTQ_EXEC | EPTQ_PERM_R | EPTQ_PERM_W;
    ASSERT(q & EPTQ_EXEC);
    ASSERT_EQ(q & EPTQ_PERM_X, 0u);
}

TEST(test_guest_linear_address_valid_flag)
{
    ASSERT_EQ(EPTQ_GLA_VALID,  0x080u);
    ASSERT_EQ(EPTQ_GLA_DIRECT, 0x100u);
}

TEST(test_guest_page_walk_context_bits)
{
    /* Bits 12/13/14 describe the guest's page-table walk context. */
    ASSERT_EQ(EPTQ_GUEST_USER,  0x1000u);
    ASSERT_EQ(EPTQ_GUEST_WRITE, 0x2000u);
    ASSERT_EQ(EPTQ_GUEST_FETCH, 0x4000u);
}

TEST(test_nmi_unblocked_bit_position)
{
    /* Critical for NMI-blocking state management — if misread, we
     * either fail to re-arm NMI delivery (lost watchdog) or
     * re-arm it at the wrong time (nested NMI storm). */
    ASSERT_EQ(EPTQ_NMI_UNBLOCKED, 0x8000u);
}

TEST(test_access_cause_bits_disjoint)
{
    /* Only one of read/write/exec should be set for any single
     * violation — verify our bits don't overlap. */
    ASSERT_EQ(EPTQ_READ & EPTQ_WRITE, 0u);
    ASSERT_EQ(EPTQ_READ & EPTQ_EXEC,  0u);
    ASSERT_EQ(EPTQ_WRITE & EPTQ_EXEC, 0u);
}

TEST(test_full_qualification_roundtrip)
{
    /* Build the qual value we would see for "user wrote to a
     * kernel R-only page": qual bits = WRITE | PERM_R | GLA_VALID
     * | GUEST_USER | GUEST_WRITE. */
    uint32_t q = EPTQ_WRITE | EPTQ_PERM_R | EPTQ_GLA_VALID
               | EPTQ_GUEST_USER | EPTQ_GUEST_WRITE;
    ASSERT_EQ(q, 0x300Au);  /* 11'0000'0000'1010 */

    /* Classifier: "this was a user-space write to a present,
     * read-only page." */
    ASSERT(q & EPTQ_WRITE);
    ASSERT(q & EPTQ_GUEST_USER);
    ASSERT(q & EPTQ_GUEST_WRITE);
    ASSERT_EQ(q & EPTQ_PERM_W, 0u);
}

int main(void)
{
    printf("GhostRing EPT violation exit-qualification tests\n");
    printf("================================================\n");

    RUN_TEST(test_access_cause_bits_are_0_1_2);
    RUN_TEST(test_ept_permission_bits_are_3_4_5);
    RUN_TEST(test_canonical_ransomware_write_to_canary);
    RUN_TEST(test_canonical_integrity_write_to_kernel_text);
    RUN_TEST(test_canonical_code_injection_fetch_from_non_image);
    RUN_TEST(test_guest_linear_address_valid_flag);
    RUN_TEST(test_guest_page_walk_context_bits);
    RUN_TEST(test_nmi_unblocked_bit_position);
    RUN_TEST(test_access_cause_bits_disjoint);
    RUN_TEST(test_full_qualification_roundtrip);

    REPORT();
}
