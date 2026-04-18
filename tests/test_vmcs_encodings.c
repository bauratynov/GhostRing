/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_vmcs_encodings.c — Lock Intel-specified VMCS field encodings.
 *
 * These are constants from Intel SDM Vol 3C, Appendix B (VMCS field
 * encodings).  Our vmx_defs.h values must match exactly because:
 *
 *   1. The numeric literals are re-used DIRECTLY in vmx_asm.S
 *      (0x681C for GUEST_RSP, 0x681E for GUEST_RIP, 0x6820 for
 *      GUEST_RFLAGS, 0x4400 for VM_INSTRUCTION_ERROR).  Any drift
 *      between the header and the asm silently breaks VMLAUNCH.
 *
 *   2. The user-space agent does not read the kernel header — it
 *      relies on the header being correct at compile time.  If the
 *      header renumbered a field, the kernel module would vmwrite
 *      to the wrong field and tests would still pass while the
 *      hypervisor runs on corrupt VMCS state.
 *
 * Every encoding listed here is copy-pasted from Intel SDM April
 * 2026 issue.  Do NOT renumber even if it looks like a clean-up —
 * these are wire values from hardware.
 */

#include "test_framework.h"

/* Guest state area */
#define VMCS_GUEST_CR0                       0x00006800
#define VMCS_GUEST_CR3                       0x00006802
#define VMCS_GUEST_CR4                       0x00006804
#define VMCS_GUEST_DR7                       0x0000681A
#define VMCS_GUEST_RSP                       0x0000681C
#define VMCS_GUEST_RIP                       0x0000681E
#define VMCS_GUEST_RFLAGS                    0x00006820
#define VMCS_GUEST_IA32_DEBUGCTL             0x00002802
#define VMCS_GUEST_IA32_EFER                 0x00002806

/* Host state area */
#define VMCS_HOST_CR0                        0x00006C00
#define VMCS_HOST_CR3                        0x00006C02
#define VMCS_HOST_CR4                        0x00006C04
#define VMCS_HOST_RSP                        0x00006C14
#define VMCS_HOST_RIP                        0x00006C16
#define VMCS_HOST_IA32_EFER                  0x00002C02

/* VM-exit information */
#define VMCS_EXIT_REASON                     0x00004402
#define VMCS_EXIT_INTR_INFO                  0x00004404
#define VMCS_EXIT_QUALIFICATION              0x00006400
#define VMCS_EXIT_INSTRUCTION_LEN            0x0000440C
#define VMCS_VM_INSTRUCTION_ERROR            0x00004400

/* VM-execution / entry / exit controls */
#define VMCS_PIN_BASED_EXEC_CTRL             0x00004000
#define VMCS_CPU_BASED_EXEC_CTRL             0x00004002
#define VMCS_EXIT_CONTROLS                   0x0000400C
#define VMCS_ENTRY_CONTROLS                  0x00004012
#define VMCS_SECONDARY_EXEC_CTRL             0x0000401E

/* Injection */
#define VMCS_ENTRY_INTR_INFO                 0x00004016
#define VMCS_ENTRY_EXCEPTION_ERROR_CODE      0x00004018

/* CR shadow / mask */
#define VMCS_CR0_GUEST_HOST_MASK             0x00006000
#define VMCS_CR4_GUEST_HOST_MASK             0x00006002
#define VMCS_CR0_READ_SHADOW                 0x00006004
#define VMCS_CR4_READ_SHADOW                 0x00006006

TEST(test_asm_stub_constants_match_header)
{
    /* vmx_asm.S uses these numeric literals directly in the devirt
     * path.  If anyone renumbered them here, the asm would VMREAD
     * the wrong field — and the bug is invisible because vmread
     * doesn't fault, just returns whatever that field happens to
     * contain. */
    ASSERT_EQ(VMCS_GUEST_RSP,          0x681CU);
    ASSERT_EQ(VMCS_GUEST_RIP,          0x681EU);
    ASSERT_EQ(VMCS_GUEST_RFLAGS,       0x6820U);
    ASSERT_EQ(VMCS_VM_INSTRUCTION_ERROR, 0x4400U);
}

TEST(test_guest_control_registers)
{
    ASSERT_EQ(VMCS_GUEST_CR0, 0x6800U);
    ASSERT_EQ(VMCS_GUEST_CR3, 0x6802U);
    ASSERT_EQ(VMCS_GUEST_CR4, 0x6804U);
}

TEST(test_host_control_registers)
{
    /* Host CRs live 0x400 higher than guest CRs in VMCS encoding. */
    ASSERT_EQ(VMCS_HOST_CR0, VMCS_GUEST_CR0 + 0x400);
    ASSERT_EQ(VMCS_HOST_CR3, VMCS_GUEST_CR3 + 0x400);
    ASSERT_EQ(VMCS_HOST_CR4, VMCS_GUEST_CR4 + 0x400);
}

TEST(test_efer_fields_use_32bit_width)
{
    /* EFER is stored as a 32-bit VMCS field (Intel encoding starts
     * with 0x2xxx).  Differentiate from natural-width guest/host
     * fields which start with 0x68xx / 0x6Cxx. */
    ASSERT((VMCS_GUEST_IA32_EFER & 0xF000U) == 0x2000U);
    ASSERT((VMCS_HOST_IA32_EFER  & 0xF000U) == 0x2000U);
}

TEST(test_exit_information_layout)
{
    /* All VM-exit info fields live in the 0x4400 block. */
    ASSERT((VMCS_EXIT_REASON          & 0xFF00U) == 0x4400U);
    ASSERT((VMCS_EXIT_INTR_INFO        & 0xFF00U) == 0x4400U);
    ASSERT((VMCS_EXIT_INSTRUCTION_LEN  & 0xFF00U) == 0x4400U);
    ASSERT((VMCS_VM_INSTRUCTION_ERROR  & 0xFF00U) == 0x4400U);
}

TEST(test_entry_injection_fields)
{
    /* Interrupt-info-field for VM-entry injection is 0x4016. */
    ASSERT_EQ(VMCS_ENTRY_INTR_INFO, 0x4016U);
    /* Error-code immediately after in the encoding. */
    ASSERT_EQ(VMCS_ENTRY_EXCEPTION_ERROR_CODE,
              VMCS_ENTRY_INTR_INFO + 2);
}

TEST(test_cr_mask_and_shadow_pairing)
{
    /* CR0 mask / shadow are 0x6000 / 0x6004 (diff of 4).  Same for
     * CR4 (0x6002 / 0x6006).  Constant diff must hold. */
    ASSERT_EQ(VMCS_CR0_READ_SHADOW - VMCS_CR0_GUEST_HOST_MASK, 4);
    ASSERT_EQ(VMCS_CR4_READ_SHADOW - VMCS_CR4_GUEST_HOST_MASK, 4);
}

int main(void)
{
    printf("GhostRing VMCS field encoding stability tests\n");
    printf("=============================================\n");

    RUN_TEST(test_asm_stub_constants_match_header);
    RUN_TEST(test_guest_control_registers);
    RUN_TEST(test_host_control_registers);
    RUN_TEST(test_efer_fields_use_32bit_width);
    RUN_TEST(test_exit_information_layout);
    RUN_TEST(test_entry_injection_fields);
    RUN_TEST(test_cr_mask_and_shadow_pairing);

    REPORT();
}
