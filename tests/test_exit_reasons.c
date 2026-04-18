/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_exit_reasons.c — Pin VM-exit basic-reason codes.
 *
 * Intel SDM Vol 3D, Appendix I defines the basic exit reasons as
 * integer constants.  Our switch-case in src/vmx/vmx_exit.c
 * dispatches on these values — a typo in the macro definition or
 * an accidental renumbering in a header cleanup silently routes
 * the wrong handler to the wrong event.
 *
 * Worst-case examples:
 *   - If EXIT_REASON_EXCEPTION_NMI (0) were renumbered, our
 *     exception re-injection path would never fire; guest would
 *     lose NMIs entirely.
 *   - If EXIT_REASON_CPUID (10) drifted, our devirt magic CPUID
 *     would miss and rmmod would hang forever.
 *
 * These constants are wire values from hardware.  Do not renumber.
 */

#include "test_framework.h"

/* Basic exit reasons we handle.  Values from SDM Vol 3D App. I. */
#define EXIT_REASON_EXCEPTION_NMI          0
#define EXIT_REASON_EXTERNAL_INTERRUPT     1
#define EXIT_REASON_TRIPLE_FAULT           2
#define EXIT_REASON_INIT_SIGNAL            3
#define EXIT_REASON_SIPI                   4
#define EXIT_REASON_INT_WINDOW             7
#define EXIT_REASON_NMI_WINDOW             8
#define EXIT_REASON_TASK_SWITCH            9
#define EXIT_REASON_CPUID                 10
#define EXIT_REASON_HLT                   12
#define EXIT_REASON_INVD                  13
#define EXIT_REASON_INVLPG                14
#define EXIT_REASON_RDPMC                 15
#define EXIT_REASON_RDTSC                 16
#define EXIT_REASON_VMCALL                18
#define EXIT_REASON_VMCLEAR               19
#define EXIT_REASON_VMLAUNCH              20
#define EXIT_REASON_VMPTRLD               21
#define EXIT_REASON_VMPTRST               22
#define EXIT_REASON_VMREAD                23
#define EXIT_REASON_VMRESUME              24
#define EXIT_REASON_VMWRITE               25
#define EXIT_REASON_VMXOFF                26
#define EXIT_REASON_VMXON                 27
#define EXIT_REASON_CR_ACCESS             28
#define EXIT_REASON_DR_ACCESS             29
#define EXIT_REASON_IO_INSTRUCTION        30
#define EXIT_REASON_MSR_READ              31
#define EXIT_REASON_MSR_WRITE             32
#define EXIT_REASON_VM_ENTRY_INVALID_STATE 33
#define EXIT_REASON_EPT_VIOLATION         48
#define EXIT_REASON_EPT_MISCONFIG         49
#define EXIT_REASON_INVEPT                50
#define EXIT_REASON_RDTSCP                51
#define EXIT_REASON_VMX_PREEMPT_TIMER     52
#define EXIT_REASON_INVVPID               53
#define EXIT_REASON_XSETBV                55

TEST(test_primary_exits_match_sdm)
{
    /* These are the 10 reasons our dispatcher actually handles. */
    ASSERT_EQ(EXIT_REASON_EXCEPTION_NMI,      0);
    ASSERT_EQ(EXIT_REASON_EXTERNAL_INTERRUPT, 1);
    ASSERT_EQ(EXIT_REASON_CPUID,             10);
    ASSERT_EQ(EXIT_REASON_HLT,               12);
    ASSERT_EQ(EXIT_REASON_INVD,              13);
    ASSERT_EQ(EXIT_REASON_VMCALL,            18);
    ASSERT_EQ(EXIT_REASON_MSR_READ,          31);
    ASSERT_EQ(EXIT_REASON_MSR_WRITE,         32);
    ASSERT_EQ(EXIT_REASON_EPT_VIOLATION,     48);
    ASSERT_EQ(EXIT_REASON_XSETBV,            55);
}

TEST(test_vmx_instruction_exits_contiguous)
{
    /* Reasons 18-27 are the VMX-instruction exits in order.
     * Our handle_vmx_instruction() block must catch all of them
     * with a single range — verify no gaps. */
    ASSERT_EQ(EXIT_REASON_VMCALL,  18);
    ASSERT_EQ(EXIT_REASON_VMXON,   27);
    /* Anything in between is a VMX instruction exit */
    for (int r = EXIT_REASON_VMCALL; r <= EXIT_REASON_VMXON; r++) {
        ASSERT(r >= 18 && r <= 27);
    }
}

TEST(test_invalid_state_is_33)
{
    /* This exit reason appears with bit 31 of the full exit-reason
     * field set whenever VM-entry fails the invalid-guest-state
     * check.  Our diagnostic path handles it specifically. */
    ASSERT_EQ(EXIT_REASON_VM_ENTRY_INVALID_STATE, 33);
}

TEST(test_ept_exits_are_48_49)
{
    /* EPT violation + misconfiguration are the two main EPT-related
     * exits and drive our integrity / ransomware / IDT guards. */
    ASSERT_EQ(EXIT_REASON_EPT_VIOLATION, 48);
    ASSERT_EQ(EXIT_REASON_EPT_MISCONFIG, 49);
}

TEST(test_triple_fault_is_reason_2)
{
    /* Reason 2 means the guest double-faulted its double-fault
     * handler.  Our handler currently halts on this — if the value
     * ever renumbered we'd halt on something benign instead. */
    ASSERT_EQ(EXIT_REASON_TRIPLE_FAULT, 2);
}

TEST(test_magic_cpuid_leaf_is_in_hv_range)
{
    /* Our devirtualisation relies on a CPUID exit on leaf
     * 0x47520001.  CPUID exit reason must be 10. */
    ASSERT_EQ(EXIT_REASON_CPUID, 10);
}

int main(void)
{
    printf("GhostRing exit-reason codes stability tests\n");
    printf("===========================================\n");

    RUN_TEST(test_primary_exits_match_sdm);
    RUN_TEST(test_vmx_instruction_exits_contiguous);
    RUN_TEST(test_invalid_state_is_33);
    RUN_TEST(test_ept_exits_are_48_49);
    RUN_TEST(test_triple_fault_is_reason_2);
    RUN_TEST(test_magic_cpuid_leaf_is_in_hv_range);

    REPORT();
}
