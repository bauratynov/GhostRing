/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * vmx_defs.h — Intel VT-x constants, VMCS field encodings, and hardware
 * structures for the VMX backend.
 *
 * All numeric values conform to the Intel Software Developer's Manual,
 * Volume 3C (Order Number 326019), revision 083 and later.
 */

#ifndef GHOSTRING_VMX_DEFS_H
#define GHOSTRING_VMX_DEFS_H

#include "../common/ghostring.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * MSR indices — See SDM Vol. 3C, Appendix A ("VMX Capability Reporting")
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MSR_IA32_VMX_BASIC                  0x480
#define MSR_IA32_VMX_PINBASED_CTLS          0x481
#define MSR_IA32_VMX_PROCBASED_CTLS         0x482
#define MSR_IA32_VMX_EXIT_CTLS              0x483
#define MSR_IA32_VMX_ENTRY_CTLS             0x484
#define MSR_IA32_VMX_MISC                   0x485
#define MSR_IA32_VMX_CR0_FIXED0             0x486
#define MSR_IA32_VMX_CR0_FIXED1             0x487
#define MSR_IA32_VMX_CR4_FIXED0             0x488
#define MSR_IA32_VMX_CR4_FIXED1             0x489
#define MSR_IA32_VMX_VMCS_ENUM              0x48A
#define MSR_IA32_VMX_PROCBASED_CTLS2        0x48B
#define MSR_IA32_VMX_EPT_VPID_CAP           0x48C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS     0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS    0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS         0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS        0x490

/* Feature control — See SDM Vol. 3C, Section 23.7 */
#define MSR_IA32_FEATURE_CONTROL            0x03A
#define FEATURE_CONTROL_LOCKED              BIT(0)
#define FEATURE_CONTROL_VMXON_IN_SMX        BIT(1)
#define FEATURE_CONTROL_VMXON_OUTSIDE_SMX   BIT(2)

/* Other useful MSRs */
#define MSR_IA32_DEBUGCTL                   0x1D9
#define MSR_IA32_SYSENTER_CS                0x174
#define MSR_IA32_SYSENTER_ESP               0x175
#define MSR_IA32_SYSENTER_EIP               0x176
#define MSR_IA32_PAT                        0x277
#define MSR_IA32_EFER                       0xC0000080
#define MSR_IA32_FS_BASE                    0xC0000100
#define MSR_IA32_GS_BASE                    0xC0000101
#define MSR_IA32_KERNEL_GS_BASE             0xC0000102
#define MSR_IA32_PERF_GLOBAL_CTRL           0x38F

/* ═══════════════════════════════════════════════════════════════════════════
 * VMX_BASIC MSR bit fields — See SDM Vol. 3C, Appendix A.1
 * ═══════════════════════════════════════════════════════════════════════════ */

#define VMX_BASIC_REVISION_MASK             0x7FFFFFFFULL
#define VMX_BASIC_VMCS_SIZE_MASK            (0x1FFFULL << 32)
#define VMX_BASIC_32BIT_ADDRESSES           BIT(48)
#define VMX_BASIC_DUAL_MONITOR              BIT(49)
#define VMX_BASIC_MEMORY_TYPE_MASK          (0xFULL << 50)
#define VMX_BASIC_INS_OUT_INFO              BIT(54)
#define VMX_BASIC_DEFAULT1_ZERO             BIT(55)

/* ═══════════════════════════════════════════════════════════════════════════
 * Pin-based VM-execution controls — See SDM Vol. 3C, Section 24.6.1
 * ═══════════════════════════════════════════════════════════════════════════ */

#define PIN_BASED_EXT_INTR_MASK             BIT(0)
#define PIN_BASED_NMI_EXITING               BIT(3)
#define PIN_BASED_VIRTUAL_NMIS              BIT(5)
#define PIN_BASED_PREEMPT_TIMER             BIT(6)
#define PIN_BASED_POSTED_INTERRUPT           BIT(7)

/* ═══════════════════════════════════════════════════════════════════════════
 * Primary processor-based VM-execution controls — SDM Vol. 3C, Sec 24.6.2
 * ═══════════════════════════════════════════════════════════════════════════ */

#define CPU_BASED_VIRTUAL_INTR_PENDING      BIT(2)
#define CPU_BASED_USE_TSC_OFFSETTING        BIT(3)
#define CPU_BASED_HLT_EXITING               BIT(7)
#define CPU_BASED_INVLPG_EXITING            BIT(9)
#define CPU_BASED_MWAIT_EXITING             BIT(10)
#define CPU_BASED_RDPMC_EXITING             BIT(11)
#define CPU_BASED_RDTSC_EXITING             BIT(12)
#define CPU_BASED_CR3_LOAD_EXITING          BIT(15)
#define CPU_BASED_CR3_STORE_EXITING         BIT(16)
#define CPU_BASED_CR8_LOAD_EXITING          BIT(19)
#define CPU_BASED_CR8_STORE_EXITING         BIT(20)
#define CPU_BASED_TPR_SHADOW                BIT(21)
#define CPU_BASED_VIRTUAL_NMI_PENDING       BIT(22)
#define CPU_BASED_MOV_DR_EXITING            BIT(23)
#define CPU_BASED_UNCOND_IO_EXITING         BIT(24)
#define CPU_BASED_ACTIVATE_IO_BITMAP        BIT(25)
#define CPU_BASED_MONITOR_TRAP_FLAG         BIT(27)
#define CPU_BASED_ACTIVATE_MSR_BITMAP       BIT(28)
#define CPU_BASED_MONITOR_EXITING           BIT(29)
#define CPU_BASED_PAUSE_EXITING             BIT(30)
#define CPU_BASED_ACTIVATE_SECONDARY_CTLS   BIT(31)

/* ═══════════════════════════════════════════════════════════════════════════
 * Secondary processor-based VM-execution controls — SDM Vol. 3C, Sec 24.6.2
 * ═══════════════════════════════════════════════════════════════════════════ */

#define SECONDARY_EXEC_VIRT_APIC_ACCESSES   BIT(0)
#define SECONDARY_EXEC_ENABLE_EPT           BIT(1)
#define SECONDARY_EXEC_DESC_TABLE_EXIT      BIT(2)
#define SECONDARY_EXEC_ENABLE_RDTSCP        BIT(3)
#define SECONDARY_EXEC_VIRT_X2APIC_MODE     BIT(4)
#define SECONDARY_EXEC_ENABLE_VPID          BIT(5)
#define SECONDARY_EXEC_WBINVD_EXITING       BIT(6)
#define SECONDARY_EXEC_UNRESTRICTED_GUEST   BIT(7)
#define SECONDARY_EXEC_APIC_REGISTER_VIRT   BIT(8)
#define SECONDARY_EXEC_VIRTUAL_INTR_DELIV   BIT(9)
#define SECONDARY_EXEC_PAUSE_LOOP_EXIT      BIT(10)
#define SECONDARY_EXEC_RDRAND_EXITING       BIT(11)
#define SECONDARY_EXEC_ENABLE_INVPCID       BIT(12)
#define SECONDARY_EXEC_ENABLE_VM_FUNCTIONS  BIT(13)
#define SECONDARY_EXEC_VMCS_SHADOWING       BIT(14)
#define SECONDARY_EXEC_ENABLE_ENCLS_EXIT    BIT(15)
#define SECONDARY_EXEC_RDSEED_EXITING       BIT(16)
#define SECONDARY_EXEC_ENABLE_PML           BIT(17)
#define SECONDARY_EXEC_VIRT_EXCEPTIONS      BIT(18)
#define SECONDARY_EXEC_CONCEAL_FROM_PT      BIT(19)
#define SECONDARY_EXEC_XSAVES              BIT(20)
#define SECONDARY_EXEC_MODE_BASED_EPT_X     BIT(22)
#define SECONDARY_EXEC_TSC_SCALING          BIT(25)

/* ═══════════════════════════════════════════════════════════════════════════
 * VM-exit controls — See SDM Vol. 3C, Section 24.7.1
 * ═══════════════════════════════════════════════════════════════════════════ */

#define VM_EXIT_SAVE_DEBUG_CTLS             BIT(2)
#define VM_EXIT_IA32E_MODE                  BIT(9)
#define VM_EXIT_LOAD_PERF_GLOBAL_CTRL       BIT(12)
#define VM_EXIT_ACK_INTR_ON_EXIT            BIT(15)
#define VM_EXIT_SAVE_GUEST_PAT              BIT(18)
#define VM_EXIT_LOAD_HOST_PAT               BIT(19)
#define VM_EXIT_SAVE_GUEST_EFER             BIT(20)
#define VM_EXIT_LOAD_HOST_EFER              BIT(21)
#define VM_EXIT_SAVE_PREEMPT_TIMER          BIT(22)
#define VM_EXIT_CLEAR_BNDCFGS               BIT(23)
#define VM_EXIT_CONCEAL_FROM_PT             BIT(24)

/* ═══════════════════════════════════════════════════════════════════════════
 * VM-entry controls — See SDM Vol. 3C, Section 24.8.1
 * ═══════════════════════════════════════════════════════════════════════════ */

#define VM_ENTRY_IA32E_MODE                 BIT(9)
#define VM_ENTRY_SMM                        BIT(10)
#define VM_ENTRY_DEACT_DUAL_MONITOR         BIT(11)
#define VM_ENTRY_LOAD_PERF_GLOBAL_CTRL      BIT(13)
#define VM_ENTRY_LOAD_GUEST_PAT             BIT(14)
#define VM_ENTRY_LOAD_GUEST_EFER            BIT(15)
#define VM_ENTRY_LOAD_BNDCFGS               BIT(16)
#define VM_ENTRY_CONCEAL_FROM_PT            BIT(17)

/* ═══════════════════════════════════════════════════════════════════════════
 * VMCS field encodings — See SDM Vol. 3C, Appendix B
 * ═══════════════════════════════════════════════════════════════════════════ */

enum vmcs_field {
    /* 16-bit control fields */
    VMCS_VIRTUAL_PROCESSOR_ID               = 0x00000000,
    VMCS_POSTED_INTR_NOTIFY_VECTOR          = 0x00000002,
    VMCS_EPTP_INDEX                         = 0x00000004,

    /* 16-bit guest-state fields */
    VMCS_GUEST_ES_SEL                       = 0x00000800,
    VMCS_GUEST_CS_SEL                       = 0x00000802,
    VMCS_GUEST_SS_SEL                       = 0x00000804,
    VMCS_GUEST_DS_SEL                       = 0x00000806,
    VMCS_GUEST_FS_SEL                       = 0x00000808,
    VMCS_GUEST_GS_SEL                       = 0x0000080A,
    VMCS_GUEST_LDTR_SEL                     = 0x0000080C,
    VMCS_GUEST_TR_SEL                       = 0x0000080E,
    VMCS_GUEST_INTR_STATUS                  = 0x00000810,
    VMCS_GUEST_PML_INDEX                    = 0x00000812,

    /* 16-bit host-state fields */
    VMCS_HOST_ES_SEL                        = 0x00000C00,
    VMCS_HOST_CS_SEL                        = 0x00000C02,
    VMCS_HOST_SS_SEL                        = 0x00000C04,
    VMCS_HOST_DS_SEL                        = 0x00000C06,
    VMCS_HOST_FS_SEL                        = 0x00000C08,
    VMCS_HOST_GS_SEL                        = 0x00000C0A,
    VMCS_HOST_TR_SEL                        = 0x00000C0C,

    /* 64-bit control fields */
    VMCS_IO_BITMAP_A                        = 0x00002000,
    VMCS_IO_BITMAP_B                        = 0x00002002,
    VMCS_MSR_BITMAP                         = 0x00002004,
    VMCS_EXIT_MSR_STORE_ADDR                = 0x00002006,
    VMCS_EXIT_MSR_LOAD_ADDR                 = 0x00002008,
    VMCS_ENTRY_MSR_LOAD_ADDR                = 0x0000200A,
    VMCS_EXECUTIVE_VMCS_PTR                 = 0x0000200C,
    VMCS_PML_ADDRESS                        = 0x0000200E,
    VMCS_TSC_OFFSET                         = 0x00002010,
    VMCS_VIRTUAL_APIC_PAGE_ADDR             = 0x00002012,
    VMCS_APIC_ACCESS_ADDR                   = 0x00002014,
    VMCS_POSTED_INTR_DESC_ADDR              = 0x00002016,
    VMCS_VM_FUNCTION_CONTROL                = 0x00002018,
    VMCS_EPT_POINTER                        = 0x0000201A,
    VMCS_EOI_EXIT_BITMAP0                   = 0x0000201C,
    VMCS_EOI_EXIT_BITMAP1                   = 0x0000201E,
    VMCS_EOI_EXIT_BITMAP2                   = 0x00002020,
    VMCS_EOI_EXIT_BITMAP3                   = 0x00002022,
    VMCS_EPTP_LIST_ADDR                     = 0x00002024,
    VMCS_VMREAD_BITMAP                      = 0x00002026,
    VMCS_VMWRITE_BITMAP                     = 0x00002028,
    VMCS_VIRT_EXCEPTION_INFO_ADDR           = 0x0000202A,
    VMCS_XSS_EXIT_BITMAP                    = 0x0000202C,
    VMCS_ENCLS_EXITING_BITMAP               = 0x0000202E,
    VMCS_TSC_MULTIPLIER                     = 0x00002032,

    /* 64-bit read-only data field */
    VMCS_GUEST_PHYS_ADDR                    = 0x00002400,

    /* 64-bit guest-state fields */
    VMCS_LINK_POINTER                       = 0x00002800,
    VMCS_GUEST_IA32_DEBUGCTL                = 0x00002802,
    VMCS_GUEST_IA32_PAT                     = 0x00002804,
    VMCS_GUEST_IA32_EFER                    = 0x00002806,
    VMCS_GUEST_IA32_PERF_GLOBAL_CTRL        = 0x00002808,
    VMCS_GUEST_PDPTE0                       = 0x0000280A,
    VMCS_GUEST_PDPTE1                       = 0x0000280C,
    VMCS_GUEST_PDPTE2                       = 0x0000280E,
    VMCS_GUEST_PDPTE3                       = 0x00002810,
    VMCS_GUEST_IA32_BNDCFGS                 = 0x00002812,

    /* 64-bit host-state fields */
    VMCS_HOST_IA32_PAT                      = 0x00002C00,
    VMCS_HOST_IA32_EFER                     = 0x00002C02,
    VMCS_HOST_IA32_PERF_GLOBAL_CTRL         = 0x00002C04,

    /* 32-bit control fields */
    VMCS_PIN_BASED_EXEC_CTRL                = 0x00004000,
    VMCS_CPU_BASED_EXEC_CTRL                = 0x00004002,
    VMCS_EXCEPTION_BITMAP                   = 0x00004004,
    VMCS_PF_ERROR_CODE_MASK                 = 0x00004006,
    VMCS_PF_ERROR_CODE_MATCH                = 0x00004008,
    VMCS_CR3_TARGET_COUNT                   = 0x0000400A,
    VMCS_EXIT_CONTROLS                      = 0x0000400C,
    VMCS_EXIT_MSR_STORE_COUNT               = 0x0000400E,
    VMCS_EXIT_MSR_LOAD_COUNT                = 0x00004010,
    VMCS_ENTRY_CONTROLS                     = 0x00004012,
    VMCS_ENTRY_MSR_LOAD_COUNT               = 0x00004014,
    VMCS_ENTRY_INTR_INFO                    = 0x00004016,
    VMCS_ENTRY_EXCEPTION_ERROR_CODE         = 0x00004018,
    VMCS_ENTRY_INSTRUCTION_LEN              = 0x0000401A,
    VMCS_TPR_THRESHOLD                      = 0x0000401C,
    VMCS_SECONDARY_EXEC_CTRL                = 0x0000401E,
    VMCS_PLE_GAP                            = 0x00004020,
    VMCS_PLE_WINDOW                         = 0x00004022,

    /* 32-bit read-only data fields */
    VMCS_VM_INSTRUCTION_ERROR               = 0x00004400,
    VMCS_EXIT_REASON                        = 0x00004402,
    VMCS_EXIT_INTR_INFO                     = 0x00004404,
    VMCS_EXIT_INTR_ERROR_CODE               = 0x00004406,
    VMCS_IDT_VECTORING_INFO                 = 0x00004408,
    VMCS_IDT_VECTORING_ERROR_CODE           = 0x0000440A,
    VMCS_EXIT_INSTRUCTION_LEN               = 0x0000440C,
    VMCS_EXIT_INSTRUCTION_INFO              = 0x0000440E,

    /* 32-bit guest-state fields */
    VMCS_GUEST_ES_LIMIT                     = 0x00004800,
    VMCS_GUEST_CS_LIMIT                     = 0x00004802,
    VMCS_GUEST_SS_LIMIT                     = 0x00004804,
    VMCS_GUEST_DS_LIMIT                     = 0x00004806,
    VMCS_GUEST_FS_LIMIT                     = 0x00004808,
    VMCS_GUEST_GS_LIMIT                     = 0x0000480A,
    VMCS_GUEST_LDTR_LIMIT                   = 0x0000480C,
    VMCS_GUEST_TR_LIMIT                     = 0x0000480E,
    VMCS_GUEST_GDTR_LIMIT                   = 0x00004810,
    VMCS_GUEST_IDTR_LIMIT                   = 0x00004812,
    VMCS_GUEST_ES_ACCESS_RIGHTS             = 0x00004814,
    VMCS_GUEST_CS_ACCESS_RIGHTS             = 0x00004816,
    VMCS_GUEST_SS_ACCESS_RIGHTS             = 0x00004818,
    VMCS_GUEST_DS_ACCESS_RIGHTS             = 0x0000481A,
    VMCS_GUEST_FS_ACCESS_RIGHTS             = 0x0000481C,
    VMCS_GUEST_GS_ACCESS_RIGHTS             = 0x0000481E,
    VMCS_GUEST_LDTR_ACCESS_RIGHTS           = 0x00004820,
    VMCS_GUEST_TR_ACCESS_RIGHTS             = 0x00004822,
    VMCS_GUEST_INTERRUPTIBILITY_INFO        = 0x00004824,
    VMCS_GUEST_ACTIVITY_STATE               = 0x00004826,
    VMCS_GUEST_SMBASE                       = 0x00004828,
    VMCS_GUEST_SYSENTER_CS                  = 0x0000482A,
    VMCS_GUEST_PREEMPT_TIMER                = 0x0000482E,

    /* 32-bit host-state field */
    VMCS_HOST_SYSENTER_CS                   = 0x00004C00,

    /* Natural-width control fields */
    VMCS_CR0_GUEST_HOST_MASK                = 0x00006000,
    VMCS_CR4_GUEST_HOST_MASK                = 0x00006002,
    VMCS_CR0_READ_SHADOW                    = 0x00006004,
    VMCS_CR4_READ_SHADOW                    = 0x00006006,
    VMCS_CR3_TARGET_VALUE0                  = 0x00006008,
    VMCS_CR3_TARGET_VALUE1                  = 0x0000600A,
    VMCS_CR3_TARGET_VALUE2                  = 0x0000600C,
    VMCS_CR3_TARGET_VALUE3                  = 0x0000600E,

    /* Natural-width read-only data fields */
    VMCS_EXIT_QUALIFICATION                 = 0x00006400,
    VMCS_IO_RCX                             = 0x00006402,
    VMCS_IO_RSI                             = 0x00006404,
    VMCS_IO_RDI                             = 0x00006406,
    VMCS_IO_RIP                             = 0x00006408,
    VMCS_GUEST_LINEAR_ADDR                  = 0x0000640A,

    /* Natural-width guest-state fields */
    VMCS_GUEST_CR0                          = 0x00006800,
    VMCS_GUEST_CR3                          = 0x00006802,
    VMCS_GUEST_CR4                          = 0x00006804,
    VMCS_GUEST_ES_BASE                      = 0x00006806,
    VMCS_GUEST_CS_BASE                      = 0x00006808,
    VMCS_GUEST_SS_BASE                      = 0x0000680A,
    VMCS_GUEST_DS_BASE                      = 0x0000680C,
    VMCS_GUEST_FS_BASE                      = 0x0000680E,
    VMCS_GUEST_GS_BASE                      = 0x00006810,
    VMCS_GUEST_LDTR_BASE                    = 0x00006812,
    VMCS_GUEST_TR_BASE                      = 0x00006814,
    VMCS_GUEST_GDTR_BASE                    = 0x00006816,
    VMCS_GUEST_IDTR_BASE                    = 0x00006818,
    VMCS_GUEST_DR7                          = 0x0000681A,
    VMCS_GUEST_RSP                          = 0x0000681C,
    VMCS_GUEST_RIP                          = 0x0000681E,
    VMCS_GUEST_RFLAGS                       = 0x00006820,
    VMCS_GUEST_PENDING_DBG_EXCEPTIONS       = 0x00006822,
    VMCS_GUEST_SYSENTER_ESP                 = 0x00006824,
    VMCS_GUEST_SYSENTER_EIP                 = 0x00006826,

    /* Natural-width host-state fields */
    VMCS_HOST_CR0                           = 0x00006C00,
    VMCS_HOST_CR3                           = 0x00006C02,
    VMCS_HOST_CR4                           = 0x00006C04,
    VMCS_HOST_FS_BASE                       = 0x00006C06,
    VMCS_HOST_GS_BASE                       = 0x00006C08,
    VMCS_HOST_TR_BASE                       = 0x00006C0A,
    VMCS_HOST_GDTR_BASE                     = 0x00006C0C,
    VMCS_HOST_IDTR_BASE                     = 0x00006C0E,
    VMCS_HOST_SYSENTER_ESP                  = 0x00006C10,
    VMCS_HOST_SYSENTER_EIP                  = 0x00006C12,
    VMCS_HOST_RSP                           = 0x00006C14,
    VMCS_HOST_RIP                           = 0x00006C16,
};

/* ═══════════════════════════════════════════════════════════════════════════
 * VM-exit reasons — See SDM Vol. 3C, Appendix C ("VMX Basic Exit Reasons")
 * ═══════════════════════════════════════════════════════════════════════════ */

enum vmx_exit_reason {
    EXIT_REASON_EXCEPTION_NMI               =  0,
    EXIT_REASON_EXTERNAL_INTERRUPT          =  1,
    EXIT_REASON_TRIPLE_FAULT                =  2,
    EXIT_REASON_INIT_SIGNAL                 =  3,
    EXIT_REASON_SIPI                        =  4,
    EXIT_REASON_IO_SMI                      =  5,
    EXIT_REASON_OTHER_SMI                   =  6,
    EXIT_REASON_PENDING_VIRT_INTR           =  7,
    EXIT_REASON_PENDING_VIRT_NMI            =  8,
    EXIT_REASON_TASK_SWITCH                 =  9,
    EXIT_REASON_CPUID                       = 10,
    EXIT_REASON_GETSEC                      = 11,
    EXIT_REASON_HLT                         = 12,
    EXIT_REASON_INVD                        = 13,
    EXIT_REASON_INVLPG                      = 14,
    EXIT_REASON_RDPMC                       = 15,
    EXIT_REASON_RDTSC                       = 16,
    EXIT_REASON_RSM                         = 17,
    EXIT_REASON_VMCALL                      = 18,
    EXIT_REASON_VMCLEAR                     = 19,
    EXIT_REASON_VMLAUNCH                    = 20,
    EXIT_REASON_VMPTRLD                     = 21,
    EXIT_REASON_VMPTRST                     = 22,
    EXIT_REASON_VMREAD                      = 23,
    EXIT_REASON_VMRESUME                    = 24,
    EXIT_REASON_VMWRITE                     = 25,
    EXIT_REASON_VMXOFF                      = 26,
    EXIT_REASON_VMXON                       = 27,
    EXIT_REASON_CR_ACCESS                   = 28,
    EXIT_REASON_DR_ACCESS                   = 29,
    EXIT_REASON_IO_INSTRUCTION              = 30,
    EXIT_REASON_MSR_READ                    = 31,
    EXIT_REASON_MSR_WRITE                   = 32,
    EXIT_REASON_INVALID_GUEST_STATE         = 33,
    EXIT_REASON_MSR_LOADING                 = 34,
    /* 35 is reserved */
    EXIT_REASON_MWAIT                       = 36,
    EXIT_REASON_MONITOR_TRAP_FLAG           = 37,
    /* 38 is reserved */
    EXIT_REASON_MONITOR                     = 39,
    EXIT_REASON_PAUSE                       = 40,
    EXIT_REASON_MCE_DURING_VMENTRY          = 41,
    /* 42 is reserved */
    EXIT_REASON_TPR_BELOW_THRESHOLD         = 43,
    EXIT_REASON_APIC_ACCESS                 = 44,
    EXIT_REASON_VIRTUALIZED_EOI             = 45,
    EXIT_REASON_GDTR_IDTR_ACCESS            = 46,
    EXIT_REASON_LDTR_TR_ACCESS              = 47,
    EXIT_REASON_EPT_VIOLATION               = 48,
    EXIT_REASON_EPT_MISCONFIG               = 49,
    EXIT_REASON_INVEPT                      = 50,
    EXIT_REASON_RDTSCP                      = 51,
    EXIT_REASON_VMX_PREEMPT_TIMER_EXPIRED   = 52,
    EXIT_REASON_INVVPID                     = 53,
    EXIT_REASON_WBINVD                      = 54,
    EXIT_REASON_XSETBV                      = 55,
    EXIT_REASON_APIC_WRITE                  = 56,
    EXIT_REASON_RDRAND                      = 57,
    EXIT_REASON_INVPCID                     = 58,
    EXIT_REASON_VMFUNC                      = 59,
    EXIT_REASON_ENCLS                       = 60,
    EXIT_REASON_RDSEED                      = 61,
    EXIT_REASON_PML_FULL                    = 62,
    EXIT_REASON_XSAVES                      = 63,
    EXIT_REASON_XRSTORS                     = 64,
    EXIT_REASON_PCOMMIT                     = 65,
    EXIT_REASON_SPP_RELATED                 = 66,
    EXIT_REASON_UMWAIT                      = 67,
    EXIT_REASON_TPAUSE                      = 68,
    EXIT_REASON_LOADIWKEY                   = 69,
    /* 70-71 reserved */
    EXIT_REASON_ENQCMD                      = 72,
    EXIT_REASON_ENQCMDS                     = 73,
    /* 74 reserved */
    EXIT_REASON_BUS_LOCK                    = 74,
    EXIT_REASON_NOTIFY                      = 75,
    EXIT_REASON_MAX
};

/* Guest activity state — See SDM Vol. 3C, Section 24.4.2 */
#define GUEST_ACTIVITY_ACTIVE               0
#define GUEST_ACTIVITY_HLT                  1
#define GUEST_ACTIVITY_SHUTDOWN             2
#define GUEST_ACTIVITY_WAIT_FOR_SIPI        3

/* ═══════════════════════════════════════════════════════════════════════════
 * MTRR constants and structures — See SDM Vol. 3A, Section 11.11
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MTRR_TYPE_UC                        0   /* Uncacheable       */
#define MTRR_TYPE_WC                        1   /* Write Combining   */
#define MTRR_TYPE_WT                        4   /* Write Through     */
#define MTRR_TYPE_WP                        5   /* Write Protected   */
#define MTRR_TYPE_WB                        6   /* Write Back        */

#define MTRR_MSR_CAPABILITIES               0x0FE
#define MTRR_MSR_DEFAULT                    0x2FF
#define MTRR_MSR_VARIABLE_BASE              0x200
#define MTRR_MSR_VARIABLE_MASK              0x201

#define MTRR_PAGE_SIZE                      4096
#define MTRR_MAX_VARIABLE_RANGES            16

/* IA32_MTRRCAP — See SDM Vol. 3A, Section 11.11.1 */
typedef union mtrr_cap {
    struct {
        uint64_t var_cnt        : 8;
        uint64_t fix_supported  : 1;
        uint64_t reserved0      : 1;
        uint64_t wc_supported   : 1;
        uint64_t smrr_supported : 1;
        uint64_t reserved1      : 52;
    };
    uint64_t raw;
} mtrr_cap_t;

/* IA32_MTRR_PHYSBASEn — See SDM Vol. 3A, Section 11.11.2 */
typedef union mtrr_var_base {
    struct {
        uint64_t type           : 8;
        uint64_t reserved0      : 4;
        uint64_t phys_base      : 36;
        uint64_t reserved1      : 16;
    };
    uint64_t raw;
} mtrr_var_base_t;

/* IA32_MTRR_PHYSMASKn — See SDM Vol. 3A, Section 11.11.2 */
typedef union mtrr_var_mask {
    struct {
        uint64_t reserved0      : 11;
        uint64_t enabled        : 1;
        uint64_t phys_mask      : 36;
        uint64_t reserved1      : 16;
    };
    uint64_t raw;
} mtrr_var_mask_t;

GR_STATIC_ASSERT(sizeof(mtrr_cap_t)      == 8, "mtrr_cap_t must be 8 bytes");
GR_STATIC_ASSERT(sizeof(mtrr_var_base_t)  == 8, "mtrr_var_base_t must be 8 bytes");
GR_STATIC_ASSERT(sizeof(mtrr_var_mask_t)  == 8, "mtrr_var_mask_t must be 8 bytes");

/* ═══════════════════════════════════════════════════════════════════════════
 * EPT capability bits — from IA32_VMX_EPT_VPID_CAP MSR
 * See SDM Vol. 3C, Appendix A.10
 * ═══════════════════════════════════════════════════════════════════════════ */

#define VMX_EPT_EXECUTE_ONLY_BIT            BIT(0)
#define VMX_EPT_PAGE_WALK_4_BIT             BIT(6)
#define VMX_EPT_PAGE_WALK_5_BIT             BIT(7)
#define VMX_EPTP_UC_BIT                     BIT(8)
#define VMX_EPTP_WB_BIT                     BIT(14)
#define VMX_EPT_2MB_PAGE_BIT                BIT(16)
#define VMX_EPT_1GB_PAGE_BIT                BIT(17)
#define VMX_EPT_INVEPT_BIT                  BIT(20)
#define VMX_EPT_AD_BIT                      BIT(21)
#define VMX_EPT_ADVANCED_EXIT_INFO_BIT      BIT(22)
#define VMX_EPT_EXTENT_INDIVIDUAL_BIT       BIT(24)
#define VMX_EPT_EXTENT_CONTEXT_BIT          BIT(25)
#define VMX_EPT_EXTENT_GLOBAL_BIT           BIT(26)

/* ═══════════════════════════════════════════════════════════════════════════
 * EPT entry structures — See SDM Vol. 3C, Section 28.2.2
 * ═══════════════════════════════════════════════════════════════════════════ */

/* EPT PML4 Entry (maps 512 GB) */
typedef union ept_pml4e {
    struct {
        uint64_t read           : 1;
        uint64_t write          : 1;
        uint64_t execute        : 1;
        uint64_t reserved0      : 5;
        uint64_t accessed       : 1;
        uint64_t ignored0       : 1;
        uint64_t user_execute   : 1;
        uint64_t ignored1       : 1;
        uint64_t pfn            : 36;   /* Physical page frame number */
        uint64_t reserved1      : 4;
        uint64_t ignored2       : 12;
    };
    uint64_t raw;
} ept_pml4e_t;

/* EPT PDPT Entry (maps 1 GB, non-leaf — points to page directory) */
typedef union ept_pdpte {
    struct {
        uint64_t read           : 1;
        uint64_t write          : 1;
        uint64_t execute        : 1;
        uint64_t reserved0      : 5;
        uint64_t accessed       : 1;
        uint64_t ignored0       : 1;
        uint64_t user_execute   : 1;
        uint64_t ignored1       : 1;
        uint64_t pfn            : 36;
        uint64_t reserved1      : 4;
        uint64_t ignored2       : 12;
    };
    uint64_t raw;
} ept_pdpte_t;

/* EPT PDE for 2MB large page (leaf entry) — See SDM Table 28-5 */
typedef union ept_pde_2mb {
    struct {
        uint64_t read           : 1;
        uint64_t write          : 1;
        uint64_t execute        : 1;
        uint64_t mem_type       : 3;    /* EPT memory type */
        uint64_t ignore_pat     : 1;
        uint64_t large          : 1;    /* Must be 1 for 2MB page */
        uint64_t accessed       : 1;
        uint64_t dirty          : 1;
        uint64_t user_execute   : 1;
        uint64_t ignored0       : 1;
        uint64_t reserved0      : 9;
        uint64_t pfn            : 27;   /* Bits 47:21 of physical address */
        uint64_t reserved1      : 4;
        uint64_t ignored1       : 11;
        uint64_t suppress_ve    : 1;
    };
    uint64_t raw;
} ept_pde_2mb_t;

/* EPT PDE (non-leaf — points to page table) */
typedef union ept_pde {
    struct {
        uint64_t read           : 1;
        uint64_t write          : 1;
        uint64_t execute        : 1;
        uint64_t reserved0      : 5;
        uint64_t accessed       : 1;
        uint64_t ignored0       : 1;
        uint64_t user_execute   : 1;
        uint64_t ignored1       : 1;
        uint64_t pfn            : 36;
        uint64_t reserved1      : 4;
        uint64_t ignored2       : 12;
    };
    uint64_t raw;
} ept_pde_t;

/* EPT PTE (4KB page, leaf entry) — See SDM Table 28-6 */
typedef union ept_pte {
    struct {
        uint64_t read           : 1;
        uint64_t write          : 1;
        uint64_t execute        : 1;
        uint64_t mem_type       : 3;
        uint64_t ignore_pat     : 1;
        uint64_t ignored0       : 1;
        uint64_t accessed       : 1;
        uint64_t dirty          : 1;
        uint64_t user_execute   : 1;
        uint64_t ignored1       : 1;
        uint64_t pfn            : 36;
        uint64_t reserved0      : 4;
        uint64_t ignored2       : 11;
        uint64_t suppress_ve    : 1;
    };
    uint64_t raw;
} ept_pte_t;

GR_STATIC_ASSERT(sizeof(ept_pml4e_t)   == 8, "ept_pml4e_t must be 8 bytes");
GR_STATIC_ASSERT(sizeof(ept_pdpte_t)   == 8, "ept_pdpte_t must be 8 bytes");
GR_STATIC_ASSERT(sizeof(ept_pde_2mb_t) == 8, "ept_pde_2mb_t must be 8 bytes");
GR_STATIC_ASSERT(sizeof(ept_pde_t)     == 8, "ept_pde_t must be 8 bytes");
GR_STATIC_ASSERT(sizeof(ept_pte_t)     == 8, "ept_pte_t must be 8 bytes");

/* ═══════════════════════════════════════════════════════════════════════════
 * EPT Pointer (EPTP) — See SDM Vol. 3C, Section 24.6.11
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef union vmx_eptp {
    struct {
        uint64_t mem_type       : 3;    /* 0=UC, 6=WB */
        uint64_t walk_length    : 3;    /* EPT page-walk length minus 1 */
        uint64_t ad_enabled     : 1;    /* Enable accessed/dirty flags */
        uint64_t reserved0      : 5;
        uint64_t pfn            : 36;   /* Physical address of PML4 >> 12 */
        uint64_t reserved1      : 16;
    };
    uint64_t raw;
} vmx_eptp_t;

GR_STATIC_ASSERT(sizeof(vmx_eptp_t) == 8, "vmx_eptp_t must be 8 bytes");

/* ═══════════════════════════════════════════════════════════════════════════
 * VMCS revision / region — See SDM Vol. 3C, Section 24.2
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct vmx_vmcs {
    uint32_t revision_id;
    uint32_t abort_indicator;
    uint8_t  data[PAGE_SIZE - 8];
} GR_PACKED vmx_vmcs_t;

GR_STATIC_ASSERT(sizeof(vmx_vmcs_t) == PAGE_SIZE, "vmx_vmcs_t must be one page");

/* ═══════════════════════════════════════════════════════════════════════════
 * GDT entry for VMCS segment access rights — See SDM Vol. 3C, Sec 24.4.1
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct vmx_gdt_entry {
    uint64_t base;
    uint32_t limit;
    union {
        struct {
            uint32_t seg_type       : 4;
            uint32_t desc_type      : 1;    /* 0=system, 1=code/data */
            uint32_t dpl            : 2;
            uint32_t present        : 1;
            uint32_t reserved       : 4;
            uint32_t avl            : 1;
            uint32_t long_mode      : 1;    /* 64-bit code segment */
            uint32_t default_big    : 1;    /* D/B flag */
            uint32_t granularity    : 1;
            uint32_t unusable       : 1;
            uint32_t reserved2      : 15;
        } bits;
        uint32_t access_rights;
    };
    uint16_t selector;
} vmx_gdt_entry_t;

/* RPL mask for clearing privilege level from selectors */
#define RPL_MASK                            0x03

/* Table indicator bit in segment selector */
#define SELECTOR_TABLE_INDEX                0x04

/* ═══════════════════════════════════════════════════════════════════════════
 * EPT permissions for gr_vmx_ept_protect_page()
 * ═══════════════════════════════════════════════════════════════════════════ */

#define EPT_PERM_READ                       BIT(0)
#define EPT_PERM_WRITE                      BIT(1)
#define EPT_PERM_EXEC                       BIT(2)
#define EPT_PERM_RWX                        (EPT_PERM_READ | EPT_PERM_WRITE | EPT_PERM_EXEC)
#define EPT_PERM_RW                         (EPT_PERM_READ | EPT_PERM_WRITE)
#define EPT_PERM_RX                         (EPT_PERM_READ | EPT_PERM_EXEC)
#define EPT_PERM_NONE                       0

/* ═══════════════════════════════════════════════════════════════════════════
 * Table sizes
 * ═══════════════════════════════════════════════════════════════════════════ */

#define PML4E_COUNT                         512
#define PDPTE_COUNT                         512
#define PDE_COUNT                           512
#define PTE_COUNT                           512

/* ═══════════════════════════════════════════════════════════════════════════
 * INVEPT descriptor and types — See SDM Vol. 3C, Section 30.3
 * ═══════════════════════════════════════════════════════════════════════════ */

#define INVEPT_SINGLE_CONTEXT               1
#define INVEPT_ALL_CONTEXT                  2

typedef struct invept_desc {
    uint64_t eptp;
    uint64_t reserved;
} invept_desc_t;

/* Hypervisor CPUID leaves */
#define HYPERV_CPUID_VENDOR_AND_MAX         0x40000000
#define HYPERV_CPUID_INTERFACE              0x40000001
#define HYPERV_HYPERVISOR_PRESENT_BIT       BIT(31)

#endif /* GHOSTRING_VMX_DEFS_H */
