/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * svm_defs.h — AMD SVM (Secure Virtual Machine) constants, VMCB field
 * offsets, exit codes, and hardware structures for the SVM backend.
 *
 * All numeric values conform to the AMD Architecture Programmer's Manual,
 * Volume 2 ("System Programming"), Chapter 15 ("Secure Virtual Machine"),
 * revision 3.41 and later.
 */

#ifndef GHOSTRING_SVM_DEFS_H
#define GHOSTRING_SVM_DEFS_H

#include "../common/ghostring.h"

/* ======================================================================
 * MSR indices — See APM Vol. 2, Section 15.30 ("SVM Related MSRs")
 * ====================================================================== */

#define MSR_VM_CR                           0xC0010114
#define MSR_VM_HSAVE_PA                     0xC0010117
#define MSR_EFER                            0xC0000080
#define MSR_STAR                            0xC0000081
#define MSR_LSTAR                           0xC0000082
#define MSR_CSTAR                           0xC0000083
#define MSR_SFMASK                          0xC0000084
#define MSR_FS_BASE                         0xC0000100
#define MSR_GS_BASE                         0xC0000101
#define MSR_KERNEL_GS_BASE                  0xC0000102
#define MSR_SYSENTER_CS                     0x174
#define MSR_SYSENTER_ESP                    0x175
#define MSR_SYSENTER_EIP                    0x176
#define MSR_PAT                             0x277
#define MSR_DEBUG_CTL                       0x1D9

/* MSR_VM_CR bit fields — APM Vol. 2, Section 15.30.1 */
#define VM_CR_DPD                           BIT(0)
#define VM_CR_R_INIT                        BIT(1)
#define VM_CR_DIS_A20M                      BIT(2)
#define VM_CR_LOCK                          BIT(3)
#define VM_CR_SVMDIS                        BIT(4)

/* MSR_EFER bits relevant to SVM — APM Vol. 2, Section 15.1 */
#define EFER_SCE                            BIT(0)
#define EFER_LME                            BIT(8)
#define EFER_LMA                            BIT(10)
#define EFER_NXE                            BIT(11)
#define EFER_SVME                           BIT(12)
#define EFER_LMSLE                          BIT(13)
#define EFER_FFXSR                          BIT(14)

/* ======================================================================
 * VMCB Control Area offsets (0x000 - 0x3FF)
 * See APM Vol. 2, Section 15.5.1 ("VMCB Layout, Control Area")
 * ====================================================================== */

#define VMCB_CTRL_INTERCEPT_CR_READ         0x000   /* 16-bit */
#define VMCB_CTRL_INTERCEPT_CR_WRITE        0x002   /* 16-bit */
#define VMCB_CTRL_INTERCEPT_DR_READ         0x004   /* 16-bit */
#define VMCB_CTRL_INTERCEPT_DR_WRITE        0x006   /* 16-bit */
#define VMCB_CTRL_INTERCEPT_EXCEPTIONS      0x008   /* 32-bit */
#define VMCB_CTRL_INTERCEPT_MISC1           0x00C   /* 32-bit */
#define VMCB_CTRL_INTERCEPT_MISC2           0x010   /* 32-bit */
#define VMCB_CTRL_INTERCEPT_MISC3           0x014   /* 32-bit */
#define VMCB_CTRL_PAUSE_FILTER_THRESHOLD    0x03C   /* 16-bit */
#define VMCB_CTRL_PAUSE_FILTER_COUNT        0x03E   /* 16-bit */
#define VMCB_CTRL_IOPM_BASE_PA              0x040   /* 64-bit */
#define VMCB_CTRL_MSRPM_BASE_PA             0x048   /* 64-bit */
#define VMCB_CTRL_TSC_OFFSET                0x050   /* 64-bit */
#define VMCB_CTRL_GUEST_ASID                0x058   /* 32-bit */
#define VMCB_CTRL_TLB_CONTROL               0x05C   /* 32-bit */
#define VMCB_CTRL_VINTR                     0x060   /* 64-bit */
#define VMCB_CTRL_INTERRUPT_SHADOW          0x068   /* 64-bit */
#define VMCB_CTRL_EXIT_CODE                 0x070   /* 64-bit */
#define VMCB_CTRL_EXIT_INFO1                0x078   /* 64-bit */
#define VMCB_CTRL_EXIT_INFO2                0x080   /* 64-bit */
#define VMCB_CTRL_EXIT_INT_INFO             0x088   /* 64-bit */
#define VMCB_CTRL_NP_ENABLE                 0x090   /* 64-bit */
#define VMCB_CTRL_AVIC_APIC_BAR            0x098   /* 64-bit */
#define VMCB_CTRL_GHCB_PA                   0x0A0   /* 64-bit */
#define VMCB_CTRL_EVENT_INJECTION           0x0A8   /* 64-bit */
#define VMCB_CTRL_EVENT_ERROR_CODE          0x0AC   /* 32-bit */
#define VMCB_CTRL_NCR3                      0x0B0   /* 64-bit */
#define VMCB_CTRL_LBR_VIRT_ENABLE           0x0B8   /* 64-bit */
#define VMCB_CTRL_VMCB_CLEAN_BITS           0x0C0   /* 64-bit */
#define VMCB_CTRL_NRIP                      0x0C8   /* 64-bit */
#define VMCB_CTRL_NUM_BYTES_FETCHED         0x0D0   /* 8-bit  */
#define VMCB_CTRL_GUEST_INSN_BYTES          0x0D1   /* 15 bytes */
#define VMCB_CTRL_AVIC_BACKING_PAGE         0x0E0   /* 64-bit */
#define VMCB_CTRL_AVIC_LOGICAL_TABLE        0x0F0   /* 64-bit */
#define VMCB_CTRL_AVIC_PHYSICAL_TABLE       0x0F8   /* 64-bit */
#define VMCB_CTRL_VMSA_PTR                  0x108   /* 64-bit */

/* ======================================================================
 * VMCB State Save Area offsets (0x400+)
 * See APM Vol. 2, Section 15.5.1 ("VMCB Layout, State Save Area")
 * ====================================================================== */

/* ES */
#define VMCB_STATE_ES_SELECTOR              0x400   /* 16-bit */
#define VMCB_STATE_ES_ATTRIB                0x402   /* 16-bit */
#define VMCB_STATE_ES_LIMIT                 0x404   /* 32-bit */
#define VMCB_STATE_ES_BASE                  0x408   /* 64-bit */

/* CS */
#define VMCB_STATE_CS_SELECTOR              0x410   /* 16-bit */
#define VMCB_STATE_CS_ATTRIB                0x412   /* 16-bit */
#define VMCB_STATE_CS_LIMIT                 0x414   /* 32-bit */
#define VMCB_STATE_CS_BASE                  0x418   /* 64-bit */

/* SS */
#define VMCB_STATE_SS_SELECTOR              0x420   /* 16-bit */
#define VMCB_STATE_SS_ATTRIB                0x422   /* 16-bit */
#define VMCB_STATE_SS_LIMIT                 0x424   /* 32-bit */
#define VMCB_STATE_SS_BASE                  0x428   /* 64-bit */

/* DS */
#define VMCB_STATE_DS_SELECTOR              0x430   /* 16-bit */
#define VMCB_STATE_DS_ATTRIB                0x432   /* 16-bit */
#define VMCB_STATE_DS_LIMIT                 0x434   /* 32-bit */
#define VMCB_STATE_DS_BASE                  0x438   /* 64-bit */

/* FS */
#define VMCB_STATE_FS_SELECTOR              0x440   /* 16-bit */
#define VMCB_STATE_FS_ATTRIB                0x442   /* 16-bit */
#define VMCB_STATE_FS_LIMIT                 0x444   /* 32-bit */
#define VMCB_STATE_FS_BASE                  0x448   /* 64-bit */

/* GS */
#define VMCB_STATE_GS_SELECTOR              0x450   /* 16-bit */
#define VMCB_STATE_GS_ATTRIB                0x452   /* 16-bit */
#define VMCB_STATE_GS_LIMIT                 0x454   /* 32-bit */
#define VMCB_STATE_GS_BASE                  0x458   /* 64-bit */

/* GDTR */
#define VMCB_STATE_GDTR_SELECTOR            0x460   /* 16-bit */
#define VMCB_STATE_GDTR_ATTRIB              0x462   /* 16-bit */
#define VMCB_STATE_GDTR_LIMIT               0x464   /* 32-bit */
#define VMCB_STATE_GDTR_BASE                0x468   /* 64-bit */

/* LDTR */
#define VMCB_STATE_LDTR_SELECTOR            0x470   /* 16-bit */
#define VMCB_STATE_LDTR_ATTRIB              0x472   /* 16-bit */
#define VMCB_STATE_LDTR_LIMIT               0x474   /* 32-bit */
#define VMCB_STATE_LDTR_BASE                0x478   /* 64-bit */

/* IDTR */
#define VMCB_STATE_IDTR_SELECTOR            0x480   /* 16-bit */
#define VMCB_STATE_IDTR_ATTRIB              0x482   /* 16-bit */
#define VMCB_STATE_IDTR_LIMIT               0x484   /* 32-bit */
#define VMCB_STATE_IDTR_BASE                0x488   /* 64-bit */

/* TR */
#define VMCB_STATE_TR_SELECTOR              0x490   /* 16-bit */
#define VMCB_STATE_TR_ATTRIB                0x492   /* 16-bit */
#define VMCB_STATE_TR_LIMIT                 0x494   /* 32-bit */
#define VMCB_STATE_TR_BASE                  0x498   /* 64-bit */

/* Misc state save fields */
#define VMCB_STATE_CPL                      0x4CB   /* 8-bit  */
#define VMCB_STATE_EFER                     0x4D0   /* 64-bit */
#define VMCB_STATE_CR4                      0x548   /* 64-bit */
#define VMCB_STATE_CR3                      0x550   /* 64-bit */
#define VMCB_STATE_CR0                      0x558   /* 64-bit */
#define VMCB_STATE_DR7                      0x560   /* 64-bit */
#define VMCB_STATE_DR6                      0x568   /* 64-bit */
#define VMCB_STATE_RFLAGS                   0x570   /* 64-bit */
#define VMCB_STATE_RIP                      0x578   /* 64-bit */
#define VMCB_STATE_RSP                      0x5D8   /* 64-bit */
#define VMCB_STATE_S_CET                    0x5E0   /* 64-bit */
#define VMCB_STATE_SSP                      0x5E8   /* 64-bit */
#define VMCB_STATE_ISST                     0x5F0   /* 64-bit */
#define VMCB_STATE_RAX                      0x5F8   /* 64-bit */
#define VMCB_STATE_STAR                     0x600   /* 64-bit */
#define VMCB_STATE_LSTAR                    0x608   /* 64-bit */
#define VMCB_STATE_CSTAR                    0x610   /* 64-bit */
#define VMCB_STATE_SFMASK                   0x618   /* 64-bit */
#define VMCB_STATE_KERNEL_GS_BASE           0x620   /* 64-bit */
#define VMCB_STATE_SYSENTER_CS              0x628   /* 64-bit */
#define VMCB_STATE_SYSENTER_ESP             0x630   /* 64-bit */
#define VMCB_STATE_SYSENTER_EIP             0x638   /* 64-bit */
#define VMCB_STATE_CR2                      0x640   /* 64-bit */
#define VMCB_STATE_PAT                      0x668   /* 64-bit */
#define VMCB_STATE_DEBUG_CTL                0x670   /* 64-bit */
#define VMCB_STATE_BR_FROM                  0x678   /* 64-bit */
#define VMCB_STATE_BR_TO                    0x680   /* 64-bit */
#define VMCB_STATE_LAST_EXCP_FROM           0x688   /* 64-bit */
#define VMCB_STATE_LAST_EXCP_TO             0x690   /* 64-bit */

/* ======================================================================
 * Intercept MISC1 bits — APM Vol. 2, Table 15-7
 * ====================================================================== */

#define SVM_INTERCEPT_MISC1_INTR            BIT(0)
#define SVM_INTERCEPT_MISC1_NMI             BIT(1)
#define SVM_INTERCEPT_MISC1_SMI             BIT(2)
#define SVM_INTERCEPT_MISC1_INIT            BIT(3)
#define SVM_INTERCEPT_MISC1_VINTR           BIT(4)
#define SVM_INTERCEPT_MISC1_CR0_SEL_WRITE   BIT(5)
#define SVM_INTERCEPT_MISC1_IDTR_READ       BIT(6)
#define SVM_INTERCEPT_MISC1_GDTR_READ       BIT(7)
#define SVM_INTERCEPT_MISC1_LDTR_READ       BIT(8)
#define SVM_INTERCEPT_MISC1_TR_READ         BIT(9)
#define SVM_INTERCEPT_MISC1_IDTR_WRITE      BIT(10)
#define SVM_INTERCEPT_MISC1_GDTR_WRITE      BIT(11)
#define SVM_INTERCEPT_MISC1_LDTR_WRITE      BIT(12)
#define SVM_INTERCEPT_MISC1_TR_WRITE        BIT(13)
#define SVM_INTERCEPT_MISC1_RDTSC           BIT(14)
#define SVM_INTERCEPT_MISC1_RDPMC           BIT(15)
#define SVM_INTERCEPT_MISC1_PUSHF           BIT(16)
#define SVM_INTERCEPT_MISC1_POPF            BIT(17)
#define SVM_INTERCEPT_MISC1_CPUID           BIT(18)
#define SVM_INTERCEPT_MISC1_RSM             BIT(19)
#define SVM_INTERCEPT_MISC1_IRET            BIT(20)
#define SVM_INTERCEPT_MISC1_INTn            BIT(21)
#define SVM_INTERCEPT_MISC1_INVD            BIT(22)
#define SVM_INTERCEPT_MISC1_PAUSE           BIT(23)
#define SVM_INTERCEPT_MISC1_HLT             BIT(24)
#define SVM_INTERCEPT_MISC1_INVLPG          BIT(25)
#define SVM_INTERCEPT_MISC1_INVLPGA         BIT(26)
#define SVM_INTERCEPT_MISC1_IOIO_PROT       BIT(27)
#define SVM_INTERCEPT_MISC1_MSR_PROT        BIT(28)
#define SVM_INTERCEPT_MISC1_TASK_SWITCH      BIT(29)
#define SVM_INTERCEPT_MISC1_FERR_FREEZE     BIT(30)
#define SVM_INTERCEPT_MISC1_SHUTDOWN        BIT(31)

/* ======================================================================
 * Intercept MISC2 bits — APM Vol. 2, Table 15-7 (continued)
 * ====================================================================== */

#define SVM_INTERCEPT_MISC2_VMRUN           BIT(0)
#define SVM_INTERCEPT_MISC2_VMMCALL         BIT(1)
#define SVM_INTERCEPT_MISC2_VMLOAD          BIT(2)
#define SVM_INTERCEPT_MISC2_VMSAVE          BIT(3)
#define SVM_INTERCEPT_MISC2_STGI            BIT(4)
#define SVM_INTERCEPT_MISC2_CLGI            BIT(5)
#define SVM_INTERCEPT_MISC2_SKINIT          BIT(6)
#define SVM_INTERCEPT_MISC2_RDTSCP          BIT(7)
#define SVM_INTERCEPT_MISC2_ICEBP           BIT(8)
#define SVM_INTERCEPT_MISC2_WBINVD          BIT(9)
#define SVM_INTERCEPT_MISC2_MONITOR         BIT(10)
#define SVM_INTERCEPT_MISC2_MWAIT_UNCOND    BIT(11)
#define SVM_INTERCEPT_MISC2_MWAIT_ARMED     BIT(12)
#define SVM_INTERCEPT_MISC2_XSETBV          BIT(13)
#define SVM_INTERCEPT_MISC2_RDPRU           BIT(14)
#define SVM_INTERCEPT_MISC2_EFER_WRITE_TRAP BIT(15)
#define SVM_INTERCEPT_MISC2_CR0_WRITE_TRAP  BIT(16)

/* ======================================================================
 * SVM Exit Codes — APM Vol. 2, Appendix C
 * ====================================================================== */

enum svm_exit_code {
    VMEXIT_CR0_READ             = 0x0000,
    VMEXIT_CR1_READ             = 0x0001,
    VMEXIT_CR2_READ             = 0x0002,
    VMEXIT_CR3_READ             = 0x0003,
    VMEXIT_CR4_READ             = 0x0004,
    VMEXIT_CR5_READ             = 0x0005,
    VMEXIT_CR6_READ             = 0x0006,
    VMEXIT_CR7_READ             = 0x0007,
    VMEXIT_CR8_READ             = 0x0008,
    VMEXIT_CR9_READ             = 0x0009,
    VMEXIT_CR10_READ            = 0x000A,
    VMEXIT_CR11_READ            = 0x000B,
    VMEXIT_CR12_READ            = 0x000C,
    VMEXIT_CR13_READ            = 0x000D,
    VMEXIT_CR14_READ            = 0x000E,
    VMEXIT_CR15_READ            = 0x000F,

    VMEXIT_CR0_WRITE            = 0x0010,
    VMEXIT_CR1_WRITE            = 0x0011,
    VMEXIT_CR2_WRITE            = 0x0012,
    VMEXIT_CR3_WRITE            = 0x0013,
    VMEXIT_CR4_WRITE            = 0x0014,
    VMEXIT_CR5_WRITE            = 0x0015,
    VMEXIT_CR6_WRITE            = 0x0016,
    VMEXIT_CR7_WRITE            = 0x0017,
    VMEXIT_CR8_WRITE            = 0x0018,

    VMEXIT_DR0_READ             = 0x0020,
    VMEXIT_DR1_READ             = 0x0021,
    VMEXIT_DR2_READ             = 0x0022,
    VMEXIT_DR3_READ             = 0x0023,
    VMEXIT_DR4_READ             = 0x0024,
    VMEXIT_DR5_READ             = 0x0025,
    VMEXIT_DR6_READ             = 0x0026,
    VMEXIT_DR7_READ             = 0x0027,

    VMEXIT_DR0_WRITE            = 0x0030,
    VMEXIT_DR1_WRITE            = 0x0031,
    VMEXIT_DR2_WRITE            = 0x0032,
    VMEXIT_DR3_WRITE            = 0x0033,
    VMEXIT_DR4_WRITE            = 0x0034,
    VMEXIT_DR5_WRITE            = 0x0035,
    VMEXIT_DR6_WRITE            = 0x0036,
    VMEXIT_DR7_WRITE            = 0x0037,

    VMEXIT_EXCP_DE              = 0x0040,   /* #DE  — Divide Error */
    VMEXIT_EXCP_DB              = 0x0041,   /* #DB  — Debug */
    VMEXIT_EXCP_NMI             = 0x0042,   /* NMI */
    VMEXIT_EXCP_BP              = 0x0043,   /* #BP  — Breakpoint */
    VMEXIT_EXCP_OF              = 0x0044,   /* #OF  — Overflow */
    VMEXIT_EXCP_BR              = 0x0045,   /* #BR  — Bound Range */
    VMEXIT_EXCP_UD              = 0x0046,   /* #UD  — Undefined Opcode */
    VMEXIT_EXCP_NM              = 0x0047,   /* #NM  — Device Not Available */
    VMEXIT_EXCP_DF              = 0x0048,   /* #DF  — Double Fault */
    VMEXIT_EXCP_09              = 0x0049,   /* reserved */
    VMEXIT_EXCP_TS              = 0x004A,   /* #TS  — Invalid TSS */
    VMEXIT_EXCP_NP              = 0x004B,   /* #NP  — Segment Not Present */
    VMEXIT_EXCP_SS              = 0x004C,   /* #SS  — Stack-Segment Fault */
    VMEXIT_EXCP_GP              = 0x004D,   /* #GP  — General Protection */
    VMEXIT_EXCP_PF              = 0x004E,   /* #PF  — Page Fault */
    VMEXIT_EXCP_15              = 0x004F,   /* reserved */
    VMEXIT_EXCP_MF              = 0x0050,   /* #MF  — x87 FP Exception */
    VMEXIT_EXCP_AC              = 0x0051,   /* #AC  — Alignment Check */
    VMEXIT_EXCP_MC              = 0x0052,   /* #MC  — Machine Check */
    VMEXIT_EXCP_XF              = 0x0053,   /* #XF  — SIMD FP Exception */

    VMEXIT_INTR                 = 0x0060,
    VMEXIT_NMI                  = 0x0061,
    VMEXIT_SMI                  = 0x0062,
    VMEXIT_INIT                 = 0x0063,
    VMEXIT_VINTR                = 0x0064,
    VMEXIT_CR0_SEL_WRITE        = 0x0065,
    VMEXIT_IDTR_READ            = 0x0066,
    VMEXIT_GDTR_READ            = 0x0067,
    VMEXIT_LDTR_READ            = 0x0068,
    VMEXIT_TR_READ              = 0x0069,
    VMEXIT_IDTR_WRITE           = 0x006A,
    VMEXIT_GDTR_WRITE           = 0x006B,
    VMEXIT_LDTR_WRITE           = 0x006C,
    VMEXIT_TR_WRITE             = 0x006D,
    VMEXIT_RDTSC                = 0x006E,
    VMEXIT_RDPMC                = 0x006F,
    VMEXIT_PUSHF                = 0x0070,
    VMEXIT_POPF                 = 0x0071,
    VMEXIT_CPUID                = 0x0072,
    VMEXIT_RSM                  = 0x0073,
    VMEXIT_IRET                 = 0x0074,
    VMEXIT_SWINT                = 0x0075,
    VMEXIT_INVD                 = 0x0076,
    VMEXIT_PAUSE                = 0x0077,
    VMEXIT_HLT                  = 0x0078,
    VMEXIT_INVLPG               = 0x0079,
    VMEXIT_INVLPGA              = 0x007A,
    VMEXIT_IOIO                 = 0x007B,
    VMEXIT_MSR                  = 0x007C,
    VMEXIT_TASK_SWITCH          = 0x007D,
    VMEXIT_FERR_FREEZE          = 0x007E,
    VMEXIT_SHUTDOWN             = 0x007F,

    VMEXIT_VMRUN                = 0x0080,
    VMEXIT_VMMCALL              = 0x0081,
    VMEXIT_VMLOAD               = 0x0082,
    VMEXIT_VMSAVE               = 0x0083,
    VMEXIT_STGI                 = 0x0084,
    VMEXIT_CLGI                 = 0x0085,
    VMEXIT_SKINIT               = 0x0086,
    VMEXIT_RDTSCP               = 0x0087,
    VMEXIT_ICEBP                = 0x0088,
    VMEXIT_WBINVD               = 0x0089,
    VMEXIT_MONITOR              = 0x008A,
    VMEXIT_MWAIT_UNCOND         = 0x008B,
    VMEXIT_MWAIT_ARMED          = 0x008C,
    VMEXIT_XSETBV               = 0x008D,
    VMEXIT_RDPRU                = 0x008E,
    VMEXIT_EFER_WRITE_TRAP      = 0x008F,
    VMEXIT_CR0_WRITE_TRAP       = 0x0090,

    VMEXIT_NPF                  = 0x0400,   /* Nested Page Fault */
    VMEXIT_AVIC_INCOMPLETE_IPI  = 0x0401,
    VMEXIT_AVIC_NOACCEL         = 0x0402,
    VMEXIT_VMGEXIT              = 0x0403,

    VMEXIT_INVALID              = -1,
};

/* ======================================================================
 * TLB control values — APM Vol. 2, Section 15.15.1
 * ====================================================================== */

#define SVM_TLB_CONTROL_DO_NOTHING          0x00
#define SVM_TLB_CONTROL_FLUSH_ALL           0x01
#define SVM_TLB_CONTROL_FLUSH_GUEST         0x03
#define SVM_TLB_CONTROL_FLUSH_GUEST_NONGLOBAL 0x07

/* ======================================================================
 * VMCB clean bits — APM Vol. 2, Section 15.15.4
 * ====================================================================== */

enum svm_vmcb_clean_bits {
    VMCB_CLEAN_INTERCEPTS       = BIT(0),
    VMCB_CLEAN_IOPM             = BIT(1),
    VMCB_CLEAN_ASID             = BIT(2),
    VMCB_CLEAN_TPR              = BIT(3),
    VMCB_CLEAN_NP               = BIT(4),
    VMCB_CLEAN_CRX              = BIT(5),
    VMCB_CLEAN_DRX              = BIT(6),
    VMCB_CLEAN_DT               = BIT(7),
    VMCB_CLEAN_SEG              = BIT(8),
    VMCB_CLEAN_CR2              = BIT(9),
    VMCB_CLEAN_LBR              = BIT(10),
    VMCB_CLEAN_AVIC             = BIT(11),
    VMCB_CLEAN_CET              = BIT(12),
    VMCB_CLEAN_ALL              = 0x1FFF,
};

/* ======================================================================
 * Event injection — APM Vol. 2, Section 15.20
 * ====================================================================== */

#define SVM_EVTINJ_VALID                    BIT(31)
#define SVM_EVTINJ_TYPE_SHIFT               8
#define SVM_EVTINJ_TYPE_MASK                (0x7ULL << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_INTR                (0ULL << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_NMI                 (2ULL << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_EXCP                (3ULL << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_SOFT_INTR           (4ULL << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_VECTOR_MASK              0xFF
#define SVM_EVTINJ_ERROR_VALID              BIT(11)

/* Compose an event injection value for exception vector */
#define SVM_INJECT_EXCEPTION(vec)                                   \
    (SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_EXCP | ((vec) & 0xFF))

/* Common exception vectors */
#define EXCEPTION_UD                        6

/* ======================================================================
 * NPF exit info1 bits — APM Vol. 2, Section 15.25.6
 * ====================================================================== */

#define NPF_INFO1_PRESENT                   BIT(0)
#define NPF_INFO1_WRITE                     BIT(1)
#define NPF_INFO1_USER                      BIT(2)
#define NPF_INFO1_RESERVED_BIT              BIT(3)
#define NPF_INFO1_EXECUTE                   BIT(4)

/* ======================================================================
 * Nested Page Table entry structures
 *
 * NPT uses the standard AMD64 page table format (not EPT-style R/W/X).
 * Permissions: Present, Read/Write, User, NX.
 * See APM Vol. 2, Section 15.25.5 ("Nested Page Table Format")
 * ====================================================================== */

/* NPT PML4 Entry (maps 512 GB) */
typedef union npt_pml4e {
    struct {
        uint64_t present        : 1;    /* P    — page present              */
        uint64_t write          : 1;    /* R/W  — read/write                */
        uint64_t user           : 1;    /* U/S  — user/supervisor           */
        uint64_t pwt            : 1;    /* PWT  — page-level write-through  */
        uint64_t pcd            : 1;    /* PCD  — page-level cache disable  */
        uint64_t accessed       : 1;    /* A    — accessed                  */
        uint64_t ignored0       : 1;
        uint64_t reserved0      : 2;    /* MBZ                              */
        uint64_t avl            : 3;    /* available to software            */
        uint64_t pfn            : 40;   /* physical page frame number       */
        uint64_t available      : 11;   /* available to software            */
        uint64_t nx             : 1;    /* NX   — no execute                */
    };
    uint64_t raw;
} npt_pml4e_t;

/* NPT PDPT Entry (non-leaf — points to page directory) */
typedef union npt_pdpte {
    struct {
        uint64_t present        : 1;
        uint64_t write          : 1;
        uint64_t user           : 1;
        uint64_t pwt            : 1;
        uint64_t pcd            : 1;
        uint64_t accessed       : 1;
        uint64_t ignored0       : 1;
        uint64_t large          : 1;    /* PS — must be 0 for non-leaf      */
        uint64_t ignored1       : 1;
        uint64_t avl            : 3;
        uint64_t pfn            : 40;
        uint64_t available      : 11;
        uint64_t nx             : 1;
    };
    uint64_t raw;
} npt_pdpte_t;

/* NPT PDE for 2MB large page (leaf entry) */
typedef union npt_pde_2mb {
    struct {
        uint64_t present        : 1;
        uint64_t write          : 1;
        uint64_t user           : 1;
        uint64_t pwt            : 1;
        uint64_t pcd            : 1;
        uint64_t accessed       : 1;
        uint64_t dirty          : 1;
        uint64_t large          : 1;    /* PS — must be 1 for 2MB page      */
        uint64_t global         : 1;
        uint64_t avl            : 3;
        uint64_t pat            : 1;    /* PAT bit for large pages          */
        uint64_t reserved0      : 8;    /* MBZ                              */
        uint64_t pfn            : 31;   /* bits 47:21 of physical address   */
        uint64_t available      : 11;
        uint64_t nx             : 1;
    };
    uint64_t raw;
} npt_pde_2mb_t;

/* NPT PDE (non-leaf — points to page table) */
typedef union npt_pde {
    struct {
        uint64_t present        : 1;
        uint64_t write          : 1;
        uint64_t user           : 1;
        uint64_t pwt            : 1;
        uint64_t pcd            : 1;
        uint64_t accessed       : 1;
        uint64_t ignored0       : 1;
        uint64_t large          : 1;    /* PS — must be 0 for non-leaf      */
        uint64_t ignored1       : 1;
        uint64_t avl            : 3;
        uint64_t pfn            : 40;
        uint64_t available      : 11;
        uint64_t nx             : 1;
    };
    uint64_t raw;
} npt_pde_t;

/* NPT PTE (4KB page, leaf entry) */
typedef union npt_pte {
    struct {
        uint64_t present        : 1;
        uint64_t write          : 1;
        uint64_t user           : 1;
        uint64_t pwt            : 1;
        uint64_t pcd            : 1;
        uint64_t accessed       : 1;
        uint64_t dirty          : 1;
        uint64_t pat            : 1;    /* PAT bit                          */
        uint64_t global         : 1;
        uint64_t avl            : 3;
        uint64_t pfn            : 40;
        uint64_t available      : 11;
        uint64_t nx             : 1;
    };
    uint64_t raw;
} npt_pte_t;

GR_STATIC_ASSERT(sizeof(npt_pml4e_t)  == 8, "npt_pml4e_t must be 8 bytes");
GR_STATIC_ASSERT(sizeof(npt_pdpte_t)  == 8, "npt_pdpte_t must be 8 bytes");
GR_STATIC_ASSERT(sizeof(npt_pde_2mb_t)== 8, "npt_pde_2mb_t must be 8 bytes");
GR_STATIC_ASSERT(sizeof(npt_pde_t)    == 8, "npt_pde_t must be 8 bytes");
GR_STATIC_ASSERT(sizeof(npt_pte_t)    == 8, "npt_pte_t must be 8 bytes");

/* ======================================================================
 * NPT permission bits for gr_svm_npt_protect_page()
 * ====================================================================== */

#define NPT_PERM_READ                       BIT(0)
#define NPT_PERM_WRITE                      BIT(1)
#define NPT_PERM_EXEC                       BIT(2)
#define NPT_PERM_RWX                        (NPT_PERM_READ | NPT_PERM_WRITE | NPT_PERM_EXEC)
#define NPT_PERM_RW                         (NPT_PERM_READ | NPT_PERM_WRITE)
#define NPT_PERM_RX                         (NPT_PERM_READ | NPT_PERM_EXEC)
#define NPT_PERM_NONE                       0

/* ======================================================================
 * VMCB structure — Control area + State save area = 2 pages (8 KiB)
 * See APM Vol. 2, Section 15.5.1
 * ====================================================================== */

#define VMCB_CONTROL_AREA_SIZE              0x400
#define VMCB_STATE_SAVE_SIZE                0x400
#define VMCB_SIZE                           (2 * PAGE_SIZE)

/* ======================================================================
 * Table sizes
 * ====================================================================== */

#define NPT_PML4E_COUNT                     512
#define NPT_PDPTE_COUNT                     512
#define NPT_PDE_COUNT                       512
#define NPT_PTE_COUNT                       512

/* ======================================================================
 * MTRR constants — shared with VMX, see APM Vol. 2, Section 7.8
 * ====================================================================== */

#define SVM_MTRR_TYPE_UC                    0   /* Uncacheable       */
#define SVM_MTRR_TYPE_WC                    1   /* Write Combining   */
#define SVM_MTRR_TYPE_WT                    4   /* Write Through     */
#define SVM_MTRR_TYPE_WP                    5   /* Write Protected   */
#define SVM_MTRR_TYPE_WB                    6   /* Write Back        */

#define SVM_MTRR_MSR_CAPABILITIES           0x0FE
#define SVM_MTRR_MSR_DEFAULT                0x2FF
#define SVM_MTRR_MSR_VARIABLE_BASE          0x200
#define SVM_MTRR_MSR_VARIABLE_MASK          0x201
#define SVM_MTRR_MAX_VARIABLE_RANGES        16

/* ======================================================================
 * MSR Permission Map — APM Vol. 2, Section 15.11
 * Two pages (8 KiB): 0000_0000 - 0000_1FFF, C000_0000 - C000_1FFF,
 *                     C001_0000 - C001_1FFF
 * Each MSR has 2 bits: bit 0 = read intercept, bit 1 = write intercept.
 * ====================================================================== */

#define SVM_MSRPM_SIZE                      (PAGE_SIZE * 2)
#define SVM_IOPM_SIZE                       (PAGE_SIZE * 3)

/* ======================================================================
 * Hypervisor CPUID leaves — shared signature with VMX backend
 * ====================================================================== */

#define HYPERV_CPUID_VENDOR_AND_MAX         0x40000000
#define HYPERV_CPUID_INTERFACE              0x40000001
#define HYPERV_HYPERVISOR_PRESENT_BIT       BIT(31)

/* ======================================================================
 * VMCB accessor macros — typed read/write into the VMCB flat region
 * Follows the same pattern as NoirVisor but with GhostRing naming.
 * ====================================================================== */

#define gr_vmcb_read8(vmcb, off)    (*(uint8_t  *)((uintptr_t)(vmcb) + (off)))
#define gr_vmcb_read16(vmcb, off)   (*(uint16_t *)((uintptr_t)(vmcb) + (off)))
#define gr_vmcb_read32(vmcb, off)   (*(uint32_t *)((uintptr_t)(vmcb) + (off)))
#define gr_vmcb_read64(vmcb, off)   (*(uint64_t *)((uintptr_t)(vmcb) + (off)))

#define gr_vmcb_write8(vmcb, off, v)    (*(uint8_t  *)((uintptr_t)(vmcb) + (off)) = (uint8_t)(v))
#define gr_vmcb_write16(vmcb, off, v)   (*(uint16_t *)((uintptr_t)(vmcb) + (off)) = (uint16_t)(v))
#define gr_vmcb_write32(vmcb, off, v)   (*(uint32_t *)((uintptr_t)(vmcb) + (off)) = (uint32_t)(v))
#define gr_vmcb_write64(vmcb, off, v)   (*(uint64_t *)((uintptr_t)(vmcb) + (off)) = (uint64_t)(v))

#endif /* GHOSTRING_SVM_DEFS_H */
