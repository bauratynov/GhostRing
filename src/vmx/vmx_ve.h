/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * vmx_ve.h — Virtualization Exception (#VE, vector 20) support.
 *
 * Instead of causing a VM-exit, certain EPT violations can be delivered
 * as exception #20 directly into the guest.  The guest handler reads
 * violation details from a per-vCPU "virtualization exception information
 * area" (VE info) and can resolve them without hypervisor involvement.
 *
 * Performance: #VE costs ~50-80 cycles (exception delivery) vs ~301
 * cycles (VM-exit round trip).  For "soft" violations (monitoring, not
 * blocking), this is 4-6× faster.
 *
 * Use cases for GhostRing:
 *   - In-guest agent handles non-critical EPT violations locally
 *   - VMFUNC + #VE enables exitless dual-EPT switching
 *   - Periodic integrity checks triggered by #VE timer
 *
 * Requires: Secondary Controls bit 18 (Enable #VE).
 * Reference: Intel SDM Vol. 3C, Section 25.5.7.
 */

#ifndef GHOSTRING_VMX_VE_H
#define GHOSTRING_VMX_VE_H

#include "vmx_defs.h"

/* ── VE Information Area (written by CPU on #VE delivery) ──────────────── */

/*
 * This structure must be placed at a known GPA and registered via the
 * VMCS VE_INFORMATION_ADDRESS field.  The CPU writes to it before
 * delivering #VE to the guest.  Must be page-aligned.
 *
 * See Intel SDM Vol. 3C, Table 25-19.
 */
typedef struct GR_PACKED gr_ve_info {
    uint32_t exit_reason;       /* 0x00: EPT_VIOLATION (48) */
    uint32_t reserved1;         /* 0x04: must be 0xFFFFFFFF on delivery */
    uint64_t exit_qualification;/* 0x08: same as EPT violation qual */
    uint64_t guest_linear;      /* 0x10: faulting linear address */
    uint64_t guest_physical;    /* 0x18: faulting physical address */
    uint16_t eptp_index;        /* 0x20: which EPTP was active */
    uint16_t reserved2[3];      /* 0x22: padding */
    uint32_t reserved3;         /* 0x28: must be 0 on delivery */
    /*
     * The "valid" sentinel: CPU sets reserved1 (offset 0x04) to
     * 0xFFFFFFFF when delivering #VE.  The guest handler must clear
     * it to 0x00000000 before returning — otherwise the CPU delivers
     * a real #DF (double fault) instead of another #VE.
     */
} gr_ve_info_t;

GR_STATIC_ASSERT(sizeof(gr_ve_info_t) == 44,
                 "VE info must match Intel SDM layout");

/* ── Per-vCPU VE context ───────────────────────────────────────────────── */

typedef struct gr_ve_ctx {
    gr_ve_info_t info GR_ALIGNED(PAGE_SIZE);  /* CPU writes here */
    bool         supported;
    bool         enabled;
} gr_ve_ctx_t;

/* ── API ───────────────────────────────────────────────────────────────── */

/* Check CPU support: CPUID.7.0:ECX bit 13 (same as VMFUNC) + secondary bit 18 */
static inline bool gr_ve_supported(void)
{
    /* #VE is controlled by Secondary Controls bit 18.
     * If the CPU allows setting bit 18, #VE is supported. */
    return true;  /* Actual check done during VMCS setup via adjust_controls */
}

/*
 * Enable #VE for a vCPU.
 *
 * Steps:
 *   1. Allocate VE info page (from ve_ctx, already page-aligned)
 *   2. VMWRITE VE_INFORMATION_ADDRESS = physical address of info page
 *   3. Set bit 18 in secondary VM-execution controls
 *   4. Configure EPT entries: set bit 63 ("suppress #VE") on pages
 *      that should cause VM-exit instead of #VE.  Pages WITHOUT bit 63
 *      will get #VE instead of exit on EPT violation.
 *
 * Security-critical pages (kernel code, IDT, MSR shadow):
 *   → Set EPT bit 63 = 1 → VM-exit (hypervisor decides)
 *
 * Non-critical monitored pages (working set tracking, profiling):
 *   → Set EPT bit 63 = 0 → #VE delivered to guest agent
 */
void gr_ve_enable(gr_ve_ctx_t *ctx);

/*
 * In-guest #VE handler (runs inside guest, NOT in hypervisor).
 * This is the IDT[20] handler installed by the GhostRing agent.
 *
 * Pseudocode:
 *   void ve_handler(void) {
 *       gr_ve_info_t *info = (gr_ve_info_t *)VE_INFO_GVA;
 *       uint64_t gpa = info->guest_physical;
 *       uint32_t qual = info->exit_qualification;
 *
 *       // Handle the violation (e.g., VMFUNC to switch EPT view)
 *       if (qual & EPT_EXECUTE_VIOLATION)
 *           gr_guest_vmfunc_switch_eptp(1);  // switch to shadow
 *
 *       // Clear valid sentinel so CPU can deliver next #VE
 *       info->reserved1 = 0;
 *       iretq;
 *   }
 */

#endif /* GHOSTRING_VMX_VE_H */
