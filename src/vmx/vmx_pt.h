/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * vmx_pt.h — Intel Processor Trace (PT) for control-flow monitoring.
 *
 * Intel PT records a compressed trace of all branches taken by the CPU.
 * From the hypervisor, we can configure PT to trace guest execution and
 * analyze the trace for:
 *   - ROP/JOP chain detection (unexpected indirect branch sequences)
 *   - Control-flow hijacking (branch to non-code pages)
 *   - Code coverage analysis (which kernel functions executed)
 *
 * PT overhead: ~5-15% CPU for full tracing, ~1-2% for filtered tracing.
 * The trace is written to a circular buffer in physical memory that the
 * hypervisor owns — invisible to the guest.
 *
 * Available: Intel Broadwell+ (5th gen Core / Xeon v4).
 * Reference: Intel SDM Vol. 3C, Chapter 32 ("Intel Processor Trace").
 */

#ifndef GHOSTRING_VMX_PT_H
#define GHOSTRING_VMX_PT_H

#include "vmx_defs.h"

/* ── PT output region (ToPA = Table of Physical Addresses) ─────────────── */

/*
 * ToPA entry: specifies a physical buffer region for PT output.
 * Multiple entries form a circular list for continuous tracing.
 */
typedef struct GR_PACKED gr_topa_entry {
    uint64_t phys_addr   : 36;  /* physical address bits [47:12] */
    uint64_t reserved1   : 9;
    uint64_t size        : 4;   /* buffer size: 2^(size+12) bytes */
    uint64_t reserved2   : 2;
    uint64_t stop        : 1;   /* stop tracing when this entry fills */
    uint64_t intr        : 1;   /* generate interrupt when filling */
    uint64_t reserved3   : 4;
    uint64_t end         : 1;   /* last entry in ToPA — wrap to first */
    uint64_t reserved4   : 6;
} gr_topa_entry_t;

GR_STATIC_ASSERT(sizeof(gr_topa_entry_t) == 8, "ToPA entry must be 8 bytes");

/* ── PT context per vCPU ───────────────────────────────────────────────── */

#define GR_PT_BUFFER_ORDER  4   /* 2^(4+12) = 64KB per buffer region */
#define GR_PT_TOPA_ENTRIES  4   /* 4 × 64KB = 256KB circular buffer */

typedef struct gr_pt_ctx {
    gr_topa_entry_t topa[GR_PT_TOPA_ENTRIES + 1] GR_ALIGNED(PAGE_SIZE);
    phys_addr_t     buffer_phys[GR_PT_TOPA_ENTRIES];
    void           *buffer_virt[GR_PT_TOPA_ENTRIES];
    bool            supported;
    bool            tracing;
} gr_pt_ctx_t;

/* ── Detection ─────────────────────────────────────────────────────────── */

static inline bool gr_pt_supported(void)
{
    uint32_t eax, ebx, ecx, edx;
    gr_cpuid(0x7, 0, &eax, &ebx, &ecx, &edx);
    return (ebx & BIT(25)) != 0;  /* CPUID.7.0:EBX.IntelPT */
}

/* ── API ───────────────────────────────────────────────────────────────── */

/* Allocate PT buffers and build ToPA table */
void gr_pt_init(gr_pt_ctx_t *ctx);

/* Start tracing guest execution on this vCPU */
void gr_pt_start(gr_pt_ctx_t *ctx);

/* Stop tracing and return buffer for analysis */
void gr_pt_stop(gr_pt_ctx_t *ctx);

/*
 * Analyze PT trace for anomalies.
 * Returns number of suspicious branch sequences detected.
 *
 * Checks:
 *   - Indirect branch to non-executable page → ROP/JOP
 *   - Excessive indirect branches in short window → spray
 *   - Branch to page outside kernel code range → injection
 */
int gr_pt_analyze(gr_pt_ctx_t *ctx,
                  uint64_t kernel_base, uint64_t kernel_size);

#endif /* GHOSTRING_VMX_PT_H */
