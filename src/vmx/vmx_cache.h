/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * vmx_cache.h — VMCS field caching with dirty-bit tracking.
 *
 * Each VMREAD costs ~50-100 cycles.  On a typical VM-exit we read 6-8
 * fields.  By reading them all once into a local cache and writing back
 * only the modified ones, we save 300-800 cycles per exit.
 *
 * Usage in the exit handler:
 *   gr_vmcs_cache_t cache;
 *   gr_vmcs_cache_load(&cache);        // batch VMREAD
 *   ... use cache.guest_rip, etc. ...
 *   cache.guest_rip += cache.exit_instr_len;
 *   cache.dirty |= VMCS_DIRTY_RIP;
 *   gr_vmcs_cache_flush(&cache);       // only dirty VMWRITE
 *
 * Reference: Intel SDM Vol. 3C, Section 24.11.2 ("VMREAD/VMWRITE").
 */

#ifndef GHOSTRING_VMX_CACHE_H
#define GHOSTRING_VMX_CACHE_H

#include "vmx_defs.h"

/* ── Dirty bit flags ───────────────────────────────────────────────────── */

#define VMCS_DIRTY_RIP          BIT(0)
#define VMCS_DIRTY_RSP          BIT(1)
#define VMCS_DIRTY_RFLAGS       BIT(2)
#define VMCS_DIRTY_CR0          BIT(3)
#define VMCS_DIRTY_CR4          BIT(4)
#define VMCS_DIRTY_INTR_INFO    BIT(5)
#define VMCS_DIRTY_INTR_ERROR   BIT(6)
#define VMCS_DIRTY_ACTIVITY     BIT(7)

/* ── Cached VMCS snapshot ──────────────────────────────────────────────── */

typedef struct gr_vmcs_cache {
    /* Read-only fields (loaded once, never written back) */
    uint64_t exit_reason;
    uint64_t exit_qualification;
    uint64_t exit_instr_len;
    uint64_t guest_phys_addr;
    uint64_t guest_linear_addr;
    uint64_t exit_intr_info;
    uint64_t exit_intr_error;

    /* Read-write fields (written back if dirty) */
    uint64_t guest_rip;
    uint64_t guest_rsp;
    uint64_t guest_rflags;
    uint64_t guest_cr0;
    uint64_t guest_cr3;
    uint64_t guest_cr4;

    /* Dirty bitmask — only set bits trigger VMWRITE on flush */
    uint32_t dirty;
} gr_vmcs_cache_t;

/* ── VMREAD/VMWRITE intrinsics ─────────────────────────────────────────── */

static inline uint64_t _gr_vmread(uint64_t field)
{
    uint64_t value;
    __asm__ volatile("vmread %[field], %[val]"
                     : [val] "=r"(value)
                     : [field] "r"(field)
                     : "cc");
    return value;
}

static inline void _gr_vmwrite(uint64_t field, uint64_t value)
{
    __asm__ volatile("vmwrite %[val], %[field]"
                     :
                     : [field] "r"(field), [val] "rm"(value)
                     : "cc", "memory");
}

/* ── Batch load: 13 VMREADs ────────────────────────────────────────────── */

static inline void gr_vmcs_cache_load(gr_vmcs_cache_t *c)
{
    c->exit_reason        = _gr_vmread(VMCS_EXIT_REASON) & 0xFFFF;
    c->exit_qualification = _gr_vmread(VMCS_EXIT_QUALIFICATION);
    c->exit_instr_len     = _gr_vmread(VMCS_EXIT_INSTRUCTION_LEN);
    c->guest_phys_addr    = _gr_vmread(VMCS_GUEST_PHYS_ADDR);
    c->guest_linear_addr  = _gr_vmread(VMCS_GUEST_LINEAR_ADDR);
    c->exit_intr_info     = _gr_vmread(VMCS_EXIT_INTR_INFO);
    c->exit_intr_error    = _gr_vmread(VMCS_EXIT_INTR_ERROR_CODE);
    c->guest_rip          = _gr_vmread(VMCS_GUEST_RIP);
    c->guest_rsp          = _gr_vmread(VMCS_GUEST_RSP);
    c->guest_rflags       = _gr_vmread(VMCS_GUEST_RFLAGS);
    c->guest_cr0          = _gr_vmread(VMCS_GUEST_CR0);
    c->guest_cr3          = _gr_vmread(VMCS_GUEST_CR3);
    c->guest_cr4          = _gr_vmread(VMCS_GUEST_CR4);
    c->dirty              = 0;
}

/* ── Selective flush: only dirty fields ────────────────────────────────── */

static inline void gr_vmcs_cache_flush(gr_vmcs_cache_t *c)
{
    uint32_t d = c->dirty;
    if (!d) return;

    if (d & VMCS_DIRTY_RIP)
        _gr_vmwrite(VMCS_GUEST_RIP, c->guest_rip);
    if (d & VMCS_DIRTY_RSP)
        _gr_vmwrite(VMCS_GUEST_RSP, c->guest_rsp);
    if (d & VMCS_DIRTY_RFLAGS)
        _gr_vmwrite(VMCS_GUEST_RFLAGS, c->guest_rflags);
    if (d & VMCS_DIRTY_CR0)
        _gr_vmwrite(VMCS_GUEST_CR0, c->guest_cr0);
    if (d & VMCS_DIRTY_CR4)
        _gr_vmwrite(VMCS_GUEST_CR4, c->guest_cr4);
    if (d & VMCS_DIRTY_INTR_INFO)
        _gr_vmwrite(VMCS_ENTRY_INTR_INFO, c->exit_intr_info);
    if (d & VMCS_DIRTY_INTR_ERROR)
        _gr_vmwrite(VMCS_ENTRY_EXCEPTION_ERROR_CODE, c->exit_intr_error);

    c->dirty = 0;
}

/* ── Convenience: advance RIP past faulting instruction ────────────────── */

static inline void gr_cache_advance_rip(gr_vmcs_cache_t *c)
{
    c->guest_rip += c->exit_instr_len;
    c->dirty |= VMCS_DIRTY_RIP;
}

/* ── Convenience: inject #GP(0) ────────────────────────────────────────── */

static inline void gr_cache_inject_gp(gr_vmcs_cache_t *c)
{
    /* Vector=13, Type=3 (HW exception), EV=1 (error code), Valid=1 */
    c->exit_intr_info = (13u) | (3u << 8) | (1u << 11) | (1u << 31);
    c->exit_intr_error = 0;
    c->dirty |= VMCS_DIRTY_INTR_INFO | VMCS_DIRTY_INTR_ERROR;
}

/* ── Convenience: inject NMI ───────────────────────────────────────────── */

static inline void gr_cache_inject_nmi(gr_vmcs_cache_t *c)
{
    /* Vector=2, Type=2 (NMI), Valid=1 */
    c->exit_intr_info = (2u) | (2u << 8) | (1u << 31);
    c->dirty |= VMCS_DIRTY_INTR_INFO;
}

#endif /* GHOSTRING_VMX_CACHE_H */
