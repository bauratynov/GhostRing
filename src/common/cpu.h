/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * cpu.h — Thin inline wrappers around privileged x86-64 instructions.
 * Every helper compiles to exactly the instruction(s) it names — no
 * hidden branches or memory allocations.  Names follow Intel SDM
 * mnemonics so grepping the manual is straightforward.
 */

#ifndef GHOSTRING_CPU_H
#define GHOSTRING_CPU_H

#include "types.h"

/* ── MSR access (Intel SDM Vol. 4, Appendix B) ──────────────────────────── */

static inline uint64_t gr_rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void gr_wrmsr(uint32_t msr, uint64_t val)
{
    uint32_t lo = (uint32_t)val;
    uint32_t hi = (uint32_t)(val >> 32);
    __asm__ volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

/* ── CPUID (Intel SDM Vol. 2A, CPUID) ───────────────────────────────────── */

static inline void gr_cpuid(uint32_t leaf, uint32_t subleaf,
                             uint32_t *eax, uint32_t *ebx,
                             uint32_t *ecx, uint32_t *edx)
{
    __asm__ volatile("cpuid"
                     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                     : "a"(leaf), "c"(subleaf));
}

/* ── Control registers ───────────────────────────────────────────────────── */

static inline uint64_t gr_read_cr0(void)
{
    uint64_t v;
    __asm__ volatile("mov %%cr0, %0" : "=r"(v));
    return v;
}

static inline void gr_write_cr0(uint64_t v)
{
    __asm__ volatile("mov %0, %%cr0" : : "r"(v));
}

static inline uint64_t gr_read_cr3(void)
{
    uint64_t v;
    __asm__ volatile("mov %%cr3, %0" : "=r"(v));
    return v;
}

static inline void gr_write_cr3(uint64_t v)
{
    __asm__ volatile("mov %0, %%cr3" : : "r"(v) : "memory");
}

static inline uint64_t gr_read_cr4(void)
{
    uint64_t v;
    __asm__ volatile("mov %%cr4, %0" : "=r"(v));
    return v;
}

static inline void gr_write_cr4(uint64_t v)
{
    __asm__ volatile("mov %0, %%cr4" : : "r"(v));
}

/* ── Debug register 7 ───────────────────────────────────────────────────── */

static inline uint64_t gr_read_dr7(void)
{
    uint64_t v;
    __asm__ volatile("mov %%dr7, %0" : "=r"(v));
    return v;
}

static inline void gr_write_dr7(uint64_t v)
{
    __asm__ volatile("mov %0, %%dr7" : : "r"(v));
}

/* ── Descriptor table registers ──────────────────────────────────────────── */

/*
 * Descriptor table register layout as stored by SGDT/SIDT.
 * The CPU writes 10 bytes: 2-byte limit followed by 8-byte base.
 * Packed to match hardware layout exactly (no padding between fields).
 */
typedef struct GR_PACKED {
    uint16_t limit;
    uint64_t base;
} gr_desc_table_reg_t;

GR_STATIC_ASSERT(sizeof(gr_desc_table_reg_t) == 10,
                 "descriptor table register must be exactly 10 bytes");

static inline void gr_sgdt(gr_desc_table_reg_t *gdtr)
{
    __asm__ volatile("sgdt %0" : "=m"(*gdtr));
}

static inline void gr_sidt(gr_desc_table_reg_t *idtr)
{
    __asm__ volatile("sidt %0" : "=m"(*idtr));
}

static inline uint16_t gr_str(void)
{
    uint16_t tr;
    __asm__ volatile("str %0" : "=r"(tr));
    return tr;
}

static inline uint16_t gr_sldt(void)
{
    uint16_t ldt;
    __asm__ volatile("sldt %0" : "=r"(ldt));
    return ldt;
}

/* ── Segment selectors ───────────────────────────────────────────────────── */

#define GR_READ_SEG(name)                                       \
    static inline uint16_t gr_read_##name(void)                 \
    {                                                           \
        uint16_t v;                                             \
        __asm__ volatile("mov %%" #name ", %0" : "=r"(v));     \
        return v;                                               \
    }

GR_READ_SEG(cs)
GR_READ_SEG(ds)
GR_READ_SEG(es)
GR_READ_SEG(fs)
GR_READ_SEG(gs)
GR_READ_SEG(ss)

#undef GR_READ_SEG

/* ── Cache management ────────────────────────────────────────────────────── */

/* Invalidate caches WITHOUT writing back — dangerous, for special cases. */
static inline void gr_invd(void)
{
    __asm__ volatile("invd" ::: "memory");
}

/* Write-back and invalidate — safe cache flush. */
static inline void gr_wbinvd(void)
{
    __asm__ volatile("wbinvd" ::: "memory");
}

/* ── Interrupt control ───────────────────────────────────────────────────── */

static inline void gr_cli(void)
{
    __asm__ volatile("cli");
}

static inline void gr_sti(void)
{
    __asm__ volatile("sti");
}

static inline uint64_t gr_read_rflags(void)
{
    uint64_t f;
    __asm__ volatile("pushfq; popq %0" : "=r"(f) :: "memory");
    return f;
}

/* ── Hints ───────────────────────────────────────────────────────────────── */

/* Signal the CPU that we are in a spin-wait loop (saves power, avoids
 * memory-order violation pipeline flushes on Intel). */
static inline void gr_pause(void)
{
    __asm__ volatile("pause");
}

/* Halt the processor until the next external interrupt. */
static inline void gr_hlt(void)
{
    __asm__ volatile("hlt");
}

#endif /* GHOSTRING_CPU_H */
