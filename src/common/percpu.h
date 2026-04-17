/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * percpu.h — Per-logical-processor state lookup.
 *
 * Each logical CPU that enters VMX root mode gets its own gr_vcpu_t.
 * This header provides O(1) access to the current CPU's vcpu pointer
 * via a simple array indexed by the initial APIC ID.
 *
 * Two identification strategies are supported:
 *   1. CPUID leaf 0x1 (EBX[31:24]) — universal, works on all x86-64.
 *   2. RDTSCP (ECX = IA32_TSC_AUX) — faster, but requires the MSR to
 *      be programmed first during BSP/AP init.
 */

#ifndef GHOSTRING_PERCPU_H
#define GHOSTRING_PERCPU_H

#include "types.h"
#include "cpu.h"

/* ── Limits ──────────────────────────────────────────────────────────────── */

#define GR_MAX_CPUS     256

/* ── Per-CPU table ───────────────────────────────────────────────────────── */

/*
 * Intentionally not a struct — it is just an array of pointers.
 * Keeping it flat avoids cache-line false-sharing issues: each CPU
 * only touches its own index, and the array fits in 2 KiB.
 */
typedef struct {
    gr_vcpu_t *vcpus[GR_MAX_CPUS];
    uint32_t   cpu_count;     /* number of CPUs that have registered */
} gr_percpu_t;

/* Single global instance — defined by the BSP startup code. */
extern gr_percpu_t g_percpu;

/* ── CPU identification ──────────────────────────────────────────────────── */

/*
 * Return the current logical processor's ID.  Uses CPUID leaf 0x1
 * which returns the initial APIC ID in EBX[31:24].  This works
 * before we have had a chance to program IA32_TSC_AUX for RDTSCP.
 */
static inline uint32_t gr_get_cpu_id(void)
{
    uint32_t eax, ebx, ecx, edx;
    gr_cpuid(0x1, 0, &eax, &ebx, &ecx, &edx);
    /* Initial APIC ID is bits 31:24 of EBX. */
    return (ebx >> 24) & 0xFF;
}

/*
 * Faster path once IA32_TSC_AUX has been programmed with the CPU index
 * during AP bring-up.  RDTSCP is serializing on the read side so it
 * is safe to use as a CPU identifier even across migrations (which
 * cannot happen inside VMX root mode anyway).
 */
static inline uint32_t gr_get_cpu_id_fast(void)
{
    uint32_t ecx;
    __asm__ volatile("rdtscp" : "=c"(ecx) : : "eax", "edx");
    return ecx;
}

/* ── vcpu accessors ──────────────────────────────────────────────────────── */

static inline gr_vcpu_t *gr_get_vcpu(void)
{
    uint32_t id = gr_get_cpu_id();
    if (unlikely(id >= GR_MAX_CPUS)) {
        return NULL;
    }
    return g_percpu.vcpus[id];
}

static inline gr_vcpu_t *gr_get_vcpu_fast(void)
{
    uint32_t id = gr_get_cpu_id_fast();
    if (unlikely(id >= GR_MAX_CPUS)) {
        return NULL;
    }
    return g_percpu.vcpus[id];
}

static inline void gr_set_vcpu(uint32_t id, gr_vcpu_t *vcpu)
{
    if (id < GR_MAX_CPUS) {
        g_percpu.vcpus[id] = vcpu;
    }
}

#endif /* GHOSTRING_PERCPU_H */
