/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * bench_vmexit.c — VM-exit latency benchmark.
 *
 * Measures the round-trip cost of a CPUID-induced VM-exit when running
 * under GhostRing.  Run this INSIDE a virtualised guest (after insmod).
 *
 * Compile: gcc -O2 -o bench_vmexit bench_vmexit.c && ./bench_vmexit
 *
 * Expected results:
 *   Bare metal (no hypervisor):  CPUID ~40-80 cycles
 *   Under GhostRing:             CPUID ~800-2000 cycles (VM-exit overhead)
 *   Under Hyper-V/KVM:           CPUID ~1500-4000 cycles
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ── RDTSC/RDTSCP ──────────────────────────────────────────────────────── */

static inline uint64_t rdtsc_start(void)
{
    uint32_t lo, hi;
    /* CPUID serialises the pipeline before reading TSC */
    __asm__ volatile("cpuid; rdtsc" : "=a"(lo), "=d"(hi)
                     : "a"(0) : "rbx", "rcx");
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtsc_end(void)
{
    uint32_t lo, hi;
    /* RDTSCP serialises the read; CPUID flushes the pipeline after */
    __asm__ volatile("rdtscp; mov %%eax, %0; mov %%edx, %1; cpuid"
                     : "=r"(lo), "=r"(hi) : : "rax", "rbx", "rcx", "rdx");
    return ((uint64_t)hi << 32) | lo;
}

/* ── Benchmark: CPUID leaf 1 (causes VM-exit under hypervisor) ─────────── */

static void bench_cpuid(int iterations)
{
    uint64_t min = UINT64_MAX, max = 0, total = 0;
    uint32_t eax, ebx, ecx, edx;

    /* Warmup */
    for (int i = 0; i < 100; i++) {
        __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                         : "a"(1), "c"(0));
    }

    for (int i = 0; i < iterations; i++) {
        uint64_t start = rdtsc_start();

        __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                         : "a"(1), "c"(0));

        uint64_t end = rdtsc_end();
        uint64_t elapsed = end - start;

        if (elapsed < min) min = elapsed;
        if (elapsed > max) max = elapsed;
        total += elapsed;
    }

    printf("  CPUID leaf 1 (%d iterations):\n", iterations);
    printf("    min:  %llu cycles\n", (unsigned long long)min);
    printf("    max:  %llu cycles\n", (unsigned long long)max);
    printf("    avg:  %llu cycles\n", (unsigned long long)(total / iterations));

    /* Check if hypervisor present */
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(1), "c"(0));
    printf("    hypervisor bit: %s\n", (ecx & (1u << 31)) ? "SET" : "clear");
}

/* ── Benchmark: CPUID leaf 0x40000000 (hypervisor vendor) ──────────────── */

static void bench_hv_cpuid(void)
{
    uint32_t eax, ebx, ecx, edx;

    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(0x40000000), "c"(0));

    char vendor[13] = {0};
    memcpy(vendor + 0, &ebx, 4);
    memcpy(vendor + 4, &ecx, 4);
    memcpy(vendor + 8, &edx, 4);

    printf("  Hypervisor vendor: \"%s\"\n", vendor);
    printf("  Max HV leaf: 0x%08x\n", eax);
}

/* ── Benchmark: VMCALL latency (only under GhostRing) ──────────────────── */

static void bench_vmcall(int iterations)
{
    uint64_t min = UINT64_MAX, max = 0, total = 0;

    for (int i = 0; i < iterations; i++) {
        uint64_t start = rdtsc_start();

        /* GR_HCALL_PING = 0x47520000 */
        uint64_t result;
        __asm__ volatile(
            "mov $0x47520000, %%rax; vmcall; mov %%rax, %0"
            : "=r"(result) : : "rax", "rcx", "rdx", "rbx"
        );

        uint64_t end = rdtsc_end();
        uint64_t elapsed = end - start;

        if (elapsed < min) min = elapsed;
        if (elapsed > max) max = elapsed;
        total += elapsed;
    }

    printf("  VMCALL PING (%d iterations):\n", iterations);
    printf("    min:  %llu cycles\n", (unsigned long long)min);
    printf("    max:  %llu cycles\n", (unsigned long long)max);
    printf("    avg:  %llu cycles\n", (unsigned long long)(total / iterations));
}

/* ── Main ──────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("GhostRing VM-Exit Benchmark\n");
    printf("===========================\n\n");

    bench_hv_cpuid();
    printf("\n");

    bench_cpuid(10000);
    printf("\n");

    /* VMCALL benchmark — only safe under GhostRing, not Hyper-V/KVM.
     * Check for our specific "GhR" signature at CPUID 0x40000000. */
    {
        uint32_t eax2, ebx2, ecx2, edx2;
        __asm__ volatile("cpuid" : "=a"(eax2), "=b"(ebx2), "=c"(ecx2), "=d"(edx2)
                         : "a"(0x40000000), "c"(0));
        /* Check if vendor starts with "GhR" (our signature) */
        if (ebx2 == 0x52684700) {
            bench_vmcall(10000);
        } else {
            printf("  VMCALL benchmark skipped (not running under GhostRing)\n");
        }
    }

    printf("\nDone.\n");
    return 0;
}
