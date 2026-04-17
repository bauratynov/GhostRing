/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * vcpu.h — Unified per-logical-processor state.
 *
 * Each physical CPU that enters VMX/SVM root mode gets one gr_vcpu_t.
 * The structure wraps the architecture-specific backend (VMX or SVM)
 * and adds common fields used by the monitor, hypercall, and loader
 * subsystems.
 *
 * Memory layout: page-aligned, all sub-structures cache-line padded
 * where contention is possible (different CPUs never share a vcpu).
 */

#ifndef GHOSTRING_VCPU_H
#define GHOSTRING_VCPU_H

#include "types.h"

/* ── Forward declarations for arch-specific backends ───────────────────── */

/* These are defined in vmx/vmx_vmcs.h and svm/svm_vmcb.h respectively.
 * We only need opaque pointers here; the full definitions are pulled in
 * by whichever backend is compiled. */
struct gr_vmx_vcpu;
struct gr_svm_vcpu;

/* ── Monitor state forward declaration ─────────────────────────────────── */

struct gr_monitor_state;

/* ── CPU vendor enum ───────────────────────────────────────────────────── */

typedef enum {
    GR_CPU_UNKNOWN = 0,
    GR_CPU_INTEL   = 1,     /* "GenuineIntel" */
    GR_CPU_AMD     = 2,     /* "AuthenticAMD" */
} gr_cpu_vendor_t;

/* ── Unified vCPU ──────────────────────────────────────────────────────── */

struct gr_vcpu {
    /* ── Identity ─────────────────────────────────────────────────────── */
    uint32_t            cpu_id;         /* APIC ID of this logical CPU    */
    gr_cpu_vendor_t     vendor;         /* Intel or AMD                   */
    uint8_t             active;         /* 1 = hypervisor running on CPU  */
    uint8_t             exit_vm;        /* 1 = pending devirtualization   */
    uint8_t             _pad[2];

    /* ── Architecture-specific backend ────────────────────────────────── */
    union {
#if GHOSTRING_VTX
        struct gr_vmx_vcpu  *vmx;
#endif
#if GHOSTRING_SVM
        struct gr_svm_vcpu  *svm;
#endif
        void                *arch;      /* generic pointer for loaders   */
    };

    /* ── Monitor subsystem state ──────────────────────────────────────── */
    struct gr_monitor_state *monitor;

    /* ── System CR3 (kernel page table base for host mode) ────────────── */
    phys_addr_t         system_cr3;

    /* ── Statistics ───────────────────────────────────────────────────── */
    uint64_t            exit_count;     /* total VM-exits handled         */
    uint64_t            ept_violation_count;
    uint64_t            msr_exit_count;
    uint64_t            cpuid_exit_count;
};

/* ── Convenience accessor ──────────────────────────────────────────────── */

/*
 * Get the unified vcpu from the per-CPU table.
 * Defined in percpu.h — included here for documentation.
 */
/* gr_vcpu_t *gr_get_vcpu(void); */

#endif /* GHOSTRING_VCPU_H */
