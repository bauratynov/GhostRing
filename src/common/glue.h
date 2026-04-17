/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * glue.h — Orchestration layer that ties the loader, VMX/SVM backend,
 *           and monitor together.
 *
 * The loader calls gr_init_cpu() on each logical processor.  This function
 * allocates the per-CPU vcpu, initialises the chosen backend (VMX or SVM),
 * sets up the monitor, and launches into VMX/SVM root mode.
 *
 * This is the single integration point — loaders only need to call two
 * functions: gr_init_cpu() and gr_shutdown_cpu().
 */

#ifndef GHOSTRING_GLUE_H
#define GHOSTRING_GLUE_H

#include "ghostring.h"
#include "vcpu.h"
#include "platform.h"

/* ── Initialisation parameters (filled by loader, consumed by glue) ──── */

typedef struct {
    gr_cpu_vendor_t vendor;         /* GR_CPU_INTEL or GR_CPU_AMD        */
    uint64_t        system_cr3;     /* kernel PML4 physical address      */
    uint64_t        kernel_text_start; /* kernel .text start GPA         */
    uint64_t        kernel_text_size;  /* kernel .text size in bytes     */
} gr_init_params_t;

/* ── Per-CPU lifecycle ─────────────────────────────────────────────────── */

/*
 * gr_init_cpu — Full per-CPU virtualisation sequence.
 *
 * Called once per logical processor from the loader's broadcast (DPC on
 * Windows, on_each_cpu on Linux).  Must be called with interrupts disabled
 * and the caller pinned to the target CPU.
 *
 * Steps:
 *   1. Allocate gr_vcpu_t from platform allocator
 *   2. Probe VMX/SVM support
 *   3. Initialise MTRR + EPT/NPT
 *   4. Enter VMX/SVM root mode
 *   5. Set up VMCS/VMCB
 *   6. Initialise monitor (integrity + MSR guard + hooks)
 *   7. VMLAUNCH/VMRUN
 *
 * Returns 0 on success (guest is now running under hypervisor).
 * Returns -1 on failure (CPU not virtualised, caller continues normally).
 */
int gr_init_cpu(const gr_init_params_t *params);

/*
 * gr_shutdown_cpu — Devirtualise the current CPU.
 *
 * Issues the magic CPUID to trigger the VMCALL-based unload path.
 * After return, the CPU is back in normal mode.
 */
void gr_shutdown_cpu(void);

/*
 * gr_is_active — Check if GhostRing is running on this CPU.
 */
bool gr_is_active(void);

#endif /* GHOSTRING_GLUE_H */
