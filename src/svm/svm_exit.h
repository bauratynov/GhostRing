/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * svm_exit.h — #VMEXIT handling interface for the GhostRing SVM backend.
 *
 * Defines the guest GPR context structure pushed by the assembly entry
 * point, and the C dispatcher called for every #VMEXIT.
 *
 * Reference: AMD APM Vol. 2, Chapter 15, Section 15.6 ("#VMEXIT").
 */

#ifndef GHOSTRING_SVM_EXIT_H
#define GHOSTRING_SVM_EXIT_H

#include "svm_vmcb.h"

/* -- Guest GPR context (matches push order in svm_asm.S) ------------------ */

/*
 * When #VMEXIT occurs, the assembly stub pushes all general-purpose
 * registers onto the stack in this order.  RAX is saved/restored via
 * the VMCB state save area, so the stack slot is a mirror.
 */
typedef struct gr_svm_guest_ctx {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbp;
    uint64_t rsp_placeholder;   /* RSP saved in VMCB, not on stack */
    uint64_t rbx;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rax;
} gr_svm_guest_ctx_t;

/* -- Public API ----------------------------------------------------------- */

/*
 * gr_svm_handle_exit — Main #VMEXIT dispatcher.
 *
 * Called from the assembly #VMEXIT entry point with pointers to the saved
 * GPR context and the VMCB.  Reads the exit code from the VMCB control
 * area, dispatches to the appropriate handler, advances guest RIP using
 * NRIP, and returns so the assembly stub can execute VMRUN again.
 *
 * @vcpu : Per-vCPU SVM state (contains VMCB).
 * @ctx  : Guest GPR context on the stack.
 */
void gr_svm_handle_exit(gr_svm_vcpu_t *vcpu, gr_svm_guest_ctx_t *ctx);

/*
 * External hook: NPF (Nested Page Fault) handler provided by the monitor
 * subsystem.
 * @gpa            : Faulting guest physical address.
 * @error_code     : NPF error code (info1): P/W/U/RSV/ID bits.
 *
 * Returns 0 to resume the guest, non-zero to inject a fault.
 */
extern int gr_monitor_npf(uint64_t gpa, uint64_t error_code);

/*
 * External hook: Hypercall dispatcher provided by the hypercall subsystem.
 * @ctx : Guest GPR context (RAX = hypercall number, RCX/RDX/R8 = args).
 */
extern void gr_hypercall_dispatch_svm(gr_svm_guest_ctx_t *ctx);

#endif /* GHOSTRING_SVM_EXIT_H */
