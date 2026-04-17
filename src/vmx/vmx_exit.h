/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * vmx_exit.h — VM-exit handling interface for the GhostRing VMX backend.
 *
 * Defines the guest GPR context structure pushed by the assembly entry
 * point, and the C dispatcher called for every VM-exit.
 *
 * Reference: Intel SDM Vol. 3C, Chapter 27 ("VM Exits").
 */

#ifndef GHOSTRING_VMX_EXIT_H
#define GHOSTRING_VMX_EXIT_H

#include "vmx_vmcs.h"

/* ── Guest GPR context (matches push order in vmx_asm.S) ──────────────── */

typedef struct gr_vmx_guest_ctx {
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
    uint64_t rsp_placeholder;   /* RSP saved in VMCS, not on stack */
    uint64_t rbx;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rax;
} gr_vmx_guest_ctx_t;

/* ── Public API ────────────────────────────────────────────────────────── */

/*
 * gr_vmx_handle_exit — Main VM-exit dispatcher.
 *
 * Called from the assembly VM-exit entry point with a pointer to the saved
 * GPR context on the stack.  Reads the exit reason from the VMCS,
 * dispatches to the appropriate handler, advances guest RIP, and returns
 * so the assembly stub can execute VMRESUME.
 */
void gr_vmx_handle_exit(gr_vmx_guest_ctx_t *ctx);

/*
 * gr_vmx_resume_failed — Called by the assembly stub when VMRESUME fails.
 * This is a fatal error path; the function must not return.
 */
GR_NORETURN void gr_vmx_resume_failed(void);

/*
 * Monitor and hypercall hooks are declared in their own headers
 * (monitor/monitor.h and hypercall/hypercall.h).  Do NOT declare
 * them here to avoid signature conflicts.  vmx_exit.c includes
 * the canonical headers directly.
 */

#endif /* GHOSTRING_VMX_EXIT_H */
