/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * hypercall.h — VMCALL-based hypercall interface for guest ←→ hypervisor
 *               communication.
 *
 * The guest kernel module invokes VMCALL with a function code in RAX
 * and up to three arguments in RCX, RDX, R8.  The hypervisor traps
 * the VMCALL VM-exit, dispatches to the requested handler, and places
 * the result in RAX before resuming the guest.
 *
 * All hypercall numbers are prefixed with 0x4752 ("GR" in ASCII) to
 * avoid collisions with other hypervisors that might share the
 * VMCALL namespace (Hyper-V, KVM, etc.).
 *
 * Security: only ring 0 callers are accepted.  A VMCALL from user-space
 * (CPL != 0) is rejected with an error code to prevent unprivileged
 * guests from triggering hypervisor operations.
 */

#ifndef GHOSTRING_HYPERCALL_H
#define GHOSTRING_HYPERCALL_H

#include "../common/ghostring.h"
#include "../vmx/vmx_exit.h"
#include "../monitor/monitor.h"

/* ── Hypercall numbers ──────────────────────────────────────────────────── */

#define GR_HCALL_PING           0x47520000  /* Liveness check            */
#define GR_HCALL_STATUS         0x47520001  /* Return monitoring stats   */
#define GR_HCALL_INTEGRITY      0x47520002  /* Trigger integrity check   */
#define GR_HCALL_DKOM_SCAN      0x47520003  /* Trigger DKOM scan         */
#define GR_HCALL_UNLOAD         0x47520004  /* Devirtualise this CPU     */

/* ── Magic response values ──────────────────────────────────────────────── */

#define GR_HCALL_MAGIC_REPLY    0x47685269  /* "GhRi" — ping response   */
#define GR_HCALL_ERR_NOT_RING0  0xFFFFFFFFFFFFFF01ULL
#define GR_HCALL_ERR_UNKNOWN    0xFFFFFFFFFFFFFF02ULL

/* ── Public API ─────────────────────────────────────────────────────────── */

/*
 * gr_hypercall_dispatch — Main hypercall entry point.
 *
 * Called from the VMCALL VM-exit handler in vmx_exit.c.  Reads the
 * hypercall number from ctx->rax, validates the caller is ring 0,
 * dispatches to the appropriate handler, and writes the result back
 * into ctx->rax.
 *
 * @ctx     : Guest GPR context (RAX = call number; RCX, RDX, R8 = args).
 * @mon     : Per-vCPU monitor state for integrity/DKOM operations.
 * @exit_vm : Pointer to the vCPU's exit flag; set to true by UNLOAD.
 */
void gr_hypercall_dispatch(gr_vmx_guest_ctx_t *ctx,
                           gr_monitor_state_t *mon,
                           bool *exit_vm);

#endif /* GHOSTRING_HYPERCALL_H */
