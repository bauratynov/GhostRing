/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * vmx_asm.S — Assembly entry/exit stubs for the GhostRing VMX backend.
 *
 * Provides:
 *   gr_vmx_entry        — VM-exit entry point (saves GPRs, calls C handler,
 *                          restores GPRs, VMRESUME).
 *   gr_vmx_launch       — VMLAUNCH wrapper; returns error code on failure.
 *   gr_vmx_vmxoff       — Clean exit from VMX root mode.
 *   gr_vmx_restore_guest — Stub that the guest RIP points to after a
 *                          successful VMLAUNCH.
 *
 * Calling convention: System V AMD64 ABI (RDI = first argument).
 * Reference: Intel SDM Vol. 3C, Sections 23-27.
 */

.intel_syntax noprefix
.text

/* ═══════════════════════════════════════════════════════════════════════════
 * gr_vmx_entry — VM-exit entry point
 *
 * The processor jumps here (HOST_RIP) on every VM-exit.  We save all
 * guest GPRs onto the host stack, call the C dispatcher, restore the
 * GPRs, and issue VMRESUME to re-enter the guest.
 *
 * Stack layout after pushes (grows downward):
 *   [RSP+0x78]  RAX   (pushed first = highest address)
 *   [RSP+0x70]  RCX
 *   [RSP+0x68]  RDX
 *   [RSP+0x60]  RBX
 *   [RSP+0x58]  RSP placeholder (not meaningful — guest RSP is in VMCS)
 *   [RSP+0x50]  RBP
 *   [RSP+0x48]  RSI
 *   [RSP+0x40]  RDI
 *   [RSP+0x38]  R8
 *   [RSP+0x30]  R9
 *   [RSP+0x28]  R10
 *   [RSP+0x20]  R11
 *   [RSP+0x18]  R12
 *   [RSP+0x10]  R13
 *   [RSP+0x08]  R14
 *   [RSP+0x00]  R15   (pushed last = lowest address)
 *
 * This matches the layout of gr_vmx_guest_ctx_t in vmx_exit.h.
 * ═══════════════════════════════════════════════════════════════════════════ */

.global gr_vmx_entry
.type   gr_vmx_entry, @function
gr_vmx_entry:
    /*
     * Save all general-purpose registers.
     * Order must match gr_vmx_guest_ctx_t exactly.
     */
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rax             /* placeholder for RSP (guest RSP is in VMCS) */
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15

    /*
     * First argument (RDI) = pointer to the saved context on the stack.
     * This is a gr_vmx_guest_ctx_t* that the C handler can read/write.
     */
    mov     rdi, rsp

    /*
     * VMScape mitigation (CVE-2025-40300): flush indirect branch predictor
     * on every VM-exit to prevent Spectre-based guest→host leakage.
     * IBPB = Indirect Branch Prediction Barrier via IA32_PRED_CMD MSR.
     * Cost: ~30-50 cycles.  Required on AMD Zen 1-5 and Intel Coffee Lake+.
     */
    mov     ecx, 0x49           /* IA32_PRED_CMD */
    xor     edx, edx
    mov     eax, 1              /* IBPB = bit 0 */
    wrmsr

    /*
     * TSA mitigation (CVE-2024-36350, AMD Zen 3/4, July 2025):
     * Transient Scheduler Attacks — CPU may execute dependent ops
     * with stale data during transient windows.  VERW clears CPU
     * buffers on privilege transition.  Required on AMD Zen 3/4.
     * Cost: ~20-30 cycles.  Harmless no-op on Intel.
     */
    sub     rsp, 8
    mov     word ptr [rsp], ds  /* any valid selector for VERW */
    verw    word ptr [rsp]
    add     rsp, 8

    /*
     * FPU/SSE/AVX state: we do NOT save/restore on every VM-exit.
     *
     * Rationale (ACRN design + audit round 5): our C exit handler is
     * compiled with -mno-sse -mno-avx -msoft-float, so it never touches
     * XMM/YMM/ZMM registers.  Saving XSAVE state costs 200-600 cycles
     * per exit — wasted for a handler that only does integer math.
     *
     * If a future handler needs FPU (e.g., AES-NI for hashing), add
     * XSAVEC/XRSTORC around that specific call, not globally.
     *
     * Guest FPU state is preserved because the CPU does not modify
     * XMM/YMM registers during VM-exit — they stay as the guest left them.
     */

    /* Call C exit handler.  RSP is 16-byte aligned (16 pushes = 128 bytes).
     * CALL pushes 8 bytes → callee sees RSP%16 == 8, correct per ABI. */
    call    gr_vmx_handle_exit

.Lrestore_gprs:
    /*
     * Restore all GPRs from the (possibly modified) context.
     */
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8          /* skip RSP placeholder */
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax

    /*
     * Re-enter guest via VMRESUME.
     * If VMRESUME succeeds, execution continues in the guest and we
     * never reach the next instruction.
     */
    vmresume

    /*
     * If we get here, VMRESUME failed.  Call the fatal error handler.
     * This function does not return.
     */
    call    gr_vmx_resume_failed

.size gr_vmx_entry, . - gr_vmx_entry


/* ═══════════════════════════════════════════════════════════════════════════
 * gr_vmx_launch — Execute VMLAUNCH and return error code on failure.
 *
 * Prototype: int gr_vmx_launch(void);
 * Returns:   0  — should never happen (success = guest is running)
 *            >0 — VM_INSTRUCTION_ERROR field value on failure
 * ═══════════════════════════════════════════════════════════════════════════ */

.global gr_vmx_launch
.type   gr_vmx_launch, @function
gr_vmx_launch:
    vmlaunch

    /*
     * If VMLAUNCH succeeds, the processor transfers to GUEST_RIP and
     * this code is never reached.  Reaching here means failure.
     *
     * Read VM_INSTRUCTION_ERROR (VMCS field 0x4400) to get the error.
     * VMCS encoding 0x4400 = VM_INSTRUCTION_ERROR.
     */
    mov     rcx, 0x4400
    vmread  rax, rcx        /* RAX = error code (return value) */
    ret

.size gr_vmx_launch, . - gr_vmx_launch


/* ═══════════════════════════════════════════════════════════════════════════
 * gr_vmx_vmxoff — Cleanly exit VMX root operation.
 *
 * Prototype: void gr_vmx_vmxoff(void);
 * ═══════════════════════════════════════════════════════════════════════════ */

.global gr_vmx_vmxoff
.type   gr_vmx_vmxoff, @function
gr_vmx_vmxoff:
    vmxoff
    ret

.size gr_vmx_vmxoff, . - gr_vmx_vmxoff


/* ═══════════════════════════════════════════════════════════════════════════
 * gr_vmx_restore_guest — Target of GUEST_RIP after successful VMLAUNCH.
 *
 * When VMLAUNCH succeeds, the processor begins executing non-root mode
 * code at this address.  In a thin hypervisor this simply returns to
 * the caller that initiated virtualisation, indicating success.
 *
 * Prototype: void gr_vmx_restore_guest(void);
 * ═══════════════════════════════════════════════════════════════════════════ */

.global gr_vmx_restore_guest
.type   gr_vmx_restore_guest, @function
gr_vmx_restore_guest:
    /*
     * Return 0 to the original caller of the launch sequence.
     * RAX = 0 signals success.
     */
    xor     eax, eax
    ret

.size gr_vmx_restore_guest, . - gr_vmx_restore_guest
