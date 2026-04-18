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

    /*
     * Post-handler hook: if the handler observed the magic CPUID
     * devirtualisation request, gr_exit_vm_flag is set.  Bail out of
     * VMX entirely and return to the caller of gr_shutdown_cpu.  This
     * is what lets `rmmod ghostring` clean up without hanging CPU 0.
     */
    mov     eax, [rip + gr_exit_vm_flag]
    test    eax, eax
    jnz     .Lleave_vmx

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

.Lleave_vmx:
    /*
     * Devirtualisation path.
     *
     * The saved guest-GPR block from the VM-exit is at [rsp..+128].
     * We need to:
     *   1. Stash guest RIP/RSP/RFLAGS into static memory (because any
     *      registers we use now will be clobbered when we restore the
     *      guest GPRs below).
     *   2. Pop all 16 GPRs — the caller of gr_cpuid needs rdi/rsi/etc
     *      back at their pre-exit values or it writes the emulated
     *      CPUID result into garbage memory and crashes the kernel.
     *   3. VMXOFF.
     *   4. Switch to the guest's RSP, restore RFLAGS, jump to post-
     *      CPUID RIP — all via indirect memory reads so the registers
     *      stay as the guest expects.
     */
    mov     rcx, 0x681E           /* VMCS_GUEST_RIP    */
    vmread  rax, rcx
    mov     [rip + _gr_devirt_rip], rax
    mov     rcx, 0x681C           /* VMCS_GUEST_RSP    */
    vmread  rax, rcx
    mov     [rip + _gr_devirt_rsp], rax
    mov     rcx, 0x6820           /* VMCS_GUEST_RFLAGS */
    vmread  rax, rcx
    mov     [rip + _gr_devirt_rflags], rax

    /* Clear the flag so a subsequent load + shutdown cycle works. */
    mov     dword ptr [rip + gr_exit_vm_flag], 0

    /* Restore all 16 guest GPRs from the saved block on hv_stack.
     * rax/rcx/rdx were overwritten by the C handler with the CPUID
     * emulation result, so popping them gives the guest the values
     * it expected to see. */
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
    add     rsp, 8                /* skip RSP placeholder */
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax

    /* Leave VMX operation. */
    vmxoff

    /* Swap to the guest stack, restore its RFLAGS, jump to post-CPUID. */
    mov     rsp, [rip + _gr_devirt_rsp]
    push    qword ptr [rip + _gr_devirt_rflags]
    popfq
    jmp     qword ptr [rip + _gr_devirt_rip]

.size gr_vmx_entry, . - gr_vmx_entry

/* Static scratch cells used only by the .Lleave_vmx path.  They live in
 * .bss so the first-use value is zero.  Single-CPU devirtualisation,
 * so no locking is needed. */
.section .bss
.align 8
_gr_devirt_rip:     .quad 0
_gr_devirt_rsp:     .quad 0
_gr_devirt_rflags:  .quad 0
.text


/* ═══════════════════════════════════════════════════════════════════════════
 * gr_vmx_launch — Execute VMLAUNCH and return error code on failure.
 *
 * Prototype: int gr_vmx_launch(void);
 * Returns:   0  — should never happen (success = guest is running)
 *            >0 — VM_INSTRUCTION_ERROR field value on failure
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * gr_vmx_launch — Proper blue-pill VMLAUNCH.
 *
 * Before VMLAUNCH we write the CURRENT host RSP, RIP(=.Lresume) and
 * RFLAGS into VMCS_GUEST_{RSP,RIP,RFLAGS}.  The CPU therefore transitions
 * the current running thread into VMX non-root mode at the instruction
 * right after vmlaunch — same stack, same next instruction.  The caller
 * returns to its original caller as if VMLAUNCH never happened, except
 * the processor is now executing under our hypervisor's control.
 *
 * VMCS field encodings used directly here:
 *   VMCS_GUEST_RSP    = 0x681C
 *   VMCS_GUEST_RIP    = 0x681E
 *   VMCS_GUEST_RFLAGS = 0x6820
 *   VM_INSTRUCTION_ERROR (on failure) = 0x4400
 */
.global gr_vmx_launch
.type   gr_vmx_launch, @function
gr_vmx_launch:
    /* Save callee-saved registers — these become guest state once
     * VMLAUNCH succeeds, and restored from stack again on the way back. */
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    pushfq                       /* save RFLAGS on stack */

    /* Write guest RSP = current host RSP (stack is identical). */
    mov     rcx, 0x681C
    vmwrite rcx, rsp

    /* Write guest RIP = label .Lresume — the CPU jumps here as guest. */
    lea     rax, [rip + .Lresume]
    mov     rcx, 0x681E
    vmwrite rcx, rax

    /* Write guest RFLAGS = currently saved RFLAGS (top of stack). */
    mov     rax, [rsp]
    mov     rcx, 0x6820
    vmwrite rcx, rax

    vmlaunch
    /*
     * VMLAUNCH success => CPU jumps to .Lresume (below) already in
     * non-root mode, execution continues transparently.
     *
     * VMLAUNCH failure => falls through to the error path; read
     * VM_INSTRUCTION_ERROR and pop state for a normal C return.
     */
    mov     rcx, 0x4400
    vmread  rax, rcx             /* RAX = non-zero error code */
    jmp     .Lreturn

.Lresume:
    /* Guest resumes here.  RSP points at our saved RFLAGS (since we
     * wrote RSP into VMCS_GUEST_RSP just before vmlaunch).  popfq/pops
     * below will unwind the stack exactly as a C-callable function. */
    xor     eax, eax             /* return 0 on success */

.Lreturn:
    popfq
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
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
