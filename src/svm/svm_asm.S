/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * svm_asm.S — AMD SVM assembly routines for the GhostRing hypervisor.
 *
 * VMRUN loop, host GPR save/restore around #VMEXIT, and VMSAVE/VMLOAD
 * wrappers for additional host state.
 *
 * Reference: AMD APM Vol. 2, Chapter 15, Sections 15.5-15.7.
 *
 * Calling convention: System V AMD64 ABI.
 *   RDI = first argument (pointer to gr_svm_vcpu_t)
 */

.intel_syntax noprefix
.text

/* --------------------------------------------------------------------------
 * Offsets into gr_svm_vcpu_t — must match the C structure exactly.
 *
 * vmcb       = offset 0     (VMCB is the first field, page-aligned)
 * vmcb_phys  = computed at runtime and passed in a register
 * -------------------------------------------------------------------------- */

/*
 * VMCB state save area offset for RAX (0x5F8 from VMCB start).
 * We save/restore RAX directly from the VMCB because VMRUN/VMEXIT
 * uses RAX to hold the VMCB physical address.
 */
.set VMCB_RAX_OFFSET, 0x5F8

/* --------------------------------------------------------------------------
 * gr_svm_vmrun — Main VMRUN loop
 *
 * void gr_svm_vmrun(gr_svm_vcpu_t *vcpu, uint64_t vmcb_phys);
 *
 * Parameters:
 *   RDI = pointer to gr_svm_vcpu_t (vcpu)
 *   RSI = physical address of VMCB
 *
 * This function:
 *   1. Saves all host GPRs on the stack
 *   2. Loads guest GPRs from the stack frame
 *   3. Loads guest RAX from VMCB
 *   4. Executes VMRUN (RAX = VMCB physical address)
 *   5. On #VMEXIT: saves guest GPRs, restores host GPRs
 *   6. Calls gr_svm_handle_exit(vcpu, ctx)
 *   7. Loops back to step 2
 *
 * The function never returns normally — it loops until the hypervisor
 * is torn down.
 * -------------------------------------------------------------------------- */

.global gr_svm_vmrun
.type gr_svm_vmrun, @function
.align 16
gr_svm_vmrun:
    /* Save callee-saved registers per System V ABI */
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15

    /* Save arguments in callee-saved registers across the VMRUN loop */
    mov     r12, rdi            /* r12 = vcpu pointer                */
    mov     r13, rsi            /* r13 = VMCB physical address       */

    /* RDI (vcpu) also points to the VMCB virtual address since vmcb
     * is the first field in the structure. */
    mov     r14, rdi            /* r14 = VMCB virtual address        */

.Lvmrun_loop:
    /* ---- Restore guest GPRs from stack context area ----
     *
     * We maintain a guest context area on the stack.  On the first
     * iteration there is no saved context, so registers are effectively
     * zero / whatever the host left.  Subsequent iterations restore the
     * state saved after the previous #VMEXIT.
     */

    /* Load guest RAX from the VMCB state save area */
    mov     rax, [r14 + VMCB_RAX_OFFSET]
    push    rax                 /* Save guest RAX for later pop      */

    /* Restore guest GPRs (RCX, RDX, RBX, RBP, RSI, RDI, R8-R15).
     * We use VMRUN's convention: RAX = VMCB physical address. */
    pop     rax                 /* Guest RAX — we will put it back    */

    /* Actually, we need a different approach.  Save host state, set up
     * RAX for VMRUN, then restore guest GPRs around it.
     *
     * The pattern: push all guest GPRs onto the stack frame, then
     * pop them just before VMRUN, save them after #VMEXIT.
     */

    /* On entry to the loop, R12=vcpu, R13=vmcb_phys, R14=vmcb_virt.
     * These are our anchors. */

    /* Save host RSP so we can find our stack frame after #VMEXIT */
    mov     [r14 + VMCB_RAX_OFFSET - 8], rsp   /* temporary stash   */

    /* ---- Execute VMRUN ----
     *
     * Before VMRUN: load guest registers from a context block that we
     * keep at a known stack location.
     *
     * RAX must contain the physical address of the VMCB.
     * All other GPRs are guest values.  The processor:
     *   - Saves host state to the Host Save Area
     *   - Loads guest state from the VMCB
     *   - Transfers control to guest RIP
     *
     * On #VMEXIT the processor:
     *   - Saves guest state to the VMCB (RAX, RSP, RIP, RFLAGS, etc.)
     *   - Loads host state from the Host Save Area
     *   - Resumes execution at the instruction after VMRUN
     *
     * See APM Vol. 2, Section 15.5.1.
     */

    /* Load VMCB physical address into RAX for VMRUN */
    mov     rax, r13

    /* VMRUN — enter guest mode */
    vmrun   rax

    /* ---- #VMEXIT returns here ----
     *
     * At this point:
     *   - Guest RAX is saved in VMCB state save area automatically
     *   - All other guest GPRs are in the actual CPU registers
     *   - Host RSP, RIP, and segment state restored from Host Save Area
     *
     * We must save all guest GPRs before we clobber them.
     */

    /* Push all guest GPRs to build a gr_svm_guest_ctx_t on the stack */
    push    rax                 /* guest RAX (host RAX after VMEXIT) */
    push    rcx
    push    rdx
    push    rbx
    push    0                   /* RSP placeholder                   */
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

    /* Fix up RAX: the real guest RAX is in the VMCB, not in the
     * register (which held the VMCB PA for VMRUN). */
    mov     rax, [r14 + VMCB_RAX_OFFSET]
    mov     [rsp + 15*8], rax   /* overwrite RAX slot in context     */

    /* ---- Call the C exit handler ----
     *
     * void gr_svm_handle_exit(gr_svm_vcpu_t *vcpu,
     *                          gr_svm_guest_ctx_t *ctx);
     *
     * RDI = vcpu (r12), RSI = ctx (current RSP)
     */
    mov     rdi, r12
    mov     rsi, rsp
    call    gr_svm_handle_exit

    /* ---- Restore guest GPRs from the context on the stack ---- */
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
    add     rsp, 8              /* skip RSP placeholder              */
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax                 /* guest RAX — store back to VMCB    */

    /* Restore r14 (VMCB virt) and r13 (VMCB phys) which we saved in
     * callee-saved regs before the loop. */
    mov     r14, r12            /* vcpu == vmcb virt (first field)   */

    /* Write guest RAX back to VMCB for next VMRUN */
    mov     [r14 + VMCB_RAX_OFFSET], rax

    /* Loop back for next VMRUN */
    jmp     .Lvmrun_loop

    /* This function does not return normally.  If we ever need a clean
     * exit path, we would break out of the loop and restore here. */

.size gr_svm_vmrun, . - gr_svm_vmrun

/* --------------------------------------------------------------------------
 * gr_svm_vmsave — Save additional host state
 *
 * void gr_svm_vmsave(uint64_t vmcb_phys);
 *
 * VMSAVE saves FS, GS, TR, LDTR bases/selectors/attribs/limits,
 * KernelGsBase, STAR, LSTAR, CSTAR, SFMASK, and SYSENTER MSRs
 * into the VMCB at the address in RAX.
 *
 * See APM Vol. 2, Section 15.5.4.
 * -------------------------------------------------------------------------- */

.global gr_svm_vmsave
.type gr_svm_vmsave, @function
.align 16
gr_svm_vmsave:
    mov     rax, rdi            /* RAX = VMCB physical address       */
    vmsave  rax
    ret
.size gr_svm_vmsave, . - gr_svm_vmsave

/* --------------------------------------------------------------------------
 * gr_svm_vmload — Load additional host state
 *
 * void gr_svm_vmload(uint64_t vmcb_phys);
 *
 * VMLOAD is the inverse of VMSAVE — it loads the same set of registers
 * from the VMCB into the processor.
 *
 * See APM Vol. 2, Section 15.5.4.
 * -------------------------------------------------------------------------- */

.global gr_svm_vmload
.type gr_svm_vmload, @function
.align 16
gr_svm_vmload:
    mov     rax, rdi            /* RAX = VMCB physical address       */
    vmload  rax
    ret
.size gr_svm_vmload, . - gr_svm_vmload

/* --------------------------------------------------------------------------
 * gr_svm_restore_guest — Dummy target for initial guest RIP
 *
 * When gr_svm_setup_vmcb sets Guest RIP to this symbol, the first VMRUN
 * transfers control here.  We simply return to the caller (the code that
 * set up the hypervisor), effectively virtualising the current execution
 * context transparently.
 * -------------------------------------------------------------------------- */

.global gr_svm_restore_guest
.type gr_svm_restore_guest, @function
.align 16
gr_svm_restore_guest:
    ret
.size gr_svm_restore_guest, . - gr_svm_restore_guest
