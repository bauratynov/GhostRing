;++
;
; GhostRing Hypervisor — Windows x64 Assembly Helpers
;
; Author:
;
;     Baurzhan Atynov <bauratynov@gmail.com>
;
; SPDX-License-Identifier: Apache-2.0
;
; Module:
;
;     ghostring_winasm.asm
;
; Abstract:
;
;     MASM x64 routines for context capture/restore, segment register
;     reads, and GDT/IDT table loads.  Pattern follows SimpleVisor.
;
; Environment:
;
;     Kernel mode only, AMD64.
;
;--

include ksamd64.inc

;; ---------------------------------------------------------------------------
;; void _str(PUINT16 TaskRegister)
;; Store the Task Register value.
;; ---------------------------------------------------------------------------
    LEAF_ENTRY _str, _TEXT$00
        str     word ptr [rcx]
        ret
    LEAF_END _str, _TEXT$00

;; ---------------------------------------------------------------------------
;; void _sldt(PUINT16 Ldtr)
;; Store the Local Descriptor Table Register value.
;; ---------------------------------------------------------------------------
    LEAF_ENTRY _sldt, _TEXT$00
        sldt    word ptr [rcx]
        ret
    LEAF_END _sldt, _TEXT$00

;; ---------------------------------------------------------------------------
;; void __lgdt(PVOID GdtBase)
;; Load the Global Descriptor Table Register from a GDTR structure.
;; ---------------------------------------------------------------------------
    LEAF_ENTRY __lgdt, _TEXT$00
        lgdt    fword ptr [rcx]
        ret
    LEAF_END __lgdt, _TEXT$00

;; ---------------------------------------------------------------------------
;; void GrVmxCleanup(UINT16 DataSelector, UINT16 TebSelector)
;; Restore DS/ES/FS segment selectors after VMX exit to prevent GPF in
;; WoW64 compatibility-mode threads (see SimpleVisor ShvVmxCleanup).
;; ---------------------------------------------------------------------------
    LEAF_ENTRY GrVmxCleanup, _TEXT$00
        mov     ds, cx
        mov     es, cx
        mov     fs, dx
        ret
    LEAF_END GrVmxCleanup, _TEXT$00

;; ---------------------------------------------------------------------------
;; void GrCaptureContext(PCONTEXT ContextRecord)
;; Wrapper around RtlCaptureContext.
;; ---------------------------------------------------------------------------
    NESTED_ENTRY GrCaptureContext, _TEXT$00
        END_PROLOGUE
        jmp     RtlCaptureContext
    NESTED_END GrCaptureContext, _TEXT$00

;; ---------------------------------------------------------------------------
;; void GrRestoreContext(PCONTEXT ContextRecord)
;; Restore full CPU context and resume execution.  Uses the SimpleVisor
;; pattern: restore all registers, push RFLAGS/RIP, then RET.
;; ---------------------------------------------------------------------------
    LEAF_ENTRY GrRestoreContext, _TEXT$00
        movaps  xmm0,  CxXmm0[rcx]
        movaps  xmm1,  CxXmm1[rcx]
        movaps  xmm2,  CxXmm2[rcx]
        movaps  xmm3,  CxXmm3[rcx]
        movaps  xmm4,  CxXmm4[rcx]
        movaps  xmm5,  CxXmm5[rcx]
        movaps  xmm6,  CxXmm6[rcx]
        movaps  xmm7,  CxXmm7[rcx]
        movaps  xmm8,  CxXmm8[rcx]
        movaps  xmm9,  CxXmm9[rcx]
        movaps  xmm10, CxXmm10[rcx]
        movaps  xmm11, CxXmm11[rcx]
        movaps  xmm12, CxXmm12[rcx]
        movaps  xmm13, CxXmm13[rcx]
        movaps  xmm14, CxXmm14[rcx]
        movaps  xmm15, CxXmm15[rcx]
        ldmxcsr CxMxCsr[rcx]

        mov     rax, CxRax[rcx]
        mov     rdx, CxRdx[rcx]
        mov     r8,  CxR8[rcx]
        mov     r9,  CxR9[rcx]
        mov     r10, CxR10[rcx]
        mov     r11, CxR11[rcx]

        mov     rbx, CxRbx[rcx]
        mov     rsi, CxRsi[rcx]
        mov     rdi, CxRdi[rcx]
        mov     rbp, CxRbp[rcx]
        mov     r12, CxR12[rcx]
        mov     r13, CxR13[rcx]
        mov     r14, CxR14[rcx]
        mov     r15, CxR15[rcx]

        cli
        push    CxEFlags[rcx]
        popfq
        mov     rsp, CxRsp[rcx]
        push    CxRip[rcx]
        mov     rcx, CxRcx[rcx]
        ret
    LEAF_END GrRestoreContext, _TEXT$00

    end
