/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * svm_exit.c — #VMEXIT dispatcher for the GhostRing SVM backend.
 *
 * Handles CPUID, MSR, INVD, NPF (Nested Page Fault), VMRUN/VMLOAD/VMSAVE,
 * and VMMCALL exits.  All other exits are treated as unexpected and trigger
 * a fatal stop.
 *
 * Reference: AMD APM Vol. 2, Chapter 15, Section 15.6 ("#VMEXIT").
 */

#include "svm_exit.h"
#include "../monitor/monitor.h"
#include "../hypercall/hypercall.h"

/* -- Intrinsics ----------------------------------------------------------- */

static inline void gr_cpuid_svm(uint32_t leaf, uint32_t subleaf,
                                 uint32_t *eax, uint32_t *ebx,
                                 uint32_t *ecx, uint32_t *edx)
{
    __asm__ volatile("cpuid"
                     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                     : "a"(leaf), "c"(subleaf));
}

static inline uint64_t gr_rdmsr_exit(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void gr_wrmsr_exit(uint32_t msr, uint64_t val)
{
    uint32_t lo = (uint32_t)val;
    uint32_t hi = (uint32_t)(val >> 32);
    __asm__ volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

static inline void gr_wbinvd_svm(void)
{
    __asm__ volatile("wbinvd" ::: "memory");
}

/* -- GhostRing hypervisor CPUID signature --------------------------------- */

/* "GhRi" as a 4-byte signature packed into EAX for leaf 0x40000001 */
#define GHOSTRING_SIG_EAX   0x52684700  /* 'G', 'h', 'R', '\0' — "GhR\0" */
#define GHOSTRING_SIG_EBX   0x69       /* 'i' */
#define GHOSTRING_SIG_ECX   0x00
#define GHOSTRING_SIG_EDX   0x00

/* -- Advance guest RIP using NRIP ----------------------------------------- */

/*
 * SVM provides the Next RIP (NRIP) in the VMCB control area at offset 0xC8.
 * This eliminates the need to decode instruction length manually.
 * See APM Vol. 2, Section 15.7.1 ("State Saved on Exit").
 */
static inline void
advance_guest_rip(uint8_t *vmcb)
{
    uint64_t nrip = gr_vmcb_read64(vmcb, VMCB_CTRL_NRIP);
    gr_vmcb_write64(vmcb, VMCB_STATE_RIP, nrip);
}

/* =========================================================================
 * Individual exit handlers
 * ========================================================================= */

/*
 * CPUID handler — Execute CPUID on the host CPU, then patch specific
 * leaves to advertise hypervisor presence.
 * See APM Vol. 3, "CPUID — CPU Identification".
 */
static void
handle_cpuid(uint8_t *vmcb, gr_svm_guest_ctx_t *ctx)
{
    uint32_t leaf    = (uint32_t)ctx->rax;
    uint32_t subleaf = (uint32_t)ctx->rcx;
    uint32_t eax, ebx, ecx, edx;

    gr_cpuid_svm(leaf, subleaf, &eax, &ebx, &ecx, &edx);

    switch (leaf) {
    case 1:
        /*
         * Set the hypervisor-present bit (ECX bit 31) so that guest OS
         * knows it is running under a hypervisor.
         */
        ecx |= HYPERV_HYPERVISOR_PRESENT_BIT;
        break;

    case HYPERV_CPUID_VENDOR_AND_MAX:
        /*
         * Report maximum hypervisor CPUID leaf and vendor signature.
         * "GhRi" = GhostRing.
         */
        eax = HYPERV_CPUID_INTERFACE;   /* Max leaf */
        ebx = 0x52684700;  /* "GhR\0" */
        ecx = 0x676E6900;  /* "ing\0" */
        edx = 0x00000000;
        break;

    case HYPERV_CPUID_INTERFACE:
        /* Return the GhostRing interface signature */
        eax = GHOSTRING_SIG_EAX;
        ebx = GHOSTRING_SIG_EBX;
        ecx = GHOSTRING_SIG_ECX;
        edx = GHOSTRING_SIG_EDX;
        break;

    default:
        break;
    }

    ctx->rax = eax;
    ctx->rbx = ebx;
    ctx->rcx = ecx;
    ctx->rdx = edx;

    /*
     * RAX is stored in both the GPR context and the VMCB state save area.
     * Update the VMCB copy as well so VMRUN restores the correct value.
     */
    gr_vmcb_write64(vmcb, VMCB_STATE_RAX, eax);

    advance_guest_rip(vmcb);
}

/*
 * INVD handler — INVD invalidates caches without writing back.
 * We execute WBINVD instead to maintain cache coherence.
 * See APM Vol. 3, "INVD — Invalidate Internal Caches".
 */
static void
handle_invd(uint8_t *vmcb, gr_svm_guest_ctx_t *ctx)
{
    (void)ctx;
    gr_wbinvd_svm();
    advance_guest_rip(vmcb);
}

/*
 * RDMSR handler — execute on host and return result to guest.
 * See APM Vol. 3, "RDMSR — Read from Model Specific Register".
 *
 * exit_info1 = 0 for RDMSR, 1 for WRMSR.
 * See APM Vol. 2, Section 15.11.
 */
static void
handle_rdmsr(uint8_t *vmcb, gr_svm_guest_ctx_t *ctx)
{
    uint32_t msr = (uint32_t)ctx->rcx;
    uint64_t val = gr_rdmsr_exit(msr);

    ctx->rax = (uint32_t)(val);
    ctx->rdx = (uint32_t)(val >> 32);

    /* Update RAX in the VMCB state save area */
    gr_vmcb_write64(vmcb, VMCB_STATE_RAX, ctx->rax);

    advance_guest_rip(vmcb);
}

/*
 * WRMSR handler — route through MSR guard before writing.
 *
 * Critical security path: rootkits modify LSTAR to hijack syscall entry.
 * The MSR guard validates the write and blocks unauthorized changes.
 * If blocked, we inject #GP(0) into the guest.
 * See APM Vol. 2, Section 15.11 ("MSR Intercepts").
 */
static void
handle_wrmsr(uint8_t *vmcb, gr_svm_guest_ctx_t *ctx)
{
    uint32_t msr = (uint32_t)ctx->rcx;
    uint64_t val = ((uint64_t)(uint32_t)ctx->rdx << 32) |
                   (uint32_t)ctx->rax;

    uint64_t guest_rip = gr_vmcb_read64(vmcb, VMCB_STATE_RIP);
    uint64_t guest_cr3 = gr_vmcb_read64(vmcb, VMCB_STATE_CR3);

    if (!gr_monitor_msr_write(NULL, msr, val, guest_rip, guest_cr3)) {
        /*
         * Inject #GP(0): vector 13, exception type, error code = 0.
         * SVM event injection format (APM Vol. 2, Section 15.20):
         *   Bits 7:0  = vector (13 = #GP)
         *   Bits 10:8 = type (3 = exception)
         *   Bit 11    = error code valid (1)
         *   Bit 31    = valid (1)
         */
        gr_vmcb_write64(vmcb, VMCB_CTRL_EVENT_INJECTION,
                        (13u) | (3u << 8) | (1u << 11) | (1u << 31));
        gr_vmcb_write32(vmcb, VMCB_CTRL_EVENT_INJECTION + 4, 0); /* error code */
        /* Do NOT advance RIP — guest sees #GP at faulting instruction */
        return;
    }

    gr_wrmsr_exit(msr, val);
    advance_guest_rip(vmcb);
}

/*
 * NPF (Nested Page Fault) handler — dispatch to the monitor subsystem.
 * See APM Vol. 2, Section 15.25.6.
 *
 * exit_info1 = error code (P/W/U/RSV/ID bits).
 * exit_info2 = faulting guest physical address.
 */
/*
 * NPF action codes — must match VMX EPT handler for symmetry.
 */
#define GR_NPF_ALLOW  0
#define GR_NPF_BLOCK  1
#define GR_NPF_LOG    2

static void
handle_npf(uint8_t *vmcb, gr_svm_guest_ctx_t *ctx)
{
    (void)ctx;

    uint64_t error_code = gr_vmcb_read64(vmcb, VMCB_CTRL_EXIT_INFO1);
    uint64_t gpa        = gr_vmcb_read64(vmcb, VMCB_CTRL_EXIT_INFO2);

    uint64_t guest_rip = gr_vmcb_read64(vmcb, VMCB_STATE_RIP);
    uint64_t guest_cr3 = gr_vmcb_read64(vmcb, VMCB_STATE_CR3);
    uint32_t access = (uint32_t)(error_code & 0x7);

    int action = gr_monitor_ept_violation(NULL, gpa, access, guest_rip, guest_cr3);

    if (action == GR_NPF_BLOCK) {
        /*
         * Inject #GP(0) to deny the access — symmetric with VMX EPT handler.
         * SVM event injection: vector=13, type=3 (exception), EV=1, V=1.
         */
        gr_vmcb_write64(vmcb, VMCB_CTRL_EVENT_INJECTION,
                        (13u) | (3u << 8) | (1u << 11) | (1u << 31));
        gr_vmcb_write32(vmcb, VMCB_CTRL_EVENT_INJECTION + 4, 0);
    }
    /* ALLOW/LOG: monitor already relaxed NPT permissions, guest retries. */
}

/*
 * VMRUN / VMLOAD / VMSAVE handler — Inject #UD to block nested SVM.
 * These instructions should not succeed inside a GhostRing guest.
 * See APM Vol. 2, Section 15.20.
 */
static void
handle_svm_instruction(uint8_t *vmcb, gr_svm_guest_ctx_t *ctx)
{
    (void)ctx;

    /*
     * Inject a #UD (Undefined Opcode, vector 6) exception.
     * The event_injection field format:
     *   Bits 7:0   = vector
     *   Bits 10:8  = type (3 = exception)
     *   Bit 11     = error code valid
     *   Bit 31     = valid
     *
     * See APM Vol. 2, Section 15.20.
     */
    gr_vmcb_write64(vmcb, VMCB_CTRL_EVENT_INJECTION,
                    SVM_INJECT_EXCEPTION(EXCEPTION_UD));

    /* Do NOT advance RIP — the exception handler will deal with it */
}

/*
 * VMMCALL handler — dispatch to the GhostRing hypercall subsystem.
 * See APM Vol. 3, "VMMCALL — Call VMM".
 */
static void
handle_vmmcall(uint8_t *vmcb, gr_svm_guest_ctx_t *ctx)
{
    gr_hypercall_dispatch_svm(ctx);

    /* Update RAX in VMCB in case the hypercall modified it */
    gr_vmcb_write64(vmcb, VMCB_STATE_RAX, ctx->rax);

    advance_guest_rip(vmcb);
}

/*
 * CR0 write handler — Selective CR0 write intercept for monitoring.
 * For now, pass through (the new CR0 value is in exit_info1).
 * See APM Vol. 2, Section 15.9.
 */
static void
handle_cr0_write(uint8_t *vmcb, gr_svm_guest_ctx_t *ctx)
{
    (void)ctx;

    /*
     * The new CR0 value is in exit_info1 for CR write intercepts
     * when CR0_WRITE_TRAP is used, otherwise it is a register-based
     * move and we simply advance RIP.
     */
    advance_guest_rip(vmcb);
}

/* =========================================================================
 * gr_svm_handle_exit — Main #VMEXIT dispatcher
 * See APM Vol. 2, Section 15.6.
 * ========================================================================= */

void
gr_svm_handle_exit(gr_svm_vcpu_t *vcpu, gr_svm_guest_ctx_t *ctx)
{
    uint8_t *vmcb = vcpu->vmcb;

    /*
     * Read the exit code from the VMCB control area.
     * See APM Vol. 2, Appendix C.
     */
    uint64_t exit_code = gr_vmcb_read64(vmcb, VMCB_CTRL_EXIT_CODE);

    switch ((int)exit_code) {
    /*
     * Exception/NMI intercept — re-inject into the guest.
     * SVM intercepts exceptions via the INTERCEPT_EXCEPTIONS bitmap.
     * NMIs (vector 2) must be re-injected or the guest's watchdog/perf
     * handlers never fire.  See APM Vol. 2, Section 15.12.
     */
    case VMEXIT_EXCP_NMI: {
        uint64_t exit_info1 = gr_vmcb_read64(vmcb, VMCB_CTRL_EXIT_INFO1);
        uint32_t vector = (uint32_t)(exit_code - VMEXIT_EXCP_DE);

        if (vector == 2) {
            /* NMI: re-inject. Type=2 (NMI), vector=2, valid=1. */
            gr_vmcb_write64(vmcb, VMCB_CTRL_EVENT_INJECTION,
                            (2u) | (2u << 8) | (1u << 31));
        } else {
            /* Other intercepted exceptions: re-inject with error code if present */
            uint64_t inject = (uint64_t)vector | (3u << 8) | (1u << 31);
            /* Vectors 8,10-14,17,21,29,30 deliver error codes */
            if (vector == 8 || (vector >= 10 && vector <= 14) ||
                vector == 17 || vector == 21 || vector == 29 || vector == 30) {
                inject |= (1u << 11);  /* error code valid */
                gr_vmcb_write32(vmcb, VMCB_CTRL_EVENT_INJECTION + 4,
                                (uint32_t)exit_info1);
            }
            gr_vmcb_write64(vmcb, VMCB_CTRL_EVENT_INJECTION, inject);
        }
        /* Do NOT advance RIP for exceptions/NMIs */
        return;
    }

    case VMEXIT_CPUID:
        handle_cpuid(vmcb, ctx);
        break;

    case VMEXIT_MSR:
        /*
         * exit_info1 = 0 for RDMSR, 1 for WRMSR.
         * See APM Vol. 2, Section 15.11.
         */
        if (gr_vmcb_read64(vmcb, VMCB_CTRL_EXIT_INFO1) == 0)
            handle_rdmsr(vmcb, ctx);
        else
            handle_wrmsr(vmcb, ctx);
        break;

    case VMEXIT_INVD:
        handle_invd(vmcb, ctx);
        break;

    case VMEXIT_NPF:
        handle_npf(vmcb, ctx);
        break;

    case VMEXIT_VMRUN:
    case VMEXIT_VMLOAD:
    case VMEXIT_VMSAVE:
        handle_svm_instruction(vmcb, ctx);
        break;

    case VMEXIT_VMMCALL:
        handle_vmmcall(vmcb, ctx);
        break;

    case VMEXIT_CR0_WRITE:
        handle_cr0_write(vmcb, ctx);
        break;

    default:
        /*
         * Unexpected exit code — this is a bug or unimplemented path.
         * In a production hypervisor we would inject a #UD or triple-fault.
         * For now, halt in an infinite loop so debugging is straightforward.
         */
        for (;;)
            __asm__ volatile("hlt");
        break;
    }

    /*
     * Clear the VMCB clean bits before re-entering the guest.
     * In a future optimisation we would set individual clean bits
     * based on which fields were actually modified.
     */
    gr_vmcb_write64(vmcb, VMCB_CTRL_VMCB_CLEAN_BITS, 0);
}
