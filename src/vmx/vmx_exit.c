/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * vmx_exit.c — VM-exit dispatcher for the GhostRing VMX backend.
 *
 * Handles CPUID, MSR, INVD, XSETBV, VMX instruction, EPT violation,
 * and VMCALL exits.  All other exits are treated as unexpected and
 * trigger a fatal stop.
 *
 * Reference: Intel SDM Vol. 3C, Chapter 27 ("VM Exits").
 */

#include "vmx_exit.h"
#include "../monitor/monitor.h"
#include "../hypercall/hypercall.h"

/* ── VMX-specific intrinsics (VMREAD/VMWRITE not in common/cpu.h) ───── */

static inline uint64_t gr_vmread(uint64_t field)
{
    uint64_t value;
    __asm__ volatile("vmread %[field], %[val]"
                     : [val] "=r"(value)
                     : [field] "r"(field)
                     : "cc");
    return value;
}

static inline void gr_vmwrite_exit(uint64_t field, uint64_t value)
{
    __asm__ volatile("vmwrite %[val], %[field]"
                     :
                     : [field] "r"(field), [val] "rm"(value)
                     : "cc", "memory");
}

static inline void gr_xsetbv(uint32_t index, uint64_t val)
{
    uint32_t lo = (uint32_t)val;
    uint32_t hi = (uint32_t)(val >> 32);
    __asm__ volatile("xsetbv" : : "c"(index), "a"(lo), "d"(hi));
}

/* Aliases to common/cpu.h for readability */
#define gr_cpuid_exit(l, s, a, b, c, d)  gr_cpuid(l, s, a, b, c, d)
#define gr_rdmsr_exit(msr)               gr_rdmsr(msr)
#define gr_wrmsr_exit(msr, val)          gr_wrmsr(msr, val)

/* ── GhostRing hypervisor CPUID signature ──────────────────────────────── */

/* "GhRi" as a 4-byte signature packed into EAX for leaf 0x40000001 */
#define GHOSTRING_SIG_EAX   0x52684700  /* 'G', 'h', 'R', '\0' — "GhR\0" */
#define GHOSTRING_SIG_EBX   0x69       /* 'i' */
#define GHOSTRING_SIG_ECX   0x00
#define GHOSTRING_SIG_EDX   0x00

/* ── Advance guest RIP past the faulting instruction ───────────────────── */

static inline void
advance_guest_rip(void)
{
    uint64_t len = gr_vmread(VMCS_EXIT_INSTRUCTION_LEN);
    uint64_t rip = gr_vmread(VMCS_GUEST_RIP);
    gr_vmwrite_exit(VMCS_GUEST_RIP, rip + len);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Individual exit handlers
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * CPUID handler — Execute CPUID on the host CPU, then patch specific
 * leaves to advertise hypervisor presence.
 * See SDM Vol. 2A, "CPUID — CPU Identification".
 */
static void
handle_cpuid(gr_vmx_guest_ctx_t *ctx)
{
    uint32_t leaf    = (uint32_t)ctx->rax;
    uint32_t subleaf = (uint32_t)ctx->rcx;
    uint32_t eax, ebx, ecx, edx;

    gr_cpuid_exit(leaf, subleaf, &eax, &ebx, &ecx, &edx);

    /*
     * Magic CPUID leaf — the devirtualisation request.  Set the
     * gr_exit_vm_flag; the asm post-processing will VMXOFF and return
     * control to the caller of gr_shutdown_cpu.  We still echo the
     * normal CPUID behaviour back to the guest so the instruction
     * doesn't observe weird state before we unwind.
     */
    if (leaf == 0x47520001 && subleaf == 0x47520001) {
        gr_exit_vm_flag = 1;
        GR_LOG_STR("vmx_exit: magic CPUID — leaving VMX root");
    }

    switch (leaf) {
    case 1:
        /*
         * Set the hypervisor-present bit (ECX bit 31) so that guest OS
         * knows it is running under a hypervisor.
         * See SDM Vol. 2A, Table 3-8.
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

    advance_guest_rip();
}

/*
 * INVD handler — INVD invalidates caches without writing back.
 * We execute WBINVD instead to maintain cache coherence.
 * See SDM Vol. 2A, "INVD — Invalidate Internal Caches".
 */
static void
handle_invd(gr_vmx_guest_ctx_t *ctx)
{
    (void)ctx;
    gr_wbinvd();
    advance_guest_rip();
}

/*
 * XSETBV handler — pass through the XSETBV instruction.
 * See SDM Vol. 2B, "XSETBV — Set Extended Control Register".
 */
static void
handle_xsetbv(gr_vmx_guest_ctx_t *ctx)
{
    uint32_t index = (uint32_t)ctx->rcx;
    uint64_t value = ((uint64_t)(uint32_t)ctx->rdx << 32) |
                     (uint32_t)ctx->rax;
    gr_xsetbv(index, value);
    advance_guest_rip();
}

/*
 * VMX instruction handler — Set CF=1 in guest RFLAGS to indicate failure.
 * This prevents nested VMX from succeeding when running under GhostRing.
 * See SDM Vol. 3C, Section 30.2.
 */
static void
handle_vmx_instruction(gr_vmx_guest_ctx_t *ctx)
{
    (void)ctx;

    uint64_t rflags = gr_vmread(VMCS_GUEST_RFLAGS);
    rflags |= BIT(0);  /* CF = 1 (VMfailInvalid) */
    rflags &= ~BIT(6); /* Clear ZF */
    gr_vmwrite_exit(VMCS_GUEST_RFLAGS, rflags);

    advance_guest_rip();
}

/*
 * EPT violation handler — dispatch to the monitor subsystem.
 *
 * The monitor returns an action code:
 *   GR_EPT_ALLOW  — relax EPT permissions so the access succeeds on retry
 *   GR_EPT_BLOCK  — inject #GP(0) to deny the access
 *   GR_EPT_LOG    — log but allow (single-shot permission relax)
 *
 * In all cases we do NOT advance RIP — the faulting instruction is either
 * retried (allow/log) or receives the injected exception (block).
 *
 * See SDM Vol. 3C, Section 28.2.3 for EPT violation exit qualification.
 */
#define GR_EPT_ALLOW  0
#define GR_EPT_BLOCK  1
#define GR_EPT_LOG    2

static void
handle_ept_violation(gr_vmx_guest_ctx_t *ctx)
{
    (void)ctx;

    uint64_t gpa  = gr_vmread(VMCS_GUEST_PHYS_ADDR);
    uint64_t qual = gr_vmread(VMCS_EXIT_QUALIFICATION);

    uint64_t guest_rip = gr_vmread(VMCS_GUEST_RIP);
    uint64_t guest_cr3 = gr_vmread(VMCS_GUEST_CR3);
    uint32_t access = (uint32_t)(qual & 0x7); /* R/W/X bits */

    int action = gr_monitor_ept_violation(NULL, gpa, access, guest_rip, guest_cr3);

    if (action == GR_EPT_BLOCK) {
        /*
         * Inject #GP(0) into the guest to signal access denied.
         * This is the correct response for a write to a protected
         * kernel code page — the guest driver/rootkit will see a
         * general protection fault at the faulting RIP.
         *
         * Injection encoding: vector=13, type=3 (HW exception),
         * deliver error code, valid bit.
         */
        gr_vmwrite_exit(VMCS_ENTRY_INTR_INFO,
                        (13u) | (3u << 8) | (1u << 11) | (1u << 31));
        gr_vmwrite_exit(VMCS_ENTRY_EXCEPTION_ERROR_CODE, 0);
    }
    /* ALLOW and LOG: monitor already relaxed EPT permissions.
     * Guest retries the access and it succeeds. */
}

/*
 * RDMSR handler — execute on host and return result to guest.
 * See SDM Vol. 2B, "RDMSR — Read from Model Specific Register".
 */
static void
handle_rdmsr(gr_vmx_guest_ctx_t *ctx)
{
    uint32_t msr = (uint32_t)ctx->rcx;
    uint64_t val = gr_rdmsr_exit(msr);

    ctx->rax = (uint32_t)(val);
    ctx->rdx = (uint32_t)(val >> 32);

    advance_guest_rip();
}

/*
 * WRMSR handler — route through MSR guard before writing.
 *
 * Critical security path: rootkits modify LSTAR to hijack syscall entry.
 * The MSR guard validates the write and blocks unauthorized changes.
 * If blocked, we inject #GP(0) into the guest instead of executing the
 * write.  See SDM Vol. 3C, Section 25.1.3 for event injection format.
 */
static void
handle_wrmsr(gr_vmx_guest_ctx_t *ctx)
{
    uint32_t msr = (uint32_t)ctx->rcx;
    uint64_t val = ((uint64_t)(uint32_t)ctx->rdx << 32) |
                   (uint32_t)ctx->rax;

    /*
     * Check with the MSR guard.  If the write is denied, inject #GP(0)
     * into the guest rather than silently dropping the write — the guest
     * OS expects either success or an exception.
     */
    uint64_t guest_rip = gr_vmread(VMCS_GUEST_RIP);
    uint64_t guest_cr3 = gr_vmread(VMCS_GUEST_CR3);

    if (!gr_monitor_msr_write(NULL, msr, val, guest_rip, guest_cr3)) {
        /*
         * Inject #GP(0): vector 13, type 3 (hardware exception),
         * deliver error code, valid.
         * Encoding: [31] Valid | [11] Deliver error | [10:8] Type=3 | [7:0] Vector=13
         */
        gr_vmwrite_exit(VMCS_ENTRY_INTR_INFO,
                        (13u) | (3u << 8) | (1u << 11) | (1u << 31));
        gr_vmwrite_exit(VMCS_ENTRY_EXCEPTION_ERROR_CODE, 0);
        /* Do NOT advance RIP — the faulting instruction is retried
         * and will see the injected #GP. */
        return;
    }

    gr_wrmsr_exit(msr, val);
    advance_guest_rip();
}

/*
 * VMCALL handler — dispatch to the GhostRing hypercall subsystem.
 * See SDM Vol. 3C, Section 24.1.
 */
/*
 * VMCALL handler — dispatch to the GhostRing hypercall subsystem.
 *
 * TODO: pass real monitor state and exit_vm flag from vcpu once
 * the glue layer is complete.  For now NULL/dummy to compile.
 */
static bool s_exit_vm = false;  /* per-CPU exit flag (temporary) */

static void
handle_vmcall(gr_vmx_guest_ctx_t *ctx)
{
    gr_hypercall_dispatch(ctx, NULL, &s_exit_vm);
    advance_guest_rip();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * gr_vmx_handle_exit — Main VM-exit dispatcher
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Demo / debug instrumentation: log the first N exits, and if exits
 * continue beyond a safety threshold, assume something is wrong and
 * emergency-VMXOFF so the host does not soft-lock. */
static uint64_t _gr_exit_count;

/*
 * Global "exit VMX" flag.  The handler sets this when it observes the
 * magic CPUID devirtualisation request; gr_vmx_entry in vmx_asm.S
 * checks this value after the C handler returns and, if non-zero,
 * jumps to a dedicated path that does VMXOFF and restores the guest
 * register state inline.  See gr_shutdown_cpu in glue.c.
 */
uint32_t gr_exit_vm_flag = 0;
#define GR_EXIT_LOG_LIMIT       20
#define GR_EXIT_SAFETY_LIMIT    10000

void
gr_vmx_handle_exit(gr_vmx_guest_ctx_t *ctx)
{
    /*
     * Read the basic exit reason (bits 15:0) from the VMCS.
     * Bit 31 indicates VM-entry failure — we mask it off for the switch.
     * See SDM Vol. 3C, Section 24.9.1.
     */
    uint32_t exit_reason = (uint32_t)gr_vmread(VMCS_EXIT_REASON) & 0xFFFF;

    /* Early-bring-up telemetry. */
    _gr_exit_count++;
    if (_gr_exit_count <= GR_EXIT_LOG_LIMIT) {
        uint64_t full_reason = gr_vmread(VMCS_EXIT_REASON);
        GR_LOG("vmx_exit: #", _gr_exit_count);
        GR_LOG("vmx_exit: reason_full=", full_reason);
        GR_LOG("vmx_exit: reason_basic=", (uint64_t)exit_reason);
        GR_LOG("vmx_exit: qualification=", gr_vmread(VMCS_EXIT_QUALIFICATION));
        GR_LOG("vmx_exit: rip=", gr_vmread(VMCS_GUEST_RIP));
        if (exit_reason == 33 || (full_reason & (1ULL << 31))) {
            /* VM-entry failure.  Per SDM Vol 3C 26.7, the qualification
             * encodes which guest state caused the rejection:
             *   1=CR3 target list
             *   2=guest MSR loading
             *   3=address of VMCS/descriptor area
             *   4=NMI injection
             * Plus full decode in the manual. */
            GR_LOG_STR("vmx_exit: INVALID GUEST STATE on VM entry");
            GR_LOG("vmx_exit: instr_error=", gr_vmread(0x4400));
        }
    }
    /* Safety limit removed — the hypervisor is expected to run
     * indefinitely and halting here would wedge the host CPU. */

    switch (exit_reason) {
    /*
     * Exception or NMI — re-inject into the guest unchanged.
     * NMIs that arrive during VM-exit handling cause an
     * EXIT_REASON_EXCEPTION_NMI exit.  We must re-inject them
     * or the guest's NMI handler never fires (watchdog timeout,
     * perf counter overflow, etc.).
     * See SDM Vol. 3C, Section 27.2.2.
     */
    case EXIT_REASON_EXCEPTION_NMI: {
        uint64_t intr_info = gr_vmread(VMCS_EXIT_INTR_INFO);
        uint32_t vector = (uint32_t)(intr_info & 0xFF);
        uint32_t type   = (uint32_t)((intr_info >> 8) & 0x7);

        if (type == 2 && vector == 2) {
            /* NMI: re-inject via VM-entry interrupt-information field.
             * Type=2 (NMI), Vector=2, Valid=1. */
            gr_vmwrite_exit(VMCS_ENTRY_INTR_INFO,
                            (2u) | (2u << 8) | (1u << 31));
        } else {
            /* Other exceptions: re-inject as-is */
            gr_vmwrite_exit(VMCS_ENTRY_INTR_INFO, (uint64_t)(uint32_t)intr_info);
            if (intr_info & BIT(11)) {
                /* Error code valid — forward it */
                uint64_t err = gr_vmread(VMCS_EXIT_INTR_ERROR_CODE);
                gr_vmwrite_exit(VMCS_ENTRY_EXCEPTION_ERROR_CODE, err);
            }
        }
        /* Do NOT advance RIP for exceptions/NMIs */
        return;
    }

    case EXIT_REASON_CPUID:
        handle_cpuid(ctx);
        break;

    case 12: /* EXIT_REASON_HLT */
        /*
         * Guest executed HLT.  Simplest strategy: just advance and
         * resume.  The guest's HLT intent is ignored (the CPU never
         * actually halts).  This burns CPU when the guest is idle but
         * leaves Linux's own ISRs free to run inside the guest, which
         * is what makes network / timer / sshd actually respond.
         * Running host-HLT here previously caused Linux ISRs to fire
         * in VMX root mode on our host stack — subtly wrong and
         * eventually stopped the network entirely.
         */
        advance_guest_rip();
        break;

    case 1: /* EXIT_REASON_EXTERNAL_INTERRUPT */
    {
        /*
         * With VM_EXIT_ACK_INTR_ON_EXIT set, the CPU has ACK'd the
         * interrupt controller and the vector is in VMCS_EXIT_INTR_INFO.
         * Re-inject it into the guest so its own IDT handler runs.
         * Without this, network / timer IRQs destined for guest user
         * space never get delivered and sshd / shells stall.
         */
        uint64_t intr_info = gr_vmread(VMCS_EXIT_INTR_INFO);
        if (intr_info & (1ULL << 31)) {                 /* valid bit */
            uint32_t vector = (uint32_t)(intr_info & 0xFF);
            /* Encode as external interrupt injection: type=0, valid=1. */
            gr_vmwrite_exit(VMCS_ENTRY_INTR_INFO,
                            (vector) | (0u << 8) | (1u << 31));
        }
        break;
    }

    case 7: /* EXIT_REASON_PENDING_INTERRUPT (aka INTERRUPT_WINDOW) */
        /* Unblock by clearing the interrupt-window exiting request —
         * but we never set it, so nothing to clear.  Just resume. */
        break;

    case EXIT_REASON_INVD:
        handle_invd(ctx);
        break;

    case EXIT_REASON_XSETBV:
        handle_xsetbv(ctx);
        break;

    /* All VMX instructions — fail with CF=1 */
    case EXIT_REASON_VMCALL:
        handle_vmcall(ctx);
        break;

    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
    case EXIT_REASON_INVEPT:
    case EXIT_REASON_INVVPID:
        handle_vmx_instruction(ctx);
        break;

    case EXIT_REASON_EPT_VIOLATION:
        handle_ept_violation(ctx);
        break;

    case EXIT_REASON_MSR_READ:
        handle_rdmsr(ctx);
        break;

    case EXIT_REASON_MSR_WRITE:
        handle_wrmsr(ctx);
        break;

    /*
     * EPT misconfiguration — our EPT entry is malformed.
     * This is always a hypervisor bug (not a guest action).
     * Log the faulting GPA and halt — continuing would cause an
     * infinite exit loop.  See SDM Vol. 3C, Section 28.2.3.1.
     */
    case EXIT_REASON_EPT_MISCONFIG: {
        uint64_t gpa = gr_vmread(VMCS_GUEST_PHYS_ADDR);
        static uint64_t eptm_once;
        if (!eptm_once++) {
            GR_LOG("vmx_exit: EPT misconfiguration at GPA=", gpa);
        }
        /* Don't halt — just resume.  In a bluepill the EPT is our own
         * identity map, so a misconfig means we built it wrong — the
         * safer action is to keep the guest going while we iterate. */
        break;
    }

    default:
        /*
         * Unhandled exit reason — advance past the instruction and
         * resume the guest rather than halting the host CPU.  Log
         * once per reason for diagnostics.  Better to let the guest
         * misbehave than to wedge the whole machine.
         */
        {
            static uint64_t unhandled_first[64];
            if (exit_reason < 64 && !unhandled_first[exit_reason]) {
                unhandled_first[exit_reason] = 1;
                GR_LOG("vmx_exit: (first) unhandled reason=",
                       (uint64_t)exit_reason);
                GR_LOG("vmx_exit: rip=", gr_vmread(VMCS_GUEST_RIP));
            }
            advance_guest_rip();
        }
        break;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * gr_vmx_resume_failed — Fatal path when VMRESUME fails
 * ═══════════════════════════════════════════════════════════════════════════ */

GR_NORETURN void
gr_vmx_resume_failed(void)
{
    /*
     * Read the VM-instruction error field for diagnostics.
     * In a real system this would log the error and panic.
     * See SDM Vol. 3C, Section 30.4.
     */
    (void)gr_vmread(VMCS_VM_INSTRUCTION_ERROR);

    for (;;)
        __asm__ volatile("hlt");
}
