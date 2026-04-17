/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * glue.c — Per-CPU virtualisation orchestrator.
 *
 * This is the single integration point between the loader (OS-specific)
 * and the hypervisor core (OS-agnostic).  All the messy wiring between
 * VMX/SVM, EPT/NPT, monitor, and memory allocation lives here so that
 * individual modules stay clean and testable.
 */

#include "glue.h"
#include "../vmx/vmx_vmcs.h"
#include "../vmx/vmx_ept.h"
#include "../monitor/monitor.h"

/* ── Magic CPUID leaf for devirtualisation ─────────────────────────────── */

#define GR_MAGIC_CPUID_LEAF     0x47520001
#define GR_MAGIC_CPUID_SUBLEAF  0x47520001

/* ═══════════════════════════════════════════════════════════════════════════
 * gr_init_cpu — Full per-CPU virtualisation sequence
 * ═══════════════════════════════════════════════════════════════════════════ */

int
gr_init_cpu(const gr_init_params_t *params)
{
    uint32_t cpu_id = gr_get_cpu_id();

    GR_LOG("glue: init CPU ", (uint64_t)cpu_id);
    gr_serial_dec(cpu_id);
    gr_serial_puts("\n");

    if (params->vendor == GR_CPU_INTEL) {
#if GHOSTRING_VTX
        /* ── Step 1: Check VMX support ──────────────────────────────── */
        if (!gr_vmx_check_support()) {
            GR_LOG_STR("glue: VMX not supported on this CPU");
            return -1;
        }

        /* ── Step 2: Allocate vcpu via platform allocator ───────────── */
        /*
         * gr_vmx_vcpu_t is large (~2MB due to EPT tables).  The platform
         * allocator provides physically contiguous, page-aligned memory.
         */
        uint32_t vcpu_pages = (sizeof(gr_vmx_vcpu_t) + PAGE_SIZE - 1) / PAGE_SIZE;
        gr_vmx_vcpu_t *vmx_vcpu = (gr_vmx_vcpu_t *)
            gr_platform_alloc_pages(vcpu_pages);

        if (!vmx_vcpu) {
            GR_LOG_STR("glue: failed to allocate VMX vcpu");
            return -1;
        }

        /* ── Step 3: Capture host state ─────────────────────────────── */
        /* Cast: gr_special_regs_t embeds a {limit, base} struct with same
         * binary layout as gr_desc_table_reg_t.  Static-asserted 10 bytes. */
        gr_sgdt((gr_desc_table_reg_t *)&vmx_vcpu->host_regs.gdtr);
        gr_sidt((gr_desc_table_reg_t *)&vmx_vcpu->host_regs.idtr);
        vmx_vcpu->host_regs.cr0 = gr_read_cr0();
        vmx_vcpu->host_regs.cr3 = gr_read_cr3();
        vmx_vcpu->host_regs.cr4 = gr_read_cr4();
        vmx_vcpu->host_regs.dr7 = gr_read_dr7();
        vmx_vcpu->host_regs.rflags = gr_read_rflags();
        vmx_vcpu->host_regs.cs = gr_read_cs();
        vmx_vcpu->host_regs.ss = gr_read_ss();
        vmx_vcpu->host_regs.ds = gr_read_ds();
        vmx_vcpu->host_regs.es = gr_read_es();
        vmx_vcpu->host_regs.fs = gr_read_fs();
        vmx_vcpu->host_regs.gs = gr_read_gs();
        vmx_vcpu->host_regs.tr = gr_str();
        vmx_vcpu->host_regs.ldtr = gr_sldt();
        vmx_vcpu->host_regs.gs_base = gr_rdmsr(0xC0000101); /* MSR_GS_BASE */
        vmx_vcpu->host_regs.debug_ctl = gr_rdmsr(0x1D9);    /* MSR_DEBUG_CTL */
        vmx_vcpu->host_regs.sysenter_cs = gr_rdmsr(0x174);
        vmx_vcpu->host_regs.sysenter_esp = gr_rdmsr(0x175);
        vmx_vcpu->host_regs.sysenter_eip = gr_rdmsr(0x176);

        vmx_vcpu->system_cr3 = params->system_cr3;

        /* ── Step 3b: Allocate hypervisor stack (16KB) ──────────────── */
        void *hv_stack = gr_platform_alloc_pages(4); /* 4 pages = 16KB */
        if (!hv_stack) {
            GR_LOG_STR("glue: failed to allocate hypervisor stack");
            gr_platform_free_pages(vmx_vcpu, vcpu_pages);
            return -1;
        }
        vmx_vcpu->hv_stack = (uintptr_t)hv_stack;
        vmx_vcpu->hv_stack_size = 4 * PAGE_SIZE;

        /* ── Step 4: MTRR + EPT ─────────────────────────────────────── */
        gr_vmx_mtrr_init(&vmx_vcpu->ept);
        gr_vmx_ept_init(&vmx_vcpu->ept);

        /* ── Step 5: Enter VMX root + setup VMCS ────────────────────── */
        if (!gr_vmx_enter_root(vmx_vcpu)) {
            GR_LOG_STR("glue: VMXON failed");
            gr_platform_free_pages(hv_stack, 4);
            gr_platform_free_pages(vmx_vcpu, vcpu_pages);
            return -1;
        }

        gr_vmx_setup_vmcs(vmx_vcpu);

        /* ── Step 6: Initialise monitor ─────────────────────────────── */
        vmx_vcpu->monitor = (gr_monitor_state_t *)
            gr_platform_alloc_pages(
                (sizeof(gr_monitor_state_t) + PAGE_SIZE - 1) / PAGE_SIZE);

        if (vmx_vcpu->monitor) {
            gr_monitor_init(vmx_vcpu->monitor,
                            vmx_vcpu->msr_bitmap,
                            &vmx_vcpu->ept,
                            params->kernel_text_start,
                            params->kernel_text_start + params->kernel_text_size);
        }

        /* ── Step 7: Register in per-CPU table ──────────────────────── */
        gr_vcpu_t *vcpu = (gr_vcpu_t *)
            gr_platform_alloc_pages(1);

        if (vcpu) {
            vcpu->cpu_id = cpu_id;
            vcpu->vendor = GR_CPU_INTEL;
            vcpu->active = 1;
            vcpu->exit_vm = 0;
            vcpu->vmx = vmx_vcpu;
            vcpu->monitor = vmx_vcpu->monitor;
            vcpu->system_cr3 = params->system_cr3;
            vcpu->exit_count = 0;
            gr_set_vcpu(cpu_id, vcpu);
            __atomic_fetch_add(&g_percpu.cpu_count, 1, __ATOMIC_RELAXED);
        }

        /* ── Step 8: VMLAUNCH ───────────────────────────────────────── */
        GR_LOG("glue: launching VMX on CPU ", (uint64_t)cpu_id);
        gr_serial_dec(cpu_id);
        gr_serial_puts("...\n");

        extern int gr_vmx_launch(void);
        int err = gr_vmx_launch();
        if (err) {
            GR_LOG("glue: VMLAUNCH failed, error ", (uint64_t)err);
            gr_serial_dec((uint64_t)err);
            gr_serial_puts("\n");
            return -1;
        }

        /* If we reach here, VMLAUNCH succeeded and we're in guest mode.
         * gr_vmx_restore_guest returned 0 via RAX. */
        GR_LOG("glue: CPU virtualised ", (uint64_t)cpu_id);
        gr_serial_dec(cpu_id);
        gr_serial_puts(" virtualised OK\n");
        return 0;
#else
        GR_LOG_STR("glue: VMX support not compiled in");
        return -1;
#endif /* GHOSTRING_VTX */

    } else if (params->vendor == GR_CPU_AMD) {
#if GHOSTRING_SVM
        /* AMD-V path — symmetric with Intel, using SVM structures */
        if (!gr_svm_check_support()) {
            GR_LOG_STR("glue: SVM not supported on this CPU");
            return -1;
        }

        /* TODO: allocate svm_vcpu, capture state, NPT init, VMCB setup,
         * monitor init, VMRUN — symmetric with Intel path above. */
        GR_LOG_STR("glue: SVM init path pending");
        return -1;
#else
        GR_LOG_STR("glue: SVM support not compiled in");
        return -1;
#endif /* GHOSTRING_SVM */
    }

    GR_LOG_STR("glue: unknown CPU vendor");
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * gr_shutdown_cpu — Devirtualise via magic CPUID
 * ═══════════════════════════════════════════════════════════════════════════ */

void
gr_shutdown_cpu(void)
{
    uint32_t eax, ebx, ecx, edx;

    /*
     * Issue the magic CPUID that the exit handler recognises as a
     * devirtualisation request.  The handler sets exit_vm=true and
     * VMXOFF runs on the next exit cycle.
     */
    gr_cpuid(GR_MAGIC_CPUID_LEAF, GR_MAGIC_CPUID_SUBLEAF,
             &eax, &ebx, &ecx, &edx);

    uint32_t cpu_id = gr_get_cpu_id();
    gr_set_vcpu(cpu_id, NULL);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * gr_is_active
 * ═══════════════════════════════════════════════════════════════════════════ */

bool
gr_is_active(void)
{
    gr_vcpu_t *vcpu = gr_get_vcpu();
    return vcpu && vcpu->active;
}
