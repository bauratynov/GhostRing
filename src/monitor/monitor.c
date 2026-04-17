/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * monitor.c — Unified security monitor orchestrator.
 *
 * Coordinates all detection subsystems (integrity, MSR guard, DKOM,
 * hooks, SSDT, driver objects, code injection, ransomware, CR guard,
 * shadow stack) and presents a single interface to the VMX exit handler.
 * The separation between monitor.c (policy/coordination) and individual
 * subsystems (mechanism) follows the principle of least privilege — each
 * subsystem only has access to the data it needs.
 */

#include "monitor.h"

/* ── Initialisation ─────────────────────────────────────────────────────── */

void gr_monitor_init(gr_monitor_state_t *mon,
                     uint8_t *msr_bitmap,
                     gr_ept_ctx_t *ept_ctx,
                     uint64_t ktext_start,
                     uint64_t ktext_end)
{
    if (!mon)
        return;

    GR_LOG_STR("monitor: initialising security subsystems");

    /* Zero the entire state to start clean */
    uint8_t *p = (uint8_t *)mon;
    for (uint64_t i = 0; i < sizeof(*mon); i++)
        p[i] = 0;

    /* MSR guard — shadow critical MSRs and arm the MSR bitmap */
    if (msr_bitmap) {
        gr_msr_guard_init(&mon->msr_shadow, msr_bitmap);
    } else {
        GR_LOG_STR("monitor: WARNING — no MSR bitmap, MSR guard disabled");
    }

    /* DKOM — initialise the CR3 tracking set */
    gr_dkom_init(&mon->cr3_set);

    /* IDT hooks — snapshot and EPT-protect the IDT */
    gr_hooks_init(&mon->hooks, ktext_start, ktext_end);
    if (ept_ctx) {
        gr_hooks_protect_idt(&mon->hooks, ept_ctx);
        mon->protected_pages++;  /* At least the IDT page */
    }

    /* DKOM config starts unconfigured — the loader must supply offsets
     * via hypercall before DKOM scans will produce meaningful results. */
    mon->dkom_config.configured = false;

    /* Phase 5 — Advanced detection subsystems */

    /* Driver object monitoring — starts empty, drivers are added via
     * gr_drvobj_add() once the loader identifies critical drivers. */
    gr_drvobj_init(&mon->drvobj);

    /* Code injection detection — bitmap starts clear, images are
     * registered as they are loaded via hypercall or image-load trap. */
    gr_code_inject_init(&mon->code_inject);

    /* Shadow stack manager — starts with no monitored processes.
     * High-value processes are enrolled via gr_shadow_stack_enable(). */
    gr_shadow_stack_init(&mon->shadow_stack);

    /* CR guard — capture clean CR0/CR4 and program VMCS guest-host
     * masks to intercept security-critical bit modifications. */
    gr_cr_guard_init(&mon->cr_guard);

    /* SSDT and ransomware canaries require additional configuration
     * from the loader (SSDT base address, canary page GPAs).  They
     * are initialised via dedicated hypercalls after the guest OS
     * has finished early boot. */

    mon->armed = true;
    GR_LOG_STR("monitor: all subsystems armed (Phase 5 detectors active)");
}

/* ── EPT violation handling ─────────────────────────────────────────────── */

int gr_monitor_ept_violation(gr_monitor_state_t *mon,
                             uint64_t gpa,
                             uint32_t access_type,
                             uint64_t guest_rip,
                             uint64_t guest_cr3)
{
    if (!mon || !mon->armed)
        return 0;  /* Not armed — allow everything */

    mon->total_ept_violations++;

    /*
     * Determine the nature of the violation and respond accordingly.
     * The EPT is configured to be restrictive: protected pages are
     * read+execute only, so a write violation is the expected case.
     */

    if (access_type & GR_EPT_ACCESS_WRITE) {
        /*
         * Write to a protected page.  This is the primary detection
         * mechanism for code patching, IDT modification, and similar
         * attacks.
         */

        /* Check if the write targets a ransomware canary page.
         * This check is first because canary hits are HIGH-CONFIDENCE
         * and require immediate response. */
        if (mon->ransomware.initialised) {
            if (gr_ransom_check_write(&mon->ransomware, gpa,
                                      guest_rip, guest_cr3)) {
                mon->total_alerts++;
                return 1;  /* Block and alert — ransomware detected */
            }
        }

        /* Check if the write targets the IDT region */
        if (mon->hooks.initialised) {
            phys_addr_t idt_start = ALIGN_DOWN(mon->hooks.idt_phys, PAGE_SIZE);
            phys_addr_t idt_end   = idt_start + GR_IDT_TOTAL_SIZE;

            if (gpa >= idt_start && gpa < idt_end) {
                GR_LOG("monitor: write to IDT page blocked, gpa=", gpa);
                gr_alert_emit(GR_ALERT_IDT_HOOK,
                              guest_rip, guest_cr3, gpa,
                              (gpa - idt_start) / GR_IDT_ENTRY_SIZE);
                mon->total_alerts++;
                /*
                 * Return non-zero to inject #GP into the guest.  The
                 * guest kernel will see a general protection fault at
                 * the instruction that tried to modify the IDT, which
                 * is the correct hardware behaviour for a write to a
                 * read-only page.
                 */
                return 1;
            }
        }

        /* Check if the write targets an SSDT page */
        if (mon->ssdt.initialised) {
            uint64_t ssdt_size = (uint64_t)mon->ssdt.entry_count * sizeof(uint64_t);
            phys_addr_t ssdt_start = ALIGN_DOWN(mon->ssdt.ssdt_base_gpa, PAGE_SIZE);
            phys_addr_t ssdt_end   = ALIGN_UP(mon->ssdt.ssdt_base_gpa + ssdt_size,
                                              PAGE_SIZE);
            if (gpa >= ssdt_start && gpa < ssdt_end) {
                GR_LOG("monitor: write to SSDT page blocked, gpa=", gpa);
                gr_alert_emit(GR_ALERT_SSDT_HOOK,
                              guest_rip, guest_cr3, gpa, 0);
                mon->total_alerts++;
                return 1;
            }
        }

        /*
         * Write to a kernel code page or other protected region.
         * This covers inline hooking attacks and code patching.
         */
        gr_alert_emit(GR_ALERT_EPT_WRITE_VIOLATION,
                      guest_rip, guest_cr3, gpa,
                      (uint64_t)access_type);
        mon->total_alerts++;

        GR_LOG("monitor: EPT write violation gpa=", gpa);
        GR_LOG("  rip=", guest_rip);

        /*
         * Policy decision: block the write.  In a production deployment
         * this could be configurable (block vs. log-and-allow) depending
         * on the protected region's sensitivity.
         */
        return 1;
    }

    if (access_type & GR_EPT_ACCESS_EXEC) {
        /*
         * Execute from a page that should not be executable.  Delegate
         * to the code injection monitor which checks the known-good
         * page bitmap.  If the page is registered (from a legitimate
         * PE/ELF image), allow execution; otherwise treat as injection.
         */
        if (mon->code_inject.initialised) {
            if (gr_code_inject_check_exec(&mon->code_inject, gpa,
                                          guest_rip, guest_cr3)) {
                mon->total_alerts++;
                return 1;  /* Injection detected — block */
            }
            /* Known-good page — allow execution (the EPT entry should
             * be updated by the caller to avoid repeated exits). */
            return 0;
        }

        /* Fallback if code injection monitor is not active */
        gr_alert_emit(GR_ALERT_CODE_INJECTION,
                      guest_rip, guest_cr3, gpa,
                      (uint64_t)access_type);
        mon->total_alerts++;

        GR_LOG("monitor: code injection detected, gpa=", gpa);
        return 1;
    }

    /*
     * Read-only violation on a non-present page or similar.  This is
     * unusual but not necessarily malicious.  Log but allow.
     */
    GR_LOG("monitor: EPT read violation (allowed), gpa=", gpa);
    return 0;
}

/* ── Periodic checks ────────────────────────────────────────────────────── */

uint32_t gr_monitor_periodic(gr_monitor_state_t *mon)
{
    if (!mon || !mon->armed)
        return 0;

    uint32_t anomalies = 0;

    /* Integrity check — CRC32 comparison of protected regions */
    if (mon->integrity_regions && mon->integrity_count > 0) {
        uint32_t mismatches = gr_integrity_check(mon->integrity_regions,
                                                  mon->integrity_count);
        anomalies += mismatches;
        if (mismatches > 0) {
            GR_LOG("monitor: integrity mismatches=", (uint64_t)mismatches);
        }
    }

    /* DKOM scan — cross-reference hardware CR3s with OS process list */
    uint32_t hidden = gr_dkom_scan(&mon->cr3_set, &mon->dkom_config);
    anomalies += hidden;
    if (hidden > 0) {
        GR_LOG("monitor: hidden processes=", (uint64_t)hidden);
    }

    /* IDT check — compare snapshot against live IDT */
    uint32_t idt_mods = gr_hooks_check_idt(&mon->hooks);
    anomalies += idt_mods;
    if (idt_mods > 0) {
        GR_LOG("monitor: IDT modifications=", (uint64_t)idt_mods);
    }

    /* SSDT check — compare snapshot against live SSDT entries */
    if (mon->ssdt.initialised) {
        uint32_t ssdt_hooks = gr_ssdt_check(&mon->ssdt);
        anomalies += ssdt_hooks;
        if (ssdt_hooks > 0) {
            GR_LOG("monitor: SSDT hooks=", (uint64_t)ssdt_hooks);
        }
    }

    /* Driver object check — scan all monitored driver dispatch tables */
    if (mon->drvobj.initialised) {
        uint32_t drv_hooks = gr_drvobj_check(&mon->drvobj);
        anomalies += drv_hooks;
        if (drv_hooks > 0) {
            GR_LOG("monitor: driver object hooks=", (uint64_t)drv_hooks);
        }
    }

    mon->total_alerts += anomalies;
    return anomalies;
}

/* ── MSR write delegation ───────────────────────────────────────────────── */

bool gr_monitor_msr_write(gr_monitor_state_t *mon,
                          uint32_t msr,
                          uint64_t value,
                          uint64_t guest_rip,
                          uint64_t guest_cr3)
{
    if (!mon || !mon->armed)
        return true;  /* Not armed — allow */

    bool allowed = gr_msr_guard_check_write(&mon->msr_shadow,
                                             msr, value,
                                             guest_rip, guest_cr3);
    if (!allowed)
        mon->total_alerts++;

    return allowed;
}

/* ── CR3 tracking delegation ────────────────────────────────────────────── */

void gr_monitor_cr3_update(gr_monitor_state_t *mon, uint64_t new_cr3)
{
    if (!mon || !mon->armed)
        return;

    gr_dkom_add_cr3(&mon->cr3_set, new_cr3);
}

/* ── CR0 / CR4 guard delegation ────────────────────────────────────────── */

bool gr_monitor_cr0_write(gr_monitor_state_t *mon,
                          uint64_t new_cr0,
                          uint64_t guest_rip,
                          uint64_t guest_cr3)
{
    if (!mon || !mon->armed)
        return true;

    bool allowed = gr_cr_guard_check_cr0(&mon->cr_guard, new_cr0,
                                          guest_rip, guest_cr3);
    if (!allowed)
        mon->total_alerts++;

    return allowed;
}

bool gr_monitor_cr4_write(gr_monitor_state_t *mon,
                          uint64_t new_cr4,
                          uint64_t guest_rip,
                          uint64_t guest_cr3)
{
    if (!mon || !mon->armed)
        return true;

    bool allowed = gr_cr_guard_check_cr4(&mon->cr_guard, new_cr4,
                                          guest_rip, guest_cr3);
    if (!allowed)
        mon->total_alerts++;

    return allowed;
}
