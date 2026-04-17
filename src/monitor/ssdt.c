/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ssdt.c — System Service Descriptor Table hook detection.
 *
 * The SSDT is one of the most historically targeted structures by Windows
 * rootkits.  Turla (Snake) replaces NtQuerySystemInformation to hide
 * processes; ZeroAccess hooks NtCreateFile to protect its installation
 * directory; Necurs patches NtEnumerateValueKey to hide registry keys.
 *
 * Modern Windows (8+) uses relative offsets in the SSDT rather than
 * absolute pointers, but the detection principle remains the same:
 * the resolved address must fall within ntoskrnl.exe's image range.
 *
 * EPT write-protection provides real-time prevention.  The periodic
 * scan catches modifications that might bypass EPT (e.g., a DMA
 * attack from a malicious PCI device, or an SSDT relocation by the
 * kernel during a hotpatch that we must re-snapshot).
 */

#include "ssdt.h"
#include "alerts.h"
#include "../vmx/vmx_ept.h"

/* ── Internal helpers ──────────────────────────────────────────────────── */

/*
 * Read a single SSDT entry from guest physical memory.
 *
 * Under the identity-mapped EPT, the GPA can be cast directly to a
 * host pointer.  In a production hypervisor this would go through a
 * safe GPA-to-HVA translation with bounds checking.
 */
static inline uint64_t ssdt_read_entry(phys_addr_t ssdt_base, uint32_t index)
{
    const uint64_t *table = (const uint64_t *)(uintptr_t)ssdt_base;
    return table[index];
}

/*
 * Determine whether a resolved SSDT target address falls within the
 * kernel image.  Addresses outside this range are almost certainly
 * rootkit redirections — legitimate kernel routines live within the
 * ntoskrnl.exe image.
 */
static inline bool ssdt_target_in_kernel(const gr_ssdt_state_t *state,
                                         uint64_t target)
{
    return (target >= state->ntoskrnl_start &&
            target <  state->ntoskrnl_end);
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void gr_ssdt_init(gr_ssdt_state_t *state,
                  phys_addr_t ssdt_base_gpa,
                  uint32_t entry_count,
                  uint64_t ntos_start,
                  uint64_t ntos_end)
{
    if (!state)
        return;

    /* Clamp to our maximum tracked entries */
    if (entry_count > GR_SSDT_MAX_ENTRIES)
        entry_count = GR_SSDT_MAX_ENTRIES;

    state->ssdt_base_gpa  = ssdt_base_gpa;
    state->entry_count    = entry_count;
    state->ntoskrnl_start = ntos_start;
    state->ntoskrnl_end   = ntos_end;

    GR_LOG("ssdt: base GPA=", ssdt_base_gpa);
    GR_LOG("ssdt: entry count=", (uint64_t)entry_count);
    GR_LOG("ssdt: ntoskrnl range [", ntos_start);
    GR_LOG("ssdt:                 ,", ntos_end);

    /*
     * Snapshot every entry.  At this point the SSDT is assumed to be
     * in a known-good state — typically called before third-party
     * drivers have had a chance to install hooks.
     */
    for (uint32_t i = 0; i < entry_count; i++)
        state->snapshot[i] = ssdt_read_entry(ssdt_base_gpa, i);

    /* Zero remaining slots for safety */
    for (uint32_t i = entry_count; i < GR_SSDT_MAX_ENTRIES; i++)
        state->snapshot[i] = 0;

    state->initialised = true;

    GR_LOG_STR("ssdt: baseline snapshot captured");
}

uint32_t gr_ssdt_check(gr_ssdt_state_t *state)
{
    if (!state || !state->initialised)
        return 0;

    uint32_t hooked = 0;

    for (uint32_t i = 0; i < state->entry_count; i++) {
        uint64_t live = ssdt_read_entry(state->ssdt_base_gpa, i);
        uint64_t snap = state->snapshot[i];

        /* Entry unchanged — nothing to check */
        if (live == snap)
            continue;

        /*
         * Entry modified.  Determine whether the new target is inside
         * ntoskrnl.exe.  If not, this is a hook — the entry was
         * redirected to attacker-controlled code.
         */
        if (!ssdt_target_in_kernel(state, live)) {
            hooked++;

            /*
             * info field: pack the SSDT index so user-space can identify
             * which system call was hooked (e.g., index 0x3F =
             * NtOpenProcess on many Windows builds).
             */
            gr_alert_emit(GR_ALERT_SSDT_HOOK,
                          live,         /* new target = "malicious handler" */
                          0,            /* CR3: not applicable for periodic */
                          state->ssdt_base_gpa + (uint64_t)i * sizeof(uint64_t),
                          (uint64_t)i);

            GR_LOG("ssdt: HOOK detected at index=", (uint64_t)i);
            GR_LOG("  original=", snap);
            GR_LOG("  current=",  live);
        } else {
            /*
             * Entry changed but still within ntoskrnl.exe.  This may
             * be a legitimate kernel hotpatch.  Log but do not alert
             * at the highest severity.
             */
            GR_LOG("ssdt: entry changed (in-kernel) index=", (uint64_t)i);
            GR_LOG("  old=", snap);
            GR_LOG("  new=", live);
        }
    }

    return hooked;
}

void gr_ssdt_protect(gr_ssdt_state_t *state, gr_ept_ctx_t *ept_ctx)
{
    if (!state || !state->initialised || !ept_ctx)
        return;

    /*
     * Compute the byte extent of the SSDT and protect every page it
     * touches.  The SSDT is a contiguous array of pointers, so its
     * size is entry_count * sizeof(uint64_t).
     */
    uint64_t ssdt_size = (uint64_t)state->entry_count * sizeof(uint64_t);
    phys_addr_t start  = ALIGN_DOWN(state->ssdt_base_gpa, PAGE_SIZE);
    phys_addr_t end    = ALIGN_UP(state->ssdt_base_gpa + ssdt_size, PAGE_SIZE);

    for (phys_addr_t page = start; page < end; page += PAGE_SIZE) {
        int ret = gr_vmx_ept_protect_page(ept_ctx, page, EPT_PERM_RX);
        if (ret != 0) {
            GR_LOG("ssdt: EPT protect failed for page=", page);
        } else {
            GR_LOG("ssdt: EPT write-protected page=", page);
        }
    }

    GR_LOG_STR("ssdt: EPT protection active");
}
