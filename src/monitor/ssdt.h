/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * ssdt.h — System Service Descriptor Table hook detection.
 *
 * The SSDT (KeServiceDescriptorTable on Windows) maps system call numbers
 * to kernel function addresses.  Rootkits such as Turla, ZeroAccess, and
 * early Necurs variants replace individual SSDT entries to intercept
 * NtOpenProcess, NtQuerySystemInformation, etc., hiding their presence
 * from user-mode enumeration tools.
 *
 * Detection strategy:
 *   1. Snapshot all SSDT entries at a known-good point (before guest boot
 *      completes or immediately after ntoskrnl.exe is mapped).
 *   2. EPT-write-protect the SSDT pages — any modification triggers an
 *      immediate VM-exit rather than waiting for a periodic scan.
 *   3. Periodic comparison: each entry is checked against the snapshot.
 *      Entries that now point outside the ntoskrnl.exe image range are
 *      flagged as hooked.
 *
 * On Windows, SSDT entries are relative offsets (since Windows 8); on
 * older versions they are absolute pointers.  We handle both by comparing
 * the resolved absolute address against the kernel image boundaries.
 */

#ifndef GHOSTRING_MONITOR_SSDT_H
#define GHOSTRING_MONITOR_SSDT_H

#include "../common/ghostring.h"

/* ── Constants ──────────────────────────────────────────────────────────── */

/*
 * Maximum number of SSDT entries we track.  Windows 10/11 has ~470
 * entries in the main SSDT; Linux does not use an SSDT in the same
 * sense (system calls go through sys_call_table), but the detection
 * logic is identical.
 */
#define GR_SSDT_MAX_ENTRIES     512

/* ── SSDT snapshot state ────────────────────────────────────────────────── */

typedef struct gr_ssdt_state {
    /*
     * Baseline SSDT entries captured at init time.  Each entry holds
     * the original value (pointer or relative offset) as it appeared
     * in guest physical memory.
     */
    uint64_t snapshot[GR_SSDT_MAX_ENTRIES];

    phys_addr_t ssdt_base_gpa;          /* GPA of the SSDT array             */
    uint32_t    entry_count;            /* Number of entries in the table     */

    /*
     * Kernel image range — entries pointing outside this range after
     * resolution are considered hooked.
     */
    uint64_t    ntoskrnl_start;
    uint64_t    ntoskrnl_end;

    bool        initialised;
} gr_ssdt_state_t;

/* ── Public API ─────────────────────────────────────────────────────────── */

/*
 * gr_ssdt_init — Take a baseline snapshot of the SSDT.
 *
 * Must be called when the SSDT is known to be clean (e.g., early boot
 * before third-party drivers have loaded).  Records all entries and
 * the kernel image range for later comparison.
 *
 * @state         : Per-vCPU SSDT state to populate.
 * @ssdt_base_gpa : Guest physical address of the SSDT array.
 * @entry_count   : Number of entries in the SSDT.
 * @ntos_start    : Start of the ntoskrnl.exe image in guest physical memory.
 * @ntos_end      : End of the ntoskrnl.exe image.
 */
void gr_ssdt_init(gr_ssdt_state_t *state,
                  phys_addr_t ssdt_base_gpa,
                  uint32_t entry_count,
                  uint64_t ntos_start,
                  uint64_t ntos_end);

/*
 * gr_ssdt_check — Scan the SSDT for hooked entries.
 *
 * Compares each live SSDT entry against the snapshot.  Any entry that
 * has been modified and now resolves to an address outside the kernel
 * image is reported as a hook.
 *
 * @state : Per-vCPU SSDT state (with snapshot).
 *
 * Returns the number of hooked entries detected.
 * Emits GR_ALERT_SSDT_HOOK for each hooked entry.
 */
uint32_t gr_ssdt_check(gr_ssdt_state_t *state);

/*
 * gr_ssdt_protect — EPT-write-protect all pages containing the SSDT.
 *
 * After this call, any guest write to the SSDT pages will cause an
 * EPT violation VM-exit, providing real-time hook prevention.
 *
 * @state   : Per-vCPU SSDT state (ssdt_base_gpa must be set).
 * @ept_ctx : EPT context for this vCPU.
 */
void gr_ssdt_protect(gr_ssdt_state_t *state, gr_ept_ctx_t *ept_ctx);

#endif /* GHOSTRING_MONITOR_SSDT_H */
