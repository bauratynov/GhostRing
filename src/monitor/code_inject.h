/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * code_inject.h — Code injection detection via EPT execute permissions.
 *
 * Modern attacks frequently inject executable code into memory that was
 * never loaded from a legitimate PE/ELF image:
 *   - Reflective DLL injection (Cobalt Strike, Metasploit)
 *   - Process hollowing (Dridex, Emotet)
 *   - Shellcode injection (any exploit payload)
 *   - ROP trampolines that pivot to injected code
 *
 * Detection strategy:
 *   We maintain a bitmap of "known-good code pages" — physical pages
 *   that were mapped from legitimate PE/ELF image sections (.text).
 *   All other pages have EPT execute permission cleared.  When the
 *   guest attempts to execute from a non-registered page, an EPT
 *   execute violation fires, and we emit GR_ALERT_CODE_INJECTION.
 *
 *   This is conceptually similar to W^X enforcement at the hypervisor
 *   level but works across the entire guest physical address space,
 *   defeating even kernel-mode code injection.
 *
 * Performance:
 *   The bitmap uses 1 bit per 4KB page.  For 4GB of physical memory,
 *   the bitmap is only 128KB — easily fitting in L2 cache.  EPT
 *   violations only fire on first execution from an unknown page;
 *   legitimate code pages are pre-registered and never trigger.
 */

#ifndef GHOSTRING_MONITOR_CODE_INJECT_H
#define GHOSTRING_MONITOR_CODE_INJECT_H

#include "../common/ghostring.h"

/* ── Constants ──────────────────────────────────────────────────────────── */

/*
 * Maximum physical memory we track.  4GB covers most VM configurations;
 * increase for larger guests.  At 1 bit per 4KB page, 4GB requires
 * exactly 131072 bytes (128KB) of bitmap.
 */
#define GR_CODE_INJECT_MAX_PHYS     (4ULL * 1024 * 1024 * 1024)
#define GR_CODE_INJECT_BITMAP_SIZE  (GR_CODE_INJECT_MAX_PHYS / PAGE_SIZE / 8)

/* ── Code injection monitor state ───────────────────────────────────────── */

typedef struct gr_code_inject_state {
    /*
     * Bitmap of legitimate code pages.  Bit N corresponds to physical
     * page at address N * PAGE_SIZE.  A set bit means "this page
     * contains code from a registered image and may be executed".
     */
    uint8_t bitmap[GR_CODE_INJECT_BITMAP_SIZE];

    uint32_t registered_images;     /* Count of registered image regions  */
    uint32_t registered_pages;      /* Total code pages marked legitimate */
    bool     initialised;
} gr_code_inject_state_t;

/* ── Public API ─────────────────────────────────────────────────────────── */

/*
 * gr_code_inject_init — Initialise the code injection monitor.
 *
 * Clears the known-good bitmap.  After this call, ALL physical pages
 * are considered non-executable until explicitly registered.
 *
 * @state : Code injection monitor state to initialise.
 */
void gr_code_inject_init(gr_code_inject_state_t *state);

/*
 * gr_code_inject_register_image — Mark a PE/ELF image's code pages as
 *                                  legitimate executable regions.
 *
 * Called when the hypervisor observes an image being loaded (e.g., via
 * a hypercall from the in-guest agent, or by intercepting the image
 * loader's page mappings).
 *
 * @state          : Code injection monitor state.
 * @image_base_gpa : Guest physical address of the image base.
 * @image_size     : Size of the image in bytes.
 *
 * Returns the number of pages registered.
 */
uint32_t gr_code_inject_register_image(gr_code_inject_state_t *state,
                                       phys_addr_t image_base_gpa,
                                       uint64_t image_size);

/*
 * gr_code_inject_check_exec — Check whether an EPT execute violation
 *                              represents code injection.
 *
 * Called from the EPT violation handler when GR_EPT_ACCESS_EXEC is set.
 *
 * @state     : Code injection monitor state.
 * @gpa       : Faulting guest physical address.
 * @guest_rip : Guest RIP at the time of violation.
 * @guest_cr3 : Guest CR3 (identifies the process).
 *
 * Returns true if the execution is from a non-registered page (injection
 * detected), false if the page is legitimate.
 */
bool gr_code_inject_check_exec(gr_code_inject_state_t *state,
                               uint64_t gpa,
                               uint64_t guest_rip,
                               uint64_t guest_cr3);

/*
 * gr_code_inject_is_known — Query whether a GPA is in the known-good set.
 *
 * @state : Code injection monitor state.
 * @gpa   : Guest physical address to check.
 *
 * Returns true if the page is registered as containing legitimate code.
 */
bool gr_code_inject_is_known(const gr_code_inject_state_t *state,
                             uint64_t gpa);

#endif /* GHOSTRING_MONITOR_CODE_INJECT_H */
