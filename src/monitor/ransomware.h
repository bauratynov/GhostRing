/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * ransomware.h — High-confidence ransomware detection via canary pages.
 *
 * Ransomware (WannaCry, Ryuk, LockBit, Conti) encrypts files on disk
 * by reading, transforming, and writing back file content.  Traditional
 * detection relies on heuristics (file entropy, extension changes,
 * volume shadow copy deletion) which produce false positives and can
 * be evaded.
 *
 * Our approach: place "canary" pages in guest physical memory that
 * contain known sentinel data.  These pages are mapped into EPT with
 * read+execute permissions only — any write triggers an EPT violation.
 * Since no legitimate software ever writes to our canary pages, a
 * write is a HIGH-CONFIDENCE indicator that something is blindly
 * encrypting memory regions.
 *
 * This technique is inspired by CryptoDrop's canary file approach
 * (Scaife et al., 2016) but operates at the hypervisor level where
 * it cannot be evaded by the guest OS.
 *
 * Canary placement strategy:
 *   - Canary pages are interspersed at regular intervals across the
 *     guest's physical memory.
 *   - Each canary contains a magic header ("GHOSTRING_CANARY_xxxx")
 *     so we can verify it was not silently corrupted.
 *   - The canary GPA ranges are not exposed to the guest OS — they
 *     appear as reserved/unusable memory in the e820 map.
 */

#ifndef GHOSTRING_MONITOR_RANSOMWARE_H
#define GHOSTRING_MONITOR_RANSOMWARE_H

#include "../common/ghostring.h"

/* ── Constants ──────────────────────────────────────────────────────────── */

/*
 * Number of canary pages to deploy.  More canaries increase detection
 * probability but consume physical memory.  16 pages (64KB) is a
 * reasonable trade-off for 4GB guests.
 */
#define GR_RANSOM_MAX_CANARIES      16

/*
 * Canary magic signature.  The first 16 bytes of each canary page
 * contain this prefix followed by a 4-byte canary index.
 */
#define GR_RANSOM_MAGIC             "GHOSTRING_CANARY"
#define GR_RANSOM_MAGIC_LEN         16

/* ── Per-canary descriptor ──────────────────────────────────────────────── */

typedef struct gr_canary_page {
    phys_addr_t gpa;            /* Guest physical address of canary page */
    uint32_t    index;          /* Canary index (for identification)     */
    bool        triggered;      /* Set once a write is detected          */
} gr_canary_page_t;

/* ── Ransomware monitor state ───────────────────────────────────────────── */

typedef struct gr_ransom_state {
    gr_canary_page_t canaries[GR_RANSOM_MAX_CANARIES];
    uint32_t         canary_count;   /* Number of deployed canaries       */
    uint32_t         triggers;       /* Total write detections            */
    bool             initialised;
} gr_ransom_state_t;

/* ── Public API ─────────────────────────────────────────────────────────── */

/*
 * gr_ransom_init — Deploy canary pages and write-protect them via EPT.
 *
 * Each canary page is filled with a recognisable sentinel pattern and
 * then EPT-write-protected.  The caller provides an array of GPAs to
 * use as canary pages (typically reserved from the guest e820 map).
 *
 * @state       : Ransomware monitor state to initialise.
 * @canary_gpas : Array of GPAs for canary pages.
 * @count       : Number of GPAs (clamped to GR_RANSOM_MAX_CANARIES).
 * @ept_ctx     : EPT context for write-protection.
 */
void gr_ransom_init(gr_ransom_state_t *state,
                    const phys_addr_t *canary_gpas,
                    uint32_t count,
                    gr_ept_ctx_t *ept_ctx);

/*
 * gr_ransom_check_write — Determine whether an EPT write violation
 *                          targets a canary page.
 *
 * Called from the EPT violation handler for write violations.
 *
 * @state     : Ransomware monitor state.
 * @gpa       : Faulting guest physical address.
 * @guest_rip : Guest RIP at the time of violation.
 * @guest_cr3 : Guest CR3 — identifies the encrypting process.
 *
 * Returns true if the write targets a canary page (ransomware detected),
 * false otherwise.
 */
bool gr_ransom_check_write(gr_ransom_state_t *state,
                           uint64_t gpa,
                           uint64_t guest_rip,
                           uint64_t guest_cr3);

#endif /* GHOSTRING_MONITOR_RANSOMWARE_H */
