/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * integrity.h — Kernel code integrity monitoring via CRC32.
 *
 * Protected regions (kernel text, critical data structures) are
 * snapshotted at init time.  Periodic checks compare the current CRC32
 * against the recorded baseline.  Any mismatch indicates that guest
 * memory was modified, either by a rootkit patching kernel code or by
 * a DMA attack that bypassed EPT protections.
 *
 * CRC32C (Castagnoli) is used when the CPU supports SSE4.2 for speed;
 * otherwise a software table-based CRC32 is used as fallback.
 */

#ifndef GHOSTRING_MONITOR_INTEGRITY_H
#define GHOSTRING_MONITOR_INTEGRITY_H

#include "../common/ghostring.h"

/* ── Constants ──────────────────────────────────────────────────────────── */

#define GR_INTEGRITY_MAX_REGIONS    64
#define GR_INTEGRITY_NAME_LEN       32

/* ── Per-region descriptor ──────────────────────────────────────────────── */

typedef struct gr_integrity_region {
    phys_addr_t gpa_start;                  /* Start of monitored region     */
    uint64_t    size;                       /* Region size in bytes          */
    uint32_t    expected_crc32;             /* Baseline CRC32 from init      */
    uint32_t    _pad;
    char        name[GR_INTEGRITY_NAME_LEN]; /* Human-readable label        */
} gr_integrity_region_t;

/* ── Public API ─────────────────────────────────────────────────────────── */

/*
 * gr_crc32 — Compute CRC32 over an arbitrary memory buffer.
 *
 * Uses hardware CRC32C via __builtin_ia32_crc32 when SSE4.2 is
 * available, with a table-based software fallback otherwise.
 */
uint32_t gr_crc32(const void *data, uint64_t len);

/*
 * gr_integrity_init — Compute and record the baseline CRC32 for each
 *                     region.  Must be called after guest memory is
 *                     mapped and before the guest has had a chance to
 *                     execute (or immediately after a known-good state).
 *
 * @regions : Array of region descriptors (gpa_start, size, name filled in).
 * @count   : Number of regions (clamped to GR_INTEGRITY_MAX_REGIONS).
 */
void gr_integrity_init(gr_integrity_region_t *regions, uint32_t count);

/*
 * gr_integrity_check — Recompute CRC32 for each region and compare
 *                       against the stored baseline.
 *
 * @regions : Array of region descriptors (same passed to _init).
 * @count   : Number of regions.
 *
 * Returns the number of regions with CRC32 mismatches (0 = all OK).
 * For each mismatch a GR_ALERT_INTEGRITY_FAIL alert is emitted.
 */
uint32_t gr_integrity_check(gr_integrity_region_t *regions, uint32_t count);

#endif /* GHOSTRING_MONITOR_INTEGRITY_H */
