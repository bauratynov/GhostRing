/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * anti_forensics.h — Evidence destruction detection.
 *
 * Detects anti-forensic tactics commonly used after a breach:
 *   1. Timestomping: file timestamps set far in the past to blend in
 *   2. Event log deletion: *.evtx files wiped to destroy audit trail
 *   3. Memory wiping: bulk zeroing of kernel structures to erase traces
 *
 * MITRE ATT&CK: T1070.006 (Timestomp), T1070.001 (Clear Windows Event Logs)
 *
 * Detection approach: monitor writes to specific memory regions via EPT
 * and analyze write patterns for anti-forensic signatures.
 */

#ifndef GHOSTRING_MONITOR_ANTI_FORENSICS_H
#define GHOSTRING_MONITOR_ANTI_FORENSICS_H

#include "../common/ghostring.h"

#define GR_MAX_WATCHED_REGIONS  64
#define GR_TIMESTOMP_THRESHOLD  (30ULL * 24 * 3600 * 10000000ULL) /* 30 days in 100ns ticks */

typedef struct {
    uint64_t gpa;
    uint64_t size;
    uint32_t zero_write_count;  /* consecutive zero writes detected */
    char     name[32];
} gr_watched_region_t;

typedef struct {
    gr_watched_region_t regions[GR_MAX_WATCHED_REGIONS];
    uint32_t count;
    uint64_t current_filetime;  /* current system time in Windows FILETIME format */
} gr_antiforensics_state_t;

void gr_antiforensics_init(gr_antiforensics_state_t *state);

/* Register a memory region to watch for bulk zeroing */
void gr_antiforensics_watch(gr_antiforensics_state_t *state,
                            uint64_t gpa, uint64_t size, const char *name);

/* Update current system time (called periodically from timer) */
void gr_antiforensics_set_time(gr_antiforensics_state_t *state, uint64_t filetime);

/*
 * Check if a file timestamp write is timestomping.
 * @new_time : FILETIME value being written
 * Returns true if suspicious (timestamp > 30 days in the past).
 */
bool gr_antiforensics_check_timestamp(gr_antiforensics_state_t *state,
                                      uint64_t new_time);

/*
 * Check if a write to a watched region looks like bulk zeroing.
 * @gpa       : target address
 * @value     : value being written
 * @size      : write size in bytes
 * Returns true if this appears to be evidence destruction.
 */
bool gr_antiforensics_check_wipe(gr_antiforensics_state_t *state,
                                 uint64_t gpa, uint64_t value, uint32_t size);

#endif /* GHOSTRING_MONITOR_ANTI_FORENSICS_H */
