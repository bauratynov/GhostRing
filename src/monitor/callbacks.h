/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * callbacks.h — Kernel callback array monitoring.
 *
 * Windows kernel maintains arrays of notification callback pointers:
 *   - PspCreateProcessNotifyRoutine (up to 64 entries)
 *   - PspLoadImageNotifyRoutine (up to 64 entries)
 *   - CmpCallBackVector (registry callbacks)
 *
 * Rootkits in 2025 (HoneyMyte APT, RealBlindingEDR) add malicious
 * callbacks or remove legitimate EDR callbacks to blind security products.
 * This is the #1 EDR evasion technique in active threat campaigns.
 *
 * Detection: EPT write-protect callback array pages.  On modification,
 * compare against baseline snapshot — alert if callback points outside
 * known kernel modules or if a valid callback was removed.
 */

#ifndef GHOSTRING_MONITOR_CALLBACKS_H
#define GHOSTRING_MONITOR_CALLBACKS_H

#include "../common/ghostring.h"

/* ── Limits ────────────────────────────────────────────────────────────── */

#define GR_MAX_CALLBACK_ARRAYS      8
#define GR_MAX_CALLBACKS_PER_ARRAY  64

/* ── Per-array state ───────────────────────────────────────────────────── */

typedef struct {
    uint64_t gpa;                                      /* array base GPA      */
    uint32_t entry_count;                               /* slots in array      */
    uint32_t entry_size;                                /* bytes per slot (8)  */
    uint64_t baseline[GR_MAX_CALLBACKS_PER_ARRAY];      /* known-good snapshot */
    uint64_t kernel_low;                                /* valid range low     */
    uint64_t kernel_high;                               /* valid range high    */
    char     name[32];
    bool     armed;
} gr_callback_array_t;

/* ── Aggregate state ───────────────────────────────────────────────────── */

typedef struct {
    gr_callback_array_t arrays[GR_MAX_CALLBACK_ARRAYS];
    uint32_t count;
} gr_callback_state_t;

/* ── API ───────────────────────────────────────────────────────────────── */

void gr_callback_init(gr_callback_state_t *state);

/*
 * Register a callback array for monitoring.
 * @gpa         : guest physical address of the array
 * @entries     : number of callback slots
 * @entry_size  : bytes per slot (typically 8 for a pointer)
 * @kernel_low  : lowest valid kernel address (ntoskrnl base)
 * @kernel_high : highest valid kernel address
 * @name        : human-readable name for alerts
 */
void gr_callback_register(gr_callback_state_t *state,
                          uint64_t gpa, uint32_t entries,
                          uint32_t entry_size,
                          uint64_t kernel_low, uint64_t kernel_high,
                          const char *name);

/* Snapshot current array values as baseline */
void gr_callback_snapshot(gr_callback_state_t *state);

/* Check all registered arrays against baselines.  Returns anomaly count. */
int  gr_callback_check(gr_callback_state_t *state);

/* Check if a GPA belongs to a monitored callback array page */
bool gr_callback_is_monitored(gr_callback_state_t *state, uint64_t gpa);

#endif /* GHOSTRING_MONITOR_CALLBACKS_H */
