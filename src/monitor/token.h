/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * token.h — Token manipulation detection.
 *
 * Privilege escalation endgame: copy SYSTEM process token into attacker's
 * EPROCESS.  This grants SYSTEM privileges to any process.  Used by 90%+
 * of kernel exploits as the final payload (MITRE ATT&CK T1134).
 *
 * Detection: EPT write-protect EPROCESS pages.  When the Token field is
 * modified, check if the new value references the SYSTEM token.
 *
 * Challenge: EPROCESS shares pool pages with other allocations, so we get
 * EPT violations for non-Token writes too.  Filter by write offset.
 */

#ifndef GHOSTRING_MONITOR_TOKEN_H
#define GHOSTRING_MONITOR_TOKEN_H

#include "../common/ghostring.h"

#define GR_MAX_MONITORED_PROCS  64

typedef struct {
    uint64_t system_token_value;        /* SYSTEM process token (reference) */
    uint64_t eprocess_token_offset;     /* OS-specific offset of Token in EPROCESS */
    struct {
        uint64_t eprocess_gpa;          /* GPA of EPROCESS structure */
        uint64_t original_token;        /* token value at registration time */
        uint32_t pid;                   /* for alert context */
    } procs[GR_MAX_MONITORED_PROCS];
    uint32_t proc_count;
} gr_token_state_t;

void gr_token_init(gr_token_state_t *state,
                   uint64_t system_token_value,
                   uint64_t token_offset);

void gr_token_monitor_process(gr_token_state_t *state,
                              uint64_t eprocess_gpa, uint32_t pid);

/*
 * Check a write to an EPROCESS page.
 * @gpa       : target of the write
 * @new_value : 64-bit value being written
 *
 * Returns true if write is allowed, false if blocked (token steal detected).
 */
bool gr_token_check_write(gr_token_state_t *state,
                          uint64_t gpa, uint64_t new_value);

/* Periodic scan: verify all monitored process tokens unchanged */
int  gr_token_scan(gr_token_state_t *state);

#endif /* GHOSTRING_MONITOR_TOKEN_H */
