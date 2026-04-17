/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
#include "token.h"
#include "alerts.h"

void gr_token_init(gr_token_state_t *state,
                   uint64_t system_token_value,
                   uint64_t token_offset)
{
    state->system_token_value = system_token_value;
    state->eprocess_token_offset = token_offset;
    state->proc_count = 0;
}

void gr_token_monitor_process(gr_token_state_t *state,
                              uint64_t eprocess_gpa, uint32_t pid)
{
    if (state->proc_count >= GR_MAX_MONITORED_PROCS)
        return;

    uint32_t idx = state->proc_count++;
    state->procs[idx].eprocess_gpa = eprocess_gpa;
    state->procs[idx].pid = pid;

    /* Read current token value as baseline */
    uint64_t token_gpa = eprocess_gpa + state->eprocess_token_offset;
    state->procs[idx].original_token = *(volatile uint64_t *)(uintptr_t)token_gpa;
}

bool gr_token_check_write(gr_token_state_t *state,
                          uint64_t gpa, uint64_t new_value)
{
    for (uint32_t i = 0; i < state->proc_count; i++) {
        uint64_t token_gpa = state->procs[i].eprocess_gpa +
                             state->eprocess_token_offset;

        /* Check if write targets the Token field (within 8 bytes) */
        if (gpa >= token_gpa && gpa < token_gpa + 8) {
            /*
             * Token values have low 4 bits used as reference count flags.
             * Mask them off for comparison (Windows uses _EX_FAST_REF).
             */
            uint64_t new_token_base = new_value & ~0xFULL;
            uint64_t sys_token_base = state->system_token_value & ~0xFULL;

            if (new_token_base == sys_token_base &&
                state->procs[i].original_token != state->system_token_value) {
                /*
                 * A non-SYSTEM process is acquiring the SYSTEM token.
                 * This is the classic privilege escalation endgame.
                 */
                GR_LOG("TOKEN STEAL: PID ", (uint64_t)state->procs[i].pid);
                return false;  /* BLOCK */
            }

            /* Update baseline for legitimate token changes */
            state->procs[i].original_token = new_value;
        }
    }

    return true;  /* ALLOW */
}

int gr_token_scan(gr_token_state_t *state)
{
    int stolen = 0;

    for (uint32_t i = 0; i < state->proc_count; i++) {
        uint64_t token_gpa = state->procs[i].eprocess_gpa +
                             state->eprocess_token_offset;
        uint64_t current = *(volatile uint64_t *)(uintptr_t)token_gpa;

        uint64_t cur_base = current & ~0xFULL;
        uint64_t sys_base = state->system_token_value & ~0xFULL;
        uint64_t orig_base = state->procs[i].original_token & ~0xFULL;

        if (cur_base == sys_base && orig_base != sys_base) {
            GR_LOG("TOKEN SCAN: stolen token at PID ", (uint64_t)state->procs[i].pid);
            stolen++;
        }
    }

    return stolen;
}
