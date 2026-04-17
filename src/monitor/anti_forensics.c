/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

#include "anti_forensics.h"
#include "alerts.h"

void gr_antiforensics_init(gr_antiforensics_state_t *state)
{
    state->count = 0;
    state->current_filetime = 0;
}

void gr_antiforensics_watch(gr_antiforensics_state_t *state,
                            uint64_t gpa, uint64_t size, const char *name)
{
    if (state->count >= GR_MAX_WATCHED_REGIONS)
        return;

    gr_watched_region_t *r = &state->regions[state->count];
    r->gpa = gpa;
    r->size = size;
    r->zero_write_count = 0;

    uint32_t i;
    for (i = 0; i < 31 && name[i]; i++)
        r->name[i] = name[i];
    r->name[i] = '\0';

    state->count++;
}

void gr_antiforensics_set_time(gr_antiforensics_state_t *state, uint64_t filetime)
{
    state->current_filetime = filetime;
}

bool gr_antiforensics_check_timestamp(gr_antiforensics_state_t *state,
                                      uint64_t new_time)
{
    if (state->current_filetime == 0)
        return false;  /* no reference time set yet */

    /*
     * Timestomping signature: new timestamp is significantly before
     * current time (attacker backdating files to avoid detection).
     * Threshold: 30 days in Windows FILETIME units (100ns ticks).
     */
    if (new_time < state->current_filetime &&
        (state->current_filetime - new_time) > GR_TIMESTOMP_THRESHOLD) {
        GR_LOG("TIMESTOMP: new time ", new_time);
        return true;
    }

    /*
     * Another indicator: sub-second precision all zeros.
     * Legitimate timestamps have non-zero sub-second fields.
     * Timestomping tools often set clean round timestamps.
     */
    if ((new_time % 10000000ULL) == 0 && new_time != 0) {
        /* Clean round second — suspicious but not definitive */
        /* Only alert if combined with other indicators */
    }

    return false;
}

bool gr_antiforensics_check_wipe(gr_antiforensics_state_t *state,
                                 uint64_t gpa, uint64_t value, uint32_t size)
{
    for (uint32_t i = 0; i < state->count; i++) {
        gr_watched_region_t *r = &state->regions[i];
        if (gpa >= r->gpa && gpa < r->gpa + r->size) {
            if (value == 0) {
                r->zero_write_count++;
                /*
                 * Heuristic: 8+ consecutive zero writes to a watched
                 * region indicates bulk zeroing (evidence destruction).
                 * Normal kernel operations rarely zero large contiguous
                 * regions of security-relevant structures.
                 */
                if (r->zero_write_count >= 8) {
                    GR_LOG("MEM WIPE detected at ", gpa);
                    r->zero_write_count = 0;  /* reset after alert */
                    return true;
                }
            } else {
                r->zero_write_count = 0;  /* non-zero write resets counter */
            }
        }
    }

    return false;
}
