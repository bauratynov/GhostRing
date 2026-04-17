/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

#include "callbacks.h"
#include "alerts.h"

void gr_callback_init(gr_callback_state_t *state)
{
    state->count = 0;
    for (uint32_t i = 0; i < GR_MAX_CALLBACK_ARRAYS; i++)
        state->arrays[i].armed = false;
}

void gr_callback_register(gr_callback_state_t *state,
                          uint64_t gpa, uint32_t entries,
                          uint32_t entry_size,
                          uint64_t kernel_low, uint64_t kernel_high,
                          const char *name)
{
    if (state->count >= GR_MAX_CALLBACK_ARRAYS)
        return;

    gr_callback_array_t *arr = &state->arrays[state->count];
    arr->gpa = gpa;
    arr->entry_count = entries > GR_MAX_CALLBACKS_PER_ARRAY
                     ? GR_MAX_CALLBACKS_PER_ARRAY : entries;
    arr->entry_size = entry_size;
    arr->kernel_low = kernel_low;
    arr->kernel_high = kernel_high;
    arr->armed = false;

    /* Copy name safely */
    uint32_t j;
    for (j = 0; j < 31 && name[j]; j++)
        arr->name[j] = name[j];
    arr->name[j] = '\0';

    state->count++;
}

void gr_callback_snapshot(gr_callback_state_t *state)
{
    for (uint32_t i = 0; i < state->count; i++) {
        gr_callback_array_t *arr = &state->arrays[i];
        /*
         * Read current callback pointers from guest memory.
         * Under identity-mapped EPT, GPA == HVA for kernel direct-map.
         */
        const uint64_t *ptrs = (const uint64_t *)(uintptr_t)arr->gpa;
        for (uint32_t j = 0; j < arr->entry_count; j++)
            arr->baseline[j] = ptrs[j];
        arr->armed = true;
    }
}

int gr_callback_check(gr_callback_state_t *state)
{
    int anomalies = 0;

    for (uint32_t i = 0; i < state->count; i++) {
        gr_callback_array_t *arr = &state->arrays[i];
        if (!arr->armed)
            continue;

        const uint64_t *ptrs = (const uint64_t *)(uintptr_t)arr->gpa;

        for (uint32_t j = 0; j < arr->entry_count; j++) {
            uint64_t current = ptrs[j];
            uint64_t expected = arr->baseline[j];

            if (current == expected)
                continue;

            /* Callback changed since baseline */
            if (current == 0 && expected != 0) {
                /* Callback removed — EDR blinding attack */
                GR_LOG("callback removed: ", expected);
                anomalies++;
            } else if (current != 0 &&
                       (current < arr->kernel_low || current > arr->kernel_high)) {
                /* New callback points outside kernel module range */
                GR_LOG("callback points outside kernel: ", current);
                anomalies++;
            } else {
                /* Callback changed to another valid kernel address */
                anomalies++;
            }

            /* Update baseline to avoid repeated alerts */
            arr->baseline[j] = current;
        }
    }

    return anomalies;
}

bool gr_callback_is_monitored(gr_callback_state_t *state, uint64_t gpa)
{
    for (uint32_t i = 0; i < state->count; i++) {
        gr_callback_array_t *arr = &state->arrays[i];
        uint64_t array_end = arr->gpa + (uint64_t)arr->entry_count * arr->entry_size;
        if (gpa >= arr->gpa && gpa < array_end)
            return true;
    }
    return false;
}
