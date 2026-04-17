/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

#include "supply_chain.h"
#include "alerts.h"
#include "integrity.h"  /* for gr_crc32 */

void gr_supply_chain_init(gr_supply_chain_state_t *state)
{
    state->count = 0;
}

void gr_supply_chain_register(gr_supply_chain_state_t *state,
                              uint64_t base_gpa,
                              uint64_t text_gpa, uint64_t text_size,
                              const char *name, bool is_signed)
{
    if (state->count >= GR_MAX_TRUSTED_MODULES)
        return;

    gr_trusted_module_t *m = &state->modules[state->count];
    m->base_gpa = base_gpa;
    m->text_gpa = text_gpa;
    m->text_size = text_size;
    m->is_signed = is_signed;
    m->active = true;

    /* Compute baseline CRC32C of .text section */
    m->text_crc32 = gr_crc32((const void *)(uintptr_t)text_gpa, text_size);

    /* Copy name */
    uint32_t i;
    for (i = 0; i < 63 && name[i]; i++)
        m->name[i] = name[i];
    m->name[i] = '\0';

    state->count++;
    GR_LOG("supply_chain: registered module at GPA ", base_gpa);
}

int gr_supply_chain_verify(gr_supply_chain_state_t *state)
{
    int tampered = 0;

    for (uint32_t i = 0; i < state->count; i++) {
        gr_trusted_module_t *m = &state->modules[i];
        if (!m->active)
            continue;

        uint32_t current = gr_crc32((const void *)(uintptr_t)m->text_gpa,
                                    m->text_size);

        if (current != m->text_crc32) {
            GR_LOG("BINARY TAMPER: .text CRC mismatch at ", m->base_gpa);
            tampered++;
            /* Update CRC to avoid repeated alerts */
            m->text_crc32 = current;
        }
    }

    return tampered;
}

bool gr_supply_chain_check_load(gr_supply_chain_state_t *state,
                                const char *name, bool is_signed)
{
    (void)state;

    /*
     * Heuristic: unsigned modules are suspicious.
     * A proper implementation would also check:
     *   - Load path (System32 vs CWD vs temp)
     *   - Publisher trust chain
     *   - Hash against known-good database
     *
     * For now, flag any unsigned module as suspicious.
     */
    if (!is_signed) {
        GR_LOG_STR("supply_chain: unsigned module loaded");
        return true;  /* suspicious */
    }

    (void)name;
    return false;  /* looks ok */
}
