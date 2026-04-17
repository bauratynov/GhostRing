/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * supply_chain.h — Supply chain attack detection.
 *
 * Detections:
 *   1. DLL hijacking: unsigned module loaded from unexpected path
 *      (CWD or temp instead of System32).  Used by APT campaigns
 *      including the CPU-Z 2.19 supply chain attack (April 2026).
 *   2. Signed binary tampering: in-memory .text section modification
 *      of a signed PE, detected via CRC32C mismatch.
 *
 * Reference: MITRE ATT&CK T1574.001 (DLL Search Order Hijacking)
 *            Kaspersky ML-Based DLL Hijacking Detection (2025)
 */

#ifndef GHOSTRING_MONITOR_SUPPLY_CHAIN_H
#define GHOSTRING_MONITOR_SUPPLY_CHAIN_H

#include "../common/ghostring.h"

#define GR_MAX_TRUSTED_MODULES 256

typedef struct {
    uint64_t base_gpa;          /* module base in guest physical memory */
    uint64_t text_gpa;          /* .text section start GPA */
    uint64_t text_size;         /* .text section size */
    uint32_t text_crc32;        /* CRC32C at load time */
    char     name[64];          /* module name */
    bool     is_signed;         /* Authenticode signed */
    bool     active;
} gr_trusted_module_t;

typedef struct {
    gr_trusted_module_t modules[GR_MAX_TRUSTED_MODULES];
    uint32_t count;
} gr_supply_chain_state_t;

void gr_supply_chain_init(gr_supply_chain_state_t *state);

void gr_supply_chain_register(gr_supply_chain_state_t *state,
                              uint64_t base_gpa,
                              uint64_t text_gpa, uint64_t text_size,
                              const char *name, bool is_signed);

/* Verify .text section integrity of all registered modules.
 * Returns number of tampered modules. */
int gr_supply_chain_verify(gr_supply_chain_state_t *state);

/* Check if a newly loaded module is suspicious.
 * Returns true if suspicious (unsigned from unexpected path). */
bool gr_supply_chain_check_load(gr_supply_chain_state_t *state,
                                const char *name, bool is_signed);

#endif /* GHOSTRING_MONITOR_SUPPLY_CHAIN_H */
