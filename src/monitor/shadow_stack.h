/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * shadow_stack.h — Return address protection via hypervisor-managed
 *                  shadow stack (lightweight CFI).
 *
 * Return-Oriented Programming (ROP) remains the dominant exploitation
 * technique for bypassing DEP/NX.  ROP works by corrupting return
 * addresses on the stack to chain together short code sequences
 * ("gadgets") from legitimate modules.
 *
 * A shadow stack is a separate, attacker-inaccessible copy of return
 * addresses.  On every CALL, we push the return address onto the
 * shadow stack.  On every RET, we compare the actual return address
 * against the shadow — any mismatch indicates stack corruption
 * (buffer overflow, ROP chain, etc.).
 *
 * Implementation:
 *   - We use the Monitor Trap Flag (MTF) or single-step VM-exits to
 *     observe CALL and RET instructions.
 *   - Shadow stacks are per-thread, identified by CR3 + RSP.
 *   - This is EXPENSIVE: MTF causes a VM-exit on every instruction.
 *     Therefore, shadow stack monitoring is only enabled for high-value
 *     processes (e.g., lsass.exe, csrss.exe) via per-CR3 configuration.
 *
 * Performance:
 *   - The ring buffer is sized to accommodate deeply nested call chains
 *     (up to 256 levels).  Overflow wraps silently — we cannot detect
 *     mismatches deeper than the buffer, but 256 levels covers >99%
 *     of real call chains.
 *   - No heap allocation in the hot path.
 *
 * Note: Intel CET (Control-flow Enforcement Technology) provides
 * hardware shadow stacks.  On CPUs that support CET, prefer enabling
 * it via CR4.CET rather than this software approach.  This module
 * exists for CPUs without CET support.
 */

#ifndef GHOSTRING_MONITOR_SHADOW_STACK_H
#define GHOSTRING_MONITOR_SHADOW_STACK_H

#include "../common/ghostring.h"

/* ── Constants ──────────────────────────────────────────────────────────── */

/*
 * Shadow stack ring buffer depth.  256 entries covers the deepest
 * call chains in typical kernel and user-mode code.  Recursive
 * functions may exceed this, but the wrap-around simply means we
 * lose history for the deepest frames — no functional impact.
 */
#define GR_SHADOW_STACK_DEPTH       256

/*
 * Maximum number of processes (CR3 values) that can be simultaneously
 * monitored with shadow stacks.  Each monitored process gets its own
 * ring buffer.
 */
#define GR_SHADOW_STACK_MAX_PROCS   8

/* ── Per-thread shadow stack ────────────────────────────────────────────── */

typedef struct gr_shadow_stack {
    /*
     * Circular buffer of return addresses.  The write pointer
     * advances on CALL and retreats on RET.
     */
    uint64_t entries[GR_SHADOW_STACK_DEPTH];

    uint32_t top;               /* Index of the next free slot           */
    uint32_t count;             /* Number of valid entries               */
    uint64_t cr3;               /* Owning process page-table root        */
    uint32_t mismatches;        /* Lifetime mismatch count               */
    bool     active;            /* Slot in use                           */
} gr_shadow_stack_t;

/* ── Shadow stack manager ───────────────────────────────────────────────── */

typedef struct gr_shadow_stack_mgr {
    gr_shadow_stack_t stacks[GR_SHADOW_STACK_MAX_PROCS];

    /*
     * CR3 whitelist: only processes with a CR3 in this list have
     * shadow stack monitoring enabled.  This avoids the crippling
     * overhead of single-stepping every process.
     */
    uint64_t monitored_cr3[GR_SHADOW_STACK_MAX_PROCS];
    uint32_t monitored_count;

    bool     initialised;
} gr_shadow_stack_mgr_t;

/* ── Public API ─────────────────────────────────────────────────────────── */

/*
 * gr_shadow_stack_init — Initialise the shadow stack manager.
 *
 * @mgr : Manager state to initialise.
 */
void gr_shadow_stack_init(gr_shadow_stack_mgr_t *mgr);

/*
 * gr_shadow_stack_enable — Enable shadow stack monitoring for a
 *                           specific process identified by CR3.
 *
 * When this process's CR3 is active and MTF is enabled, CALL/RET
 * instructions will be tracked.
 *
 * @mgr : Manager state.
 * @cr3 : Process page-table root to monitor.
 *
 * Returns 0 on success, -1 if the table is full.
 */
int gr_shadow_stack_enable(gr_shadow_stack_mgr_t *mgr, uint64_t cr3);

/*
 * gr_shadow_stack_disable — Stop monitoring a specific process.
 *
 * @mgr : Manager state.
 * @cr3 : Process page-table root to stop monitoring.
 */
void gr_shadow_stack_disable(gr_shadow_stack_mgr_t *mgr, uint64_t cr3);

/*
 * gr_shadow_stack_is_monitored — Check whether a CR3 is in the
 *                                 monitored set.
 *
 * Called from the MTF exit handler to decide whether to process
 * the instruction.
 *
 * @mgr : Manager state.
 * @cr3 : Process page-table root to check.
 *
 * Returns true if the process is monitored.
 */
bool gr_shadow_stack_is_monitored(const gr_shadow_stack_mgr_t *mgr,
                                  uint64_t cr3);

/*
 * gr_shadow_push — Record a return address for a CALL instruction.
 *
 * Called when a CALL instruction is decoded from an MTF single-step
 * exit in a monitored process.
 *
 * @mgr      : Manager state.
 * @cr3      : Current process CR3.
 * @ret_addr : Return address pushed by the CALL.
 */
void gr_shadow_push(gr_shadow_stack_mgr_t *mgr,
                    uint64_t cr3,
                    uint64_t ret_addr);

/*
 * gr_shadow_check — Verify a return address for a RET instruction.
 *
 * Called when a RET instruction is decoded from an MTF single-step
 * exit in a monitored process.  Compares the actual return address
 * against the shadow stack.
 *
 * @mgr      : Manager state.
 * @cr3      : Current process CR3.
 * @ret_addr : Actual return address the RET will jump to.
 * @rip      : Current RIP (for alert context).
 *
 * Returns true if the return address matches (clean), false if
 * a mismatch is detected (possible ROP).
 */
bool gr_shadow_check(gr_shadow_stack_mgr_t *mgr,
                     uint64_t cr3,
                     uint64_t ret_addr,
                     uint64_t rip);

#endif /* GHOSTRING_MONITOR_SHADOW_STACK_H */
