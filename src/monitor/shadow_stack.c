/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * shadow_stack.c — Hypervisor-managed return address shadow stack.
 *
 * This module provides software-based return address protection for
 * CPUs that lack Intel CET support.  It detects ROP (Return-Oriented
 * Programming) attacks by maintaining a hypervisor-controlled copy
 * of return addresses that the guest cannot tamper with.
 *
 * Real-world attacks detected:
 *   - Classic ROP chains: used by virtually every modern kernel exploit
 *     (EternalBlue/MS17-010, BlueKeep/CVE-2019-0708, PrintNightmare).
 *   - Stack pivot: the attacker redirects RSP to a controlled buffer
 *     containing fake return addresses.  The shadow stack still holds
 *     the legitimate addresses, so every RET triggers a mismatch.
 *   - JOP (Jump-Oriented Programming): while JOP uses indirect jumps
 *     rather than returns, many JOP chains include RET instructions
 *     for cleanup, which we catch.
 *
 * Overhead consideration:
 *   MTF (Monitor Trap Flag) causes a VM-exit after every guest
 *   instruction.  At ~1000 cycles per VM-exit, this reduces guest
 *   throughput by roughly 100x.  Therefore:
 *     - ONLY enable for critical processes (lsass.exe, csrss.exe).
 *     - Consider enabling only during high-risk windows (e.g., while
 *       processing untrusted input).
 *     - On CET-capable CPUs, use hardware shadow stacks instead.
 */

#include "shadow_stack.h"
#include "alerts.h"

/* ── Internal helpers ──────────────────────────────────────────────────── */

/*
 * Find the shadow stack for a given CR3.  Returns NULL if the process
 * is not being monitored.
 */
static gr_shadow_stack_t *find_stack(gr_shadow_stack_mgr_t *mgr,
                                     uint64_t cr3)
{
    for (uint32_t i = 0; i < GR_SHADOW_STACK_MAX_PROCS; i++) {
        if (mgr->stacks[i].active && mgr->stacks[i].cr3 == cr3)
            return &mgr->stacks[i];
    }
    return NULL;
}

/*
 * Allocate a new shadow stack slot for the given CR3.
 */
static gr_shadow_stack_t *alloc_stack(gr_shadow_stack_mgr_t *mgr,
                                      uint64_t cr3)
{
    for (uint32_t i = 0; i < GR_SHADOW_STACK_MAX_PROCS; i++) {
        if (!mgr->stacks[i].active) {
            gr_shadow_stack_t *ss = &mgr->stacks[i];

            /* Zero the entries */
            for (uint32_t j = 0; j < GR_SHADOW_STACK_DEPTH; j++)
                ss->entries[j] = 0;

            ss->top        = 0;
            ss->count      = 0;
            ss->cr3        = cr3;
            ss->mismatches = 0;
            ss->active     = true;

            return ss;
        }
    }
    return NULL;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void gr_shadow_stack_init(gr_shadow_stack_mgr_t *mgr)
{
    if (!mgr)
        return;

    uint8_t *p = (uint8_t *)mgr;
    for (uint64_t i = 0; i < sizeof(*mgr); i++)
        p[i] = 0;

    mgr->initialised = true;

    GR_LOG_STR("shadow_stack: manager initialised");
    GR_LOG_STR("shadow_stack: WARNING — MTF single-step is expensive, "
               "enable only for high-value processes");
}

int gr_shadow_stack_enable(gr_shadow_stack_mgr_t *mgr, uint64_t cr3)
{
    if (!mgr || !mgr->initialised)
        return -1;

    /* Check if already monitored */
    for (uint32_t i = 0; i < mgr->monitored_count; i++) {
        if (mgr->monitored_cr3[i] == cr3)
            return 0;  /* Already enabled */
    }

    if (mgr->monitored_count >= GR_SHADOW_STACK_MAX_PROCS) {
        GR_LOG_STR("shadow_stack: cannot enable — max processes reached");
        return -1;
    }

    /* Allocate a shadow stack for this process */
    gr_shadow_stack_t *ss = alloc_stack(mgr, cr3);
    if (!ss) {
        GR_LOG_STR("shadow_stack: cannot allocate stack slot");
        return -1;
    }

    mgr->monitored_cr3[mgr->monitored_count] = cr3;
    mgr->monitored_count++;

    GR_LOG("shadow_stack: enabled for CR3=", cr3);

    return 0;
}

void gr_shadow_stack_disable(gr_shadow_stack_mgr_t *mgr, uint64_t cr3)
{
    if (!mgr || !mgr->initialised)
        return;

    /* Remove from monitored list */
    for (uint32_t i = 0; i < mgr->monitored_count; i++) {
        if (mgr->monitored_cr3[i] == cr3) {
            /* Shift remaining entries down */
            for (uint32_t j = i; j < mgr->monitored_count - 1; j++)
                mgr->monitored_cr3[j] = mgr->monitored_cr3[j + 1];
            mgr->monitored_count--;
            break;
        }
    }

    /* Deactivate the stack */
    gr_shadow_stack_t *ss = find_stack(mgr, cr3);
    if (ss)
        ss->active = false;

    GR_LOG("shadow_stack: disabled for CR3=", cr3);
}

bool gr_shadow_stack_is_monitored(const gr_shadow_stack_mgr_t *mgr,
                                  uint64_t cr3)
{
    if (!mgr || !mgr->initialised)
        return false;

    for (uint32_t i = 0; i < mgr->monitored_count; i++) {
        if (mgr->monitored_cr3[i] == cr3)
            return true;
    }

    return false;
}

void gr_shadow_push(gr_shadow_stack_mgr_t *mgr,
                    uint64_t cr3,
                    uint64_t ret_addr)
{
    if (!mgr || !mgr->initialised)
        return;

    gr_shadow_stack_t *ss = find_stack(mgr, cr3);
    if (!ss)
        return;

    /*
     * Push the return address onto the ring buffer.  If the buffer
     * is full, we wrap around — losing the oldest entry.  This means
     * very deep recursion (>256 levels) will not be fully tracked,
     * but this covers the vast majority of real call chains.
     */
    ss->entries[ss->top] = ret_addr;
    ss->top = (ss->top + 1) % GR_SHADOW_STACK_DEPTH;

    if (ss->count < GR_SHADOW_STACK_DEPTH)
        ss->count++;
}

bool gr_shadow_check(gr_shadow_stack_mgr_t *mgr,
                     uint64_t cr3,
                     uint64_t ret_addr,
                     uint64_t rip)
{
    if (!mgr || !mgr->initialised)
        return true;  /* Not initialised — assume clean */

    gr_shadow_stack_t *ss = find_stack(mgr, cr3);
    if (!ss)
        return true;  /* Not monitored — assume clean */

    if (ss->count == 0) {
        /*
         * Shadow stack is empty.  This can happen if monitoring was
         * enabled mid-execution (after several CALLs that we missed).
         * Do not alert — we have no baseline to compare against.
         */
        return true;
    }

    /*
     * Pop the most recent return address from the shadow stack.
     * The top pointer is one past the last push, so we decrement
     * first (with wrap-around).
     */
    uint32_t idx = (ss->top == 0) ? GR_SHADOW_STACK_DEPTH - 1 : ss->top - 1;
    uint64_t expected = ss->entries[idx];

    /* Consume the entry */
    ss->top = idx;
    ss->count--;

    if (expected == ret_addr) {
        /* Return address matches — no tampering */
        return true;
    }

    /*
     * MISMATCH — the return address on the real stack differs from
     * what was pushed by the corresponding CALL.  This indicates:
     *   - Stack buffer overflow corrupting the return address
     *   - ROP chain manipulation
     *   - Stack pivot to attacker-controlled memory
     *
     * This is a HIGH-SEVERITY detection.
     */
    ss->mismatches++;

    gr_alert_emit(GR_ALERT_ROP_DETECTED,
                  rip,
                  cr3,
                  0,              /* GPA not applicable */
                  ret_addr);      /* info = actual (corrupted) return addr */

    GR_LOG("shadow_stack: ROP DETECTED — return address mismatch!");
    GR_LOG("  rip=", rip);
    GR_LOG("  expected=", expected);
    GR_LOG("  actual=",   ret_addr);
    GR_LOG("  cr3=", cr3);

    return false;
}
