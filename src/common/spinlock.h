/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * spinlock.h — Ticket-based spinlock for short critical sections.
 *
 * A ticket lock guarantees strict FIFO ordering among waiters, which
 * prevents starvation that naive test-and-set locks suffer from under
 * contention.  The PAUSE instruction inside the spin loop prevents
 * excessive power draw and avoids Intel's memory-order-violation
 * pipeline flush on tight loops.
 *
 * These locks must only be held with interrupts disabled — a preempted
 * lock holder on the same CPU would deadlock.
 */

#ifndef GHOSTRING_SPINLOCK_H
#define GHOSTRING_SPINLOCK_H

#include "types.h"

/* ── Type ────────────────────────────────────────────────────────────────── */

typedef struct {
    volatile uint32_t ticket;   /* next ticket to hand out           */
    volatile uint32_t serving;  /* ticket currently being served     */
} gr_spinlock_t;

/* Convenience initializer for static / stack allocation. */
#define GR_SPINLOCK_INIT { 0, 0 }

/* ── API ─────────────────────────────────────────────────────────────────── */

static inline void gr_spin_init(gr_spinlock_t *lock)
{
    lock->ticket  = 0;
    lock->serving = 0;
    /* Ensure the stores are visible before anyone tries to acquire. */
    __asm__ volatile("" ::: "memory");
}

static inline void gr_spin_lock(gr_spinlock_t *lock)
{
    /*
     * Atomically take the next ticket number.  __ATOMIC_SEQ_CST gives
     * us a full barrier so no loads/stores leak past the acquisition.
     */
    uint32_t my_ticket = __atomic_fetch_add(&lock->ticket, 1,
                                            __ATOMIC_SEQ_CST);

    /* Spin until our ticket is called. */
    while (__atomic_load_n(&lock->serving, __ATOMIC_ACQUIRE) != my_ticket) {
        __asm__ volatile("pause");
    }
}

static inline void gr_spin_unlock(gr_spinlock_t *lock)
{
    /*
     * Advance to the next ticket.  RELEASE ordering ensures all
     * stores inside the critical section are visible before the
     * lock is dropped.
     */
    __atomic_fetch_add(&lock->serving, 1, __ATOMIC_RELEASE);
}

/* ── Convenience: lock with interrupts disabled ──────────────────────────── */

/*
 * Saves RFLAGS, disables interrupts, then acquires the lock.
 * Returns the saved RFLAGS value for gr_spin_unlock_irqrestore.
 */
static inline uint64_t gr_spin_lock_irqsave(gr_spinlock_t *lock)
{
    uint64_t flags;
    __asm__ volatile("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    gr_spin_lock(lock);
    return flags;
}

/*
 * Releases the lock and restores the RFLAGS value saved by
 * gr_spin_lock_irqsave, re-enabling interrupts if they were on.
 */
static inline void gr_spin_unlock_irqrestore(gr_spinlock_t *lock,
                                              uint64_t flags)
{
    gr_spin_unlock(lock);
    __asm__ volatile("pushq %0; popfq" : : "r"(flags) : "memory");
}

#endif /* GHOSTRING_SPINLOCK_H */
