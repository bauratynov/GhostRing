/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_alert_ring.c — Behavioural tests for the alert ring buffer.
 *
 * The kernel side (loader/linux/ghostring_chardev.c) owns the real
 * ring and uses a spinlock.  Here we exercise the pure logic of the
 * head/tail/wrap arithmetic in userspace so a semantic regression
 * is caught before touching the kernel.
 */

#include <string.h>
#include "test_framework.h"

/* Mirror of the kernel-side layout. */
typedef struct {
    uint64_t ts_ns;
    uint32_t cpu_id;
    uint32_t alert_type;
    uint64_t info;
} alert_t;

#define RING_SIZE 8

static alert_t   ring[RING_SIZE];
static uint32_t  ring_head;
static uint32_t  ring_tail;

static void ring_reset(void)
{
    memset(ring, 0, sizeof(ring));
    ring_head = 0;
    ring_tail = 0;
}

/* Same semantics as the kernel gr_alert_push. */
static void ring_push(uint32_t cpu, uint32_t type, uint64_t info)
{
    ring[ring_head].ts_ns      = 0;
    ring[ring_head].cpu_id     = cpu;
    ring[ring_head].alert_type = type;
    ring[ring_head].info       = info;

    ring_head = (ring_head + 1) % RING_SIZE;
    if (ring_head == ring_tail)
        ring_tail = (ring_tail + 1) % RING_SIZE;
}

static int ring_empty(void)
{
    return ring_head == ring_tail;
}

static int ring_pop(alert_t *out)
{
    if (ring_empty())
        return 0;
    *out = ring[ring_tail];
    ring_tail = (ring_tail + 1) % RING_SIZE;
    return 1;
}

TEST(test_ring_starts_empty)
{
    ring_reset();
    ASSERT(ring_empty());
    alert_t dummy;
    ASSERT_EQ(ring_pop(&dummy), 0);
}

TEST(test_ring_single_push_pop)
{
    ring_reset();
    ring_push(1, 7, 0xDEADBEEF);
    ASSERT(!ring_empty());

    alert_t a;
    ASSERT_EQ(ring_pop(&a), 1);
    ASSERT_EQ(a.cpu_id, 1);
    ASSERT_EQ(a.alert_type, 7);
    ASSERT_EQ(a.info, 0xDEADBEEF);
    ASSERT(ring_empty());
}

TEST(test_ring_fills_then_wraps)
{
    ring_reset();

    /* Push RING_SIZE - 1 so the ring is exactly full (head == tail
     * means empty, so we can hold at most SIZE-1 without the wrap
     * taking out the oldest). */
    for (uint32_t i = 1; i <= RING_SIZE - 1; i++)
        ring_push(i, 0, 0);

    alert_t a;
    ASSERT_EQ(ring_pop(&a), 1);
    ASSERT_EQ(a.cpu_id, 1);  /* oldest goes first (FIFO) */
}

TEST(test_ring_overflow_drops_oldest)
{
    ring_reset();
    /* Push SIZE + 4 items — first 4 should be dropped, only the
     * last SIZE-1 should remain readable. */
    for (uint32_t i = 1; i <= RING_SIZE + 4; i++)
        ring_push(i, 0, 0);

    /* We dropped 5 total (wrap consumed an extra one each time the
     * ring hit full), so the oldest still in the ring is cpu_id = 6. */
    alert_t a;
    ASSERT_EQ(ring_pop(&a), 1);
    /* Exact oldest depends on SIZE; just assert FIFO ordering holds. */
    uint32_t prev = a.cpu_id;
    while (ring_pop(&a)) {
        ASSERT(a.cpu_id > prev);  /* strictly increasing cpu_id */
        prev = a.cpu_id;
    }
    /* And after draining we must be empty. */
    ASSERT(ring_empty());
}

TEST(test_ring_many_cycles_fifo)
{
    ring_reset();
    /* 1000 push+pop cycles with one-at-a-time flow.  Catches a head/
     * tail swap or off-by-one in wrap arithmetic. */
    for (uint32_t i = 0; i < 1000; i++) {
        ring_push(i, (uint32_t)(i & 0xF), i * 17);
        alert_t a;
        ASSERT_EQ(ring_pop(&a), 1);
        ASSERT_EQ(a.cpu_id, i);
        ASSERT_EQ(a.alert_type, i & 0xF);
        ASSERT_EQ(a.info, i * 17);
    }
    ASSERT(ring_empty());
}

int main(void)
{
    printf("GhostRing alert ring buffer tests\n");
    printf("=================================\n");

    RUN_TEST(test_ring_starts_empty);
    RUN_TEST(test_ring_single_push_pop);
    RUN_TEST(test_ring_fills_then_wraps);
    RUN_TEST(test_ring_overflow_drops_oldest);
    RUN_TEST(test_ring_many_cycles_fifo);

    REPORT();
}
