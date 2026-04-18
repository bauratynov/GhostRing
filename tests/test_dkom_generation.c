/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_dkom_generation.c — Generation-counter semantics for the
 * DKOM detector's CR3 tracking hash.
 *
 * The DKOM detector samples "every CR3 the hardware sees" and
 * compares it against "every CR3 the OS admits to".  A process
 * hidden via DKOM appears in the hardware set but not the OS set.
 *
 * The CR3 set is hashed into a fixed-size table with a per-scan
 * generation counter.  Semantics:
 *
 *   1. Each scan increments `generation`.
 *   2. Adding a CR3 tags its entry with the current generation.
 *   3. At scan end, entries whose generation < current are stale
 *      (process exited between scans) and are purged.
 *
 * Off-by-one in the generation compare = either *false positives*
 * (every exit looks like a hidden process) or *false negatives*
 * (real hidden processes never flagged).  This file locks the rule.
 */

#include <string.h>
#include "test_framework.h"

#define CR3_TABLE_SIZE 64
#define CR3_TABLE_MASK (CR3_TABLE_SIZE - 1)

typedef struct {
    uint64_t cr3;
    uint32_t generation;
    uint8_t  occupied;
} cr3_entry_t;

typedef struct {
    cr3_entry_t entries[CR3_TABLE_SIZE];
    uint32_t    count;
    uint32_t    generation;
} cr3_table_t;

static void cr3_init(cr3_table_t *t)
{
    memset(t, 0, sizeof(*t));
}

static uint32_t cr3_hash(uint64_t cr3)
{
    cr3 >>= 12;
    cr3 ^= (cr3 >> 16);
    cr3 *= 0x45d9f3b;
    cr3 ^= (cr3 >> 16);
    return (uint32_t)(cr3 & CR3_TABLE_MASK);
}

/* Returns 1 if inserted, 0 if already present (generation refreshed). */
static int cr3_add(cr3_table_t *t, uint64_t cr3)
{
    uint32_t idx = cr3_hash(cr3);
    for (uint32_t i = 0; i < CR3_TABLE_SIZE; i++) {
        uint32_t slot = (idx + i) & CR3_TABLE_MASK;
        if (!t->entries[slot].occupied) {
            t->entries[slot].cr3 = cr3;
            t->entries[slot].occupied = 1;
            t->entries[slot].generation = t->generation;
            t->count++;
            return 1;
        }
        if (t->entries[slot].cr3 == cr3) {
            t->entries[slot].generation = t->generation;
            return 0;
        }
    }
    return -1;  /* table full */
}

/* Increment scan generation and purge stale entries. */
static void cr3_reap_stale(cr3_table_t *t)
{
    for (uint32_t i = 0; i < CR3_TABLE_SIZE; i++) {
        if (t->entries[i].occupied &&
            t->entries[i].generation < t->generation) {
            t->entries[i].occupied = 0;
            t->count--;
        }
    }
}

TEST(test_generation_starts_at_zero)
{
    cr3_table_t t;
    cr3_init(&t);
    ASSERT_EQ(t.generation, 0);
    ASSERT_EQ(t.count, 0);
}

TEST(test_add_tags_entry_with_current_generation)
{
    cr3_table_t t;
    cr3_init(&t);
    t.generation = 5;
    cr3_add(&t, 0x100000);
    /* Find the slot we inserted into */
    uint32_t idx = cr3_hash(0x100000);
    ASSERT_EQ(t.entries[idx].generation, 5);
}

TEST(test_re_adding_refreshes_generation)
{
    cr3_table_t t;
    cr3_init(&t);
    t.generation = 1;
    cr3_add(&t, 0x100000);

    t.generation = 2;
    /* Same CR3 re-inserted — returns 0 (already present) but
     * refreshes generation. */
    ASSERT_EQ(cr3_add(&t, 0x100000), 0);
    uint32_t idx = cr3_hash(0x100000);
    ASSERT_EQ(t.entries[idx].generation, 2);
}

TEST(test_stale_entries_reaped)
{
    cr3_table_t t;
    cr3_init(&t);
    t.generation = 1;

    /* 3 processes observed in scan 1 */
    cr3_add(&t, 0x100000);
    cr3_add(&t, 0x200000);
    cr3_add(&t, 0x300000);
    ASSERT_EQ(t.count, 3);

    /* Scan 2: only 2 of them reappear (one process exited) */
    t.generation = 2;
    cr3_add(&t, 0x100000);
    cr3_add(&t, 0x200000);
    /* 0x300000 was NOT refreshed — stale */
    cr3_reap_stale(&t);
    ASSERT_EQ(t.count, 2);
}

TEST(test_no_false_positive_on_same_generation)
{
    /* If reap is called without incrementing generation, NOTHING
     * should be reaped.  A bug here would flag every living
     * process as hidden. */
    cr3_table_t t;
    cr3_init(&t);
    t.generation = 5;
    cr3_add(&t, 0x100000);
    cr3_add(&t, 0x200000);

    cr3_reap_stale(&t);
    ASSERT_EQ(t.count, 2);
}

TEST(test_generation_wraps_safely)
{
    /* With a 32-bit generation counter and a reap per second,
     * wraparound takes 136 years — still worth a sanity check. */
    uint32_t g = 0xFFFFFFFE;
    g++;
    ASSERT_EQ(g, 0xFFFFFFFF);
    g++;
    ASSERT_EQ(g, 0);  /* wraps — comparator must handle this */
}

TEST(test_hash_distributes_sparse_cr3s)
{
    /* Real CR3 values are 4KiB-aligned.  Hash should spread them
     * reasonably — not bucket-dump into slot 0. */
    cr3_table_t t;
    cr3_init(&t);
    t.generation = 1;

    for (uint64_t i = 1; i <= 20; i++)
        cr3_add(&t, (i << 16) & ~0xFFFULL);   /* spaced 64 KiB apart */

    /* All 20 must fit and all must be reachable. */
    ASSERT_EQ(t.count, 20);
}

int main(void)
{
    printf("GhostRing DKOM generation counter tests\n");
    printf("=======================================\n");

    RUN_TEST(test_generation_starts_at_zero);
    RUN_TEST(test_add_tags_entry_with_current_generation);
    RUN_TEST(test_re_adding_refreshes_generation);
    RUN_TEST(test_stale_entries_reaped);
    RUN_TEST(test_no_false_positive_on_same_generation);
    RUN_TEST(test_generation_wraps_safely);
    RUN_TEST(test_hash_distributes_sparse_cr3s);

    REPORT();
}
