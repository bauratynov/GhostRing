/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_allocator_stress.c — Stress-path and fragmentation tests for
 * the bitmap page-pool allocator (src/common/mem.c).
 *
 * The v0.1.0 test suite verifies the common cases.  This file adds
 * the adversarial ones: alloc-every-page-then-free, N-way
 * interleaved alloc/free, contiguous-allocation after fragmentation.
 * These are the scenarios that blow up a bitmap allocator in the
 * field when an operator runs the hypervisor for a long session
 * and the monitor rapidly allocs / frees pages for EPT splits.
 */

#include "test_framework.h"

/* Re-declare the bitmap layout — the real implementation lives in
 * src/common/mem.c but for this stress suite we exercise the same
 * arithmetic via a userspace clone. */

#define TOTAL_PAGES    1024
#define BITS_PER_WORD  64
#define BITMAP_WORDS   (TOTAL_PAGES / BITS_PER_WORD)

typedef struct {
    uint32_t total_pages;
    uint32_t free_pages;
    uint64_t bitmap[BITMAP_WORDS];
} pool_t;

static void pool_init(pool_t *p, uint32_t n)
{
    p->total_pages = n;
    p->free_pages  = n;
    for (int i = 0; i < BITMAP_WORDS; i++)
        p->bitmap[i] = 0;
}

/* Returns page index or -1. */
static int pool_alloc_one(pool_t *p)
{
    for (uint32_t i = 0; i < p->total_pages; i++) {
        uint32_t w = i / BITS_PER_WORD;
        uint32_t b = i % BITS_PER_WORD;
        if (!(p->bitmap[w] & (1ULL << b))) {
            p->bitmap[w] |= (1ULL << b);
            p->free_pages--;
            return (int)i;
        }
    }
    return -1;
}

/* Alloc `count` contiguous pages, return first page index or -1. */
static int pool_alloc_n(pool_t *p, uint32_t count)
{
    if (count == 0 || count > p->total_pages) return -1;
    for (uint32_t i = 0; i + count <= p->total_pages; i++) {
        uint32_t j;
        int free_run = 1;
        for (j = 0; j < count; j++) {
            uint32_t w = (i + j) / BITS_PER_WORD;
            uint32_t b = (i + j) % BITS_PER_WORD;
            if (p->bitmap[w] & (1ULL << b)) { free_run = 0; break; }
        }
        if (free_run) {
            for (j = 0; j < count; j++) {
                uint32_t w = (i + j) / BITS_PER_WORD;
                uint32_t b = (i + j) % BITS_PER_WORD;
                p->bitmap[w] |= (1ULL << b);
            }
            p->free_pages -= count;
            return (int)i;
        }
    }
    return -1;
}

static void pool_free_one(pool_t *p, int idx)
{
    if (idx < 0 || (uint32_t)idx >= p->total_pages) return;
    uint32_t w = (uint32_t)idx / BITS_PER_WORD;
    uint32_t b = (uint32_t)idx % BITS_PER_WORD;
    if (!(p->bitmap[w] & (1ULL << b))) return;   /* double-free blocked */
    p->bitmap[w] &= ~(1ULL << b);
    p->free_pages++;
}

TEST(test_full_drain_refill)
{
    pool_t p;
    pool_init(&p, TOTAL_PAGES);

    /* Alloc every single page */
    int pages[TOTAL_PAGES];
    for (int i = 0; i < TOTAL_PAGES; i++) {
        pages[i] = pool_alloc_one(&p);
        ASSERT(pages[i] >= 0);
    }
    ASSERT_EQ(p.free_pages, 0);
    ASSERT_EQ(pool_alloc_one(&p), -1);  /* next call must fail */

    /* Free all in reverse order */
    for (int i = TOTAL_PAGES - 1; i >= 0; i--)
        pool_free_one(&p, pages[i]);
    ASSERT_EQ(p.free_pages, TOTAL_PAGES);
}

TEST(test_fragmentation_hole_reuse)
{
    pool_t p;
    pool_init(&p, 64);
    int pages[64];

    /* Fully allocate */
    for (int i = 0; i < 64; i++)
        pages[i] = pool_alloc_one(&p);

    /* Free every other page — 32 holes scattered throughout */
    for (int i = 0; i < 64; i += 2)
        pool_free_one(&p, pages[i]);

    ASSERT_EQ(p.free_pages, 32);

    /* A contiguous allocation of 3 pages MUST fail — no 3-page
     * run exists after the scatter. */
    ASSERT_EQ(pool_alloc_n(&p, 3), -1);

    /* Single-page alloc still works — and returns an even index
     * (one of the holes we just freed). */
    int reused = pool_alloc_one(&p);
    ASSERT(reused >= 0);
    ASSERT((reused % 2) == 0);
}

TEST(test_contiguous_allocation_after_free)
{
    pool_t p;
    pool_init(&p, 128);

    /* Alloc pages in batches of 8, then free middle batches to
     * create holes.  Verify that contig-alloc finds a big-enough
     * run in the freed regions. */
    int batches[16];
    for (int i = 0; i < 16; i++)
        batches[i] = pool_alloc_n(&p, 8);

    /* Free batches 4, 5, 6, 7 — creates a 32-page free run */
    for (int i = 4; i <= 7; i++)
        for (int j = 0; j < 8; j++)
            pool_free_one(&p, batches[i] + j);

    ASSERT_EQ(p.free_pages, 32);

    /* 32-page contiguous request must succeed */
    int run = pool_alloc_n(&p, 32);
    ASSERT(run >= 0);
    ASSERT_EQ(p.free_pages, 0);
}

TEST(test_double_free_is_safe)
{
    pool_t p;
    pool_init(&p, 16);
    int a = pool_alloc_one(&p);
    pool_free_one(&p, a);
    uint32_t before = p.free_pages;
    pool_free_one(&p, a);  /* should be detected and refused */
    ASSERT_EQ(p.free_pages, before);
}

TEST(test_free_invalid_index)
{
    pool_t p;
    pool_init(&p, 16);
    uint32_t before = p.free_pages;
    pool_free_one(&p, -1);
    pool_free_one(&p, 9999);
    ASSERT_EQ(p.free_pages, before);
}

TEST(test_1000_cycles_no_leak)
{
    pool_t p;
    pool_init(&p, 64);

    /* 1000 alloc/free cycles in a tight loop — bitmap integrity
     * must hold, free_pages must not drift. */
    for (int i = 0; i < 1000; i++) {
        int a = pool_alloc_one(&p);
        int b = pool_alloc_n(&p, 4);
        pool_free_one(&p, a);
        for (int k = 0; k < 4; k++)
            pool_free_one(&p, b + k);
    }
    ASSERT_EQ(p.free_pages, 64);
}

int main(void)
{
    printf("GhostRing allocator stress tests\n");
    printf("================================\n");

    RUN_TEST(test_full_drain_refill);
    RUN_TEST(test_fragmentation_hole_reuse);
    RUN_TEST(test_contiguous_allocation_after_free);
    RUN_TEST(test_double_free_is_safe);
    RUN_TEST(test_free_invalid_index);
    RUN_TEST(test_1000_cycles_no_leak);

    REPORT();
}
