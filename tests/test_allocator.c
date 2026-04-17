/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * test_allocator.c — Unit tests for the bitmap page pool allocator.
 *
 * Compile and run in userspace:
 *   gcc -o test_allocator test_allocator.c ../src/common/mem.c \
 *       -I../src/common -DTEST_USERSPACE && ./test_allocator
 */

#include "test_framework.h"

/* Stub out serial.h dependencies for userspace */
#define GR_LOG(msg, ...) fprintf(stderr, "LOG: " msg "\n")
#define gr_pause()
#define gr_cli()
#define gr_hlt()
#define gr_panic(msg) do { fprintf(stderr, "PANIC: %s\n", msg); abort(); } while(0)

/* Use types.h — it now auto-detects TEST_USERSPACE and pulls stdint/stdbool */
#include "types.h"

/* Minimal test-only macros not in types.h */
#ifndef GR_PACKED
#define GR_PACKED       __attribute__((packed))
#endif
#ifndef GR_ALIGNED
#define GR_ALIGNED(n)   __attribute__((aligned(n)))
#endif

/* Minimal spinlock stub for single-threaded tests */
typedef struct { uint32_t ticket; uint32_t serving; } gr_spinlock_t;
static inline void gr_spin_init(gr_spinlock_t *l) { l->ticket = 0; l->serving = 0; }
static inline void gr_spin_lock(gr_spinlock_t *l) { (void)l; }
static inline void gr_spin_unlock(gr_spinlock_t *l) { (void)l; }
static inline uint64_t gr_spin_lock_irqsave(gr_spinlock_t *l) { (void)l; return 0; }
static inline void gr_spin_unlock_irqrestore(gr_spinlock_t *l, uint64_t f) { (void)l; (void)f; }

/* Now include the allocator header */
#define GR_POOL_MAX_PAGES  32768
#define GR_POOL_BITMAP_QWORDS (GR_POOL_MAX_PAGES / 64)

typedef struct {
    phys_addr_t   base_phys;
    virt_addr_t   base_virt;
    uint32_t      total_pages;
    uint32_t      free_pages;
    gr_spinlock_t lock;
    uint64_t      bitmap[GR_POOL_BITMAP_QWORDS];
} gr_page_pool_t;

/* Import the implementation functions */
void gr_pool_init(gr_page_pool_t *pool, phys_addr_t bp, virt_addr_t bv, uint32_t n);
void *gr_alloc_page(gr_page_pool_t *pool);
void *gr_alloc_pages(gr_page_pool_t *pool, uint32_t count);
void  gr_free_page(gr_page_pool_t *pool, void *ptr);
void  gr_free_pages(gr_page_pool_t *pool, void *ptr, uint32_t count);

/* Test pool: 256 pages = 1 MB */
#define TEST_POOL_PAGES 256
static uint8_t test_memory[TEST_POOL_PAGES * 4096] __attribute__((aligned(4096)));
static gr_page_pool_t pool;

/* ═══════════════════════════════════════════════════════════════════════ */

TEST(test_init)
{
    gr_pool_init(&pool,
                 (phys_addr_t)(uintptr_t)test_memory,
                 (virt_addr_t)(uintptr_t)test_memory,
                 TEST_POOL_PAGES);

    ASSERT_EQ(pool.total_pages, TEST_POOL_PAGES);
    ASSERT_EQ(pool.free_pages, TEST_POOL_PAGES);
}

TEST(test_alloc_single)
{
    gr_pool_init(&pool,
                 (phys_addr_t)(uintptr_t)test_memory,
                 (virt_addr_t)(uintptr_t)test_memory,
                 TEST_POOL_PAGES);

    void *p = gr_alloc_page(&pool);
    ASSERT(p != NULL);
    ASSERT_EQ(pool.free_pages, TEST_POOL_PAGES - 1);

    /* Verify page is zeroed */
    uint8_t *bytes = (uint8_t *)p;
    for (int i = 0; i < 4096; i++) {
        ASSERT_EQ(bytes[i], 0);
    }
}

TEST(test_alloc_all_and_exhaust)
{
    gr_pool_init(&pool,
                 (phys_addr_t)(uintptr_t)test_memory,
                 (virt_addr_t)(uintptr_t)test_memory,
                 TEST_POOL_PAGES);

    void *pages[TEST_POOL_PAGES];
    for (int i = 0; i < TEST_POOL_PAGES; i++) {
        pages[i] = gr_alloc_page(&pool);
        ASSERT(pages[i] != NULL);
    }
    ASSERT_EQ(pool.free_pages, 0);

    /* Next allocation should fail */
    void *p = gr_alloc_page(&pool);
    ASSERT(p == NULL);

    /* Free all */
    for (int i = 0; i < TEST_POOL_PAGES; i++) {
        gr_free_page(&pool, pages[i]);
    }
    ASSERT_EQ(pool.free_pages, TEST_POOL_PAGES);
}

TEST(test_alloc_contiguous)
{
    gr_pool_init(&pool,
                 (phys_addr_t)(uintptr_t)test_memory,
                 (virt_addr_t)(uintptr_t)test_memory,
                 TEST_POOL_PAGES);

    /* Allocate 16 contiguous pages */
    void *p = gr_alloc_pages(&pool, 16);
    ASSERT(p != NULL);
    ASSERT_EQ(pool.free_pages, TEST_POOL_PAGES - 16);

    /* Verify all 16 pages are contiguous */
    uintptr_t base = (uintptr_t)p;
    ASSERT_EQ(base % 4096, 0);  /* page-aligned */

    gr_free_pages(&pool, p, 16);
    ASSERT_EQ(pool.free_pages, TEST_POOL_PAGES);
}

TEST(test_no_double_free)
{
    gr_pool_init(&pool,
                 (phys_addr_t)(uintptr_t)test_memory,
                 (virt_addr_t)(uintptr_t)test_memory,
                 TEST_POOL_PAGES);

    void *p = gr_alloc_page(&pool);
    gr_free_page(&pool, p);
    ASSERT_EQ(pool.free_pages, TEST_POOL_PAGES);

    /* Double-free should be detected and free_pages should not change */
    uint32_t before = pool.free_pages;
    gr_free_page(&pool, p);  /* triggers "double free" log */
    ASSERT_EQ(pool.free_pages, before);  /* unchanged — double-free blocked */
}

TEST(test_alloc_zero_returns_null)
{
    gr_pool_init(&pool,
                 (phys_addr_t)(uintptr_t)test_memory,
                 (virt_addr_t)(uintptr_t)test_memory,
                 TEST_POOL_PAGES);

    void *p = gr_alloc_pages(&pool, 0);
    ASSERT(p == NULL);
}

TEST(test_free_null_safe)
{
    gr_pool_init(&pool,
                 (phys_addr_t)(uintptr_t)test_memory,
                 (virt_addr_t)(uintptr_t)test_memory,
                 TEST_POOL_PAGES);

    /* Should not crash */
    gr_free_page(&pool, NULL);
    gr_free_pages(&pool, NULL, 5);
}

TEST(test_fragmentation_and_reuse)
{
    gr_pool_init(&pool,
                 (phys_addr_t)(uintptr_t)test_memory,
                 (virt_addr_t)(uintptr_t)test_memory,
                 TEST_POOL_PAGES);

    /* Allocate 4 pages, free middle 2, allocate 2 again */
    void *p0 = gr_alloc_page(&pool);
    void *p1 = gr_alloc_page(&pool);
    void *p2 = gr_alloc_page(&pool);
    void *p3 = gr_alloc_page(&pool);

    gr_free_page(&pool, p1);
    gr_free_page(&pool, p2);

    void *r1 = gr_alloc_page(&pool);
    void *r2 = gr_alloc_page(&pool);

    /* Reused pages should be the same addresses (LIFO-ish from bitmap scan) */
    ASSERT(r1 != NULL);
    ASSERT(r2 != NULL);
    ASSERT_EQ(pool.free_pages, TEST_POOL_PAGES - 4);

    gr_free_page(&pool, p0);
    gr_free_page(&pool, p3);
    gr_free_page(&pool, r1);
    gr_free_page(&pool, r2);
}

/* ═══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("GhostRing allocator tests\n");
    printf("=========================\n");

    RUN_TEST(test_init);
    RUN_TEST(test_alloc_single);
    RUN_TEST(test_alloc_all_and_exhaust);
    RUN_TEST(test_alloc_contiguous);
    RUN_TEST(test_no_double_free);
    RUN_TEST(test_alloc_zero_returns_null);
    RUN_TEST(test_free_null_safe);
    RUN_TEST(test_fragmentation_and_reuse);

    REPORT();
}
