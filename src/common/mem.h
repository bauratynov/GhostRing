/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * mem.h — Page-granularity pool allocator.
 *
 * Inspired by MiniVisorPkg's MemoryManager: a contiguous physical region
 * is carved into 4 KiB pages tracked by a bitmap.  No heap, no malloc,
 * no fragmentation — every allocation is page-aligned and every free is
 * O(1).  Multi-page allocations scan for contiguous runs using
 * __builtin_ctzll to skip 64-page groups at a time.
 *
 * Thread safety is provided by a per-pool ticket spinlock.
 */

#ifndef GHOSTRING_MEM_H
#define GHOSTRING_MEM_H

#include "types.h"
#include "spinlock.h"

/* ── Limits ──────────────────────────────────────────────────────────────── */

/*
 * Maximum pages the pool can manage.  32768 pages = 128 MiB, which is
 * generous for a hypervisor's internal data structures.  The bitmap
 * uses 32768 / 8 = 4 KiB — exactly one page.
 */
#define GR_POOL_MAX_PAGES       32768
#define GR_POOL_BITMAP_QWORDS   (GR_POOL_MAX_PAGES / 64)

/* ── Pool structure ──────────────────────────────────────────────────────── */

/* Ensure typedef is available even when included without ghostring.h */
#ifndef GHOSTRING_PAGE_POOL_TYPEDEF
#define GHOSTRING_PAGE_POOL_TYPEDEF
typedef struct gr_page_pool gr_page_pool_t;
#endif

struct gr_page_pool {
    phys_addr_t     base_phys;          /* physical start address         */
    virt_addr_t     base_virt;          /* virtual mapping of same region */
    uint32_t        total_pages;        /* usable page count              */
    uint32_t        free_pages;         /* pages currently free           */
    gr_spinlock_t   lock;

    /*
     * Bitmap: bit 0 = free, bit 1 = allocated.  Using "allocated = 1"
     * lets us detect double-frees by checking the bit is set before
     * clearing.  Each uint64_t covers 64 consecutive pages.
     */
    uint64_t        bitmap[GR_POOL_BITMAP_QWORDS];
};

/* ── API ─────────────────────────────────────────────────────────────────── */

/*
 * Initialise a pool over [base_phys, base_phys + num_pages * PAGE_SIZE).
 * base_virt must be the linear mapping of base_phys.
 */
void gr_pool_init(gr_page_pool_t *pool,
                  phys_addr_t     base_phys,
                  virt_addr_t     base_virt,
                  uint32_t        num_pages);

/*
 * Allocate a single zeroed page.  Returns virtual address or NULL on
 * exhaustion.
 */
void *gr_alloc_page(gr_page_pool_t *pool);

/*
 * Allocate `count` physically-contiguous zeroed pages.
 * Returns virtual address of the first page or NULL.
 */
void *gr_alloc_pages(gr_page_pool_t *pool, uint32_t count);

/*
 * Free a single page previously returned by gr_alloc_page.
 */
void gr_free_page(gr_page_pool_t *pool, void *ptr);

/*
 * Free `count` contiguous pages starting at `ptr`.
 */
void gr_free_pages(gr_page_pool_t *pool, void *ptr, uint32_t count);

/* ── Inline helpers ──────────────────────────────────────────────────────── */

/* Convert pool-relative virtual address to physical. */
static inline phys_addr_t gr_pool_virt_to_phys(gr_page_pool_t *pool,
                                                void *virt)
{
    return pool->base_phys + ((virt_addr_t)virt - pool->base_virt);
}

/* Convert pool-relative physical address to virtual. */
static inline void *gr_pool_phys_to_virt(gr_page_pool_t *pool,
                                          phys_addr_t phys)
{
    return (void *)(pool->base_virt + (phys - pool->base_phys));
}

#endif /* GHOSTRING_MEM_H */
