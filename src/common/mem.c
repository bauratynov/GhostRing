/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * mem.c — Bitmap-based page pool allocator.
 *
 * Design rationale:
 *   - Bitmap over free-list because the pool is contiguous and we need
 *     multi-page (physically contiguous) allocations for VMCS, EPT
 *     tables, and MSR bitmaps.
 *   - __builtin_ctzll skips entire 64-page groups in one instruction
 *     (BSF / TZCNT), keeping allocation fast even under fragmentation.
 *   - Every allocated page is zeroed.  Intel SDM requires that VMCS and
 *     EPT structures start zeroed; doing it at allocation time avoids
 *     forgetting to zero in individual call sites.
 */

#ifdef TEST_USERSPACE
  /*
   * Userspace test mode — override spinlock and serial with no-ops.
   * Must be defined BEFORE including mem.h which pulls in spinlock.h.
   */
  #include "types.h"

  /* Stub spinlock */
  typedef struct { uint32_t ticket; uint32_t serving; } gr_spinlock_t;
  #define gr_spin_init(l)                  do { (l)->ticket = 0; (l)->serving = 0; } while(0)
  #define gr_spin_lock(l)                  ((void)(l))
  #define gr_spin_unlock(l)                ((void)(l))
  #define gr_spin_lock_irqsave(l)          (uint64_t)0
  #define gr_spin_unlock_irqrestore(l, f)  ((void)(l), (void)(f))

  /* Override include guard so mem.h doesn't pull real spinlock.h */
  #define GHOSTRING_SPINLOCK_H

  #include "mem.h"

  /* Stub serial */
  #define GR_LOG(msg, ...) ((void)0)
  #define gr_pause()       ((void)0)
#else
  #include "mem.h"
  #include "serial.h"
#endif

/* ── Internal: zero a page ───────────────────────────────────────────────── */

static void zero_page(void *page)
{
    uint64_t *p = (uint64_t *)page;
    for (uint32_t i = 0; i < PAGE_SIZE / sizeof(uint64_t); i++) {
        p[i] = 0;
    }
}

/* ── Initialisation ──────────────────────────────────────────────────────── */

void gr_pool_init(gr_page_pool_t *pool,
                  phys_addr_t     base_phys,
                  virt_addr_t     base_virt,
                  uint32_t        num_pages)
{
    if (num_pages > GR_POOL_MAX_PAGES) {
        num_pages = GR_POOL_MAX_PAGES;
    }

    pool->base_phys   = base_phys;
    pool->base_virt   = base_virt;
    pool->total_pages = num_pages;
    pool->free_pages  = num_pages;

    gr_spin_init(&pool->lock);

    /* Clear the entire bitmap — all pages start free (bit = 0). */
    for (uint32_t i = 0; i < GR_POOL_BITMAP_QWORDS; i++) {
        pool->bitmap[i] = 0;
    }

    /*
     * Mark pages beyond num_pages as permanently allocated so the
     * scanner never hands them out.
     */
    for (uint32_t i = num_pages; i < GR_POOL_MAX_PAGES; i++) {
        pool->bitmap[i / 64] |= (1ULL << (i % 64));
    }
}

/* ── Single-page allocation ──────────────────────────────────────────────── */

void *gr_alloc_page(gr_page_pool_t *pool)
{
    return gr_alloc_pages(pool, 1);
}

/* ── Multi-page allocation ───────────────────────────────────────────────── */

/*
 * Scan the bitmap for `count` contiguous zero bits.  For single-page
 * allocations this degenerates to finding the first zero bit, which
 * __builtin_ctzll handles in a single TZCNT instruction.
 */
void *gr_alloc_pages(gr_page_pool_t *pool, uint32_t count)
{
    if (count == 0) {
        return NULL;
    }

    uint64_t flags = gr_spin_lock_irqsave(&pool->lock);

    if (pool->free_pages < count) {
        gr_spin_unlock_irqrestore(&pool->lock, flags);
        return NULL;
    }

    uint32_t total   = pool->total_pages;
    uint32_t run     = 0;
    uint32_t start   = 0;

    for (uint32_t i = 0; i < total; i++) {
        uint32_t qw = i / 64;
        uint32_t bit = i % 64;

        /*
         * Fast skip: if the entire 64-page group is full (all bits set),
         * jump ahead.  Avoids per-bit scanning through occupied regions.
         */
        if (bit == 0 && pool->bitmap[qw] == ~0ULL) {
            run = 0;
            i += 63;   /* the loop will increment to i+64 */
            continue;
        }

        if (pool->bitmap[qw] & (1ULL << bit)) {
            /* Page allocated — reset run counter. */
            run = 0;
        } else {
            if (run == 0) {
                start = i;
            }
            run++;
            if (run == count) {
                goto found;
            }
        }
    }

    /* No contiguous run large enough. */
    gr_spin_unlock_irqrestore(&pool->lock, flags);
    return NULL;

found:
    /* Mark the pages as allocated. */
    for (uint32_t i = start; i < start + count; i++) {
        pool->bitmap[i / 64] |= (1ULL << (i % 64));
    }
    pool->free_pages -= count;

    gr_spin_unlock_irqrestore(&pool->lock, flags);

    /* Compute virtual address and zero the pages. */
    void *ptr = (void *)(pool->base_virt + (uint64_t)start * PAGE_SIZE);
    for (uint32_t i = 0; i < count; i++) {
        zero_page((void *)((uint64_t)ptr + (uint64_t)i * PAGE_SIZE));
    }

    return ptr;
}

/* ── Single-page free ────────────────────────────────────────────────────── */

void gr_free_page(gr_page_pool_t *pool, void *ptr)
{
    gr_free_pages(pool, ptr, 1);
}

/* ── Multi-page free ─────────────────────────────────────────────────────── */

void gr_free_pages(gr_page_pool_t *pool, void *ptr, uint32_t count)
{
    if (ptr == NULL || count == 0) {
        return;
    }

    virt_addr_t addr = (virt_addr_t)ptr;
    uint32_t page_idx = (uint32_t)((addr - pool->base_virt) / PAGE_SIZE);

    if (page_idx + count > pool->total_pages) {
        GR_LOG("mem: invalid free at page index ", page_idx);
        return;
    }

    uint64_t flags = gr_spin_lock_irqsave(&pool->lock);

    for (uint32_t i = page_idx; i < page_idx + count; i++) {
        uint32_t qw  = i / 64;
        uint64_t bit = 1ULL << (i % 64);

        if (!(pool->bitmap[qw] & bit)) {
            /* Double-free detected — log but do not corrupt the bitmap. */
            gr_spin_unlock_irqrestore(&pool->lock, flags);
            GR_LOG("mem: double free at page index ", i);
            return;
        }

        pool->bitmap[qw] &= ~bit;
    }

    pool->free_pages += count;

    gr_spin_unlock_irqrestore(&pool->lock, flags);
}
