/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * platform.h — Abstraction layer between the hypervisor core and the
 *              host operating system (Linux kmod, Windows KMDF, UEFI).
 *
 * The loader registers a set of callbacks at init time.  The hypervisor
 * core and monitor subsystems use these callbacks instead of calling
 * OS-specific APIs directly.  This keeps src/ free of any #include
 * <linux/...> or <ntddk.h> contamination.
 */

#ifndef GHOSTRING_PLATFORM_H
#define GHOSTRING_PLATFORM_H

#include "types.h"

/* ── Platform callback table ───────────────────────────────────────────── */

typedef struct {
    /*
     * Virtual-to-physical translation.  Must work for any kernel VA
     * (kmalloc'd memory, vmalloc'd memory, direct-map regions).
     *
     * Linux:   virt_to_phys(va)
     * Windows: MmGetPhysicalAddress(va).QuadPart
     * UEFI:    identity — return (phys_addr_t)va
     */
    phys_addr_t (*virt_to_phys)(void *va);

    /*
     * Physical-to-virtual translation.
     *
     * Linux:   phys_to_virt(pa)  (works for direct-map only)
     * Windows: MmGetVirtualForPhysical(pa)
     * UEFI:    identity — return (void *)pa
     */
    void *(*phys_to_virt)(phys_addr_t pa);

    /*
     * Allocate `count` physically-contiguous, page-aligned, zeroed pages.
     *
     * Linux:   alloc_pages(GFP_KERNEL, order) + page_address()
     * Windows: MmAllocateContiguousMemory(count * PAGE_SIZE, max_pa)
     * UEFI:    gBS->AllocatePages()
     */
    void *(*alloc_contiguous)(uint32_t count);

    /*
     * Free pages returned by alloc_contiguous.
     */
    void (*free_contiguous)(void *ptr, uint32_t count);

    /*
     * Debug log — platform's equivalent of printk / DbgPrint.
     * Used only during init/shutdown, not on the hot VM-exit path.
     */
    void (*log)(const char *msg);

} gr_platform_ops_t;

/* ── Global platform state ─────────────────────────────────────────────── */

extern gr_platform_ops_t g_platform;

/* ── Registration (called once by the loader at init) ──────────────────── */

static inline void gr_platform_register(const gr_platform_ops_t *ops)
{
    g_platform = *ops;
}

/* ── Convenience wrappers ──────────────────────────────────────────────── */

static inline phys_addr_t gr_virt_to_phys(void *va)
{
    return g_platform.virt_to_phys(va);
}

static inline void *gr_phys_to_virt(phys_addr_t pa)
{
    return g_platform.phys_to_virt(pa);
}

static inline void *gr_platform_alloc_pages(uint32_t count)
{
    return g_platform.alloc_contiguous(count);
}

static inline void gr_platform_free_pages(void *ptr, uint32_t count)
{
    g_platform.free_contiguous(ptr, count);
}

#endif /* GHOSTRING_PLATFORM_H */
