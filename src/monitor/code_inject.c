/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * code_inject.c — EPT-based code injection detection.
 *
 * This module enforces a simple invariant: only physical pages that
 * belong to a legitimately loaded PE/ELF image may be executed.  Any
 * execution from an unregistered page is treated as code injection.
 *
 * Attack vectors detected:
 *   - Reflective DLL injection (Cobalt Strike beacon, Metasploit
 *     meterpreter): allocates RWX memory, copies a DLL, and executes
 *     it without ever touching the file system or the OS loader.
 *   - Process hollowing (Dridex, Emotet): unmaps the legitimate image
 *     and replaces it with malicious code.  The new code pages are not
 *     in our registered set.
 *   - Shellcode execution: exploit payloads that execute from stack,
 *     heap, or other data regions.
 *   - APC injection: queues an APC to run shellcode in another process's
 *     context.  The target pages are still unregistered.
 *
 * Limitations:
 *   - JIT engines (V8, .NET CLR) generate code at runtime.  These pages
 *     must be explicitly registered or whitelisted per-process (CR3).
 *   - Self-modifying code (rare in legitimate software) will trigger
 *     false positives.
 *
 * The bitmap approach (1 bit per 4KB page) is extremely cache-friendly
 * and has zero overhead on the common case (executing from registered
 * pages), since the EPT permissions are set correctly at registration
 * time.
 */

#include "code_inject.h"
#include "alerts.h"

/* ── Bitmap manipulation helpers ────────────────────────────────────────── */

/*
 * Convert a guest physical address to a page index in the bitmap.
 * Returns UINT32_MAX if the address is beyond our tracked range.
 */
static inline uint32_t gpa_to_page_index(uint64_t gpa)
{
    uint64_t page_num = gpa / PAGE_SIZE;
    if (page_num >= GR_CODE_INJECT_MAX_PHYS / PAGE_SIZE)
        return (uint32_t)-1;
    return (uint32_t)page_num;
}

static inline void bitmap_set(uint8_t *bitmap, uint32_t index)
{
    bitmap[index / 8] |= (uint8_t)(1U << (index % 8));
}

static inline bool bitmap_test(const uint8_t *bitmap, uint32_t index)
{
    return (bitmap[index / 8] & (1U << (index % 8))) != 0;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void gr_code_inject_init(gr_code_inject_state_t *state)
{
    if (!state)
        return;

    /*
     * Clear the entire bitmap — all pages start as "unknown / not
     * executable".  The EPT should also have execute permission
     * cleared for all non-kernel pages at this point.
     */
    uint8_t *p = (uint8_t *)state;
    for (uint64_t i = 0; i < sizeof(*state); i++)
        p[i] = 0;

    state->initialised = true;

    GR_LOG_STR("code_inject: monitor initialised, all pages non-executable");
    GR_LOG("code_inject: bitmap size=",
           (uint64_t)GR_CODE_INJECT_BITMAP_SIZE);
}

uint32_t gr_code_inject_register_image(gr_code_inject_state_t *state,
                                       phys_addr_t image_base_gpa,
                                       uint64_t image_size)
{
    if (!state || !state->initialised)
        return 0;

    if (image_size == 0)
        return 0;

    /*
     * Mark every page covered by this image as legitimate code.
     * In a more sophisticated implementation, we would parse the PE/ELF
     * section headers and only mark .text (executable) sections.  For
     * now we conservatively mark the entire image to avoid false
     * positives from images with non-standard layouts.
     */
    phys_addr_t start = ALIGN_DOWN(image_base_gpa, PAGE_SIZE);
    phys_addr_t end   = ALIGN_UP(image_base_gpa + image_size, PAGE_SIZE);

    uint32_t pages_registered = 0;

    for (phys_addr_t page = start; page < end; page += PAGE_SIZE) {
        uint32_t idx = gpa_to_page_index(page);
        if (idx == (uint32_t)-1)
            break;  /* Beyond our tracked range */

        if (!bitmap_test(state->bitmap, idx)) {
            bitmap_set(state->bitmap, idx);
            pages_registered++;
        }
    }

    state->registered_images++;
    state->registered_pages += pages_registered;

    GR_LOG("code_inject: registered image at GPA=", image_base_gpa);
    GR_LOG("  size=", image_size);
    GR_LOG("  new pages=", (uint64_t)pages_registered);

    return pages_registered;
}

bool gr_code_inject_check_exec(gr_code_inject_state_t *state,
                               uint64_t gpa,
                               uint64_t guest_rip,
                               uint64_t guest_cr3)
{
    if (!state || !state->initialised)
        return false;

    uint32_t idx = gpa_to_page_index(gpa);
    if (idx == (uint32_t)-1) {
        /*
         * Address beyond our tracking range.  This is suspicious in
         * itself — execution from very high physical addresses is
         * unusual.  Treat it as an injection attempt.
         */
        gr_alert_emit(GR_ALERT_CODE_INJECTION,
                      guest_rip, guest_cr3, gpa,
                      0);
        return true;
    }

    if (bitmap_test(state->bitmap, idx)) {
        /* Page is in the known-good set — legitimate execution */
        return false;
    }

    /*
     * Execution from an unregistered page.  This is the core detection:
     * no legitimate image was loaded at this physical address, so
     * something injected executable code here.
     */
    gr_alert_emit(GR_ALERT_CODE_INJECTION,
                  guest_rip, guest_cr3, gpa,
                  guest_cr3);  /* info = process CR3 for attribution */

    GR_LOG("code_inject: INJECTION detected at GPA=", gpa);
    GR_LOG("  guest_rip=", guest_rip);
    GR_LOG("  guest_cr3=", guest_cr3);

    return true;
}

bool gr_code_inject_is_known(const gr_code_inject_state_t *state,
                             uint64_t gpa)
{
    if (!state || !state->initialised)
        return false;

    uint32_t idx = gpa_to_page_index(gpa);
    if (idx == (uint32_t)-1)
        return false;

    return bitmap_test(state->bitmap, idx);
}
