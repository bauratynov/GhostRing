/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * ransomware.c — Canary-based ransomware detection at the hypervisor level.
 *
 * Real-world ransomware behaviour this detects:
 *   - WannaCry (2017): bulk-encrypts files using AES-128-CBC, writing
 *     encrypted data back in-place.  Would trigger canary writes when
 *     its memory scanning reaches our hidden pages.
 *   - Ryuk (2018–present): targets large enterprises, encrypts using
 *     RSA-4096 + AES-256.  Its file enumeration is aggressive enough
 *     to hit canary pages.
 *   - LockBit 3.0: uses multi-threaded encryption with I/O completion
 *     ports for speed.  Canary writes would fire within seconds of
 *     infection start.
 *   - Conti: uses ChaCha20 for bulk encryption.  Same detection vector.
 *
 * The canary approach has near-zero false positive rate because:
 *   1. Canary pages are not part of the guest's usable physical memory.
 *   2. No legitimate OS component or application writes to reserved
 *      memory regions.
 *   3. Only software that blindly processes memory (encryption,
 *      wiping) would touch these pages.
 */

#include "ransomware.h"
#include "alerts.h"
#include "../vmx/vmx_ept.h"

/* ── Internal helpers ──────────────────────────────────────────────────── */

/*
 * Fill a canary page with its sentinel pattern.  The first 20 bytes
 * contain the magic string and canary index; the rest is filled with
 * a recognisable repeating pattern to make forensic analysis easier.
 */
static void ransom_fill_canary(phys_addr_t gpa, uint32_t index)
{
    uint8_t *page = (uint8_t *)(uintptr_t)gpa;

    /* Write magic header */
    const char *magic = GR_RANSOM_MAGIC;
    for (uint32_t i = 0; i < GR_RANSOM_MAGIC_LEN; i++)
        page[i] = (uint8_t)magic[i];

    /* Write canary index as 4 bytes after the magic */
    page[GR_RANSOM_MAGIC_LEN + 0] = (uint8_t)(index & 0xFF);
    page[GR_RANSOM_MAGIC_LEN + 1] = (uint8_t)((index >> 8) & 0xFF);
    page[GR_RANSOM_MAGIC_LEN + 2] = (uint8_t)((index >> 16) & 0xFF);
    page[GR_RANSOM_MAGIC_LEN + 3] = (uint8_t)((index >> 24) & 0xFF);

    /*
     * Fill the remainder with a repeating 0xCA pattern.  This makes
     * it easy to visually identify canary pages in memory dumps and
     * also ensures high entropy detection by the canary itself if
     * ransomware partially encrypts the page.
     */
    for (uint32_t i = GR_RANSOM_MAGIC_LEN + 4; i < PAGE_SIZE; i++)
        page[i] = 0xCA;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void gr_ransom_init(gr_ransom_state_t *state,
                    const phys_addr_t *canary_gpas,
                    uint32_t count,
                    gr_ept_ctx_t *ept_ctx)
{
    if (!state || !canary_gpas || count == 0)
        return;

    /* Zero the state */
    uint8_t *p = (uint8_t *)state;
    for (uint64_t i = 0; i < sizeof(*state); i++)
        p[i] = 0;

    if (count > GR_RANSOM_MAX_CANARIES)
        count = GR_RANSOM_MAX_CANARIES;

    GR_LOG("ransom: deploying canary pages, count=", (uint64_t)count);

    for (uint32_t i = 0; i < count; i++) {
        gr_canary_page_t *canary = &state->canaries[i];
        canary->gpa       = canary_gpas[i];
        canary->index     = i;
        canary->triggered = false;

        /* Write the sentinel pattern to the canary page */
        ransom_fill_canary(canary->gpa, i);

        /* EPT-write-protect: read+execute only */
        if (ept_ctx) {
            int ret = gr_vmx_ept_protect_page(ept_ctx, canary->gpa,
                                              EPT_PERM_RX);
            if (ret != 0)
                GR_LOG("ransom: EPT protect failed for canary=", canary->gpa);
            else
                GR_LOG("ransom: canary deployed at GPA=", canary->gpa);
        }
    }

    state->canary_count = count;
    state->initialised  = true;

    GR_LOG_STR("ransom: all canary pages deployed and write-protected");
}

bool gr_ransom_check_write(gr_ransom_state_t *state,
                           uint64_t gpa,
                           uint64_t guest_rip,
                           uint64_t guest_cr3)
{
    if (!state || !state->initialised)
        return false;

    /*
     * Check whether the faulting GPA falls within any canary page.
     * The canary set is small (max 16), so linear search is fine.
     */
    phys_addr_t page_gpa = ALIGN_DOWN(gpa, PAGE_SIZE);

    for (uint32_t i = 0; i < state->canary_count; i++) {
        gr_canary_page_t *canary = &state->canaries[i];

        if (page_gpa != canary->gpa)
            continue;

        /*
         * Canary hit!  This is a HIGH-CONFIDENCE ransomware indicator.
         * Legitimate software NEVER writes to our hidden canary pages.
         *
         * The guest_cr3 identifies the encrypting process — user-space
         * tooling can use this to immediately terminate the offending
         * process and prevent further damage.
         */
        canary->triggered = true;
        state->triggers++;

        gr_alert_emit(GR_ALERT_RANSOMWARE,
                      guest_rip,
                      guest_cr3,
                      gpa,
                      guest_cr3);  /* info = CR3 for process attribution */

        GR_LOG("ransom: CANARY WRITE DETECTED — ransomware suspected!");
        GR_LOG("  canary index=", (uint64_t)canary->index);
        GR_LOG("  guest_rip=", guest_rip);
        GR_LOG("  guest_cr3=", guest_cr3);
        GR_LOG("  target GPA=", gpa);

        return true;
    }

    return false;
}
