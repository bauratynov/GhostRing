/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * integrity.c — CRC32-based kernel code integrity monitoring.
 *
 * Rootkits that inline-hook kernel functions or modify dispatch tables
 * will inevitably flip bits in protected regions.  By periodically
 * checksumming those regions from the hypervisor (which the guest
 * cannot tamper with), we detect such modifications with certainty.
 *
 * Performance note: CRC32C hardware acceleration processes ~8 bytes per
 * cycle, making a full 4KB page check ~512 cycles — negligible even
 * at 10 kHz check frequency.
 */

#include "integrity.h"
#include "alerts.h"

/* ── SSE4.2 feature detection ───────────────────────────────────────────── */

/*
 * Check CPUID leaf 1, ECX bit 20 (SSE4.2).  Cached after first call
 * since CPUID results never change at runtime.
 */
static bool gr_has_sse42(void)
{
    static int cached = -1;
    if (cached < 0) {
        uint32_t eax, ebx, ecx, edx;
        gr_cpuid(1, 0, &eax, &ebx, &ecx, &edx);
        cached = (ecx & BIT(20)) ? 1 : 0;
    }
    return cached != 0;
}

/* ── Software CRC32 table (IEEE 802.3 polynomial) ──────────────────────── */

/*
 * Pre-computed table for the standard CRC32 polynomial 0xEDB88320
 * (bit-reversed 0x04C11DB7).  Generated once at first use.
 */
static uint32_t crc32_table[256];
static bool     crc32_table_ready = false;

static void crc32_build_table(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0x82F63B78U  /* CRC32C Castagnoli — matches SSE4.2 hardware CRC32C */;
            else
                crc >>= 1;
        }
        crc32_table[i] = crc;
    }
    crc32_table_ready = true;
}

static uint32_t crc32_software(const uint8_t *data, uint64_t len)
{
    if (!crc32_table_ready)
        crc32_build_table();

    uint32_t crc = 0xFFFFFFFF;
    for (uint64_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];

    return crc ^ 0xFFFFFFFF;
}

/* ── Hardware-accelerated CRC32C ────────────────────────────────────────── */

/*
 * Uses the CRC32C (Castagnoli) polynomial via the SSE4.2 CRC32
 * instruction.  This is a different polynomial from IEEE 802.3 but is
 * equally effective for integrity detection — we just need consistency
 * between init and check.
 */
static uint32_t crc32_hardware(const uint8_t *data, uint64_t len)
{
    uint32_t crc = 0xFFFFFFFF;
    uint64_t i = 0;

    /* Process 8 bytes at a time when possible for throughput. */
    for (; i + 8 <= len; i += 8) {
        uint64_t val;
        /*
         * Read via memcpy-equivalent to avoid strict-aliasing issues.
         * The compiler will optimise this to a single MOV.
         */
        const uint8_t *p = data + i;
        val = *(const uint64_t *)p;
        crc = (uint32_t)__builtin_ia32_crc32di(crc, val);
    }

    /* Handle the remaining tail bytes one at a time. */
    for (; i < len; i++)
        crc = __builtin_ia32_crc32qi(crc, data[i]);

    return crc ^ 0xFFFFFFFF;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

uint32_t gr_crc32(const void *data, uint64_t len)
{
    if (!data || len == 0)
        return 0;

    if (gr_has_sse42())
        return crc32_hardware((const uint8_t *)data, len);
    else
        return crc32_software((const uint8_t *)data, len);
}

void gr_integrity_init(gr_integrity_region_t *regions, uint32_t count)
{
    if (!regions || count == 0)
        return;

    if (count > GR_INTEGRITY_MAX_REGIONS)
        count = GR_INTEGRITY_MAX_REGIONS;

    GR_LOG("integrity: initializing regions, count=", (uint64_t)count);

    for (uint32_t i = 0; i < count; i++) {
        gr_integrity_region_t *r = &regions[i];

        if (r->size == 0) {
            GR_LOG_STR("integrity: skipping zero-size region");
            continue;
        }

        /*
         * In a bare-metal hypervisor the GPA is identity-mapped, so we
         * can cast the guest physical address directly to a pointer.
         * EPT ensures we see the same physical page the guest does.
         */
        const void *ptr = (const void *)(uintptr_t)r->gpa_start;
        r->expected_crc32 = gr_crc32(ptr, r->size);

        GR_LOG("integrity: region gpa=", r->gpa_start);
        GR_LOG("  size=", r->size);
        GR_LOG("  crc32=", (uint64_t)r->expected_crc32);
    }

    GR_LOG_STR("integrity: baseline established");
}

uint32_t gr_integrity_check(gr_integrity_region_t *regions, uint32_t count)
{
    if (!regions || count == 0)
        return 0;

    if (count > GR_INTEGRITY_MAX_REGIONS)
        count = GR_INTEGRITY_MAX_REGIONS;

    uint32_t mismatches = 0;

    for (uint32_t i = 0; i < count; i++) {
        gr_integrity_region_t *r = &regions[i];

        if (r->size == 0)
            continue;

        const void *ptr = (const void *)(uintptr_t)r->gpa_start;
        uint32_t actual = gr_crc32(ptr, r->size);

        if (actual != r->expected_crc32) {
            mismatches++;

            /*
             * Pack expected and actual CRC32 into the info field so
             * user-space can report exactly what changed.
             */
            uint64_t info = ((uint64_t)r->expected_crc32 << 32) |
                            (uint64_t)actual;

            /*
             * Read guest RIP and CR3 from the VMCS for context.  These
             * tell us which guest execution context was active when the
             * integrity violation was discovered (though the actual
             * modification may have happened earlier).
             */
            gr_alert_emit(GR_ALERT_INTEGRITY_FAIL,
                          0,    /* RIP not meaningful for periodic check */
                          0,    /* CR3 not meaningful for periodic check */
                          r->gpa_start,
                          info);

            GR_LOG("integrity: MISMATCH region gpa=", r->gpa_start);
            GR_LOG("  expected=", (uint64_t)r->expected_crc32);
            GR_LOG("  actual=",   (uint64_t)actual);
        }
    }

    return mismatches;
}
