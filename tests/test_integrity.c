/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_integrity.c — Unit tests for CRC32 integrity checking.
 *
 * Compile: gcc -o test_integrity test_integrity.c -msse4.2 && ./test_integrity
 */

#include "test_framework.h"

/* Portable memory-fill helper (bypasses string.h / memset feature-test
   macros that can bite under strict -std=c99 + -Werror). */
static void fill_bytes(void *dst, uint8_t val, size_t n)
{
    uint8_t *p = (uint8_t *)dst;
    for (size_t i = 0; i < n; i++)
        p[i] = val;
}

/* Software CRC32 for testing — matches the one in integrity.c */
static uint32_t crc32_table[256];
static int table_init = 0;

static void init_crc32_table(void)
{
    if (table_init) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c >> 1) ^ ((c & 1) ? 0xEDB88320 : 0);
        crc32_table[i] = c;
    }
    table_init = 1;
}

static uint32_t gr_crc32(const void *data, uint64_t len)
{
    init_crc32_table();
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFF;
    for (uint64_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32_table[(crc ^ p[i]) & 0xFF];
    return crc ^ 0xFFFFFFFF;
}

/* ═══════════════════════════════════════════════════════════════════════ */

TEST(test_crc32_empty)
{
    uint32_t crc = gr_crc32("", 0);
    /* CRC32 of empty string = 0x00000000 */
    ASSERT_EQ(crc, 0x00000000);
}

TEST(test_crc32_known_value)
{
    /* CRC32 of "123456789" = 0xCBF43926 (standard test vector) */
    uint32_t crc = gr_crc32("123456789", 9);
    ASSERT_EQ(crc, 0xCBF43926);
}

TEST(test_crc32_detects_single_bit_flip)
{
    uint8_t data[64];
    fill_bytes(data, 0xAA, sizeof(data));

    uint32_t original = gr_crc32(data, sizeof(data));

    /* Flip one bit */
    data[32] ^= 0x01;
    uint32_t modified = gr_crc32(data, sizeof(data));

    ASSERT_NEQ(original, modified);
}

TEST(test_crc32_page_sized)
{
    /* Simulate a 4KB kernel code page */
    uint8_t page[4096];
    for (int i = 0; i < 4096; i++)
        page[i] = (uint8_t)(i * 37 + 13);  /* deterministic pattern */

    uint32_t crc1 = gr_crc32(page, 4096);
    uint32_t crc2 = gr_crc32(page, 4096);
    ASSERT_EQ(crc1, crc2);  /* same data = same CRC */

    /* Modify one byte in the middle (simulating a rootkit patch) */
    page[2048] ^= 0xFF;
    uint32_t crc3 = gr_crc32(page, 4096);
    ASSERT_NEQ(crc1, crc3);  /* modification detected */
}

TEST(test_integrity_region_workflow)
{
    /* Simulate the full workflow: init baseline, check, detect tamper */
    uint8_t kernel_text[8192];
    fill_bytes(kernel_text, 0xCC, sizeof(kernel_text));  /* INT3 opcode fill */

    /* Baseline */
    uint32_t baseline = gr_crc32(kernel_text, sizeof(kernel_text));

    /* Check 1: no modification */
    uint32_t check1 = gr_crc32(kernel_text, sizeof(kernel_text));
    ASSERT_EQ(check1, baseline);

    /* Simulate rootkit: overwrite first 16 bytes of kernel function */
    fill_bytes(kernel_text + 1024, 0x90, 16);  /* NOP sled injection */

    /* Check 2: tampered */
    uint32_t check2 = gr_crc32(kernel_text, sizeof(kernel_text));
    ASSERT_NEQ(check2, baseline);
}

/* ═══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("GhostRing integrity tests\n");
    printf("=========================\n");

    RUN_TEST(test_crc32_empty);
    RUN_TEST(test_crc32_known_value);
    RUN_TEST(test_crc32_detects_single_bit_flip);
    RUN_TEST(test_crc32_page_sized);
    RUN_TEST(test_integrity_region_workflow);

    REPORT();
}
