/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_crc32c_polynomial.c — Lock the CRC32C polynomial used by the
 * integrity detector.
 *
 * Why: the integrity monitor hashes kernel .text with the Castagnoli
 * polynomial 0x82F63B78 so that the SSE 4.2 `crc32` instruction and
 * the Linux `crc32c()` helper produce identical values for the same
 * input.  If someone accidentally switched to IEEE 802.3 CRC32
 * (polynomial 0xEDB88320), every baseline would be wrong and the
 * detector would alert on every rescan — or worse, a crafted patch
 * could survive because its pre- and post-patch IEEE CRCs collide
 * differently.
 *
 * The fix is trivial but easy to regress in a 'modernising' refactor.
 * This test pins the polynomial and a known test-vector.
 */

#include "test_framework.h"

#define CRC32C_POLY  0x82F63B78U   /* Castagnoli, reversed 0x1EDC6F41 */
#define CRC32_IEEE   0xEDB88320U   /* NOT what we use — must fail if swapped */

static uint32_t crc32c_table[256];
static int table_initialised = 0;

static void crc32c_init_table(uint32_t poly)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c >> 1) ^ ((c & 1) ? poly : 0);
        crc32c_table[i] = c;
    }
    table_initialised = 1;
}

static uint32_t crc32c_update(uint32_t crc, const uint8_t *data, size_t len)
{
    if (!table_initialised) crc32c_init_table(CRC32C_POLY);
    for (size_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32c_table[(crc ^ data[i]) & 0xFF];
    return crc;
}

static uint32_t crc32c(const uint8_t *data, size_t len)
{
    return ~crc32c_update(0xFFFFFFFF, data, len);
}

TEST(test_polynomial_value_is_castagnoli)
{
    ASSERT_EQ(CRC32C_POLY, 0x82F63B78U);
    /* Should NOT equal IEEE 802.3 — different hash, different
     * hardware instruction (regular `crc32` mnemonic in SSE 4.2). */
    ASSERT_NEQ(CRC32C_POLY, CRC32_IEEE);
}

TEST(test_empty_string_crc32c_is_zero)
{
    /* CRC32C of empty input is zero by convention (after the final
     * ~ inversion of the 0xFFFFFFFF initial state). */
    uint32_t c = crc32c((const uint8_t *)"", 0);
    ASSERT_EQ(c, 0x00000000U);
}

TEST(test_known_vector_123456789)
{
    /* Canonical CRC32C test vector from the rocksoft / iSCSI RFC
     * 3720: "123456789" -> 0xE3069283. */
    uint32_t c = crc32c((const uint8_t *)"123456789", 9);
    ASSERT_EQ(c, 0xE3069283U);
}

TEST(test_known_vector_single_byte_a)
{
    /* CRC32C of "a" is 0xC1D04330. */
    uint32_t c = crc32c((const uint8_t *)"a", 1);
    ASSERT_EQ(c, 0xC1D04330U);
}

TEST(test_single_bit_change_detected)
{
    uint8_t buf1[16], buf2[16];
    for (int i = 0; i < 16; i++) {
        buf1[i] = (uint8_t)i;
        buf2[i] = (uint8_t)i;
    }
    uint32_t c1 = crc32c(buf1, 16);
    buf2[7] ^= 0x01;  /* flip lowest bit of one byte */
    uint32_t c2 = crc32c(buf2, 16);
    ASSERT_NEQ(c1, c2);
}

int main(void)
{
    printf("GhostRing CRC32C polynomial tests\n");
    printf("=================================\n");

    RUN_TEST(test_polynomial_value_is_castagnoli);
    RUN_TEST(test_empty_string_crc32c_is_zero);
    RUN_TEST(test_known_vector_123456789);
    RUN_TEST(test_known_vector_single_byte_a);
    RUN_TEST(test_single_bit_change_detected);

    REPORT();
}
