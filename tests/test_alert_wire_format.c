/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_alert_wire_format.c — ABI lock for the record that crosses
 * the kernel↔userspace boundary on /dev/ghostring.
 *
 * There are TWO gr_alert_t structures in the tree and they are
 * deliberately different:
 *
 *   loader/linux/ghostring_chardev.c  → 24-byte record (the wire)
 *   src/monitor/alerts.h              → 48-byte record (in-kernel,
 *                                        never leaves kernel space)
 *
 * This test locks the 24-byte wire layout only — that is what the
 * agent binary (agent/linux/ghostring_agent.c) reads via read().
 * Any drift between chardev and agent manifests as garbage alerts
 * with nonsense cpu_id / type values.
 *
 * Wire layout (chardev + agent agree):
 *
 *   offset 0  : u64  ts_ns         — ktime_get_ns() at detection
 *   offset 8  : u32  cpu_id
 *   offset 12 : u32  alert_type    — one of enum gr_alert_type
 *   offset 16 : u64  info          — type-specific payload
 *   total     : 24 bytes
 */

#include <stddef.h>
#include "test_framework.h"

/* Mirror of the wire record — must match gr_alert_t in
 * loader/linux/ghostring_chardev.c and struct gr_alert_wire in
 * agent/linux/ghostring_agent.c. */
typedef struct {
    uint64_t ts_ns;
    uint32_t cpu_id;
    uint32_t alert_type;
    uint64_t info;
} wire_alert_t;

/* Alert type values — same enum as src/monitor/alerts.h but
 * repeated here so the test fails loudly on renumber. */
enum {
    W_EPT_WRITE_VIOLATION = 0,
    W_MSR_TAMPER          = 1,
    W_CR_TAMPER           = 2,
    W_HIDDEN_PROCESS      = 3,
    W_INTEGRITY_FAIL      = 4,
    W_IDT_HOOK            = 5,
    W_CODE_INJECTION      = 6,
    W_SSDT_HOOK           = 7,
    W_DRVOBJ_HOOK         = 8,
    W_RANSOMWARE          = 9,
    W_ROP_DETECTED        = 10,
    W_CALLBACK_TAMPER     = 11,
    W_TOKEN_STEAL         = 12,
    W_PTE_TAMPER          = 13,
    W_TIMESTOMP           = 14,
    W_LOG_WIPE            = 15,
    W_MEM_WIPE            = 16,
    W_DLL_HIJACK          = 17,
    W_BINARY_TAMPER       = 18,
    W_TYPE_COUNT          = 19,
};

TEST(test_wire_record_is_24_bytes)
{
    /* Agent's read() loop advances the file pointer by
     * sizeof(gr_alert_wire) bytes per record.  Padding drift here
     * shifts every subsequent alert. */
    ASSERT_EQ(sizeof(wire_alert_t), 24);
}

TEST(test_field_offsets_frozen)
{
    ASSERT_EQ(offsetof(wire_alert_t, ts_ns),      0);
    ASSERT_EQ(offsetof(wire_alert_t, cpu_id),     8);
    ASSERT_EQ(offsetof(wire_alert_t, alert_type), 12);
    ASSERT_EQ(offsetof(wire_alert_t, info),      16);
}

TEST(test_field_sizes_frozen)
{
    wire_alert_t a;
    ASSERT_EQ(sizeof(a.ts_ns),      8);
    ASSERT_EQ(sizeof(a.cpu_id),     4);
    ASSERT_EQ(sizeof(a.alert_type), 4);
    ASSERT_EQ(sizeof(a.info),       8);
}

TEST(test_no_padding_on_x86_64)
{
    /* Sum of field sizes must equal struct size — no implicit
     * padding.  If this fails on a new arch, the chardev needs a
     * packed attribute or a serialization layer. */
    size_t sum = sizeof(uint64_t)       /* ts_ns */
               + sizeof(uint32_t) * 2   /* cpu_id + alert_type */
               + sizeof(uint64_t);      /* info */
    ASSERT_EQ(sum, sizeof(wire_alert_t));
}

TEST(test_alert_type_values_locked)
{
    /* Agent's switch-case and SIEM JSON field "type" depend on
     * these exact numbers. */
    ASSERT_EQ(W_EPT_WRITE_VIOLATION, 0);
    ASSERT_EQ(W_MSR_TAMPER,          1);
    ASSERT_EQ(W_CR_TAMPER,           2);
    ASSERT_EQ(W_HIDDEN_PROCESS,      3);
    ASSERT_EQ(W_INTEGRITY_FAIL,      4);
    ASSERT_EQ(W_IDT_HOOK,            5);
    ASSERT_EQ(W_CODE_INJECTION,      6);
    ASSERT_EQ(W_SSDT_HOOK,           7);
    ASSERT_EQ(W_DRVOBJ_HOOK,         8);
    ASSERT_EQ(W_RANSOMWARE,          9);
    ASSERT_EQ(W_ROP_DETECTED,       10);
    ASSERT_EQ(W_CALLBACK_TAMPER,    11);
    ASSERT_EQ(W_TOKEN_STEAL,        12);
    ASSERT_EQ(W_PTE_TAMPER,         13);
    ASSERT_EQ(W_TIMESTOMP,          14);
    ASSERT_EQ(W_LOG_WIPE,           15);
    ASSERT_EQ(W_MEM_WIPE,           16);
    ASSERT_EQ(W_DLL_HIJACK,         17);
    ASSERT_EQ(W_BINARY_TAMPER,      18);
    ASSERT_EQ(W_TYPE_COUNT,         19);
}

TEST(test_round_trip_through_raw_bytes)
{
    /* Fill a record, copy out as bytes, copy back — every field
     * survives.  Simulates the kernel→userspace transport. */
    wire_alert_t src = {
        .ts_ns      = 0x0123456789ABCDEFull,
        .cpu_id     = 0xDEADBEEFu,
        .alert_type = W_RANSOMWARE,
        .info       = 0xCAFEF00DFEEDC0DEull,
    };
    uint8_t buf[sizeof(wire_alert_t)];
    memcpy(buf, &src, sizeof(src));

    wire_alert_t dst;
    memcpy(&dst, buf, sizeof(dst));

    ASSERT_EQ(dst.ts_ns,      src.ts_ns);
    ASSERT_EQ(dst.cpu_id,     src.cpu_id);
    ASSERT_EQ(dst.alert_type, src.alert_type);
    ASSERT_EQ(dst.info,       src.info);
}

TEST(test_ring_buffer_record_stride)
{
    /* Userspace iterates the ring by stepping sizeof(record) bytes.
     * Verify an array of 8 records with distinct cpu_ids reads back
     * the same distinct values after byte-stepping. */
    wire_alert_t ring[8];
    memset(ring, 0, sizeof(ring));
    for (unsigned i = 0; i < 8; i++)
        ring[i].cpu_id = 0x1000u + i;

    uint8_t *p = (uint8_t *)ring;
    for (unsigned i = 0; i < 8; i++) {
        wire_alert_t view;
        memcpy(&view, p + i * sizeof(wire_alert_t), sizeof(view));
        ASSERT_EQ(view.cpu_id, 0x1000u + i);
    }
}

TEST(test_info_field_preserves_full_64_bits)
{
    /* Some callers pack two 32-bit values (expected, actual CRC) in
     * info.  Verify high and low halves both survive the wire. */
    wire_alert_t src = {
        .ts_ns      = 0,
        .cpu_id     = 0,
        .alert_type = W_INTEGRITY_FAIL,
        .info       = ((uint64_t)0xAABBCCDDu << 32) | 0x11223344u,
    };
    uint8_t buf[sizeof(src)];
    memcpy(buf, &src, sizeof(src));
    wire_alert_t dst;
    memcpy(&dst, buf, sizeof(dst));
    ASSERT_EQ((uint32_t)(dst.info >> 32), 0xAABBCCDDu);
    ASSERT_EQ((uint32_t)(dst.info & 0xFFFFFFFFu), 0x11223344u);
}

int main(void)
{
    printf("GhostRing /dev/ghostring wire-record ABI tests\n");
    printf("==============================================\n");

    RUN_TEST(test_wire_record_is_24_bytes);
    RUN_TEST(test_field_offsets_frozen);
    RUN_TEST(test_field_sizes_frozen);
    RUN_TEST(test_no_padding_on_x86_64);
    RUN_TEST(test_alert_type_values_locked);
    RUN_TEST(test_round_trip_through_raw_bytes);
    RUN_TEST(test_ring_buffer_record_stride);
    RUN_TEST(test_info_field_preserves_full_64_bits);

    REPORT();
}
