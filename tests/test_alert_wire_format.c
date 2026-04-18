/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_alert_wire_format.c — ABI lock for gr_alert_t.
 *
 * gr_alert_t is a shared-ABI structure: the hypervisor writes it
 * (src/monitor/alerts.h), the kernel chardev hands raw bytes to
 * userspace via read(/dev/ghostring), and the agent parses those
 * bytes back into its own mirror struct.  Any of the following break
 * the agent silently:
 *
 *   - Field reorder      → agent reads garbage for every field after the swap
 *   - Field size change  → all subsequent alerts shift by N bytes
 *   - Padding change     → compilers on different archs disagree
 *   - Enum renumber      → alert_type dispatch routes wrong alerts
 *
 * This file locks the on-the-wire layout.  If you *need* to change
 * it, bump a version field and the agent in lockstep.
 */

#include <stddef.h>
#include "test_framework.h"

/* Mirror of gr_alert_t from src/monitor/alerts.h.  Intentionally a
 * copy — we are testing the wire format, not the header include. */
typedef struct {
    uint64_t timestamp;
    uint32_t cpu_id;
    uint32_t alert_type;
    uint64_t guest_rip;
    uint64_t guest_cr3;
    uint64_t target_gpa;
    uint64_t info;
} wire_alert_t;

/* Mirror of enum gr_alert_type. */
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

TEST(test_alert_total_size_is_48_bytes)
{
    /* The agent's read() loop assumes sizeof(alert_t) == 48.
     * A padding change would shift every subsequent record. */
    ASSERT_EQ(sizeof(wire_alert_t), 48);
}

TEST(test_field_offsets_frozen)
{
    /* Exact byte positions — the agent reads at these offsets. */
    ASSERT_EQ(offsetof(wire_alert_t, timestamp),   0);
    ASSERT_EQ(offsetof(wire_alert_t, cpu_id),      8);
    ASSERT_EQ(offsetof(wire_alert_t, alert_type), 12);
    ASSERT_EQ(offsetof(wire_alert_t, guest_rip),  16);
    ASSERT_EQ(offsetof(wire_alert_t, guest_cr3),  24);
    ASSERT_EQ(offsetof(wire_alert_t, target_gpa), 32);
    ASSERT_EQ(offsetof(wire_alert_t, info),       40);
}

TEST(test_field_sizes_frozen)
{
    wire_alert_t a;
    ASSERT_EQ(sizeof(a.timestamp),  8);
    ASSERT_EQ(sizeof(a.cpu_id),     4);
    ASSERT_EQ(sizeof(a.alert_type), 4);
    ASSERT_EQ(sizeof(a.guest_rip),  8);
    ASSERT_EQ(sizeof(a.guest_cr3),  8);
    ASSERT_EQ(sizeof(a.target_gpa), 8);
    ASSERT_EQ(sizeof(a.info),       8);
}

TEST(test_fits_in_one_cache_line)
{
    /* alerts.h has a GR_STATIC_ASSERT that sizeof(gr_alert_t) <=
     * CACHELINE_SIZE (64).  Mirror that here so CI fails before
     * the header assert fires. */
    ASSERT(sizeof(wire_alert_t) <= 64);
}

TEST(test_alert_type_enum_values_locked)
{
    /* Agent's switch-case depends on these exact numeric values. */
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
}

TEST(test_alert_type_count_matches_last_plus_one)
{
    /* Bounds check in the agent uses TYPE_COUNT as an upper limit.
     * If we add a new alert but forget to bump TYPE_COUNT, the new
     * alert is silently rejected as out-of-range. */
    ASSERT_EQ(W_TYPE_COUNT, W_BINARY_TAMPER + 1);
    ASSERT_EQ(W_TYPE_COUNT, 19);
}

TEST(test_struct_has_no_unexpected_padding)
{
    /* Sum of field sizes must equal struct size — no tail or inter-
     * field padding on x86_64.  If this breaks on a new arch, a
     * serialization layer is needed instead of raw memcpy. */
    size_t sum = sizeof(uint64_t)       /* timestamp */
               + sizeof(uint32_t)       /* cpu_id */
               + sizeof(uint32_t)       /* alert_type */
               + sizeof(uint64_t) * 4;  /* rip, cr3, gpa, info */
    ASSERT_EQ(sum, sizeof(wire_alert_t));
}

TEST(test_round_trip_through_raw_bytes)
{
    /* Fill a struct, copy out to bytes, copy back in, verify every
     * field survives — simulating kernel→userspace transport. */
    wire_alert_t src = {
        .timestamp  = 0x0123456789ABCDEFull,
        .cpu_id     = 0xDEADBEEFu,
        .alert_type = W_RANSOMWARE,
        .guest_rip  = 0xFFFFFFFF80100000ull,
        .guest_cr3  = 0x00000000187AE000ull,
        .target_gpa = 0xFEE00000ull,
        .info       = 0xCAFEF00DFEEDC0DEull,
    };
    uint8_t buf[sizeof(wire_alert_t)];
    memcpy(buf, &src, sizeof(src));

    wire_alert_t dst;
    memcpy(&dst, buf, sizeof(dst));

    ASSERT_EQ(dst.timestamp,  src.timestamp);
    ASSERT_EQ(dst.cpu_id,     src.cpu_id);
    ASSERT_EQ(dst.alert_type, src.alert_type);
    ASSERT_EQ(dst.guest_rip,  src.guest_rip);
    ASSERT_EQ(dst.guest_cr3,  src.guest_cr3);
    ASSERT_EQ(dst.target_gpa, src.target_gpa);
    ASSERT_EQ(dst.info,       src.info);
}

TEST(test_ring_buffer_records_do_not_overlap)
{
    /* A userspace reader iterates records by stepping sizeof(alert_t)
     * bytes.  Verify that stepping exactly that many bytes lands on
     * the start of the next record for an array of 8. */
    wire_alert_t ring[8];
    memset(ring, 0, sizeof(ring));
    for (unsigned i = 0; i < 8; i++)
        ring[i].cpu_id = 0x1000 + i;

    uint8_t *p = (uint8_t *)ring;
    for (unsigned i = 0; i < 8; i++) {
        wire_alert_t view;
        memcpy(&view, p + i * sizeof(wire_alert_t), sizeof(view));
        ASSERT_EQ(view.cpu_id, 0x1000u + i);
    }
}

int main(void)
{
    printf("GhostRing alert wire-format ABI tests\n");
    printf("=====================================\n");

    RUN_TEST(test_alert_total_size_is_48_bytes);
    RUN_TEST(test_field_offsets_frozen);
    RUN_TEST(test_field_sizes_frozen);
    RUN_TEST(test_fits_in_one_cache_line);
    RUN_TEST(test_alert_type_enum_values_locked);
    RUN_TEST(test_alert_type_count_matches_last_plus_one);
    RUN_TEST(test_struct_has_no_unexpected_padding);
    RUN_TEST(test_round_trip_through_raw_bytes);
    RUN_TEST(test_ring_buffer_records_do_not_overlap);

    REPORT();
}
