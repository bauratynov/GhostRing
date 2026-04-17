/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_dkom.c — Unit tests for the CR3 hash table used in DKOM detection.
 *
 * Compile: gcc -o test_dkom test_dkom.c && ./test_dkom
 */

#include "test_framework.h"

/* Simple CR3 hash table reimplementation for testing */
#define CR3_TABLE_SIZE 4096
#define CR3_TABLE_MASK (CR3_TABLE_SIZE - 1)

typedef struct {
    uint64_t cr3;
    uint32_t generation;
    uint8_t  occupied;
} cr3_entry_t;

typedef struct {
    cr3_entry_t entries[CR3_TABLE_SIZE];
    uint32_t    count;
    uint32_t    generation;
} cr3_table_t;

static void cr3_table_init(cr3_table_t *t)
{
    uint8_t *p = (uint8_t *)t;
    for (size_t i = 0; i < sizeof(*t); i++)
        p[i] = 0;
}

static uint32_t cr3_hash(uint64_t cr3)
{
    /* CR3 is page-aligned (low 12 bits = PCID or zero), so shift down */
    cr3 >>= 12;
    cr3 ^= (cr3 >> 16);
    cr3 *= 0x45d9f3b;
    cr3 ^= (cr3 >> 16);
    return (uint32_t)(cr3 & CR3_TABLE_MASK);
}

static int cr3_add(cr3_table_t *t, uint64_t cr3)
{
    uint32_t idx = cr3_hash(cr3);
    for (uint32_t i = 0; i < CR3_TABLE_SIZE; i++) {
        uint32_t slot = (idx + i) & CR3_TABLE_MASK;
        if (!t->entries[slot].occupied) {
            t->entries[slot].cr3 = cr3;
            t->entries[slot].occupied = 1;
            t->entries[slot].generation = t->generation;
            t->count++;
            return 1;
        }
        if (t->entries[slot].cr3 == cr3) {
            t->entries[slot].generation = t->generation;
            return 0;  /* already present */
        }
    }
    return -1;  /* table full */
}

static int cr3_contains(cr3_table_t *t, uint64_t cr3)
{
    uint32_t idx = cr3_hash(cr3);
    for (uint32_t i = 0; i < CR3_TABLE_SIZE; i++) {
        uint32_t slot = (idx + i) & CR3_TABLE_MASK;
        if (!t->entries[slot].occupied)
            return 0;
        if (t->entries[slot].cr3 == cr3)
            return 1;
    }
    return 0;
}

static cr3_table_t table;

/* ═══════════════════════════════════════════════════════════════════════ */

TEST(test_cr3_init_empty)
{
    cr3_table_init(&table);
    ASSERT_EQ(table.count, 0);
    ASSERT(!cr3_contains(&table, 0x1000));
}

TEST(test_cr3_add_and_find)
{
    cr3_table_init(&table);

    cr3_add(&table, 0x00100000);
    cr3_add(&table, 0x00200000);
    cr3_add(&table, 0x00300000);

    ASSERT(cr3_contains(&table, 0x00100000));
    ASSERT(cr3_contains(&table, 0x00200000));
    ASSERT(cr3_contains(&table, 0x00300000));
    ASSERT(!cr3_contains(&table, 0x00400000));
    ASSERT_EQ(table.count, 3);
}

TEST(test_cr3_no_duplicates)
{
    cr3_table_init(&table);

    cr3_add(&table, 0x00100000);
    cr3_add(&table, 0x00100000);  /* duplicate */
    cr3_add(&table, 0x00100000);  /* duplicate */

    ASSERT_EQ(table.count, 1);
}

TEST(test_cr3_many_entries)
{
    cr3_table_init(&table);

    /* Add 1000 unique CR3 values */
    for (uint64_t i = 0; i < 1000; i++) {
        cr3_add(&table, (i + 1) * 0x1000);
    }
    ASSERT_EQ(table.count, 1000);

    /* Verify all present */
    for (uint64_t i = 0; i < 1000; i++) {
        ASSERT(cr3_contains(&table, (i + 1) * 0x1000));
    }

    /* Verify absent */
    ASSERT(!cr3_contains(&table, 0xDEAD0000));
}

TEST(test_cr3_hidden_process_detection)
{
    cr3_table_init(&table);

    /* Simulate: 5 processes observed via CR3 switches */
    uint64_t hw_cr3s[] = { 0x100000, 0x200000, 0x300000, 0x400000, 0x500000 };
    for (int i = 0; i < 5; i++)
        cr3_add(&table, hw_cr3s[i]);

    /* Simulate: OS reports only 4 processes (0x300000 hidden by DKOM) */
    uint64_t os_cr3s[] = { 0x100000, 0x200000, 0x400000, 0x500000 };
    int os_count = 4;

    /* Cross-reference: find CR3s in hardware but not in OS list */
    int hidden = 0;
    for (int i = 0; i < 5; i++) {
        int found_in_os = 0;
        for (int j = 0; j < os_count; j++) {
            if (hw_cr3s[i] == os_cr3s[j]) {
                found_in_os = 1;
                break;
            }
        }
        if (!found_in_os) {
            hidden++;
            ASSERT_EQ(hw_cr3s[i], 0x300000);  /* the hidden one */
        }
    }
    ASSERT_EQ(hidden, 1);
}

/* ═══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("GhostRing DKOM hash table tests\n");
    printf("================================\n");

    RUN_TEST(test_cr3_init_empty);
    RUN_TEST(test_cr3_add_and_find);
    RUN_TEST(test_cr3_no_duplicates);
    RUN_TEST(test_cr3_many_entries);
    RUN_TEST(test_cr3_hidden_process_detection);

    REPORT();
}
