/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_framework.h — Minimal unit test framework for GhostRing.
 *
 * Runs in userspace (no kernel, no VT-x needed).  Tests the pure-logic
 * components: allocator, hash tables, CRC32, data structures.
 *
 * Usage:
 *   TEST(test_name) { ASSERT(condition); ASSERT_EQ(a, b); }
 *   int main() { RUN_TEST(test_name); REPORT(); }
 */

#ifndef GHOSTRING_TEST_FRAMEWORK_H
#define GHOSTRING_TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int _tests_run    = 0;
static int _tests_passed = 0;
static int _tests_failed = 0;

#define TEST(name) static void name(void)

#define ASSERT(cond) do {                                               \
    if (!(cond)) {                                                      \
        fprintf(stderr, "  FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        _tests_failed++;                                                \
        return;                                                         \
    }                                                                   \
} while (0)

#define ASSERT_EQ(a, b) do {                                            \
    uint64_t _a = (uint64_t)(a), _b = (uint64_t)(b);                   \
    if (_a != _b) {                                                     \
        fprintf(stderr, "  FAIL: %s:%d: %s == %llu, expected %llu\n",  \
                __FILE__, __LINE__, #a,                                 \
                (unsigned long long)_a, (unsigned long long)_b);        \
        _tests_failed++;                                                \
        return;                                                         \
    }                                                                   \
} while (0)

#define ASSERT_NEQ(a, b) do {                                           \
    if ((uint64_t)(a) == (uint64_t)(b)) {                               \
        fprintf(stderr, "  FAIL: %s:%d: %s should not equal %s\n",     \
                __FILE__, __LINE__, #a, #b);                            \
        _tests_failed++;                                                \
        return;                                                         \
    }                                                                   \
} while (0)

#define RUN_TEST(name) do {                                             \
    _tests_run++;                                                       \
    int _before = _tests_failed;                                        \
    name();                                                             \
    if (_tests_failed == _before) {                                     \
        _tests_passed++;                                                \
        printf("  PASS: %s\n", #name);                                  \
    } else {                                                            \
        printf("  FAIL: %s\n", #name);                                  \
    }                                                                   \
} while (0)

#define REPORT() do {                                                   \
    printf("\n%d/%d tests passed", _tests_passed, _tests_run);          \
    if (_tests_failed > 0)                                              \
        printf(", %d FAILED", _tests_failed);                           \
    printf("\n");                                                       \
    return _tests_failed > 0 ? 1 : 0;                                  \
} while (0)

#endif /* GHOSTRING_TEST_FRAMEWORK_H */
