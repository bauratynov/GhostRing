/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * string.h — Freestanding memset/memcpy/memcmp.
 *
 * GCC and Clang emit implicit calls to memset/memcpy for struct
 * assignments, compound literals, and zero-initialization.  Without
 * these definitions, the linker fails with "undefined reference to
 * memset" in a freestanding build.
 *
 * The implementations are intentionally simple byte loops.  The
 * hypervisor core is compiled with -mno-sse -mno-avx so the compiler
 * will not auto-vectorize these into SIMD — keeping them safe for
 * use before/after XSAVE context.
 */

#ifndef GHOSTRING_STRING_H
#define GHOSTRING_STRING_H

#include "types.h"

static inline void *memset(void *s, int c, size_t n)
{
    uint8_t *p = (uint8_t *)s;
    while (n--)
        *p++ = (uint8_t)c;
    return s;
}

static inline void *memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--)
        *d++ = *s++;
    return dst;
}

static inline int memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *p = (const uint8_t *)a;
    const uint8_t *q = (const uint8_t *)b;
    for (size_t i = 0; i < n; i++)
        if (p[i] != q[i])
            return (int)p[i] - (int)q[i];
    return 0;
}

static inline size_t strlen(const char *s)
{
    size_t len = 0;
    while (s[len])
        len++;
    return len;
}

#endif /* GHOSTRING_STRING_H */
