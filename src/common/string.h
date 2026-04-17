/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * string.h — Freestanding memset/memcpy/memcmp.
 *
 * Three build modes:
 *   TEST_USERSPACE  — use libc string.h
 *   __KERNEL__       — use kernel's linux/string.h (defines everything)
 *   (freestanding)   — define our own
 */

#ifndef GHOSTRING_STRING_H
#define GHOSTRING_STRING_H

#include "types.h"

#if defined(TEST_USERSPACE)
  #include <string.h>

#elif defined(__KERNEL__)
  #include <linux/string.h>

#else
  /* Freestanding hypervisor — compiler generates implicit calls to
   * memset/memcpy/memcmp, so we must provide them. */

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
#endif

#endif /* GHOSTRING_STRING_H */
