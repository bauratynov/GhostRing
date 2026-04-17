/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * types.h — Fundamental types and utility macros for a freestanding C99
 * environment. No standard library dependency — sizes are derived from
 * compiler-provided __SIZEOF_*__ macros which GCC and Clang guarantee.
 */

#ifndef GHOSTRING_TYPES_H
#define GHOSTRING_TYPES_H

/* ── Fixed-width integers ────────────────────────────────────────────────── */

/*
 * In userspace test builds, <stdint.h> defines these.  Guard against
 * redefinition when compiling alongside the system headers.
 */
#ifdef TEST_USERSPACE
  #include <stdint.h>
  #include <stddef.h>
  #include <stdbool.h>
#else
  typedef unsigned char           uint8_t;
  typedef unsigned short          uint16_t;
  typedef unsigned int            uint32_t;
  typedef unsigned long long      uint64_t;

  typedef signed char             int8_t;
  typedef signed short            int16_t;
  typedef signed int              int32_t;
  typedef signed long long        int64_t;

  /* Pointer-width types — on x86-64 pointers are always 8 bytes. */
  typedef uint64_t                uintptr_t;
  typedef int64_t                 intptr_t;
  typedef uint64_t                size_t;
#endif

/* ── Boolean ─────────────────────────────────────────────────────────────── */

#ifndef TEST_USERSPACE
typedef _Bool                   bool;
#define true                    1
#define false                   0
#endif

/* ── NULL ────────────────────────────────────────────────────────────────── */

#ifndef NULL
#define NULL                    ((void *)0)
#endif

/* ── Physical / virtual address aliases ──────────────────────────────────── */

typedef uint64_t                phys_addr_t;
typedef uint64_t                virt_addr_t;

/* ── Page & alignment constants ──────────────────────────────────────────── */

#define PAGE_SHIFT              12
#define PAGE_SIZE               (1ULL << PAGE_SHIFT)       /* 4 KiB */
#define PAGE_MASK               (~(PAGE_SIZE - 1))

#define _2MB                    (2ULL * 1024 * 1024)
#define _1GB                    (1ULL * 1024 * 1024 * 1024)

/* ── Alignment helpers ───────────────────────────────────────────────────── */

/* Round x UP to the nearest multiple of a (a must be power of 2). */
#define ALIGN_UP(x, a)          (((x) + ((a) - 1)) & ~((a) - 1))

/* Round x DOWN to the nearest multiple of a (a must be power of 2). */
#define ALIGN_DOWN(x, a)        ((x) & ~((a) - 1))

/* ── Bit manipulation ────────────────────────────────────────────────────── */

#define BIT(n)                  (1ULL << (n))

/* ── Array utilities ─────────────────────────────────────────────────────── */

#define ARRAY_SIZE(arr)         (sizeof(arr) / sizeof((arr)[0]))

/* ── Compiler attributes ─────────────────────────────────────────────────── */

#define GR_PACKED               __attribute__((packed))
#define GR_ALIGNED(n)           __attribute__((aligned(n)))
#define GR_UNUSED               __attribute__((unused))
#define GR_NORETURN             __attribute__((noreturn))
#define GR_NOINLINE             __attribute__((noinline))

/* ── Cache line size (Intel / AMD desktop / server CPUs) ─────────────────── */

#define CACHELINE_SIZE          64

/* ── Static assertion ────────────────────────────────────────────────────── */

/*
 * C11 _Static_assert is available in GCC >= 4.6 and Clang >= 3.0 even in
 * C99 mode as an extension.  Provide a fallback for anything older.
 */
#define GR_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)

/* ── Branch prediction hints ─────────────────────────────────────────────── */

#define likely(x)               __builtin_expect(!!(x), 1)
#define unlikely(x)             __builtin_expect(!!(x), 0)

/* ── Inline barrier helpers ──────────────────────────────────────────────── */

/* Full compiler memory fence — prevents reordering across this point. */
#define gr_compiler_barrier()   __asm__ volatile("" ::: "memory")

/* ── Sanity checks ───────────────────────────────────────────────────────── */

GR_STATIC_ASSERT(sizeof(uint8_t)   == 1, "uint8_t must be 1 byte");
GR_STATIC_ASSERT(sizeof(uint16_t)  == 2, "uint16_t must be 2 bytes");
GR_STATIC_ASSERT(sizeof(uint32_t)  == 4, "uint32_t must be 4 bytes");
GR_STATIC_ASSERT(sizeof(uint64_t)  == 8, "uint64_t must be 8 bytes");
GR_STATIC_ASSERT(sizeof(uintptr_t) == 8, "uintptr_t must match pointer width");
GR_STATIC_ASSERT(sizeof(void *)    == 8, "only 64-bit pointers supported");

#endif /* GHOSTRING_TYPES_H */
