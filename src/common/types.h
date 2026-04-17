/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * types.h — Fundamental types and utility macros for GhostRing.
 *
 * Three build modes:
 *   TEST_USERSPACE  — userspace unit tests (use system stdint.h)
 *   __KERNEL__       — Linux kernel module (use kernel's types)
 *   (freestanding)   — bare hypervisor with no libc
 */

#ifndef GHOSTRING_TYPES_H
#define GHOSTRING_TYPES_H

/* ── Type definitions based on build mode ────────────────────────────── */

#if defined(TEST_USERSPACE)
  /* Userspace test build: system headers provide everything */
  #include <stdint.h>
  #include <stddef.h>
  #include <stdbool.h>

#elif defined(__KERNEL__)
  /* Linux kernel module build: kernel defines all standard types */
  #include <linux/types.h>
  #include <linux/stddef.h>
  #include <linux/bits.h>      /* BIT macro */
  #include <linux/compiler.h>  /* likely/unlikely */
  #include <linux/align.h>     /* ALIGN_DOWN */
  #include <asm/page.h>        /* PAGE_SIZE, PAGE_SHIFT, PAGE_MASK */
  /* bool is _Bool in modern kernels; ensure it's available */
  #ifndef __cplusplus
    #ifndef bool
      typedef _Bool bool;
      #define true  1
      #define false 0
    #endif
  #endif

#else
  /* Freestanding hypervisor build: define everything ourselves */
  typedef unsigned char           uint8_t;
  typedef unsigned short          uint16_t;
  typedef unsigned int            uint32_t;
  typedef unsigned long long      uint64_t;

  typedef signed char             int8_t;
  typedef signed short            int16_t;
  typedef signed int              int32_t;
  typedef signed long long        int64_t;

  typedef uint64_t                uintptr_t;
  typedef int64_t                 intptr_t;
  typedef uint64_t                size_t;

  typedef _Bool                   bool;
  #define true                    1
  #define false                   0
#endif

/* ── NULL ────────────────────────────────────────────────────────────── */

#ifndef NULL
#define NULL                    ((void *)0)
#endif

/* ── Physical / virtual address aliases ──────────────────────────────── */

/*
 * Kernel build already has phys_addr_t defined in linux/types.h,
 * and our definition would conflict.  Use our names in freestanding mode.
 */
#ifndef __KERNEL__
typedef uint64_t                phys_addr_t;
#endif
typedef uint64_t                virt_addr_t;

/* ── Page & alignment constants ──────────────────────────────────────── */

/*
 * Linux kernel defines PAGE_SHIFT, PAGE_SIZE, PAGE_MASK, ALIGN_DOWN,
 * BIT etc. in asm/page_types.h and linux/bits.h.  Use those when
 * building as a kernel module.
 */
#ifndef __KERNEL__
#define PAGE_SHIFT              12
#define PAGE_SIZE               (1ULL << PAGE_SHIFT)       /* 4 KiB */
#define PAGE_MASK               (~(PAGE_SIZE - 1))
#define ALIGN_DOWN(x, a)        ((x) & ~((a) - 1))
#define BIT(n)                  (1ULL << (n))
#endif

/* ALIGN_UP is our own macro — not defined by kernel */
#ifndef ALIGN_UP
#define ALIGN_UP(x, a)          (((x) + ((a) - 1)) & ~((a) - 1))
#endif

/* Macros always ours (not in kernel) */
#define _2MB                    (2ULL * 1024 * 1024)
#define _1GB                    (1ULL * 1024 * 1024 * 1024)

#ifndef __KERNEL__
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr)         (sizeof(arr) / sizeof((arr)[0]))
#endif
#endif

/* ── Compiler attributes ─────────────────────────────────────────────── */

#define GR_PACKED               __attribute__((packed))
#define GR_ALIGNED(n)           __attribute__((aligned(n)))
#define GR_UNUSED               __attribute__((unused))
#define GR_NORETURN             __attribute__((noreturn))
#define GR_NOINLINE             __attribute__((noinline))

#define CACHELINE_SIZE          64

#define GR_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)

/* ── Branch prediction hints (kernel already defines these) ──────────── */

#ifndef __KERNEL__
#define likely(x)               __builtin_expect(!!(x), 1)
#define unlikely(x)             __builtin_expect(!!(x), 0)
#endif

#define gr_compiler_barrier()   __asm__ volatile("" ::: "memory")

/* ── Sanity checks ───────────────────────────────────────────────────── */

GR_STATIC_ASSERT(sizeof(uint8_t)   == 1, "uint8_t must be 1 byte");
GR_STATIC_ASSERT(sizeof(uint16_t)  == 2, "uint16_t must be 2 bytes");
GR_STATIC_ASSERT(sizeof(uint32_t)  == 4, "uint32_t must be 4 bytes");
GR_STATIC_ASSERT(sizeof(uint64_t)  == 8, "uint64_t must be 8 bytes");
GR_STATIC_ASSERT(sizeof(void *)    == 8, "only 64-bit pointers supported");

#endif /* GHOSTRING_TYPES_H */
