/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * globals.c — Definitions for global variables declared extern in headers.
 *
 * This file must be compiled into exactly one translation unit.  For the
 * Linux kernel module, it is linked as part of ghostring.ko.  For Windows,
 * as part of ghostring.sys.  For unit tests, the test stub provides its
 * own definitions and this file is excluded.
 */

#include "ghostring.h"

/* ── Platform callbacks (platform.h) ───────────────────────────────────── */

/*
 * Initialised to zero — all function pointers are NULL until the loader
 * registers its implementations via gr_platform_register().
 */
gr_platform_ops_t g_platform = { 0 };

/* ── Per-CPU table (percpu.h) ──────────────────────────────────────────── */

/*
 * All vcpu pointers start NULL.  The loader populates them during the
 * per-CPU virtualisation broadcast.
 */
gr_percpu_t g_percpu = { .cpu_count = 0 };
