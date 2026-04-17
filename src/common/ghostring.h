/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * ghostring.h — Master header for the GhostRing hypervisor platform.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 */

#ifndef GHOSTRING_H
#define GHOSTRING_H

/* ── Version ─────────────────────────────────────────────────────────────── */

#define GHOSTRING_VERSION_MAJOR  0
#define GHOSTRING_VERSION_MINOR  1
#define GHOSTRING_VERSION_PATCH  0
#define GHOSTRING_VERSION_STRING "0.1.0"

/* ── Architecture gate ───────────────────────────────────────────────────── */

#if !defined(__x86_64__) && !defined(_M_X64)
#error "GhostRing only supports x86-64 (Intel 64 / AMD64)."
#endif

/* ── Feature flags ───────────────────────────────────────────────────────── */

/*
 * Enable Intel VT-x (VMX) support. Controls compilation of VMCS setup,
 * VM-entry / VM-exit handlers, and EPT management.
 */
#ifndef GHOSTRING_VTX
#define GHOSTRING_VTX  1
#endif

/*
 * Enable AMD-V (SVM) support. Controls compilation of VMCB setup,
 * #VMEXIT handlers, and Nested Page Table management.
 */
#ifndef GHOSTRING_SVM
#define GHOSTRING_SVM  0
#endif

/* ── Forward declarations ────────────────────────────────────────────────── */

/*
 * Core types referenced across subsystems before their full definitions
 * are available. Keeps inter-header coupling minimal.
 */
typedef struct gr_vcpu         gr_vcpu_t;
typedef struct gr_vm           gr_vm_t;
typedef struct gr_ept_ctx      gr_ept_ctx_t;
typedef struct gr_vmcs_region  gr_vmcs_region_t;
typedef struct gr_page_pool    gr_page_pool_t;

/* ── Common headers ──────────────────────────────────────────────────────── */

#include "types.h"
#include "string.h"
#include "spinlock.h"
#include "cpu.h"
#include "serial.h"
#include "mem.h"
#include "platform.h"
#include "vcpu.h"
#include "percpu.h"

#endif /* GHOSTRING_H */
