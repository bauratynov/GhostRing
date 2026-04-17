/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * alerts.h — Security alert types and structures for the monitoring engine.
 *
 * Every detection subsystem (integrity, MSR guard, DKOM, hooks) emits
 * alerts through a common gr_alert_t structure.  This keeps the
 * user-space reporting path unified and makes it trivial to add new
 * detection categories without touching the chardev transport layer.
 *
 * Alert records are immutable once constructed — no locking required on
 * the read side after gr_alert_push() copies them into the ring buffer.
 */

#ifndef GHOSTRING_MONITOR_ALERTS_H
#define GHOSTRING_MONITOR_ALERTS_H

#include "../common/ghostring.h"

/* ── Alert type enumeration ─────────────────────────────────────────────── */

/*
 * Each value represents a distinct security-relevant event detected by
 * the hypervisor.  User-space tooling switches on these to decide
 * severity and response actions.
 */
enum gr_alert_type {
    GR_ALERT_EPT_WRITE_VIOLATION  = 0,  /* Write to EPT-protected kernel page    */
    GR_ALERT_MSR_TAMPER           = 1,  /* LSTAR / SYSENTER modification attempt */
    GR_ALERT_CR_TAMPER            = 2,  /* Suspicious CR0 / CR4 modification     */
    GR_ALERT_HIDDEN_PROCESS       = 3,  /* DKOM: CR3 active but not in OS list   */
    GR_ALERT_INTEGRITY_FAIL       = 4,  /* CRC32 mismatch on protected region    */
    GR_ALERT_IDT_HOOK             = 5,  /* IDT entry modified from snapshot      */
    GR_ALERT_CODE_INJECTION       = 6,  /* Execute from non-image page           */
    GR_ALERT_SSDT_HOOK            = 7,  /* SSDT entry redirected outside kernel  */
    GR_ALERT_DRVOBJ_HOOK          = 8,  /* Driver dispatch table tampered        */
    GR_ALERT_RANSOMWARE           = 9,  /* Write to canary page — encryption     */
    GR_ALERT_ROP_DETECTED         = 10, /* Shadow stack return address mismatch  */
    GR_ALERT_CALLBACK_TAMPER      = 11, /* Kernel callback array modification    */
    GR_ALERT_TOKEN_STEAL          = 12, /* SYSTEM token copied to another proc   */
    GR_ALERT_PTE_TAMPER           = 13, /* Malicious page table entry write      */
    GR_ALERT_TIMESTOMP            = 14, /* File timestamp set far in the past    */
    GR_ALERT_LOG_WIPE             = 15, /* Event log file deletion/truncation    */
    GR_ALERT_MEM_WIPE             = 16, /* Bulk zeroing of kernel structures     */
    GR_ALERT_DLL_HIJACK           = 17, /* Unsigned DLL from unexpected path     */
    GR_ALERT_BINARY_TAMPER        = 18, /* In-memory modification of signed PE   */

    GR_ALERT_TYPE_COUNT                 /* Must be last — used for bounds checks */
};

/* ── Alert structure ────────────────────────────────────────────────────── */

/*
 * Fixed-size, cache-line-aligned record pushed to the chardev ring buffer.
 *
 * Fields are ordered so that the most commonly inspected data (type, RIP,
 * CR3) falls within a single 64-byte cache line for fast filtering.
 */
typedef struct gr_alert {
    uint64_t timestamp;         /* RDTSC value at detection time             */
    uint32_t cpu_id;            /* Logical processor that raised the alert   */
    uint32_t alert_type;        /* One of enum gr_alert_type                 */
    uint64_t guest_rip;         /* Guest instruction pointer at the fault    */
    uint64_t guest_cr3;         /* Guest address space (page-table root)     */
    uint64_t target_gpa;        /* Guest physical address that was targeted  */
    uint64_t info;              /* Type-specific payload:
                                 *   INTEGRITY_FAIL  : expected CRC32 in [63:32],
                                 *                     actual   CRC32 in [31:0]
                                 *   MSR_TAMPER      : MSR index
                                 *   IDT_HOOK        : vector number
                                 *   HIDDEN_PROCESS  : detected CR3 value
                                 *   EPT_WRITE       : exit qualification
                                 *   SSDT_HOOK       : SSDT entry index
                                 *   DRVOBJ_HOOK     : IRP major function code
                                 *   RANSOMWARE      : source process CR3
                                 *   ROP_DETECTED    : corrupted return address
                                 */
} gr_alert_t;

GR_STATIC_ASSERT(sizeof(gr_alert_t) <= CACHELINE_SIZE,
                 "gr_alert_t must fit in one cache line");

/* ── Alert emission helper ──────────────────────────────────────────────── */

/*
 * Read the TSC and current CPU ID, fill in the common fields, then push
 * through the chardev ring buffer.  Designed to be called from within
 * VM-exit handlers where latency matters — no heap allocation, no locks
 * beyond the ring buffer's own.
 */
static inline void gr_alert_emit(uint32_t type, uint64_t rip,
                                 uint64_t cr3, uint64_t gpa,
                                 uint64_t info)
{
    uint32_t cpu = gr_get_cpu_id();
    gr_alert_push(cpu, type, info);

    GR_LOG("ALERT type=", (uint64_t)type);
    GR_LOG("  rip=", rip);
    GR_LOG("  cr3=", cr3);
    GR_LOG("  gpa=", gpa);
}

#endif /* GHOSTRING_MONITOR_ALERTS_H */
