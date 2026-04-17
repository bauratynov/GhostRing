/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * dkom.h — Hidden process detection via Direct Kernel Object Manipulation.
 *
 * Rootkits commonly unlink a process from the kernel's PsActiveProcessList
 * (Windows) or task_struct list (Linux) to hide from tools like ps/taskmgr.
 * The process still runs — it still has a CR3 (page-table root) and
 * receives CPU time — but OS-level enumeration APIs skip it.
 *
 * Our detection cross-references two independent views:
 *   1. Hardware view  — CR3 values observed from MOV-to-CR3 VM-exits.
 *   2. OS kernel view — CR3 values extracted by walking the process list.
 *
 * Any CR3 present in (1) but absent from (2) indicates a hidden process.
 *
 * The CR3 set is stored in an open-addressed hash table (power-of-2 size)
 * for O(1) average-case lookup, which is critical since MOV-CR3 exits
 * are extremely frequent (every context switch).
 */

#ifndef GHOSTRING_MONITOR_DKOM_H
#define GHOSTRING_MONITOR_DKOM_H

#include "../common/ghostring.h"

/* ── CR3 hash table ─────────────────────────────────────────────────────── */

#define GR_CR3_SET_SLOTS    4096    /* Must be power of 2 */

/*
 * Each slot stores a CR3 value and a generation counter.  The generation
 * is bumped on every scan cycle; stale entries (from terminated processes)
 * are implicitly expired when their generation falls behind.
 */
typedef struct gr_cr3_entry {
    uint64_t cr3;               /* CR3 value (0 = empty slot)            */
    uint32_t generation;        /* Last-seen generation                  */
    uint32_t flags;             /* Reserved for future use               */
} gr_cr3_entry_t;

typedef struct gr_cr3_set {
    gr_cr3_entry_t slots[GR_CR3_SET_SLOTS];
    uint32_t       count;       /* Number of occupied slots              */
    uint32_t       generation;  /* Current generation counter            */
    gr_spinlock_t  lock;        /* Protects concurrent MOV-CR3 updates   */
} gr_cr3_set_t;

/* ── Linux task_struct traversal offsets ─────────────────────────────────── */

/*
 * These offsets are kernel-version-dependent and must be supplied by the
 * loader or a configuration hypercall.  Defaults below are for a
 * typical Linux 5.15+ x86_64 kernel with default configs.
 *
 * User-space can update these via a hypercall before arming detection.
 */
typedef struct gr_dkom_config {
    uint64_t init_task_gva;         /* &init_task kernel virtual address */
    uint32_t tasks_offset;          /* offsetof(struct task_struct, tasks) */
    uint32_t mm_offset;             /* offsetof(struct task_struct, mm) */
    uint32_t pgd_offset;            /* offsetof(struct mm_struct, pgd) */
    uint64_t kernel_text_start;     /* Start of kernel text mapping      */
    uint64_t kernel_text_end;       /* End of kernel text mapping        */
    bool     configured;            /* Set to true after offsets supplied */
} gr_dkom_config_t;

/* ── Public API ─────────────────────────────────────────────────────────── */

/*
 * gr_dkom_init — Initialise the CR3 set hash table.
 *
 * Must be called once per vCPU before any CR3 tracking begins.
 */
void gr_dkom_init(gr_cr3_set_t *set);

/*
 * gr_dkom_add_cr3 — Record a CR3 value observed from a MOV-to-CR3 exit.
 *
 * Called from the CR-access VM-exit handler on every context switch.
 * Ignores the kernel's own CR3 (matching kernel_text range) to reduce
 * noise — the kernel identity is never "hidden".
 */
void gr_dkom_add_cr3(gr_cr3_set_t *set, uint64_t cr3_value);

/*
 * gr_dkom_remove_cr3 — Remove a CR3 value from the set.
 *
 * Called when a process termination is observed (optional — stale
 * entries are also handled by generation expiry).
 */
void gr_dkom_remove_cr3(gr_cr3_set_t *set, uint64_t cr3_value);

/*
 * gr_dkom_scan — Perform a full hidden-process scan.
 *
 * Walks the kernel's process list, collects all legitimate CR3 values,
 * then compares against the hardware-observed CR3 set.  Any CR3 found
 * in hardware but not in the OS list triggers a GR_ALERT_HIDDEN_PROCESS.
 *
 * @set    : The CR3 set populated by MOV-CR3 exit tracking.
 * @config : Kernel structure offsets for task_struct traversal.
 *
 * Returns the number of hidden processes detected.
 */
uint32_t gr_dkom_scan(gr_cr3_set_t *set, const gr_dkom_config_t *config);

#endif /* GHOSTRING_MONITOR_DKOM_H */
