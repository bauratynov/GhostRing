/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * dkom.c — Hidden process detection through CR3 cross-referencing.
 *
 * The fundamental insight: a rootkit can lie to the OS about what
 * processes exist, but it cannot hide the fact that a process's page
 * tables are loaded into CR3 for execution.  By capturing every
 * MOV-to-CR3 (which causes a VM-exit when CR3-load exiting is enabled)
 * we build a ground-truth set of active address spaces.  Comparing
 * this set against the kernel's own process list reveals discrepancies.
 *
 * Hash table design: open-addressing with linear probing and power-of-2
 * table size.  CR3 values are page-aligned (low 12 bits zero), so we
 * use bits [12..23] as the hash to avoid clustering on the zero bits.
 */

#include "dkom.h"
#include "alerts.h"

/* ── Hash function ──────────────────────────────────────────────────────── */

/*
 * CR3 values are always page-aligned (bits [11:0] = 0 or contain PCID).
 * We shift right by 12 and mask to the table size for a simple but
 * effective distribution.  Linear probing handles the remaining
 * collisions.
 */
static inline uint32_t cr3_hash(uint64_t cr3)
{
    /* Strip PCID bits (low 12) and fold upper bits down */
    uint64_t key = cr3 >> PAGE_SHIFT;
    key ^= (key >> 16);
    key ^= (key >> 8);
    return (uint32_t)(key & (GR_CR3_SET_SLOTS - 1));
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void gr_dkom_init(gr_cr3_set_t *set)
{
    if (!set)
        return;

    /* Zero all slots — cr3 == 0 marks an empty slot */
    for (uint32_t i = 0; i < GR_CR3_SET_SLOTS; i++) {
        set->slots[i].cr3        = 0;
        set->slots[i].generation = 0;
        set->slots[i].flags      = 0;
    }
    set->count      = 0;
    set->generation  = 1;
    gr_spin_init(&set->lock);

    GR_LOG_STR("dkom: CR3 set initialised");
}

void gr_dkom_add_cr3(gr_cr3_set_t *set, uint64_t cr3_value)
{
    if (!set || cr3_value == 0)
        return;

    /*
     * Mask off PCID (bits [11:0]) so we compare page-table roots only.
     * Two processes with different PCIDs but the same physical root
     * would be the same address space.
     */
    uint64_t cr3_clean = cr3_value & PAGE_MASK;

    uint64_t flags = gr_spin_lock_irqsave(&set->lock);

    uint32_t idx = cr3_hash(cr3_clean);

    for (uint32_t probe = 0; probe < GR_CR3_SET_SLOTS; probe++) {
        uint32_t slot = (idx + probe) & (GR_CR3_SET_SLOTS - 1);

        if (set->slots[slot].cr3 == cr3_clean) {
            /* Already tracked — refresh generation */
            set->slots[slot].generation = set->generation;
            gr_spin_unlock_irqrestore(&set->lock, flags);
            return;
        }

        if (set->slots[slot].cr3 == 0) {
            /* Empty slot — insert */
            set->slots[slot].cr3        = cr3_clean;
            set->slots[slot].generation = set->generation;
            set->count++;
            gr_spin_unlock_irqrestore(&set->lock, flags);
            return;
        }
    }

    /*
     * Table full — this should not happen with 4096 slots unless the
     * system has an extraordinary number of processes.  Log and move on.
     */
    gr_spin_unlock_irqrestore(&set->lock, flags);
    GR_LOG_STR("dkom: CR3 set full, cannot insert");
}

void gr_dkom_remove_cr3(gr_cr3_set_t *set, uint64_t cr3_value)
{
    if (!set || cr3_value == 0)
        return;

    uint64_t cr3_clean = cr3_value & PAGE_MASK;

    uint64_t flags = gr_spin_lock_irqsave(&set->lock);

    uint32_t idx = cr3_hash(cr3_clean);

    for (uint32_t probe = 0; probe < GR_CR3_SET_SLOTS; probe++) {
        uint32_t slot = (idx + probe) & (GR_CR3_SET_SLOTS - 1);

        if (set->slots[slot].cr3 == cr3_clean) {
            set->slots[slot].cr3        = 0;
            set->slots[slot].generation = 0;
            set->count--;
            gr_spin_unlock_irqrestore(&set->lock, flags);
            return;
        }

        if (set->slots[slot].cr3 == 0) {
            /* Hit an empty slot — entry not present */
            break;
        }
    }

    gr_spin_unlock_irqrestore(&set->lock, flags);
}

/* ── Kernel process list traversal ──────────────────────────────────────── */

/*
 * Walk the Linux kernel's circular doubly-linked task list starting
 * from init_task.  For each task, extract mm->pgd to obtain its CR3.
 *
 * Safety: we read guest memory via the identity-mapped EPT, so
 * the pointers are guest-virtual addresses that we must translate.
 * For simplicity (and because the kernel's virtual mapping is linear
 * on x86_64), we assume the standard direct-map offset.
 *
 * Returns the number of legitimate CR3 values found, stored in the
 * output array (must hold at least GR_CR3_SET_SLOTS entries).
 */

/*
 * Read a 64-bit value from a guest virtual address.  In a bare-metal
 * hypervisor with identity-mapped EPT and kernel direct-map, the GVA
 * is directly accessible.  In production this should go through a
 * proper GVA-to-GPA translation layer.
 */
static inline uint64_t read_guest_u64(uint64_t gva)
{
    return *(volatile const uint64_t *)(uintptr_t)gva;
}

static uint32_t walk_linux_tasks(const gr_dkom_config_t *config,
                                 uint64_t *cr3_out,
                                 uint32_t max_out)
{
    if (!config->configured || config->init_task_gva == 0)
        return 0;

    uint32_t found = 0;
    uint64_t init_task = config->init_task_gva;

    /*
     * init_task.tasks is a list_head.  The first entry (next pointer)
     * at init_task + tasks_offset points to the next task's tasks field.
     */
    uint64_t head_ptr = init_task + config->tasks_offset;
    uint64_t current  = read_guest_u64(head_ptr);  /* first next pointer */

    /*
     * Safety limit: do not traverse more than 32768 entries to bound
     * execution time in case of a corrupted list.
     */
    uint32_t max_walk = 32768;

    while (current != head_ptr && found < max_out && max_walk-- > 0) {
        /*
         * current points to the 'tasks' list_head inside a task_struct.
         * The task_struct base is at (current - tasks_offset).
         */
        uint64_t task_base = current - config->tasks_offset;

        /* Read task_struct->mm (pointer to mm_struct) */
        uint64_t mm_ptr = read_guest_u64(task_base + config->mm_offset);

        if (mm_ptr != 0) {
            /* Read mm_struct->pgd (pointer to PGD page) */
            uint64_t pgd_ptr = read_guest_u64(mm_ptr + config->pgd_offset);

            if (pgd_ptr != 0) {
                /*
                 * pgd_ptr is a kernel virtual address of the PGD.
                 * The physical CR3 is pgd_ptr minus the kernel direct-map
                 * base (typically 0xffff888000000000 on x86_64 Linux).
                 * For our comparison, we store the physical page address.
                 */
                uint64_t cr3_phys = pgd_ptr & PAGE_MASK;

                /*
                 * Filter: only store if it looks like a valid physical
                 * address (below the reasonable physical memory limit).
                 */
                if (cr3_phys != 0 && cr3_phys < (1ULL << 46)) {
                    cr3_out[found++] = cr3_phys;
                }
            }
        }

        /* Advance to next task: read the 'next' pointer */
        current = read_guest_u64(current);
    }

    return found;
}

/* ── Cross-reference and detection ──────────────────────────────────────── */

/*
 * Check whether a given CR3 appears in the kernel-enumerated list.
 * Linear scan is acceptable because the typical process count is in
 * the hundreds, and this runs infrequently (periodic or on-demand).
 */
static bool cr3_in_list(uint64_t cr3, const uint64_t *list, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        if (list[i] == cr3)
            return true;
    }
    return false;
}

uint32_t gr_dkom_scan(gr_cr3_set_t *set, const gr_dkom_config_t *config)
{
    if (!set || !config)
        return 0;

    if (!config->configured) {
        GR_LOG_STR("dkom: not configured, skipping scan");
        return 0;
    }

    /*
     * Step 1: Walk the kernel process list and collect all legitimate
     * CR3 values into a temporary array.
     */
    static uint64_t kernel_cr3s[GR_CR3_SET_SLOTS];
    uint32_t kernel_count = walk_linux_tasks(config, kernel_cr3s,
                                             GR_CR3_SET_SLOTS);

    GR_LOG("dkom: kernel reports processes=", (uint64_t)kernel_count);

    if (kernel_count == 0) {
        GR_LOG_STR("dkom: no kernel processes found (misconfigured?)");
        return 0;
    }

    /*
     * Step 2: For every CR3 in the hardware-observed set, check if the
     * kernel's process list accounts for it.  Any unaccounted CR3
     * indicates a hidden process.
     */
    uint32_t hidden = 0;

    uint64_t flags = gr_spin_lock_irqsave(&set->lock);

    for (uint32_t i = 0; i < GR_CR3_SET_SLOTS; i++) {
        uint64_t cr3 = set->slots[i].cr3;
        if (cr3 == 0)
            continue;

        /*
         * Skip stale entries: if the generation is more than 2 cycles
         * behind, the process likely terminated.  Remove it to keep
         * the set clean.
         */
        if (set->generation - set->slots[i].generation > 2) {
            set->slots[i].cr3 = 0;
            set->count--;
            continue;
        }

        if (!cr3_in_list(cr3, kernel_cr3s, kernel_count)) {
            hidden++;

            gr_alert_emit(GR_ALERT_HIDDEN_PROCESS,
                          0,    /* RIP: not available for hidden proc */
                          cr3,  /* CR3 of the hidden process */
                          0,    /* GPA: not applicable */
                          cr3); /* info: duplicate CR3 for easy parsing */

            GR_LOG("dkom: HIDDEN PROCESS cr3=", cr3);
        }
    }

    /* Advance generation for next scan cycle */
    set->generation++;

    gr_spin_unlock_irqrestore(&set->lock, flags);

    GR_LOG("dkom: scan complete, hidden=", (uint64_t)hidden);
    return hidden;
}
