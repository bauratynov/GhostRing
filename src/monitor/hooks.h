/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * hooks.h — IDT hook detection and EPT-based IDT protection.
 *
 * The Interrupt Descriptor Table is a high-value rootkit target: by
 * replacing an IDT entry's handler address, an attacker can intercept
 * any interrupt or exception — page faults, system calls (via INT 0x80
 * on legacy paths), debug traps, etc.
 *
 * We snapshot the IDT at hypervisor load time (before guest code has
 * had a chance to tamper), then periodically compare against the live
 * copy.  Additionally, we EPT-write-protect the IDT pages so that
 * direct modification triggers an immediate VM-exit rather than
 * waiting for the next periodic check.
 *
 * On x86_64, the IDT contains 256 gate descriptors of 16 bytes each,
 * totalling 4096 bytes (exactly one page in the common case).
 */

#ifndef GHOSTRING_MONITOR_HOOKS_H
#define GHOSTRING_MONITOR_HOOKS_H

#include "../common/ghostring.h"

/* ── Constants ──────────────────────────────────────────────────────────── */

#define GR_IDT_ENTRIES          256
#define GR_IDT_ENTRY_SIZE       16      /* 16 bytes per gate on x86_64 */
#define GR_IDT_TOTAL_SIZE       (GR_IDT_ENTRIES * GR_IDT_ENTRY_SIZE)

/* ── IDT gate descriptor (x86_64 interrupt/trap gate) ───────────────────── */

/*
 * Intel SDM Vol. 3A, Section 6.14.1.  On x86_64, interrupt and trap
 * gates are 16 bytes.  The handler address is split across three fields.
 */
typedef struct GR_PACKED gr_idt_gate {
    uint16_t offset_low;        /* Handler address bits [15:0]           */
    uint16_t segment_selector;  /* Code segment selector                 */
    uint8_t  ist;               /* IST index (bits [2:0]), rest reserved */
    uint8_t  type_attr;         /* Type (4 bits), S, DPL, P              */
    uint16_t offset_mid;        /* Handler address bits [31:16]          */
    uint32_t offset_high;       /* Handler address bits [63:32]          */
    uint32_t reserved;
} gr_idt_gate_t;

GR_STATIC_ASSERT(sizeof(gr_idt_gate_t) == GR_IDT_ENTRY_SIZE,
                 "IDT gate must be 16 bytes");

/* ── IDT snapshot state ─────────────────────────────────────────────────── */

typedef struct gr_hooks_state {
    gr_idt_gate_t snapshot[GR_IDT_ENTRIES]; /* Baseline IDT copy         */
    phys_addr_t   idt_phys;                 /* Physical address of IDT   */
    uint64_t      idt_base_gva;             /* Guest virtual address     */
    uint64_t      kernel_text_start;        /* Kernel text low bound     */
    uint64_t      kernel_text_end;          /* Kernel text high bound    */
    bool          initialised;
} gr_hooks_state_t;

/* ── Public API ─────────────────────────────────────────────────────────── */

/*
 * gr_hooks_init — Snapshot the current IDT contents as the baseline.
 *
 * Reads IDTR from the VMCS to find the guest's IDT base and limit,
 * then copies all 256 entries into the snapshot buffer.  Also records
 * the kernel text address range for filtering legitimate handler
 * addresses during checks.
 *
 * @state             : Per-vCPU hooks state to populate.
 * @kernel_text_start : Start of kernel text section.
 * @kernel_text_end   : End of kernel text section.
 */
void gr_hooks_init(gr_hooks_state_t *state,
                   uint64_t kernel_text_start,
                   uint64_t kernel_text_end);

/*
 * gr_hooks_check_idt — Compare current IDT against the snapshot.
 *
 * For each modified entry, checks whether the new handler address
 * falls within the kernel text range.  Handlers pointing outside
 * kernel text are highly suspicious — likely an attacker redirect.
 *
 * @state : Per-vCPU hooks state (with snapshot).
 *
 * Returns the number of modified IDT entries detected.
 * Emits GR_ALERT_IDT_HOOK for each suspicious modification.
 */
uint32_t gr_hooks_check_idt(gr_hooks_state_t *state);

/*
 * gr_hooks_protect_idt — EPT-write-protect the pages containing the IDT.
 *
 * After this call, any guest attempt to write to the IDT pages will
 * cause an EPT violation VM-exit, allowing immediate detection and
 * blocking of IDT modifications.
 *
 * @state   : Per-vCPU hooks state (idt_phys must be set).
 * @ept_ctx : EPT context for this vCPU.
 */
void gr_hooks_protect_idt(gr_hooks_state_t *state, gr_ept_ctx_t *ept_ctx);

#endif /* GHOSTRING_MONITOR_HOOKS_H */
