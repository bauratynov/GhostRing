/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * msr_guard.c — WRMSR interception and shadow enforcement.
 *
 * The attack surface: a kernel-mode rootkit can execute WRMSR to hijack
 * LSTAR (SYSCALL entry) or SYSENTER_EIP, redirecting every system call
 * to attacker-controlled code.  Clearing EFER.NXE re-opens the door to
 * data-execution attacks that W^X was designed to prevent.
 *
 * By shadowing these MSRs and intercepting writes via the VMX MSR
 * bitmap, we block tampering at the hardware virtualisation layer —
 * beneath anything the guest kernel can influence.
 */

#include "msr_guard.h"
#include "alerts.h"

/* ── MSR bitmap layout constants ────────────────────────────────────────── */

/*
 * Intel SDM Vol. 3C, Section 24.6.9:
 *   Bytes [0x000..0x3FF]: Read bitmap, MSRs 0x00000000 – 0x00001FFF
 *   Bytes [0x400..0x7FF]: Read bitmap, MSRs 0xC0000000 – 0xC0001FFF
 *   Bytes [0x800..0xBFF]: Write bitmap, MSRs 0x00000000 – 0x00001FFF
 *   Bytes [0xC00..0xFFF]: Write bitmap, MSRs 0xC0000000 – 0xC0001FFF
 */
#define MSR_BITMAP_WRITE_LOW_BASE   0x800
#define MSR_BITMAP_WRITE_HIGH_BASE  0xC00
#define MSR_LOW_RANGE_END           0x00001FFF
#define MSR_HIGH_RANGE_START        0xC0000000
#define MSR_HIGH_RANGE_END          0xC0001FFF

/* ── Internal helpers ───────────────────────────────────────────────────── */

void gr_msr_bitmap_protect(uint8_t *msr_bitmap, uint32_t msr_index)
{
    if (!msr_bitmap)
        return;

    uint32_t byte_offset;
    uint32_t bit_index;

    if (msr_index <= MSR_LOW_RANGE_END) {
        /* Low-range MSR: write bitmap starts at offset 0x800 */
        byte_offset = MSR_BITMAP_WRITE_LOW_BASE + (msr_index / 8);
        bit_index   = msr_index % 8;
    } else if (msr_index >= MSR_HIGH_RANGE_START &&
               msr_index <= MSR_HIGH_RANGE_END) {
        /* High-range MSR (0xC000xxxx): write bitmap starts at 0xC00 */
        uint32_t relative = msr_index - MSR_HIGH_RANGE_START;
        byte_offset = MSR_BITMAP_WRITE_HIGH_BASE + (relative / 8);
        bit_index   = relative % 8;
    } else {
        /* MSR outside interceptable ranges — cannot protect via bitmap */
        GR_LOG("msr_guard: MSR outside bitmap range: ", (uint64_t)msr_index);
        return;
    }

    /* Bounds check against the 4KB bitmap page */
    if (byte_offset >= PAGE_SIZE) {
        GR_LOG("msr_guard: bitmap offset overflow for MSR ", (uint64_t)msr_index);
        return;
    }

    msr_bitmap[byte_offset] |= (uint8_t)(1U << bit_index);
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void gr_msr_guard_init(gr_msr_shadow_t *shadow, uint8_t *msr_bitmap)
{
    if (!shadow || !msr_bitmap)
        return;

    /*
     * Snapshot current MSR values.  At this point the hypervisor has
     * just captured the CPU, so these values reflect the legitimate
     * kernel configuration.
     */
    shadow->lstar        = gr_rdmsr(MSR_IA32_LSTAR);
    shadow->sysenter_eip = gr_rdmsr(MSR_IA32_SYSENTER_EIP);
    shadow->sysenter_esp = gr_rdmsr(MSR_IA32_SYSENTER_ESP);
    shadow->efer         = gr_rdmsr(MSR_IA32_EFER);
    shadow->initialised  = true;

    GR_LOG("msr_guard: shadow LSTAR=",        shadow->lstar);
    GR_LOG("msr_guard: shadow SYSENTER_EIP=", shadow->sysenter_eip);
    GR_LOG("msr_guard: shadow SYSENTER_ESP=", shadow->sysenter_esp);
    GR_LOG("msr_guard: shadow EFER=",         shadow->efer);

    /*
     * Enable write interception for all protected MSRs.  Read
     * interception is not needed — we only care about writes.
     */
    gr_msr_bitmap_protect(msr_bitmap, MSR_IA32_LSTAR);
    gr_msr_bitmap_protect(msr_bitmap, MSR_IA32_SYSENTER_EIP);
    gr_msr_bitmap_protect(msr_bitmap, MSR_IA32_SYSENTER_ESP);
    gr_msr_bitmap_protect(msr_bitmap, MSR_IA32_EFER);

    GR_LOG_STR("msr_guard: MSR bitmap configured, interception active");
}

bool gr_msr_guard_check_write(gr_msr_shadow_t *shadow,
                              uint32_t msr_index,
                              uint64_t new_value,
                              uint64_t guest_rip,
                              uint64_t guest_cr3)
{
    if (!shadow || !shadow->initialised)
        return true;  /* Not yet armed — allow all writes */

    switch (msr_index) {

    case MSR_IA32_LSTAR:
        /*
         * LSTAR holds the kernel SYSCALL entry point.  Changing it
         * redirects every user-to-kernel transition through arbitrary
         * code — the most powerful single-instruction rootkit primitive.
         */
        if (new_value != shadow->lstar) {
            GR_LOG("msr_guard: LSTAR tamper blocked, new=", new_value);
            GR_LOG("  expected=", shadow->lstar);
            gr_alert_emit(GR_ALERT_MSR_TAMPER, guest_rip, guest_cr3,
                          0, (uint64_t)msr_index);
            return false;
        }
        return true;

    case MSR_IA32_SYSENTER_EIP:
        /*
         * SYSENTER_EIP is the 32-bit fast system call entry point.
         * On 64-bit kernels this is typically unused in favour of SYSCALL,
         * but some OSes still configure it.  A change is suspicious.
         */
        if (new_value != shadow->sysenter_eip) {
            GR_LOG("msr_guard: SYSENTER_EIP tamper blocked, new=", new_value);
            gr_alert_emit(GR_ALERT_MSR_TAMPER, guest_rip, guest_cr3,
                          0, (uint64_t)msr_index);
            return false;
        }
        return true;

    case MSR_IA32_SYSENTER_ESP:
        /*
         * SYSENTER_ESP is less commonly targeted but modifying it
         * can redirect the kernel stack pointer, enabling stack-pivot
         * attacks on the fast system call path.
         */
        if (new_value != shadow->sysenter_esp) {
            GR_LOG("msr_guard: SYSENTER_ESP tamper blocked, new=", new_value);
            gr_alert_emit(GR_ALERT_MSR_TAMPER, guest_rip, guest_cr3,
                          0, (uint64_t)msr_index);
            return false;
        }
        return true;

    case MSR_IA32_EFER:
        /*
         * EFER controls critical CPU operating modes.  Clearing NXE
         * disables the no-execute page permission, re-opening data-
         * execution attacks.  Clearing LME would drop out of 64-bit
         * long mode, which is always illegitimate on a running 64-bit OS.
         *
         * We allow writes that do not clear NXE or LME relative to
         * the shadow.  Other bit changes (e.g. SCE toggling) are
         * permitted but the shadow is updated to track them.
         */
        {
            uint64_t critical_bits = EFER_NXE | EFER_LME;
            uint64_t removed = (shadow->efer & critical_bits) &
                               ~(new_value & critical_bits);
            if (removed) {
                GR_LOG("msr_guard: EFER tamper blocked, removing bits=", removed);
                gr_alert_emit(GR_ALERT_MSR_TAMPER, guest_rip, guest_cr3,
                              0, (uint64_t)msr_index);
                return false;
            }
            /* Allowed — update shadow to track non-critical changes */
            shadow->efer = new_value;
            return true;
        }

    default:
        /*
         * MSR not in our protected set.  This should not happen if the
         * MSR bitmap is configured correctly, but handle gracefully.
         */
        GR_LOG("msr_guard: unexpected MSR intercept, index=", (uint64_t)msr_index);
        return true;
    }
}
