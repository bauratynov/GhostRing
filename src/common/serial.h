/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * serial.h — 16550 UART debug output over COM1.
 *
 * Serial is the only reliable output channel in a pre-OS hypervisor
 * context.  All logging ultimately funnels through these routines.
 */

#ifndef GHOSTRING_SERIAL_H
#define GHOSTRING_SERIAL_H

#include "types.h"

/* ── Port constants ──────────────────────────────────────────────────────── */

#define GR_COM1_PORT    0x3F8

/* ── Core API ────────────────────────────────────────────────────────────── */

void gr_serial_init(void);
void gr_serial_putc(char c);
void gr_serial_puts(const char *s);
void gr_serial_hex64(uint64_t val);
void gr_serial_dec(uint64_t val);

/* ── Logging macros ──────────────────────────────────────────────────────── */

/*
 * GR_LOG — lightweight "printf" that prints a tag, a string literal, and
 * an optional 64-bit hex value.  No format parsing at all; keeps the
 * hypervisor text footprint tiny.
 *
 * Usage:
 *   GR_LOG("vmx: VMXON region at ", vmxon_phys);
 *   GR_LOG_STR("vmx: entering VMX root mode");
 */
#define GR_LOG(msg, val)                        \
    do {                                        \
        gr_serial_puts("[GR] ");                \
        gr_serial_puts(msg);                    \
        gr_serial_hex64((uint64_t)(val));        \
        gr_serial_putc('\n');                    \
    } while (0)

#define GR_LOG_STR(msg)                         \
    do {                                        \
        gr_serial_puts("[GR] ");                \
        gr_serial_puts(msg);                    \
        gr_serial_putc('\n');                    \
    } while (0)

/*
 * GR_PANIC — unrecoverable error.  Prints the message and halts every
 * logical processor.  Never returns.
 */
GR_NORETURN void gr_panic(const char *msg);

#define GR_PANIC(msg)                           \
    do {                                        \
        gr_serial_puts("[GR PANIC] ");          \
        gr_serial_puts(msg);                    \
        gr_serial_putc('\n');                    \
        gr_panic(msg);                          \
    } while (0)

#endif /* GHOSTRING_SERIAL_H */
