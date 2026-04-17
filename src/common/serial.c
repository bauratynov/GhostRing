/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

/*
 * serial.c — 16550 UART driver for COM1 debug output.
 *
 * The 16550 is the simplest universally-available output device on x86
 * hardware and virtual machines alike.  We program it in polled mode
 * (no IRQ) with 115200 baud, 8N1 — the de-facto standard for firmware
 * and hypervisor debug consoles.
 */

#include "serial.h"
#include "cpu.h"

/* ── I/O port helpers ────────────────────────────────────────────────────── */

static inline void outb(uint16_t port, uint8_t val)
{
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port)
{
    uint8_t val;
    __asm__ volatile("inb %1, %0" : "=a"(val) : "Nd"(port));
    return val;
}

/* ── 16550 register offsets ──────────────────────────────────────────────── */

#define UART_DATA       0   /* TX/RX data                        */
#define UART_IER        1   /* Interrupt Enable Register          */
#define UART_FCR        2   /* FIFO Control Register              */
#define UART_LCR        3   /* Line Control Register              */
#define UART_MCR        4   /* Modem Control Register             */
#define UART_LSR        5   /* Line Status Register               */
#define UART_DLL        0   /* Divisor Latch Low (DLAB=1)         */
#define UART_DLH        1   /* Divisor Latch High (DLAB=1)        */

/* LSR bits we care about. */
#define LSR_THRE        BIT(5)  /* Transmitter Holding Register Empty */

/* ── Initialisation ──────────────────────────────────────────────────────── */

void gr_serial_init(void)
{
    uint16_t port = GR_COM1_PORT;

    /* Disable all UART interrupts — we use polling only. */
    outb(port + UART_IER, 0x00);

    /*
     * Set baud rate divisor.  The base clock is 1.8432 MHz.
     * Divisor = 115200 => 1 (0x0001).
     * Enable DLAB to access divisor latches.
     */
    outb(port + UART_LCR, 0x80);       /* DLAB = 1                     */
    outb(port + UART_DLL, 0x01);       /* Divisor low byte  (115200)   */
    outb(port + UART_DLH, 0x00);       /* Divisor high byte            */

    /* 8 data bits, no parity, 1 stop bit (8N1).  Clears DLAB. */
    outb(port + UART_LCR, 0x03);

    /* Enable and clear FIFOs, set 14-byte trigger level. */
    outb(port + UART_FCR, 0xC7);

    /* DTR + RTS + OUT2 (needed for some hardware to generate IRQs). */
    outb(port + UART_MCR, 0x0B);
}

/* ── Single character output ─────────────────────────────────────────────── */

void gr_serial_putc(char c)
{
    uint16_t port = GR_COM1_PORT;

    /* Convert bare newlines to CR+LF for terminal compatibility. */
    if (c == '\n') {
        gr_serial_putc('\r');
    }

    /* Spin until the transmit holding register is empty. */
    while ((inb(port + UART_LSR) & LSR_THRE) == 0) {
        gr_pause();
    }

    outb(port + UART_DATA, (uint8_t)c);
}

/* ── String output ───────────────────────────────────────────────────────── */

void gr_serial_puts(const char *s)
{
    while (*s) {
        gr_serial_putc(*s++);
    }
}

/* ── Hex output ──────────────────────────────────────────────────────────── */

static const char hex_chars[] = "0123456789abcdef";

void gr_serial_hex64(uint64_t val)
{
    gr_serial_puts("0x");

    /* Skip leading zeros but always print at least one digit. */
    bool started = false;
    for (int i = 60; i >= 0; i -= 4) {
        uint8_t nibble = (val >> i) & 0xF;
        if (nibble != 0) {
            started = true;
        }
        if (started || i == 0) {
            gr_serial_putc(hex_chars[nibble]);
        }
    }
}

/* ── Decimal output ──────────────────────────────────────────────────────── */

void gr_serial_dec(uint64_t val)
{
    /* Max uint64 is 20 digits. */
    char buf[21];
    int  pos = 20;

    buf[pos] = '\0';

    if (val == 0) {
        gr_serial_putc('0');
        return;
    }

    while (val > 0) {
        buf[--pos] = '0' + (char)(val % 10);
        val /= 10;
    }

    gr_serial_puts(&buf[pos]);
}

/* ── Panic halt ──────────────────────────────────────────────────────────── */

void gr_panic(const char *msg)
{
    (void)msg;  /* Already printed by the GR_PANIC macro. */

    /* Disable interrupts and halt — loop in case of NMI wakeup. */
    for (;;) {
        gr_cli();
        gr_hlt();
    }
}
