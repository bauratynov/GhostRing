# GhostRing

Lightweight open-source hypervisor for endpoint security. Runs beneath the
operating system (Ring -1) using Intel VT-x and AMD-V hardware virtualization
to provide invisible kernel integrity monitoring, rootkit detection, and memory
forensics.

> **Status:** active development -- contributions welcome.

---

## Features

- **Blue-pill architecture** -- virtualizes the running OS in-place, no reboot
- **Intel VT-x + AMD-V** dual-architecture support
- **EPT / NPT-based kernel code protection** -- read-only executable pages
- **Hidden process detection** -- catches DKOM (Direct Kernel Object Manipulation)
- **MSR tampering prevention** -- guards LSTAR, SYSENTER_EIP, and friends
- **IDT hook detection** -- alerts on interrupt descriptor table modifications
- **CRC32 integrity monitoring** -- periodic hash checks of critical regions
- **Hypercall interface** -- clean API for a userspace security agent
- **Linux kernel module loader** -- `insmod` / `rmmod`, no custom boot chain
- **Serial port debugging** -- output to COM1 for early-stage bring-up
- **Zero external dependencies** -- freestanding C99, no libc, no allocator

---

## Architecture

```
 ┌──────────────────────────────────────────────────────┐
 │                    Userspace Agent                    │  Ring 3
 │           (communicates via /dev/ghostring)           │
 └──────────────────┬───────────────────────────────────┘
                    │  hypercall (VMCALL / VMMCALL)
 ┌──────────────────▼───────────────────────────────────┐
 │                  Linux Kernel (guest)                 │  Ring 0
 │        ghostring.ko  ──  thin shim + loader          │
 └──────────────────┬───────────────────────────────────┘
                    │  VM-exit / #VMEXIT
 ╔══════════════════▼═══════════════════════════════════╗
 ║               GhostRing Hypervisor                   ║  Ring -1
 ║                                                      ║
 ║   ┌──────────┐  ┌──────────┐  ┌───────────────┐     ║
 ║   │  VMCS /  │  │   EPT /  │  │  Monitoring   │     ║
 ║   │  VMCB    │  │   NPT    │  │    Engine      │     ║
 ║   │ Manager  │  │  Manager │  │               │     ║
 ║   └──────────┘  └──────────┘  └───────────────┘     ║
 ║                                                      ║
 ║   ┌──────────┐  ┌──────────┐  ┌───────────────┐     ║
 ║   │ Hypercall│  │   MSR    │  │  Serial Debug │     ║
 ║   │ Dispatch │  │  Filter  │  │   (COM1)      │     ║
 ║   └──────────┘  └──────────┘  └───────────────┘     ║
 ╚══════════════════════════════════════════════════════╝
                        │
              ┌─────────▼─────────┐
              │   CPU Hardware    │
              │  VT-x  /  AMD-V  │
              └───────────────────┘
```

---

## Building

### Prerequisites

| Requirement             | Notes                                      |
|-------------------------|--------------------------------------------|
| Linux kernel headers    | `apt install linux-headers-$(uname -r)`    |
| GCC (x86-64)           | Any recent version with `-ffreestanding`   |
| CPU virtualization      | Intel VT-x **or** AMD-V, enabled in BIOS  |

### Build

```bash
make            # auto-detect CPU vendor, build matching target
make vmx        # force Intel VT-x build
make svm        # force AMD-V build
```

### Load

```bash
sudo insmod loader/linux/ghostring.ko
dmesg | grep GhostRing
```

Expected output:

```
[GhostRing] v0.1.0 loaded — virtualizing 4 logical CPUs
[GhostRing] EPT enabled, kernel .text marked read-execute
[GhostRing] monitoring active
```

### Unload

```bash
sudo rmmod ghostring
dmesg | grep GhostRing
```

---

## Project Structure

```
GhostRing/
├── LICENSE
├── Makefile
├── README.md
├── include/
│   ├── ghostring.h          # public API and constants
│   ├── vmx.h                # Intel VT-x structures (VMCS, etc.)
│   ├── svm.h                # AMD-V structures (VMCB, etc.)
│   ├── ept.h                # Extended Page Tables
│   ├── npt.h                # Nested Page Tables
│   ├── msr.h                # MSR definitions
│   ├── monitor.h            # integrity monitoring interface
│   └── hypercall.h          # hypercall numbers and protocol
├── src/
│   ├── core/
│   │   ├── entry.c          # hypervisor entry point
│   │   ├── percpu.c         # per-CPU state management
│   │   └── serial.c         # COM1 debug output
│   ├── vmx/
│   │   ├── vmx_init.c       # VMXON, VMCS setup
│   │   ├── vmx_exit.c       # VM-exit handler
│   │   └── vmx_asm.S        # low-level VT-x assembly stubs
│   ├── svm/
│   │   ├── svm_init.c       # VMCB setup, EFER.SVME
│   │   ├── svm_exit.c       # #VMEXIT handler
│   │   └── svm_asm.S        # low-level AMD-V assembly stubs
│   ├── mm/
│   │   ├── ept.c            # EPT setup and violation handler
│   │   └── npt.c            # NPT setup and violation handler
│   └── monitor/
│       ├── dkom.c           # hidden process detection
│       ├── msr_guard.c      # MSR write interception
│       ├── idt_check.c      # IDT integrity verification
│       └── crc32.c          # code region hashing
├── loader/
│   └── linux/
│       ├── Makefile          # kbuild Makefile
│       └── module.c          # kernel module init/exit
├── agent/
│   └── ghostring-agent.c    # userspace monitoring daemon
└── tests/
    ├── Makefile
    ├── test_ept.c
    ├── test_hypercall.c
    └── test_crc32.c
```

---

## How It Works

GhostRing uses the **blue-pill** technique to virtualize the already-running
operating system without a reboot:

1. **Load** -- `insmod ghostring.ko` triggers the kernel module entry point.
2. **Detect** -- the module checks CPUID for VT-x (`ECX.VMX`) or AMD-V
   (`ECX.SVM`) and reads relevant MSRs.
3. **Virtualize** -- on each logical CPU, GhostRing executes `VMXON` (Intel)
   or sets `EFER.SVME` (AMD), builds the control structure (VMCS / VMCB),
   and launches the guest with `VMLAUNCH` / `VMRUN`. The OS continues
   executing as an unaware guest.
4. **Monitor** -- VM-exits triggered by EPT violations, MSR writes, CPUID,
   and hypercalls are routed to the monitoring engine.
5. **Report** -- alerts are written to the serial console and forwarded to
   the userspace agent via the hypercall interface.

---

## Security Monitoring

| Check                | Technique                          | VM-Exit Trigger         |
|----------------------|------------------------------------|-------------------------|
| Kernel code patching | EPT read-execute, no write         | EPT violation           |
| Hidden processes     | Walk `task_struct` vs. `/proc`     | Periodic timer          |
| MSR hooks            | Intercept `WRMSR` to LSTAR et al. | MSR write               |
| IDT modifications    | Snapshot + CRC32 comparison        | Periodic timer          |
| SSDT hooks           | Hash system call table             | Periodic timer          |
| Inline hooks         | CRC32 of function prologues        | Periodic timer          |

---

## Hypercall API

The userspace agent communicates with the hypervisor through `VMCALL` (Intel)
or `VMMCALL` (AMD). The kernel module exposes `/dev/ghostring` as a relay.

| Number | Name                    | Description                          |
|--------|-------------------------|--------------------------------------|
| 0x00   | `GR_HC_PING`           | Liveness check, returns magic value  |
| 0x01   | `GR_HC_GET_VERSION`    | Return hypervisor version string     |
| 0x10   | `GR_HC_SCAN_PROCS`     | Trigger hidden-process scan          |
| 0x11   | `GR_HC_SCAN_IDT`       | Trigger IDT integrity check          |
| 0x12   | `GR_HC_SCAN_MSR`       | Trigger MSR verification             |
| 0x20   | `GR_HC_GET_ALERTS`     | Retrieve pending alert queue         |
| 0x21   | `GR_HC_ACK_ALERT`      | Acknowledge and dismiss an alert     |
| 0xFF   | `GR_HC_SHUTDOWN`       | Devirtualize and unload cleanly      |

---

## Testing

GhostRing is designed to run inside a virtual machine with **nested
virtualization** enabled.

### VirtualBox

1. Enable nested VT-x:
   ```bash
   VBoxManage modifyvm "YourVM" --nested-hw-virt on
   ```
2. Boot the VM, build GhostRing, and load the module.
3. Watch serial output on COM1 (pipe to a host file or `socat`).

### QEMU/KVM

```bash
qemu-system-x86_64 -enable-kvm -cpu host \
    -serial stdio -m 2G -kernel bzImage ...
```

### Unit Tests

```bash
make test
```

Runs user-mode tests for EPT table construction, CRC32, and hypercall
encoding/decoding. No hardware virtualization required.

---

## Roadmap

- [x] Phase 1: Minimal VT-x hypervisor (VMXON, VMLAUNCH, basic exits)
- [x] Phase 2: EPT protection + integrity monitoring engine
- [x] Phase 3: AMD-V / SVM support
- [x] Phase 4: Windows kernel driver (KMDF) + Linux/Windows agents
- [x] Phase 5: Advanced detection (SSDT, driver objects, code injection, ransomware canary, CR guard, shadow stack)
- [ ] Phase 6: UEFI pre-boot loader (bypass `insmod` entirely)
- [x] Unit tests (allocator, CRC32 integrity, DKOM hash table)
- [x] QEMU integration test script
- [x] NMI re-injection + XSAVE/XRSTOR for guest state safety
- [x] Nested hypervisor detection (abort gracefully under Hyper-V/KVM)
- [x] Platform abstraction layer for cross-OS portability

---

## References

- [Intel SDM Vol. 3C](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html), Chapters 23--33 -- VMX specification
- [AMD APM Vol. 2](https://www.amd.com/en/search/documentation/hub.html), Chapter 15 -- SVM specification
- [SimpleVisor](https://github.com/ionescu007/SimpleVisor) by Alex Ionescu -- minimal Intel hypervisor reference
- [HyperDbg](https://github.com/HyperDbg/HyperDbg) by Sina Karvandi -- debugger built on a hypervisor

---

## Author

**Baurzhan Atynov** -- [bauratynov@gmail.com](mailto:bauratynov@gmail.com)

---

## License

MIT -- see [LICENSE](LICENSE).
