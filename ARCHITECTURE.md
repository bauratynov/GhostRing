# GhostRing — Hypervisor-Based Security Platform

## What Is GhostRing

Open-source thin hypervisor (ring -1) that sits UNDER the OS and monitors kernel integrity, detects rootkits, and provides memory forensics — invisible to malware running inside the guest.

```
┌─────────────────────────────────┐
│  Windows / Linux  (Ring 0)      │  ← OS thinks it's alone
│  ├── kernel, drivers            │
│  └── rootkit ← visible to us   │
├─────────────────────────────────┤
│  GhostRing  (Ring -1, VMX root) │  ← we see everything
│  ├── EPT page protection        │
│  ├── MSR/CR intercepts          │
│  ├── DKOM detection             │
│  └── integrity hashing          │
├─────────────────────────────────┤
│  CPU  (VT-x / AMD-V hardware)  │
└─────────────────────────────────┘
```

## Architecture Decision Record

Based on analysis of 22 reference repos (350 MB, ~400K LOC) and 71 DeepSeek research articles:

### Language: C99 (not C++, not Rust)

Why:
- Our entire stack is C99 (github/, project/, EntropyX, anslib)
- Hypervisor code must be freestanding — no stdlib, no allocator, no runtime
- SimpleVisor proves 2000 LOC of C is enough for a working hypervisor
- C++ templates/RAII add nothing in ring -1 (no exceptions, no heap)
- Rust UEFI toolchain is immature for production (illusion-rs is experimental)

### Dual Architecture: Intel VT-x + AMD-V (SVM)

Why:
- Kazakhstan government buys both Intel Xeon and AMD EPYC
- NoirVisor proves dual-arch is achievable with compile-time `#ifdef`
- SimpleSvm (AMD) + SimpleVisor (Intel) give clean reference for both
- Abstraction: common `ghostring_vcpu` struct, arch-specific backends

### Boot Method: Type-2 first, Type-1 (UEFI) later

Why:
- Type-2 (kernel driver/module) is 10× easier to develop and debug
- SimpleVisor, HyperPlatform, DdiMon all use Type-2 for Windows
- Linux kmod even simpler (insmod, no signing needed for dev)
- Type-1 (UEFI) added in Phase 3 using MiniVisorPkg as reference
- Phase 1-2 don't need UEFI

### Open-Source Model: Apache 2.0 core + GPL v2 Linux loader + commercial enterprise

```
Open source (per-subsystem):                 Commercial (closed):
Apache-2.0:                                  ├── management console (web UI)
├── src/vmx/     (Intel VT-x)                ├── Windows WHQL-signed driver
├── src/svm/     (AMD-V)                     ├── certified builds for gov
├── src/ept/     (page tables)               ├── NexusEye integration
├── src/monitor/ (integrity)                 ├── HVMI-style detection rules
├── src/common/  (shared)                    └── SLA + support
├── loader/windows/ (Windows driver)
├── loader/uefi/    (UEFI loader)
├── agent/          (userspace)
├── docs/, tests/
GPL-2.0-only:
└── loader/linux/   (kbuild requires GPL)
```

---

## File Structure

```
GhostRing/
├── ARCHITECTURE.md          ← this file
├── LICENSE                  ← dual-license index (Apache-2.0 + GPL-2.0)
├── README.md
├── Makefile
│
├── src/
│   ├── common/
│   │   ├── ghostring.h      ← master header, feature flags
│   │   ├── types.h          ← u8/u16/u32/u64, bool, NULL
│   │   ├── cpu.h            ← CPUID, MSR read/write, CR access
│   │   ├── cpu.c
│   │   ├── mem.h            ← bitmap page allocator (no malloc)
│   │   ├── mem.c            ←   pre-allocated pool like MiniVisorPkg
│   │   ├── serial.h         ← COM port debug output
│   │   ├── serial.c
│   │   ├── spinlock.h       ← simple ticket spinlock
│   │   └── percpu.h         ← per-CPU data access macros
│   │
│   ├── vmx/                  ← Intel VT-x backend
│   │   ├── vmx_init.c       ← VMXON, VMCLEAR, VMPTRLD sequence
│   │   ├── vmx_vmcs.c       ← VMCS field setup (guest + host state)
│   │   ├── vmx_vmcs.h       ← VMCS field encodings (from SimpleVisor vmx.h)
│   │   ├── vmx_exit.c       ← VM-exit dispatcher + handlers
│   │   ├── vmx_exit.h       ← exit reason enum (93 reasons)
│   │   ├── vmx_ept.c        ← EPT build, protect, hook
│   │   ├── vmx_ept.h        ← EPT entry structures
│   │   ├── vmx_msr.c        ← MSR bitmap + capability probing
│   │   └── vmx_asm.S        ← VMLAUNCH/VMRESUME, context save/restore
│   │
│   ├── svm/                  ← AMD-V backend
│   │   ├── svm_init.c       ← VMRUN setup, HSAVE area
│   │   ├── svm_vmcb.c       ← VMCB field setup
│   │   ├── svm_vmcb.h       ← VMCB offsets (from NoirVisor svm_vmcb.h)
│   │   ├── svm_exit.c       ← #VMEXIT dispatcher + handlers
│   │   ├── svm_exit.h       ← exit code macros (165 codes)
│   │   ├── svm_npt.c        ← Nested Page Tables build/protect
│   │   ├── svm_npt.h        ← NPT entry structures
│   │   ├── svm_msr.c        ← MSRPM bitmap
│   │   └── svm_asm.S        ← VMRUN/VMSAVE/VMLOAD, context switch
│   │
│   ├── monitor/              ← Security monitoring (arch-independent)
│   │   ├── integrity.c       ← CRC32 hash of kernel code pages
│   │   ├── integrity.h
│   │   ├── dkom.c            ← hidden process detection via CR3 walk
│   │   ├── dkom.h
│   │   ├── hooks.c           ← SSDT/IDT hook detection
│   │   ├── hooks.h
│   │   ├── msr_guard.c       ← LSTAR/SYSENTER protection
│   │   ├── msr_guard.h
│   │   └── alerts.h          ← alert structures (EPT violation, etc.)
│   │
│   └── hypercall/
│       ├── hypercall.c       ← VMCALL interface: agent ↔ hypervisor
│       └── hypercall.h       ← hypercall numbers + ABI
│
├── loader/
│   ├── linux/
│   │   ├── ghostring_kmod.c  ← Linux kernel module entry
│   │   ├── Makefile          ← kbuild
│   │   └── ghostring.ko      ← (built)
│   │
│   ├── windows/
│   │   ├── ghostring_drv.c   ← Windows KMDF driver entry
│   │   ├── ghostring.inf     ← driver install manifest
│   │   └── ghostring.sys     ← (built)
│   │
│   └── uefi/                 ← Phase 3
│       ├── ghostring_dxe.c   ← DXE_RUNTIME_DRIVER entry
│       └── GhostRingDxe.inf  ← EDK2 module descriptor
│
├── agent/                    ← Userspace companion (reports alerts)
│   ├── linux/
│   │   └── ghostring-agent.c ← reads /dev/ghostring, prints alerts
│   └── windows/
│       └── ghostring-agent.c ← reads \\.\GhostRing device, prints alerts
│
├── tests/
│   ├── test_ept.c            ← EPT construction unit tests
│   ├── test_vmcs.c           ← VMCS field encoding tests
│   ├── test_integrity.c      ← CRC32 integrity tests
│   └── test_vm.py            ← Integration: boot VM, load hypervisor, verify
│
└── reference/                ← Cloned repos (22 projects, 350 MB)
    ├── SimpleVisor/
    ├── HyperDbg/
    ├── NoirVisor/
    ├── ...
    └── (21 more)
```

---

## What to Copy from Each Reference

| Reference | What to take | Files |
|-----------|-------------|-------|
| **SimpleVisor** | Blue-pill boot sequence, VMCS setup, EPT identity map | `shvvmx.c:286-522` → our `vmx_vmcs.c` |
| **SimpleVisor** | VM-exit entry ASM (context save) | `shvvmxhvx64.asm` → our `vmx_asm.S` |
| **SimpleVisor** | MTRR-aware EPT memory types | `shvvmx.c:77-175` → our `vmx_ept.c` |
| **SimpleSvm** | AMD-V VMCB setup, NPT init | full file → our `svm_vmcb.c`, `svm_npt.c` |
| **SimpleSvmHook** | AMD NPT hooking pattern | NPT hook code → our `svm_npt.c` hooks |
| **NoirVisor** | Dual-arch abstraction (`#ifdef _vt_core`) | `noirhvm.h:199-339` → our `ghostring.h` |
| **NoirVisor** | VMCB offset definitions | `svm_vmcb.h` → our `svm_vmcb.h` |
| **NoirVisor** | TLB tagging (VPID/ASID) unification | `noirhvm.h:216-230` → our `percpu.h` |
| **MiniVisorPkg** | Bitmap page allocator | `MemoryManager.c` → our `mem.c` |
| **MiniVisorPkg** | UEFI DXE boot sequence | `efimain.c` → our `loader/uefi/` (Phase 3) |
| **DdiMon** | EPT invisible hook pattern | hook impl → our `monitor/hooks.c` |
| **HyperDbg** | EPT breakpoint + event dispatch | EPT hook code → our `vmx_ept.c` hooks |
| **HVMI** | Alert structures + CAMI OS database | `intro_types.h` → our `alerts.h` pattern |
| **HVMI** | Integrity region CRC32 | `integrity.h` → our `monitor/integrity.c` |
| **Intel HAXM** | Clean VT-x capability probing | capability code → our `vmx_msr.c` |
| **gbhv** | Documented EPT shadow hook | comments → our documentation |

---

## Implementation Roadmap

### Phase 1: Minimal Viable Hypervisor (Week 1-3)

**Goal:** `insmod ghostring.ko` → OS continues running under hypervisor → `rmmod` cleanly

**Deliverables:**
- `src/vmx/` — Intel VT-x: VMXON → VMCS → VMLAUNCH → handle CPUID exit → VMRESUME
- `src/common/` — types, CPU intrinsics, serial debug, spinlock
- `loader/linux/` — kernel module that calls vmx_init() per CPU
- VM-exit handles: CPUID (inject hypervisor bit), INVD, XSETBV, VMX instructions (fail)
- EPT identity map with 2MB pages + MTRR

**Copy from:** SimpleVisor (entire flow), Intel HAXM (capability probing)

**Benchmark gate:** `dmesg | grep GhostRing` shows "installed on N CPUs", OS runs stable 24h

**Test:** VirtualBox with nested VT-x, or bare metal test machine

### Phase 2: EPT Protection + Monitoring (Week 4-6)

**Goal:** Detect kernel code modification in real-time

**Deliverables:**
- `vmx_ept.c` — write-protect kernel .text pages via EPT (RX, no W)
- `monitor/integrity.c` — CRC32 of protected regions, periodic check
- `monitor/msr_guard.c` — intercept writes to LSTAR, SYSENTER_EIP
- `monitor/dkom.c` — walk CR3 page tables, compare process list vs PsActiveProcessList
- `agent/linux/` — read alerts via /dev/ghostring chardev

**Copy from:** DdiMon (EPT hook), HVMI (integrity hash), HyperDbg (event dispatch)

**Benchmark gate:** Load test rootkit (manual DKOM via /dev/mem), GhostRing detects it

### Phase 3: AMD-V + UEFI (Week 7-10)

**Goal:** Support AMD Zen processors, boot from UEFI

**Deliverables:**
- `src/svm/` — AMD-V: VMRUN setup, VMCB, NPT, #VMEXIT handler
- `loader/uefi/` — DXE_RUNTIME_DRIVER, loads before OS
- Unified `ghostring.h` with `#ifdef GHOSTRING_VTX` / `#ifdef GHOSTRING_SVM`

**Copy from:** SimpleSvm + SimpleSvmHook (AMD-V), MiniVisorPkg (UEFI), NoirVisor (dual-arch)

**Benchmark gate:** Works on AMD Ryzen/EPYC, boots from UEFI USB stick

### Phase 4: Windows Support (Week 11-13)

**Goal:** `ghostring.sys` Windows kernel driver

**Deliverables:**
- `loader/windows/` — KMDF driver, DPC-based per-CPU init (SimpleVisor pattern)
- `agent/windows/` — reads `\\.\GhostRing` device for alerts
- Test signing or EV cert for driver signature

**Copy from:** SimpleVisor `nt/shvos.c` (entire Windows driver pattern)

### Phase 5: Advanced Detection (Week 14-18)

**Goal:** Production-grade detection engine

**Deliverables:**
- SSDT hook detection (compare shadow SSDT vs live)
- IDT protection (write-protect via EPT)
- Driver object integrity (validate dispatch tables)
- Code injection detection (EPT execute trap on non-image pages)
- Fileless malware detection (monitor PowerShell/WMI memory regions)
- Ransomware canary (EPT-protect decoy files)

**Copy from:** HVMI (detection logic), DRAKVUF (analysis patterns)

### Phase 6: Polish + Release (Week 19-22)

**Goal:** GitHub release with documentation, CI, tests

**Deliverables:**
- README with architecture diagrams
- CI/CD: build + test on VirtualBox nested VT-x
- Documentation: Intel SDM references for every VMCS field
- Performance benchmarks: VM-exit latency, overhead %
- Security audit checklist
- Blog post + Hacker News submission

---

## Key Technical Decisions

### Memory Allocator (No malloc in ring -1)

Copy MiniVisorPkg pattern: pre-allocate pool at load time, bitmap allocator.

```c
// mem.h
#define GR_PAGE_POOL_PAGES  1024  // 4 MB pre-allocated

typedef struct {
    uint8_t *base;           // pool base (page-aligned)
    uint64_t bitmap[1024/64]; // 1 bit per page
    uint32_t total_pages;
    uint32_t free_pages;
    gr_spinlock_t lock;
} gr_page_pool_t;

void *gr_alloc_page(gr_page_pool_t *pool);
void  gr_free_page(gr_page_pool_t *pool, void *page);
```

### Debug Output (No printk in ring -1)

Serial port (COM1, 0x3F8). Works in VirtualBox, bare metal, UEFI.

```c
// serial.h
void gr_serial_init(void);
void gr_serial_putc(char c);
void gr_serial_puts(const char *s);
void gr_serial_hex(uint64_t val);

#define GR_LOG(fmt, ...) gr_serial_printf(fmt, ##__VA_ARGS__)
```

### Per-CPU State

One `gr_vcpu_t` per logical CPU, allocated from page pool:

```c
typedef struct {
    // VMX regions (must be page-aligned)
    uint8_t  vmxon_region[4096]  __attribute__((aligned(4096)));
    uint8_t  vmcs_region[4096]   __attribute__((aligned(4096)));
    uint8_t  msr_bitmap[4096]    __attribute__((aligned(4096)));

    // EPT structures
    uint64_t epml4[512]          __attribute__((aligned(4096)));
    uint64_t epdpt[512]          __attribute__((aligned(4096)));
    uint64_t epde[512][512]      __attribute__((aligned(4096)));

    // Hypervisor stack (16 KB)
    uint8_t  hv_stack[16384]     __attribute__((aligned(16)));

    // Saved guest state
    uint64_t guest_cr0, guest_cr3, guest_cr4;
    uint64_t guest_rip, guest_rsp, guest_rflags;
    // ... all GPRs

    // Monitoring state
    uint32_t integrity_crc32[256]; // CRC32 of protected pages
    uint64_t msr_lstar_shadow;     // expected LSTAR value
    uint64_t msr_sysenter_shadow;  // expected SYSENTER_EIP

    uint32_t cpu_id;
    uint8_t  active;               // hypervisor running on this CPU?
} gr_vcpu_t;
```

### VM-Exit Dispatch

Flat switch statement (SimpleVisor pattern, not vtable):

```c
void gr_handle_exit(gr_vcpu_t *vcpu) {
    uint32_t reason = gr_vmread(VM_EXIT_REASON) & 0xFFFF;

    switch (reason) {
    case EXIT_REASON_CPUID:        gr_handle_cpuid(vcpu); break;
    case EXIT_REASON_RDMSR:        gr_handle_rdmsr(vcpu); break;
    case EXIT_REASON_WRMSR:        gr_handle_wrmsr(vcpu); break;
    case EXIT_REASON_EPT_VIOLATION: gr_handle_ept_violation(vcpu); break;
    case EXIT_REASON_INVD:         __wbinvd(); break;
    case EXIT_REASON_XSETBV:       gr_handle_xsetbv(vcpu); break;
    case EXIT_REASON_VMCALL:       gr_handle_hypercall(vcpu); break;

    // Block all VMX instructions (no nested)
    case EXIT_REASON_VMCLEAR: case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMPTRLD: case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:  case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE: case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
        vcpu->guest_rflags |= 1; // set CF = fail
        break;

    default:
        GR_LOG("unhandled exit: %u at RIP=%lx\n", reason, vcpu->guest_rip);
        break;
    }

    // Advance RIP past faulting instruction
    vcpu->guest_rip += gr_vmread(VM_EXIT_INSTRUCTION_LEN);
    gr_vmwrite(GUEST_RIP, vcpu->guest_rip);
}
```

### EPT Protection Pattern

```c
void gr_ept_protect_page(gr_vcpu_t *vcpu, uint64_t gpa, uint8_t perms) {
    // Find PDE for this address (2MB granularity)
    uint64_t pml4_idx = (gpa >> 39) & 0x1FF;
    uint64_t pdpt_idx = (gpa >> 30) & 0x1FF;
    uint64_t pd_idx   = (gpa >> 21) & 0x1FF;

    uint64_t *pde = &vcpu->epde[pdpt_idx][pd_idx];

    // Split 2MB page to 4KB if needed for fine-grained protection
    // ... (allocate PT from page pool)

    // Set permissions: R=bit0, W=bit1, X=bit2
    uint64_t pt_idx = (gpa >> 12) & 0x1FF;
    pt[pt_idx] = (pt[pt_idx] & ~7ULL) | (perms & 7);

    // Flush EPT TLB for this address
    gr_invept_single(vcpu->eptp, gpa);
}

// Usage: write-protect kernel .text
// gr_ept_protect_page(vcpu, kernel_text_gpa, EPT_READ | EPT_EXECUTE);
// Any write to kernel .text → EPT violation → alert
```

---

## What Makes GhostRing Unique

1. **First open-source hypervisor-security from Central Asia**
2. **Dual-arch from day 1** (Intel + AMD) — most projects are Intel-only
3. **C99, zero dependencies** — matches our entire stack philosophy
4. **Designed for government** — auditable, certifiable, no cloud
5. **Integrates with NexusEye** — video forensics + endpoint security = one platform
6. **Production path via HVMI patterns** — Bitdefender open-sourced their detection engine

---

## Reference Materials

- Intel SDM Vol. 3C, Chapters 23-33 (VMX)
- AMD APM Vol. 2, Chapter 15 (SVM)
- 22 cloned repos in `reference/` (350 MB)
- 71 DeepSeek research articles in `BZ/research/`
- CPU KB: `BZ/CPU_PERFORMANCE_KNOWLEDGE_BASE.md` (SIMD, memory, cache)
