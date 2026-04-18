# Research notes — running log

Private / working notes from periodic literature and competitor
review.  Used to steer engineering priorities.  Each block tagged
with the date it was added.

## 2026-04-18 — cycle 2 — competitor landscape

### Single most important finding

**Bitdefender HVMI (github.com/bitdefender/hvmi) was archived on
2026-01-26** — marked "no longer maintained".  That was the only
production-grade opensource Linux/Xen/KVM introspection EDR.  Its
archival leaves a vacuum GhostRing can plausibly fill.

### State of the art around us

| Project          | Status          | License           | Platform         | Detection pack? |
|------------------|-----------------|-------------------|------------------|-----------------|
| SimpleVisor      | Frozen 2018-12  | **No LICENSE**    | Windows x64 + UEFI | No            |
| HyperPlatform    | Slow (2023-11)  | MIT               | Windows          | No (platform)  |
| HyperDbg         | **Active**      | GPL-3.0 (viral)   | Windows          | No (debugger)  |
| DdiMon / MemoryMon / GuardMon | ≤2022 (dead) | MIT | Windows        | Some (3 proto) |
| BitVisor 3.0     | Active 2024-08  | BSD-2             | Type-1 bare      | I/O-level only |
| Nitro / KVM-VMI  | 2025-10 (alive) | MIT-ish           | KVM guest        | Forensics      |
| **HVMI**         | **Archived 2026-01** | Apache-2.0   | Xen / KVM / Napoca | Yes         |
| **GhostRing**    | v0.1 (us)       | Apache-2 + GPL-2  | Linux / Windows  | **19 + MITRE** |

### GhostRing's differentiators (position clearly)

- **Only active Linux-first blue-pill EDR in 2026.**  Every Windows
  alternative is dead or debugger-not-EDR.
- **Dual Apache-2.0 + GPL-v2** — permissive core with GPL Linux
  loader; HyperPlatform's MIT loses patent grant, HyperDbg's GPL-3
  scares enterprise legal.
- **19 MITRE-mapped detectors** shipped.  DdiMon/MemoryMon/GuardMon
  combined shipped three experimental prototypes and stopped.
- **Verified Hyper-V nested bring-up** with responsive guest.
  HyperPlatform still has open issues on newer Windows builds.

### Gaps we still have vs competitors

- HyperDbg has richer debugger surface (`!epthook2`, scripting).
  Not an EDR gap — we are not a debugger.
- BitVisor has AArch64.  We are x86_64 only.
- HVMI had **deep Windows introspection** (signed struct DB,
  exception handling for kernel exploits).  For Windows-side parity
  we need the equivalent PDB-driven struct resolution.  Track in
  v0.3 roadmap.

### Actionable follow-ups

- [ ] Cite HVMI archival in `README.md` "Why now?" section.
- [ ] Add `HyperPlatform → GhostRing migration notes` doc — likely
      a common question from existing HyperPlatform users now that
      it's slow-maintained.
- [ ] Ping Alex Ionescu's SimpleVisor repo with an offer to clarify
      its LICENSE status — either he answers and we link, or we
      state clearly that SimpleVisor is unlicensed (practical
      blocker for downstream reuse we can highlight).

## 2026-04-18 — cycle 1

### Hardening in exit path (actionable — matches what we already ship)

- Generic VM-exit mitigation suite: IBPB, VERW, eIBRS + LFENCE
  return-thunks, GPR scrub before indirect call in exit dispatcher.
- GhostRing's `src/vmx/vmx_asm.S` already does IBPB on every exit
  and VERW on privilege transition.  Verify: single-step through
  `gr_vmx_entry` in kgdb and confirm those two instructions execute
  on every exit, not just the first.

### Hyper-V nested "invalid-guest-state" checklist

Items to audit in `src/vmx/vmx_vmcs.c` every time we touch VMCS
setup:

1. Guest CR0.PE = 1, CR0.PG = 1, CR4.VMXE = 1 (with
   unrestricted-guest off, which is our current default).
2. Guest RFLAGS.VM = 0 and reserved bit 1 = 1.  We already force
   `VMCS_GUEST_RFLAGS = 0x2` for this reason.
3. Segment AR bytes: Type / S / P / DPL consistent with CS.L / CS.D.
   Protected by `tests/test_vmcs_segment.c` as of v0.1.0.
4. Under Hyper-V L1, `SECONDARY_EXEC_UNRESTRICTED_GUEST` may be
   reported in capability MSRs but refuse to take effect on VMWRITE.
   **Action**: after every secondary-control write, re-`vmread` the
   field and compare.  Log a warning if the value differs.

### Guest-side constraints on Linux 6.12 (critical for agent side)

- **BTF over hard-coded offsets.**  Linux builds with
  `CONFIG_DEBUG_INFO_BTF=y` expose `/sys/kernel/btf/vmlinux`.  Our
  agent (`agent/linux/`) and any in-kernel detector that needs
  `task_struct` / `mm_struct` / `cred` layout must resolve at load
  time via BTF, not compile-time constants.  SLAB_HARDENED + RANDSTRUCT
  reshuffle fields per build.
- **ENDBR64 for CET-IBT.**  If GhostRing ever injects a trampoline
  into guest `.text` (Phase 3 code_inject sub-detector), the landing
  instruction must be `ENDBR64` or the guest traps `#CP`.
- **Shadow-stack.**  Under `CR4.CET = 1`, injecting a call frame
  also requires updating `IA32_PL0_SSP` — otherwise `#CP` on `ret`.
- **CR3 churn from KPTI.**  Kernel flips CR3 on every syscall.  Do
  not enable `CR3_TARGET_COUNT`-based exits without filtering — you
  will drown CPU 0 in exits.
- **Retbleed / SRSO.**  Guest writes `IA32_SPEC_CTRL` frequently.
  Pass-through via MSR bitmap; do not trap.

## Open questions carried forward

- Do we need a dedicated `tests/detect_probes/` suite that runs the
  four classic hypervisor-presence probes from user space?  CPUID-
  vs-rdtscp timing, VMFUNC-from-ring-3, Intel-PT packet gap, HLAT
  silent-widen.  Would be the proof that our exit path is under a
  sane cycle budget and doesn't leak via hardware side channels.

- Bare-metal harness — exactly which BIOS setting layout for 13th-gen
  Intel consumer boards is "VMX locked but outside-SMX enabled"?
  Need to document for every OEM model we encounter.

- **Alert ABI mismatch discovered 2026-04-18.**  In-kernel
  `gr_alert_t` (src/monitor/alerts.h) has seven fields including
  `guest_rip`, `guest_cr3`, `target_gpa`.  The chardev wire
  record (loader/linux/ghostring_chardev.c) is only
  `{ts_ns, cpu_id, alert_type, info}`, and `gr_alert_emit()`'s
  `rip/cr3/gpa` arguments currently only go to `GR_LOG` (dmesg).
  Userspace agents therefore see "integrity failure on CPU 3"
  but not *which* page was hit.  Decide before v0.2 whether to:
    a) widen the wire record to match the monitor struct (ABI
       break — agent needs recompile), or
    b) strip the unused rip/cr3/gpa parameters from `gr_alert_emit`
       and be honest about what userspace receives.
  Option (a) is more useful for SIEM correlation.

## Sources reviewed

- GhostRing tree: `src/vmx/vmx_harden.h`, `vmx_hlat.h`, `vmx_pt.h`,
  `vmx_ve.h`, `vmx_vmfunc.h`, `vmx_spp.h`, `vmx_dual_ept.h`
  (inventory of what we already wire up).
- Intel SDM Vol 3C sections 24.4.1 (guest-state area), 27.3
  (VM-entry checks on VMCS).
- Microsoft Hyper-V TLFS (github.com/MicrosoftDocs/Virtualization-
  Documentation) — nested virt feature toggles.
- Linux kernel 6.12 changelog — KPTI, Retbleed, IBT, SRSO, BTF.

### Unverified / needs confirmation later

- CVE-2025-40300 (VMScape) — referenced in GhostRing commit messages
  as a reason for IBPB-on-exit.  The CVE identifier and MITRE/NVD
  advisory URL need to be pulled from a live source before we cite
  it in marketing material.
- CVE-2024-36350 (TSA on AMD Zen 3/4) — same status.  The class
  (transient scheduler attack / store-to-load forwarding) is real;
  the exact CVE string is unverified in this research round.
