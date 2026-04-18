# Research notes — running log

Private / working notes from periodic literature and competitor
review.  Used to steer engineering priorities.  Each block tagged
with the date it was added.

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
