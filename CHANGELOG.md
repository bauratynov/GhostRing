# Changelog

All notable changes to GhostRing are recorded here.  Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses semantic versioning from v1.0.0 onward; v0.x releases are
research previews where the public API may shift between tags.

## [Unreleased]

### Added

- Regression-lock test suite expanded to cover the invariants
  discovered during v0.1.0 bring-up.  Each suite is named after
  the rule it protects and refers to the SDM section number in its
  header comment.  Covered so far: VMX capability-MSR adjustment,
  CR0/CR4 fixed bits, VM-entry interruption-information field
  layout, VMCS field encodings, segment access-rights / RFLAGS /
  selector encoding, EPT entry and EPTP layout, pin/primary/secondary
  exec-control bit positions, MSR bitmap bit arithmetic, MTRR
  memory types, VM-exit reason codes, allocator stress and
  fragmentation, CRC32C polynomial, hypercall IDs, alert ring
  semantics and on-the-wire layout, DKOM generation-counter
  semantics, platform virt↔phys round-trip.
- `docs/WINDOWS-BUILD.md` — full VS 2022 + WDK recipe for building,
  signing, and loading the Windows KMDF loader.
- `docs/RESEARCH-NOTES.md` — running log of competitor and
  literature review (HVMI archival, SimpleVisor licensing, etc.).

### Changed

- `src/monitor/integrity.c` — corrected comment that referred to
  the IEEE 802.3 polynomial; the code actually uses the Castagnoli
  CRC32C polynomial (0x82F63B78) via SSE4.2.
- `src/vmx/vmx_vmcs.c` — after writing `VMCS_SECONDARY_EXEC_CTRL`
  the field is now read back and any mismatch is logged.  Catches
  the Hyper-V case where secondary bits are silently dropped.
- `README.md` — 'Why now' paragraph citing Bitdefender HVMI's
  January 2026 archival as the market opening we move into.

### Planned

- Clean `rmmod` via `kgdb`-guided repair of the `.Lleave_vmx` asm
  path (see `docs/KGDB.md`).
- Bare-metal bring-up transcript to complement `docs/live-run.txt`.

## [0.1.0] — 2026-04-18 — Research Preview

### Added

- Intel VT-x blue-pill: VMXON / VMCS setup / VMLAUNCH / exit
  dispatch.  Verified on Hyper-V nested VT-x with Debian 13 / Linux
  6.12.74 guest.
- Proper blue-pill continuation in `gr_vmx_launch` — writes
  `GUEST_RSP/RIP/RFLAGS` inline so the guest resumes on its own
  stack with transparent control-flow continuity.
- External-interrupt re-injection path with
  `VM_EXIT_ACK_INTR_ON_EXIT`.
- Hyper-V paravirt passthrough: unknown `VMCALL` hypercalls are
  forwarded to the outer hypervisor so the guest's SynIC interrupts
  continue flowing (restored userspace networking under the HV).
- 15 detector subsystems initialised on arm: `msr_guard`, `cr_guard`,
  `integrity`, `dkom`, `hooks`, `ssdt`, `ransomware`, `shadow_stack`,
  `code_inject`, `callbacks`, `anti_forensics`, `supply_chain`,
  `token`, `driver_obj`, `pte_monitor`.
- Alert ring buffer on `/dev/ghostring`, consumed by
  `agent/linux/ghostring-agent --monitor`.
- Userspace agent (`agent/linux/`) with `--status / --integrity /
  --monitor` commands and a `--json` output mode for SIEM / syslog
  pipelines.
- Dual-license structure: Apache-2.0 for core and userspace,
  GPL-2.0-only for the Linux loader, LICENSE index + NOTICE.
- Regression lock: `tests/test_vmcs_segment.c` protects against the
  `flags2 << 4` access-rights encoding bug.
- Documentation: `docs/DEMO.md` reproducible bring-up,
  `docs/DETECTORS.md` catalogue of all 19 detector slots with MITRE
  ATT&CK mapping, `docs/KGDB.md` kernel-debug recipe,
  `docs/BAREMETAL.md` real-hardware install, `docs/ROADMAP.md`.
- Verified transcripts in `docs/`: `session-transcript.log` (serial
  VMXON/VMCS capture), `dmesg-transcript.log`, `live-run.txt` (ping
  0 % loss under the loaded hypervisor).

### Fixed during v0.1.0 development

- `gdt_to_vmx_entry` mis-encoded segment access-rights: shifted
  `flags2 & 0xF0` by 4 bits instead of 8, which placed `G/D/L/AVL`
  into reserved bits 11:8 and silently cleared long-mode `L` on
  entry.  VMLAUNCH failed with invalid-guest-state until this was
  fixed.
- `IA32_EFER` was not captured into `host_regs` so
  `VMCS_GUEST_IA32_EFER` stayed zero; with `VM_ENTRY_IA32E_MODE=1`
  the invalid-guest-state check rejected the entry.  Now read from
  MSR `0xC0000080` and written with `VM_ENTRY_LOAD_GUEST_EFER`.
- EPT PDE walk dereferenced stored PFN as a virtual pointer, causing
  a kernel page fault during early `gr_vmx_ept_protect_page`.  Now
  goes through `gr_phys_to_virt` to land on a kernel-mapped address.
- Magic-CPUID devirt trigger matched on `leaf && subleaf`; the kmod
  loader calls CPUID with `ecx=0`, so the devirt path never fired.
  Now match on leaf alone.

### Known issues

- `rmmod ghostring` panics the guest — devirt asm path NYI.  Power-
  cycle VM to reload.
- Sporadic SSH / userspace stalls under HV after sustained alert
  traffic; ring buffer backpressure suspected.  Investigation
  blocked on `kgdb`.
- VirtualBox 7.1 rejects our VMXON from inside a nested guest even
  with all MSR / CR pre-conditions satisfied; Hyper-V is the only
  verified outer hypervisor.

[Unreleased]: https://github.com/bauratynov/GhostRing/compare/v0.1.0...master
[0.1.0]: https://github.com/bauratynov/GhostRing/releases/tag/v0.1.0
