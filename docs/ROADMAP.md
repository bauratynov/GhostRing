# GhostRing — Roadmap

A buyer asking "where is this going?" gets answered from this file.
Priorities are ordered by blocker impact, not by effort.

## v0.1.0 — Research Preview *(current, April 2026)*

- Intel VT-x blue-pill on Debian 13 / Linux 6.12, tested under
  Hyper-V nested VT-x.
- 15 active detectors + 4 planned slots wired into the monitor
  dispatcher.
- Apache-2.0 core + GPL-2.0 Linux loader per-subsystem licensing.
- Userspace agent with `--status / --integrity / --monitor / --json`.
- Verified artefacts: real `docs/session-transcript.log` serial
  capture and `docs/live-run.txt` ping under the loaded hypervisor.

### Known limitations v0.1.0

- `rmmod` is NYI (panics guest; power-cycle VM to reload).
- Userspace I/O under HV works but can stall under sustained load —
  SynIC passthrough fidelity is not 100 %.
- Only Hyper-V outer hypervisor validated.  VirtualBox 7.1 rejected
  our VMXON; bare metal not yet tested end-to-end.
- AMD-V back-end compiles but has no live hardware run yet.

## v0.2.0 — Single-customer pilot *(target: May 2026)*

Blocks for a first paid PoC.  All of this work is already mapped
out — nothing remains a research question.

- [ ] `rmmod` clean path (`kgdb`-driven debug of the `.Lleave_vmx`
      asm; see `docs/KGDB.md`).
- [ ] Bare-metal bring-up on a dedicated Intel box; record the
      equivalent of `docs/live-run.txt` from real hardware.
- [ ] IDT EPT protection re-enabled (pending fixmap → real-phys
      translation via page-walk).
- [ ] Diamorphine-style attack test: load a sample rootkit, show
      `ghostring-agent --monitor` emitting an `idt_hook` alert.
- [ ] Performance benchmark: kernel compile / `pgbench` overhead
      numbers with / without the hypervisor loaded.
- [ ] Windows KMDF loader reaches `insmod`-equivalent parity
      (`Start-Service ghostring`) and is signed for Test-Mode deploy.
- [ ] Add GitHub Actions job for `make -C loader/linux` so every
      commit produces a verified `.ko` artefact.

## v0.3.0 — Multi-customer beta *(target: Q3 2026)*

- [ ] AMD-V bring-up on real hardware (Zen 3 or newer).
- [ ] UEFI Type-1 loader (`loader/uefi/`) — pre-OS launch so
      GhostRing sits below even the early bootloader.
- [ ] TPM / DRTM integration (Intel TXT, AMD SKINIT) — the hypervisor
      proves its own identity to a remote attestation service.
- [ ] SIEM-side parser: a Splunk app + an Elastic integration that
      ingests the `ghostring-agent --json` output.
- [ ] Kazakhstan government regulatory review: алгоритмическая
      экспертиза for government-sector deployment.

## v1.0.0 — General availability *(target: late 2026 / early 2027)*

- [ ] WHQL signed Windows driver for Secure-Boot enabled deploy.
- [ ] Commercial enterprise console: multi-endpoint management,
      alert triage, integration with MITRE ATT&CK Navigator JSON.
- [ ] External security audit (pen-test plus a code review by an
      independent firm — results published in `docs/AUDIT-v1.md`).
- [ ] CVE bug-bounty programme, first-blood reward 5 k USD.
- [ ] Localised UI / documentation — EN / RU / KZ.
- [ ] First CVE *found with GhostRing* in an out-of-tree kernel
      module — the story that closes the "does it actually work"
      question forever.

## Out-of-scope (forever)

- Full system emulation — we are a thin blue-pill, not a cloud
  hypervisor competitor.
- Anti-cheat / DRM workloads — different threat model, different
  design constraints.
- Firmware-level rootkit detection below Ring -2 (SMM).  We rely
  on Intel BootGuard / TPM for that layer.

## How to propose a change

Open an issue tagged `roadmap` with:
- Which milestone it should land in (v0.2 / v0.3 / v1.0).
- Justification: which detector gets stronger or which blocker is
  removed.
- Rough implementation sketch.

Pull requests welcome even before the issue is opened if the change
is self-contained (docs, tests, a single detector tweak).
