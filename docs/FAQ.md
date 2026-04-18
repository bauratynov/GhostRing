# GhostRing — Frequently Asked Questions

Written for evaluators who spent ten minutes on the README and want
the next layer of detail without having to read 15 k LOC of C.

## What is GhostRing in one sentence?

A Ring -1 hypervisor, written in freestanding C99 + x86-64 assembly,
that takes over a running Linux kernel via VMXON+VMLAUNCH and
monitors 19 attack surfaces from a vantage point rootkits can't
reach.

## Isn't this just another KVM / Xen?

No.  KVM and Xen are *Type-2* or *Type-1* hypervisors designed to
host multiple guests.  GhostRing is a *thin blue-pill*: one guest
(the already-running OS), zero additional guest management, no
scheduler.  Its only job is to intercept specific privileged
events — MSR writes, CR tampering, IDT/SSDT hooks — and forward them
to an alert pipeline.  This class of project includes SimpleVisor,
HyperPlatform, DdiMon.  GhostRing is unique in being Apache-2.0
opensource with 19 built-in detectors and an SIEM-ready JSON agent.

## How does this differ from an EDR like CrowdStrike?

Traditional EDR lives at Ring 0 alongside the kernel it is trying
to defend.  When a kernel rootkit wins the Ring 0 race, the EDR is
either blinded or outright disabled.  GhostRing lives one ring
below — the kernel rootkit cannot see or modify Ring -1 without
first defeating Intel VT-x hardware, which is a much harder target.

## What does "blue-pill" mean?

The term comes from Joanna Rutkowska's 2006 Black Hat talk.  A
blue-pill hypervisor virtualises an already-running OS in place —
no reboot, no new guest.  From the kernel's perspective the
hypervisor "appeared" out of nowhere.  GhostRing does this
transparently: after `insmod ghostring.ko`, the kernel continues
running at full speed, only trapping on the specific events our
monitor subscribes to.

## Is this actually working?

Yes, verifiably.  See `docs/session-transcript.log` for the raw
serial-port capture of a real VMXON / VMCS / VMLAUNCH sequence, and
`docs/live-run.txt` for `ping 8.8.8.8` returning 0 % packet loss at
55 ms RTT *with the hypervisor loaded on CPU 0*.  Those artefacts
contain hex addresses from the running kernel — they're not mock
data.

## What platforms are supported?

- Intel VT-x — **verified** on Hyper-V nested, Debian 13, Linux
  6.12.74.
- Intel VT-x on bare metal — **planned for v0.2** (see
  `docs/BAREMETAL.md`).
- AMD-V — **code complete, not tested** on real hardware yet.
- Windows loader (KMDF) — **builds**, not yet signed for WHQL.
- UEFI Type-1 loader — **skeleton**, Phase 3 milestone.

## Can I unload it (`rmmod`)?

Not in v0.1.0 — `rmmod` panics the guest.  The devirtualisation
asm path is in place but has a subtle register/stack invariant
issue that we couldn't chase without `kgdb` attached.  The
workflow today is: power-cycle the VM / machine to reload.
See `docs/KGDB.md` for the fix plan.

## Performance overhead?

Uncommitted as of v0.1.0.  We will publish kernel-compile and
pgbench numbers from real hardware in v0.2.  Theoretical cost per
VM-exit: ~300 cycles for CPUID, ~150 cycles for our VMFUNC path.
Not all operations exit — MSR bitmap filters only security-relevant
accesses.  We target sub-2 % user-visible overhead on bare metal.

## What's the licensing story?

Dual-license per subsystem:

- `src/`, `agent/`, `tests/`, `loader/windows/`, `loader/uefi/` —
  **Apache-2.0** (patent grant protection, compatible with
  proprietary downstream).
- `loader/linux/` — **GPL-2.0-only** (Linux kernel modules must be
  GPL to link against `EXPORT_SYMBOL_GPL` symbols; `MODULE_LICENSE`
  is `"GPL v2"` to avoid tainting the kernel).

The full text is in `LICENSE`, `LICENSE-APACHE`, `LICENSE-GPL`,
`NOTICE`.  Every source file carries its own `SPDX-License-Identifier`
header.

## Commercial license / consulting?

Email `bauratynov@gmail.com`.  Commercial licensing for the
GPL-incompatible cases is handled through **JQ innovations LLP**.

## What's "SynIC passthrough"?

When GhostRing runs under Hyper-V, the guest Linux's Synthetic
Interrupt Controller makes `VMCALL`-based hypercalls that expect
Hyper-V to service them.  GhostRing intercepts every `VMCALL`, so
unknown hypercall numbers would otherwise be silently dropped —
breaking timekeeping and network.  The passthrough path issues the
same `VMCALL` from VMX root, which nested VT-x delivers to the real
Hyper-V, and returns the result.  See `src/hypercall/hypercall.c`.

## Is the code audited?

Not externally yet.  v1.0 ships with a published third-party audit
(`docs/AUDIT-v1.md`).  For now the `tests/` directory has an 18/18
test suite covering the allocator, DKOM hash table, CRC32C, and the
segment access-rights encoding that bit us during bring-up.

## Are you hiring?

When commercial revenue lands, yes — kernel-security engineers
familiar with Intel SDM, AMD APM, or Windows Driver Framework.
Ping `bauratynov@gmail.com`.

## Where do I report a security issue?

**Not** on the public issue tracker.  See `SECURITY.md`:  email
`bauratynov@gmail.com`, acknowledgement within 48 hours,
fix-or-mitigation within 30 days for critical findings.
