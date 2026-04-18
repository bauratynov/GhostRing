# GhostRing — Threat Model

## Scope

This document describes which adversaries GhostRing is designed to
detect, which ones it is **not** designed to handle, and the
assumptions that must hold for the guarantees to apply.  It is the
first thing a security architect asks for and the first thing that
gets scrutinised during an audit — so it is short, specific, and
honest.

## Assets to protect

1. **Linux kernel code pages** — every `.text` mapping in the guest
   kernel and in loaded modules.  Integrity is monitored via CRC32C
   against the arm-time baseline.
2. **Kernel control-flow tables** — IDT, SSDT (on Windows), driver
   dispatch-routine tables, notification-callback lists.  These are
   the classic rootkit hooking points.
3. **Critical MSRs** — `LSTAR`, `SYSENTER_EIP/ESP`, `EFER`.  Altering
   any of them redirects syscall entry to rootkit-controlled code.
4. **Control registers** — CR0 bits `WP` (kernel write protection)
   and `PG` (paging); CR4 bits `SMEP`, `SMAP`, `CET`.  Clearing any
   of these is a precursor to kernel-space exploitation.
5. **User-data canary pages** — optional seed files in user home
   directories used to detect ransomware encryption waves before the
   real files are lost.
6. **Alert transport** — `/dev/ghostring` ring buffer + the
   userspace agent → SIEM pipeline.  The alerts themselves are
   authenticity evidence.

## Adversary capabilities

We model three adversary tiers; each is strictly more capable than
the previous:

### Tier 1 — Ring 3 malware, any privilege

- Can execute arbitrary user-mode code.
- Can call syscalls, IPC, read/write own memory.
- **Cannot** inject into kernel, load drivers, read arbitrary
  kernel memory.

GhostRing value at this tier: **indirect**.  We do not block Ring 3
malware directly, but we become relevant when a Ring 3 exploit
chain tries to transition into Ring 0 — the CR or MSR write that
lands the escalation exits to us.

### Tier 2 — Ring 0 kernel-level attacker

- Loaded a rootkit / malicious driver (e.g. via a signed-driver
  vulnerability, BYOVD, exploit of a kernel CVE).
- Can read/write any physical memory, hook IDT/SSDT, overwrite
  kernel `.text`, steal tokens, hide processes via DKOM.
- **Cannot** execute VT-x instructions without triggering our
  exits.

**Primary target of GhostRing.**  Every detector in `docs/DETECTORS.md`
is designed to flag a Tier 2 behaviour in real time.

### Tier 3 — Ring -1 / Ring -2 / firmware adversary

- Controls UEFI firmware, SMM, management engine, or an outer
  hypervisor.
- Runs below the kernel but also below GhostRing.
- Can in principle observe and modify our VMCS / EPT.

**Out of scope.**  We explicitly do **not** defend against this
tier.  Intel BootGuard, AMD PSB, Intel TXT / TDX, or Secure Launch
(DRTM) are the correct mitigations and they operate below us.
v0.3 will add an attestation hook so that GhostRing can report
"I loaded under a trusted launch" to a remote verifier, but the
root of trust will remain the firmware.

## Trust boundary

| Entity                       | Trusted?  | Notes                                               |
|------------------------------|-----------|-----------------------------------------------------|
| CPU (VT-x, EPT, MSR bitmap)  | Yes       | Root of trust for execution isolation               |
| Firmware (UEFI, SMM)         | Yes       | Out of scope — see Tier 3 above                     |
| Bootloader                   | Yes       | Until UEFI loader ships, we rely on the OS loader   |
| Linux kernel **at load time**| Yes       | Image integrity is the user's responsibility (IMA)  |
| Linux kernel **after load**  | No        | We monitor it for post-load tampering               |
| Kernel modules               | No        | Monitored via integrity + SSDT/driver-obj checks    |
| Userspace processes          | No        | Isolated by CPU privilege, only agent talks to us   |
| `/dev/ghostring` consumers   | Mostly    | Restricted by unix file permissions (0600 root)     |
| Network path to SIEM         | No        | Agent forwards over TLS (SIEM-side responsibility)  |

## Assumptions

1. **CPU supports Intel VT-x with EPT and unrestricted guest** (all
   Intel chips from 6th-gen onward).  AMD-V path is symmetric but
   not yet validated in production.
2. **Secure Boot is enabled** so the kernel image and our module
   can be cryptographically verified before load.  With Secure Boot
   off, an attacker can pre-place a malicious `ghostring.ko` on
   disk — integrity ceases to be meaningful.
3. **IA32_FEATURE_CONTROL is locked with VMXON-outside-SMX enabled**.
   This is the BIOS-level switch that tells the CPU VMX is
   permitted outside Intel TXT.  If it is unset or unlocked, VMXON
   fails and GhostRing silently refuses to load.
4. **No other hypervisor is active** unless `allow_nested=1` is
   passed explicitly (a development flag).  In production we will
   warn-and-abort if we detect an outer hypervisor.
5. **The `root` account is not compromised** between module load
   and first alert — it controls `/dev/ghostring` permissions.
   Compromise after that point is detectable via the integrity /
   MSR / CR guards.

## Detection reliability

| Attack class                                | Detection | False-positive rate | Mean time to detect |
|---------------------------------------------|-----------|--------------------:|--------------------:|
| IDT / SSDT hook                             | Strong    | ~0 %                | < 1 ms (EPT exit)   |
| MSR rewrite (`LSTAR` etc.)                  | Strong    | ~0 %                | < 1 ms (MSR bitmap) |
| Kernel `.text` inline patch                 | Strong    | < 0.1 % (periodic rescan) | seconds (scan interval) |
| CR0 / CR4 protection-bit flip               | Strong    | ~0 %                | < 1 ms              |
| Ransomware mass encryption                  | Medium    | heuristic: ~1 % on canary contact | seconds (until first canary hit) |
| DKOM process hide                           | Medium    | depends on polling interval | minutes |
| Token stealing (SYSTEM impersonation)       | Medium    | heuristic            | seconds              |
| ROP / JOP chain                             | Medium    | 5 - 10 % FP (MTF noise) | microseconds        |

"Strong" means one missed event requires an in-silicon CPU flaw or
firmware compromise (Tier 3).  "Medium" means the detector uses
heuristics with honest FP rates published here.

## What we explicitly do **not** claim

- We do **not** prevent attacks — we detect and alert.  Blocking
  is the downstream SOC's decision (though `gr_monitor_ept_violation`
  returning `BLOCK` is possible for specific detectors).
- We do **not** defend against an adversary who controls SMM, the
  ME, or the UEFI firmware.
- We do **not** replace EDR — we complement it.  EDR keeps
  visibility into user-mode and application-layer behaviour; we
  keep visibility into the kernel even if the EDR is disabled.
- We do **not** guarantee timing SLAs across all kernel versions
  and hardware generations — performance characterisation for each
  target landed in v0.2+.

## Open research questions

- **Hypervisor rootkit detection.**  If an adversary loads a second
  hypervisor below us after our VMXON, we currently have no signal.
  Intel HLAT (VT-rp) or nested-EPT self-audit may help; not yet
  implemented.
- **Side-channel leakage** from VM-exit timing (Spectre-in-VMX
  variants).  We follow the VMScape / TSA mitigations published in
  July 2025, but new classes keep appearing.
- **Covert channels** via EPT access patterns between detectors.
  Needs constant-time detector implementations.

These are acknowledged limitations — any customer-facing answer about
them should cite this section rather than improvise.
