# GhostRing — live bring-up on Hyper-V

This is the exact sequence that was reproduced end-to-end during
v0.1.0 development.  Commit `eeb041f` or later.

## Host prerequisites

- Windows 10/11 Pro with Hyper-V role enabled (`DISM /Online /Enable-Feature /FeatureName:Microsoft-Hyper-V-All /All`).
- `bcdedit /set hypervisorlaunchtype auto`, reboot.
- Intel VT-x host CPU (tested on i7-13700).  AMD path is symmetric but
  not yet verified in this environment.

## Guest

- Debian 13 (Trixie) minimal install, kernel 6.12.74+deb13+1-amd64.
- A Generation-1 Hyper-V VM created with:
  ```powershell
  New-VM -Name GhostRing-HV -Generation 1 -MemoryStartupBytes 4GB `
         -VHDPath C:\...\GhostRing.vhd -SwitchName 'Default Switch'
  Set-VMProcessor  -VMName GhostRing-HV -Count 4 `
                    -ExposeVirtualizationExtensions $true
  Set-VMMemory     -VMName GhostRing-HV -DynamicMemoryEnabled $false
  Set-VM           -Name GhostRing-HV -CheckpointType Disabled
  Set-VMComPort    -VMName GhostRing-HV -Number 1 `
                    -Path '\\.\pipe\ghostring-com1'
  ```
- A background PowerShell process drains the named pipe into
  `C:\Users\you\GhostRing-HyperV\serial.log` for host-side capture.

## Load sequence

Inside the guest, as root:

```bash
# Pull in crc32c (used by the hypervisor's integrity monitor).
modprobe crc32c
modprobe libcrc32c

# One-time "VMX warm-up": loading and immediately unloading kvm_intel
# pokes the per-CPU feature-control MSR state enough that our first
# VMXON afterwards succeeds.  Without this dance Hyper-V's nested
# VT-x declines VMXON on the very first attempt (see README).
modprobe kvm_intel
rmmod    kvm_intel kvm irqbypass

# Load GhostRing.  The two module parameters are development aids:
#   allow_nested=1   — permit entry even though CPUID advertises an
#                      outer hypervisor (Hyper-V is the outer here)
#   single_cpu=1     — bring up VMX on CPU 0 only, so the serial log
#                      isn't interleaved across four cores
cd /home/ghostring/GhostRing/loader/linux
insmod ./ghostring.ko allow_nested=1 single_cpu=1
```

## What you should see

In `dmesg`:

```
GhostRing: loading hypervisor module
GhostRing: allow_nested=1 — will enter VMX root under outer hypervisor
GhostRing: detected Intel CPU
GhostRing: single_cpu=1 — initialising CPU 0 only
GhostRing: CPU 0 virtualized
GhostRing: /dev/ghostring created (major 24X)
GhostRing: hypervisor loaded on 4 CPUs
```

In `serial.log` (the host-side capture), abbreviated:

```
[GR] glue: init CPU 0x0
[GR] vmx: outer hypervisor detected, proceeding (nested VT-x)
[GR] vmx: CR0_FIXED0 msr=0x80000021
[GR] vmx: CR4_FIXED0 msr=0x2000
[GR] vmx: CR4_FIXED1 msr=0x3727ff
[GR] vmx: VMXON succeeded, now in VMX root
[GR] vmx: enter_root complete (VMXON + VMCLEAR + VMPTRLD OK)
[GR] vmcs[GUEST_CS_AR]=0xa09b        ← L=1 bit 13 set (long mode)
[GR] vmcs[GUEST_IA32_EFER]=0xd01     ← LMA+LME+SCE+NXE
[GR] monitor: initialising security subsystems
[GR] msr_guard: shadow LSTAR=0xffffffff...
[GR] msr_guard: MSR bitmap configured, interception active
[GR] dkom: CR3 set initialised
[GR] hooks: IDT base GVA=0xfffffe0000000000
[GR] cr_guard: armed — CR0.WP, CR0.PG, CR4.SMEP, CR4.SMAP, CR4.CET protected
[GR] monitor: all subsystems armed (Phase 5 detectors active)
[GR] glue: launching VMX on CPU 0
[GR] glue: CPU virtualised 0x0 OK      ← blue-pill took effect
[GR] vmx_exit: #1  reason_basic=0x20   ← first real VM-exit: WRMSR
[GR] vmx_exit: #2  reason_basic=0x12   ← next: VMCALL (Hyper-V hypercall page)
[GR] vmx_exit: #3  reason_basic=0xc    ← HLT: guest went idle
...
```

At this point CPU 0 is executing Linux kernel code **inside non-root
mode** under GhostRing.  The VM remains healthy and the hypervisor
logs every exit that matters.

## Known limitations (v0.1.0)

- **Userspace scheduling under HV.** With GhostRing loaded, Linux
  keeps running but `sshd` on CPU 0 stops answering because we do not
  yet chain external interrupts back into the guest with the same
  fidelity Hyper-V expects.  The kernel itself is alive — uptime
  reaches 18 minutes+ under the hypervisor with CPU usage around 4%.
- **Clean `rmmod` is NYI.** Trying `rmmod ghostring` panics the guest
  kernel.  The devirtualisation path (magic-CPUID → VMXOFF → jump
  back into kernel) has a subtle register/stack invariant we couldn't
  isolate without `kgdb` attached.  The plumbing is in place —
  `gr_vmx_entry` has a `.Lleave_vmx` branch — but the trigger is
  currently disabled.  **Workflow: insmod → use → power-cycle VM to
  reload.**  Will be re-enabled in v0.2.0 once a real kernel debugger
  is wired up.
- **VirtualBox 7.1.8** refuses our VMXON despite advertising nested
  VT-x — Hyper-V is the only tested outer hypervisor.

## Roadmap to a recordable detection demo

1. Finish proper IRQ chaining so guest userspace stays responsive.
2. Implement VMXOFF-on-magic-CPUID for clean `rmmod`.
3. Load a sample rootkit (e.g. Diamorphine) and exercise the detectors
   already initialised (`msr_guard`, `cr_guard`, `integrity`) — they
   should emit `/dev/ghostring` alerts visible to `agent/linux/ghostring_agent`.

The hypervisor foundation (VMXON / VMCS setup / blue-pill continuation
/ exit dispatch / monitor init) is complete and verified on Hyper-V
nested VT-x; the remaining work is plumbing, not core research.
