# Running GhostRing on bare metal

Nested VT-x under Hyper-V is the development harness, but the real
target is bare metal.  Most v0.1.0 edge cases (SynIC passthrough
flakiness, sporadic userspace stalls) disappear on bare metal because
there is no outer hypervisor to coordinate with.

This is the minimum setup to bring GhostRing up on a dedicated box.

## 1. Hardware

- Intel CPU with VT-x + EPT + unrestricted-guest (6th gen or later is
  safe; tested on i7-13700).  AMD-V will come later.
- 8 GB RAM minimum (GhostRing itself fits in < 10 MB but Linux needs
  room).
- UEFI firmware with VT-x enabled and **Intel TXT disabled** (our
  hypervisor does not run under TXT).
- Secure Boot **OFF**.  The module is signed for development; with
  Secure Boot on the kernel refuses unsigned out-of-tree modules.

## 2. OS install

Debian 13 (Trixie) net-install, kernel 6.12.74+deb13+1-amd64
(the same combination we use in Hyper-V, so binaries are
drop-in replaceable).

During install:
- Install `build-essential`, `linux-headers-$(uname -r)`, `git`,
  `make`, `openssh-server`.
- Do **not** install Hyper-V integration tools / open-vm-tools /
  virtualbox-guest-utils — they can fight our blue-pill on real
  hardware.

After first boot:
```bash
apt install -y build-essential linux-headers-$(uname -r) git \
               openssh-server python3
systemctl enable --now ssh
```

## 3. Hardware diagnostics (run *before* load)

```bash
# Must print 'vmx' and 'ept'
grep -Eo 'vmx|ept' /proc/cpuinfo | sort -u

# Confirm IA32_FEATURE_CONTROL is locked with VMXON-outside-SMX enabled
rdmsr 0x3A   # expect bit 0 (lock) and bit 2 (VMXON outside SMX) set
             # e.g. '5' means bits 0+2 → OK
```

If `rdmsr` reports `2` instead of `5`, the BIOS lock is set without
VMXON — reboot into BIOS and toggle VT-x off/on to clear the lock.

## 4. Build and load

```bash
git clone https://github.com/bauratynov/GhostRing.git
cd GhostRing/loader/linux
make

# crc32c is a hard dependency today
modprobe crc32c
modprobe libcrc32c

# First real-hardware load — no need for allow_nested, no KVM warm-up
insmod ./ghostring.ko single_cpu=1
```

Expected output in dmesg:

```
GhostRing: loading hypervisor module
GhostRing: detected Intel CPU
GhostRing: single_cpu=1 — initialising CPU 0 only
GhostRing: CPU 0 virtualized
GhostRing: hypervisor loaded on <N> CPUs
```

On bare metal CPUID should **not** report an outer hypervisor, so the
`allow_nested` parameter is unused.

## 5. Verify

```bash
ls /dev/ghostring             # device should exist
agent/linux/ghostring-agent --status   # status=loaded, online_cpus=N
ping -c 3 1.1.1.1             # userspace I/O still works
```

## 6. Removing ghostring (v0.1.0)

**NOT SUPPORTED.**  `rmmod ghostring` will panic the kernel in this
release.  Power-cycle the machine, boot back into Linux, and you're
clean.  See `docs/KGDB.md` for the plan to fix this properly.

## 7. What's known to work differently on bare metal

| Feature                  | Hyper-V nested | Bare metal |
|--------------------------|----------------|------------|
| `allow_nested=1` needed  | yes            | no         |
| `kvm_intel` warm-up      | yes            | no         |
| SynIC VMCALL passthrough | critical       | dead code  |
| Userspace I/O stability  | flaky          | solid      |
| Expected overhead        | 5-15 %         | < 2 %      |

The `forward_unknown_vmcall_to_outer_hv` path in `hypercall.c` is a
no-op on bare metal (there is nothing above us to forward to).  We
keep the branch in the code so a single binary works in both modes;
Hyper-V users turn it on implicitly by running nested, bare-metal
users never take the path.

## 8. Safety net

If the kernel panics during `insmod`, power-cycle the machine.
GhostRing state lives in the module's allocated pages — nothing is
written to disk or firmware.  There is no persistent damage in any
failure mode we have observed.

If panics happen reliably, run `serial.log` capture by adding
`console=ttyS0,115200` to the kernel command line and tail the
port — gives us the same hex-dump evidence we capture under Hyper-V.
