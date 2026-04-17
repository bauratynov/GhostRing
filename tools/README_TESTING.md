# GhostRing — Testing Setup Guide

## Quick Start

### Step 1: Disable Hyper-V (required for nested VT-x in VirtualBox)

Open PowerShell as Administrator:
```powershell
bcdedit /set hypervisorlaunchtype off
```
**REBOOT your machine.** WSL2 will stop working until you re-enable Hyper-V.

To re-enable later:
```powershell
bcdedit /set hypervisorlaunchtype auto
```

### Step 2: Install VirtualBox

Run `tools\VirtualBox-7.1.8-Win.exe` and install with defaults.

### Step 3: Create Test VM

Run `tools\setup_testvm.bat` — it creates a VM with:
- 4 CPUs, 4 GB RAM
- **Nested VT-x enabled**
- Serial port → file (for hypervisor debug output)
- SSH port forwarding (host 2222 → guest 22)
- Alpine Linux ISO attached

### Step 4: Install Alpine Linux

```
VBoxManage startvm GhostRing-TestVM
```

In the VM console:
1. Login as `root` (no password)
2. Run `setup-alpine` — answer prompts (keyboard, timezone, mirror, disk: `sda`, `sys`)
3. Reboot
4. Login, install build tools:

```sh
apk update
apk add gcc make musl-dev linux-headers bash
```

### Step 5: Copy GhostRing into VM

Option A — Shared folder:
```sh
# On host:
VBoxManage sharedfolder add GhostRing-TestVM --name ghostring --hostpath "D:\apps\GhostRing" --automount

# In VM:
apk add virtualbox-guest-additions
mount -t vboxsf ghostring /mnt
```

Option B — SCP:
```sh
# From host PowerShell:
scp -P 2222 -r D:\apps\GhostRing\src D:\apps\GhostRing\loader root@localhost:/root/ghostring/
```

### Step 6: Build and Load

```sh
cd /root/ghostring/loader/linux
make
insmod ghostring.ko
dmesg | grep GhostRing
```

### Step 7: Check Serial Output

On the host, the serial log is at:
```
%USERPROFILE%\VirtualBox VMs\GhostRing-TestVM\serial.log
```

This file shows all `GR_LOG()` output from the hypervisor — VMXON status,
EPT setup, monitor init, etc.

### Step 8: Run Benchmark

```sh
cd /root/ghostring/tests
gcc -O2 -o bench_vmexit bench_vmexit.c
./bench_vmexit
```

Expected output under GhostRing:
```
Hypervisor vendor: "GhRing"
CPUID leaf 1: avg ~1200 cycles (vs ~80 bare metal)
VMCALL PING: avg ~800 cycles
```

### Step 9: Unload

```sh
rmmod ghostring
dmesg | grep GhostRing    # should show "unloaded"
```

## Troubleshooting

**"VT-x is not available"** — Hyper-V still enabled. Check: `bcdedit | findstr hypervisor`

**"VMXON failed"** — BIOS has VT-x disabled. Enter BIOS → Intel Virtualization → Enable.

**"Nested VT-x not available"** — VirtualBox version too old (need 6.1+) or `--nested-hw-virt on` not set.

**Kernel module won't build** — Missing headers: `apk add linux-headers`

**Serial log empty** — VM not using COM1. Check: `VBoxManage showvminfo GhostRing-TestVM | grep UART`
