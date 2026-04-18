# Attaching `kgdb` to the GhostRing Hyper-V guest

The two remaining v0.1.0 issues (clean `rmmod` crash and sporadic
userspace stalls) need interactive kernel debugging to pin down.
This doc is the exact recipe to get `kgdb` talking to a running
GhostRing guest over a second serial port, with `gdb` driving from
the Windows host.

All commands copy-paste without changes; no judgement calls.

## 1. Host: expose a second named pipe for COM2

PowerShell, admin:

```powershell
Set-VMComPort -VMName GhostRing-HV -Number 2 -Path '\\.\pipe\ghostring-kgdb'
```

(COM1 stays on `\\.\pipe\ghostring-com1` for our hypervisor serial log.)

## 2. Host: bridge the named pipe to TCP 5555

`gdb` on Windows can't speak named-pipe directly, so relay it to
localhost TCP:

```powershell
# One-liner launcher — leave it running in its own PowerShell window
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream `
          '.', 'ghostring-kgdb', [System.IO.Pipes.PipeDirection]::InOut
$pipe.Connect()
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 5555)
$listener.Start()
$client = $listener.AcceptTcpClient()
$clientStream = $client.GetStream()

$t1 = Start-Job -ArgumentList $pipe,$clientStream -ScriptBlock {
    param($a,$b); $buf = New-Object byte[] 4096
    while ($true) { $n = $a.Read($buf,0,$buf.Length); if ($n -le 0) { return }; $b.Write($buf,0,$n); $b.Flush() }
}
$t2 = Start-Job -ArgumentList $clientStream,$pipe -ScriptBlock {
    param($a,$b); $buf = New-Object byte[] 4096
    while ($true) { $n = $a.Read($buf,0,$buf.Length); if ($n -le 0) { return }; $b.Write($buf,0,$n); $b.Flush() }
}
Wait-Job $t1,$t2
```

## 3. Guest: kernel command line with `kgdbwait`

Edit `/etc/default/grub` inside the VM:

```
GRUB_CMDLINE_LINUX_DEFAULT="quiet kgdboc=ttyS1,115200 kgdbwait"
```

Then:

```bash
update-grub
reboot
```

The guest kernel will pause during boot waiting for gdb to attach.

## 4. Host: attach gdb

Install `gdb-multiarch` (e.g. from Strawberry Perl or MSYS2 distros).
Then:

```bash
gdb-multiarch /lib/modules/6.12.74+deb13+1-amd64/build/vmlinux
(gdb) target remote :5555
(gdb) set architecture i386:x86-64
(gdb) continue
```

Guest boot resumes.  From there, set breakpoints in `ghostring.ko`:

```
(gdb) add-symbol-file /home/ghostring/GhostRing/loader/linux/ghostring.ko \
      <module .text addr from /sys/module/ghostring/sections/.text>
(gdb) break gr_vmx_entry
(gdb) break .Lleave_vmx
(gdb) break gr_vmx_handle_exit
```

## 5. Trigger the bug

Inside the guest, `rmmod ghostring` — gdb stops at `.Lleave_vmx`.
Single-step through the VMXOFF path; one of these registers or stack
slots is wrong and that is what we need to see.

## What to look at first

1. After `vmxoff`, confirm RSP/RIP values we're about to load.
2. After `jmp`, see which kernel address we actually land at.
3. If the kernel panics, the backtrace tells us which gr_cpuid output-
   store hit garbage — that confirms the register restore theory.

Once root-caused, update `vmx_asm.S` and re-enable the
`gr_exit_vm_flag` trigger in `vmx_exit.c:handle_cpuid`.

## Sanity-check the setup *before* diving

The cheapest verification that kgdb is working end-to-end is to set
a breakpoint on `ghostring_init` in the module, then `insmod` — if
gdb hits the breakpoint, the plumbing is correct and only the devirt
asm is left to fix.
