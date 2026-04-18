---
name: Bug report
about: Something is broken in GhostRing
title: "[BUG] "
labels: bug
---

## Environment

- GhostRing version / commit SHA:
- Host OS and kernel (`uname -a`):
- Outer hypervisor (bare metal / Hyper-V / VirtualBox / KVM / other):
- CPU (`grep 'model name' /proc/cpuinfo | head -1`):

## What did you run?

Exact commands — copy from your shell, not paraphrased.

```
# e.g.
modprobe crc32c && modprobe libcrc32c
insmod ./ghostring.ko allow_nested=1 single_cpu=1
```

## What did you expect?

## What happened?

Include the relevant output.  If a hang or panic occurred, attach:

- `dmesg | grep -iE 'GhostRing|BUG|Oops|Call Trace' > dmesg.txt`
- The serial log file if COM1 is piped (`docs/DEMO.md` explains setup).

## Extra context

Anything else we should know (custom kernel config, SELinux / AppArmor
state, previous `rmmod` attempts, etc.)
