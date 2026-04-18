# GhostRing — Detector Catalogue

Each row is one source module under `src/monitor/`.  This file is the
single reference for "what does GhostRing actually look at?" — answers
to the common investor / architect question.

| # | Source                | Symbol                          | MITRE ATT&CK     | What it catches                                                                 | Method                                                |
|---|-----------------------|---------------------------------|------------------|---------------------------------------------------------------------------------|-------------------------------------------------------|
| 1 | `msr_guard.c`         | `gr_msr_guard_*`                | T1014, T1562     | Rootkits rewriting `LSTAR`, `SYSENTER_EIP/ESP`, `EFER` to redirect syscalls     | MSR bitmap → VM-exit on write → shadow compare        |
| 2 | `cr_guard.c`          | `gr_cr_guard_*`                 | T1068, T1562     | CR0.WP/PG or CR4.SMEP/SMAP/CET cleared to disable kernel self-protection         | VMCS guest-host mask → VM-exit on intercepted bit    |
| 3 | `hooks.c`             | `gr_hooks_*`                    | T1014, T1546     | IDT entry overwrite (kernel-level interrupt hook)                               | Snapshot on arm + EPT write-protection of IDT pages*  |
| 4 | `ssdt.c`              | `gr_ssdt_*`                     | T1014            | SSDT (Windows system-service table) entry hooking                               | EPT write-protect + CRC comparison                   |
| 5 | `integrity.c`         | `gr_integrity_*`                | T1601, T1014     | Kernel `.text` or driver image patch (inline hook, JMP injection)               | Periodic CRC32C over arm-time snapshot                |
| 6 | `dkom.c`              | `gr_dkom_*`                     | T1014            | Processes hidden by unlinking from `EPROCESS` / `task_struct` lists             | CR3 set from hardware exits vs OS process list diff   |
| 7 | `driver_obj.c`        | `gr_drvobj_*`                   | T1547.006        | `DRIVER_OBJECT` IRP-handler tampering (malicious filter drivers)                | Hash of dispatch-routine tables                       |
| 8 | `code_inject.c`       | `gr_code_inject_*`              | T1055, T1620     | Remote-thread injection, RWX allocations, reflective DLL loading                | Known-good page bitmap + exec fault detector          |
| 9 | `callbacks.c`         | `gr_callbacks_*`                | T1546            | Kernel notify-callback list tampering (process / image / registry)              | Baseline snapshot vs current scan                     |
| 10| `ransomware.c`        | `gr_ransom_check_write`         | T1486, T1490     | Mass-encryption wave before user data is lost                                   | EPT canary pages seeded in user docs directories      |
| 11| `anti_forensics.c`    | `gr_anti_forensics_*`           | T1070, T1529     | Log clearing, event-log silencing, system-shutdown attempts from unusual origin | Syscall-pattern + MSR guard integration              |
| 12| `supply_chain.c`      | `gr_supply_chain_*`             | T1574.001/.002   | DLL search-order hijack, phantom DLL injection                                  | Image-load path profiling                             |
| 13| `token.c`             | `gr_token_*`                    | T1134            | Kernel-mode token-stealing (SYSTEM impersonation)                               | Token-field validation on privileged syscalls         |
| 14| `shadow_stack.c`      | `gr_shadow_stack_*`             | T1620            | ROP / JOP / call-oriented programming chains                                    | Intel CET shadow-stack mismatch via MTF single-step   |
| 15| `pte_monitor.c`       | `gr_pte_*`                      | T1003            | LSASS / credential-store reads from unauthorized addresses                      | PTE dirty-bit scan on protected ranges                |
| 16| `alerts.c / alerts.h` | `gr_alert_emit`, `gr_alert_push`| (transport)       | Emits all detector events through `/dev/ghostring` ring buffer                 | Lock-free SPSC ring, polled by userspace agent        |
| 17| `monitor.c`           | `gr_monitor_*`                  | (glue)           | Arms / disarms the subsystems, routes EPT / MSR / CR exits to the right detector | Central dispatcher                                 |
| 18|  — (planned)           | VMFUNC exitless tracer          | (research)       | High-volume events without full VM-exit                                         | VMFUNC EPTP switching (134 cycles)                    |
| 19|  — (planned)           | Intel PT integration            | (research)       | Control-flow trace for attack reconstruction                                    | Hardware branch trace via IA32_RTIT_CTL               |

\* IDT EPT protection is temporarily disabled in v0.1.0 (see source
comment in `monitor.c` — fixmap-phys translation pending).  The IDT
snapshot still runs and integrity checks will resume once the fixmap
→ real-phys path ships.

## Alert type IDs (ring buffer wire format)

Used by `agent/linux/ghostring-agent --monitor`:

| ID | Symbol                        | Emitted by               |
|----|-------------------------------|--------------------------|
| 1  | `msr_write`                   | msr_guard                |
| 2  | `ept_write_violation`         | monitor / integrity      |
| 3  | `idt_hook`                    | hooks                    |
| 4  | `ssdt_hook`                   | ssdt                     |
| 5  | `cr_write`                    | cr_guard                 |
| 6  | `ransomware_canary`           | ransomware               |
| 7  | `rop_violation`               | shadow_stack             |
| 8  | `code_inject`                 | code_inject              |
| 9  | `integrity_crc_mismatch`      | integrity                |
| 10 | `dkom_hidden_cr3`             | dkom                     |

Other IDs (0, 11+) are reserved for forward-compat; the agent maps
them to the generic `other` label.

## What is *not* in scope for GhostRing

- Firmware attacks (SMM, UEFI firmware rootkits) — requires Intel
  BootGuard / TXT, out of Ring -1 reach.
- Network-only threats (phishing, DNS poisoning) — handled upstream
  by NDR / EDR sensors.
- Account-based lateral movement — handled by IAM / SIEM layers.

Everything above is explicitly *not* claimed; the detectors table is
exhaustive for the 19 slots.
