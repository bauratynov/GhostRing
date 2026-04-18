# Building the Windows driver

Applies to `loader/windows/` — the KMDF-style driver that will
eventually be the Windows counterpart of the Linux loader.  v0.1.0
ships the source but **no pre-built `.sys`** — Windows kernel-mode
code cannot be loaded on a stock machine without a Microsoft-signed
binary.

## Prerequisites

- Windows 10/11 Pro or Enterprise on the build box.
- **Visual Studio 2022** (Community is fine) with the "Desktop
  development with C++" workload.
- **Windows Driver Kit (WDK) 10.0.22621** or newer.  Must be the
  same major version as your Visual Studio install.
- **Windows SDK** matching the WDK version.
- `signtool.exe` (ships with the SDK) for test-signing.
- **Enable Test Signing mode** on the machine where the driver is
  loaded:
  ```
  bcdedit /set testsigning on
  shutdown /r /t 0
  ```
  This is reversible (`bcdedit /set testsigning off`) and confined
  to the test VM — not a production operation.

## Build steps

The `loader/windows/` tree expects a `.vcxproj` generated inside
Visual Studio.  First-time setup:

1. Open VS 2022 → New Project → Kernel Mode Driver (KMDF) →
   "WDM Driver, Empty".  Name it `ghostring`.
2. Delete the auto-generated template files — keep only the
   `.vcxproj` and `.sln`.
3. Add existing items:
   - `loader/windows/ghostring_drv.c`
   - `loader/windows/ghostring_win.h`
   - `loader/windows/ghostring_winasm.asm`
4. Add reference to the core tree:
   - Project → Properties → C/C++ → General → Additional Include
     Directories → `..\..\src\common;..\..\src\vmx`
5. Add the VMX core sources (project → Add existing item):
   - `src/vmx/vmx_vmcs.c`, `vmx_ept.c`, `vmx_exit.c`
   - `src/monitor/*.c` (all 15 detector sources)
   - `src/common/globals.c`, `glue.c`, `serial.c`
6. Project → Properties → Driver Settings → Target OS Version →
   "Windows 10" (Win11 also works).
7. Build configuration: **x64 / Release**.

The output goes to `x64/Release/ghostring.sys` plus `.pdb`, `.inf`
(a generated copy), and `.cat`.

## Test-signing the driver

After the first successful build:

```
# One-time: create a self-signed test cert
MakeCert -r -pe -ss PrivateCertStore -n "CN=GhostRing Test" ghostring.cer

# Sign the .sys
signtool sign /v /fd SHA256 /s PrivateCertStore /n "GhostRing Test" \
  /t http://timestamp.digicert.com x64\Release\ghostring.sys

# Build the catalog so the .inf can reference it
Inf2Cat /v /driver:x64\Release /os:10_x64

# Sign the catalog as well
signtool sign /v /fd SHA256 /s PrivateCertStore /n "GhostRing Test" \
  /t http://timestamp.digicert.com x64\Release\ghostring.cat
```

## Installing and loading

On the target VM (with test-signing enabled, see above):

```
:: Copy ghostring.sys, ghostring.inf, ghostring.cat into a folder.
:: Then from an admin cmd in that folder:

sc create GhostRing type= kernel binPath= "C:\path\to\ghostring.sys"
sc start GhostRing

:: Check load status
sc query GhostRing
```

To unload (v0.1.0 has the same devirt-NYI caveat as Linux — expect
a BSoD; power-cycle the VM):

```
sc stop GhostRing
sc delete GhostRing
```

## WHQL / production signing

For general-public deployment, the driver must be:

1. **Attestation-signed** via the Hardware Dev Center (Partner
   Center) — free, requires the `.sys` to be submitted and
   cross-signed by Microsoft's attestation service.  No hardware
   lab testing involved.
2. OR **WHQL-certified** via the HLK (Hardware Lab Kit) — mandatory
   for driver classes that need EV certification.  Paid via an EV
   (Extended Validation) code-signing certificate from a CA like
   DigiCert / Sectigo (~$400/yr).

GhostRing's target customers in v0.3 will prefer attestation-signed
(cheaper, faster) for internal deployment.  WHQL is deferred to v1.0.

## Relationship to the .inf

`loader/windows/ghostring.inf` is the installation manifest.  It
declares:

- `Class = System` / `ClassGuid = {4D36E97D-...}` — registers us
  under "System devices" in Device Manager.
- `ServiceType = 1` (SERVICE_KERNEL_DRIVER).
- `StartType = 3` (SERVICE_DEMAND_START) — we load on demand via
  `sc start`, not automatically at boot.  v0.2+ may switch to
  `StartType = 0` (SERVICE_BOOT_START) once we have the UEFI
  loader to verify our integrity before Windows boot.

### Missing for production — tracked in roadmap

- [ ] `PnpLockdown = 1` stanza (required by Windows 10 1709+ DCH).
- [ ] Separate `Manufacturer` + `Models.NTamd64` sections so
      Device Manager shows a proper friendly name.
- [ ] Localised `DisplayName` (RU/KZ/EN) for regional deployment.

These are noted but deliberately deferred — v0.1 is not an
end-user installable driver yet, only a developer artefact.
