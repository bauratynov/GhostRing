## Summary

One or two lines on what this PR changes and why.

## Change class

- [ ] Detector — new or improved
- [ ] Loader / platform glue (Linux / Windows / UEFI)
- [ ] Hypervisor core (VMX / VMCS / EPT / exit handling)
- [ ] Userspace agent
- [ ] Tests
- [ ] Documentation only

## Licensing

- [ ] New source files carry the correct `SPDX-License-Identifier`
      for their subsystem (Apache-2.0 for everything except
      `loader/linux/` which is GPL-2.0-only).

## Testing

- [ ] `make -C tests run` passes locally.
- [ ] `make -C loader/linux` produces `ghostring.ko`.
- [ ] If the PR touches the VM-exit path, a serial-log transcript
      of a live load is attached.

## Related issue / milestone

`Closes #` / `Roadmap v0.x`
