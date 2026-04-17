# Contributing to GhostRing

Thank you for your interest in GhostRing. Contributions are welcome.

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-change`
3. Make your changes
4. Run the tests: `cd tests && make run`
5. Submit a pull request

## Code Style

- C99, freestanding (no stdlib in `src/`)
- 4-space indentation, no tabs
- Function names: `gr_subsystem_action()` (e.g., `gr_vmx_setup_vmcs()`)
- Constants: `UPPER_SNAKE_CASE`
- Types: `gr_type_name_t`
- Every file starts with the license header
- Comments explain *why*, not *what*
- Reference Intel SDM / AMD APM section numbers for VMX/SVM code

## Architecture Rules

- `src/common/` — no OS-specific code, no `#include <linux/...>`
- `src/vmx/` — Intel VT-x only
- `src/svm/` — AMD-V only
- `src/monitor/` — architecture-independent security logic
- `loader/` — OS-specific code (Linux kmod, Windows KMDF, UEFI)
- Platform abstraction via `platform.h` callbacks

## Testing

- Unit tests in `tests/` run in userspace (no VT-x needed)
- Integration tests require QEMU with nested VT-x or bare metal
- All PRs must pass `make -C tests run` before merge

## What We Need Help With

- AMD-V testing on real hardware (Zen 3/4/5)
- Windows driver testing and WHQL preparation
- UEFI loader development (EDK2)
- Additional detection modules for the monitor
- Documentation and tutorials
- Performance benchmarking

## Security

If you find a security vulnerability, please email bauratynov@gmail.com
directly instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed
under the license that applies to the directory you are modifying:

- **Apache-2.0** for `src/`, `agent/`, `tests/`, `loader/windows/`, `loader/uefi/`
- **GPL-2.0-only** for `loader/linux/` (required by the Linux kernel)

See the project [LICENSE](LICENSE) index for the full per-subsystem map.
New files must carry an `SPDX-License-Identifier` header matching their
subsystem.
