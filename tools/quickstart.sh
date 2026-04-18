#!/usr/bin/env bash
# GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# tools/quickstart.sh — One-command onboarding for GhostRing evaluators.
#
# Run this inside a fresh Debian 13 / Ubuntu 22.04 VM with Intel VT-x:
#
#   curl -sSL https://raw.githubusercontent.com/bauratynov/GhostRing/master/tools/quickstart.sh \
#        | bash
#
# It performs ONLY the safe, reversible steps:
#
#   1. Checks that your CPU supports VT-x and the BIOS has enabled it.
#   2. Installs the 4 build dependencies.
#   3. Clones the repo into the current directory.
#   4. Builds the kernel module AND the userspace agent.
#   5. Runs the 18/18 userspace unit tests.
#   6. Prints the exact next command to load GhostRing on this host.
#
# It does NOT insmod the module — that is your decision.

set -euo pipefail

BOLD=$(tput bold 2>/dev/null || printf '')
RESET=$(tput sgr0 2>/dev/null || printf '')
RED=$(tput setaf 1 2>/dev/null || printf '')
GREEN=$(tput setaf 2 2>/dev/null || printf '')
YELLOW=$(tput setaf 3 2>/dev/null || printf '')

say()   { printf "${BOLD}==>${RESET} %s\n" "$*"; }
okay()  { printf "    ${GREEN}✓${RESET} %s\n" "$*"; }
warn()  { printf "    ${YELLOW}!${RESET} %s\n" "$*"; }
die()   { printf "    ${RED}✗${RESET} %s\n" "$*" >&2; exit 1; }

# ── Step 1: sanity-check the CPU & BIOS ────────────────────────────
say "Checking CPU virtualization support"

vendor=$(grep -m1 'vendor_id' /proc/cpuinfo | awk '{print $NF}')
if [[ "$vendor" != "GenuineIntel" ]]; then
    warn "Non-Intel CPU detected ($vendor). GhostRing v0.1 targets Intel VT-x."
    warn "The AMD-V backend compiles but is untested — proceeding anyway."
fi

if grep -qE '^flags.*\bvmx\b' /proc/cpuinfo; then
    okay "CPU advertises VMX"
else
    die "CPU does not advertise VMX — enable VT-x in BIOS/UEFI and retry."
fi

# ── Step 2: install build dependencies ─────────────────────────────
say "Installing build dependencies"

missing=()
for pkg in build-essential "linux-headers-$(uname -r)" git gcc make; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        missing+=("$pkg")
    fi
done

if (( ${#missing[@]} > 0 )); then
    sudo apt-get update -qq
    sudo apt-get install -y "${missing[@]}"
    okay "Installed ${#missing[@]} package(s): ${missing[*]}"
else
    okay "All build dependencies already present"
fi

# ── Step 3: clone GhostRing ────────────────────────────────────────
say "Cloning GhostRing"

if [[ -d GhostRing/.git ]]; then
    okay "Existing checkout found — pulling latest"
    (cd GhostRing && git pull --ff-only)
else
    git clone --depth 1 https://github.com/bauratynov/GhostRing.git
    okay "Cloned https://github.com/bauratynov/GhostRing.git"
fi
cd GhostRing

# ── Step 4: build kernel module + agent ────────────────────────────
say "Building ghostring.ko"
make -C loader/linux -s
okay "loader/linux/ghostring.ko ($(stat -c%s loader/linux/ghostring.ko) bytes)"

say "Building ghostring-agent"
make -C agent/linux -s
okay "agent/linux/ghostring-agent ($(stat -c%s agent/linux/ghostring-agent) bytes)"

# ── Step 5: run userspace unit tests ───────────────────────────────
say "Running unit tests"
make -C tests run 2>&1 | tail -20

# ── Step 6: print next-step recipe ────────────────────────────────
say "Build complete.  Next steps (you must run these manually):"
cat <<EOF

    # Pre-requisite kernel dependencies:
    sudo modprobe crc32c libcrc32c

    # First, prime the CPU's VMX state (one-time dance required
    # under Hyper-V nested VT-x — no-op on bare metal).  Skip if
    # you are on bare metal.
    sudo modprobe kvm_intel && sudo rmmod kvm_intel kvm irqbypass

    # Load GhostRing (single-CPU mode for a clean serial log):
    sudo insmod ./loader/linux/ghostring.ko allow_nested=1 single_cpu=1

    # Verify:
    dmesg | tail -12
    lsmod | grep ghostring
    ls /dev/ghostring

    # Query status via the agent:
    sudo ./agent/linux/ghostring-agent --status
    sudo ./agent/linux/ghostring-agent --json --monitor

    # NOTE: \`rmmod ghostring\` is NOT SUPPORTED in v0.1.0 — it
    # panics the guest.  Power-cycle the VM to reload.

    Full walkthrough: docs/DEMO.md
    All documentation: docs/ directory
    Commercial licensing: bauratynov@gmail.com

EOF
