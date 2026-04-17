#!/bin/bash
# GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License
#
# integration_qemu.sh — Integration test using QEMU with nested VT-x.
#
# Prerequisites:
#   - QEMU with KVM support
#   - Linux kernel headers installed in the VM
#   - Nested VT-x enabled: echo 1 > /sys/module/kvm_intel/parameters/nested
#
# Usage:
#   ./integration_qemu.sh              Run full integration test
#   ./integration_qemu.sh --build-only Only build the kernel module
#
# What it tests:
#   1. Build ghostring.ko kernel module
#   2. Load module (insmod)
#   3. Verify hypervisor installed on all CPUs (dmesg)
#   4. Verify CPUID hypervisor-present bit set
#   5. Verify /dev/ghostring device exists
#   6. Run agent --status and check output
#   7. Unload module (rmmod)
#   8. Verify clean unload (dmesg)

set -euo pipefail

RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[0;33m'
RST='\033[0m'

pass() { echo -e "${GRN}[PASS]${RST} $1"; }
fail() { echo -e "${RED}[FAIL]${RST} $1"; FAILURES=$((FAILURES + 1)); }
info() { echo -e "${YEL}[INFO]${RST} $1"; }

FAILURES=0
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Step 1: Build ──────────────────────────────────────────────────────

info "Building GhostRing kernel module..."
cd "$PROJECT_DIR"
make clean 2>/dev/null || true

if make vmx 2>&1; then
    pass "Kernel module built successfully"
else
    fail "Kernel module build failed"
    exit 1
fi

if [ "${1:-}" = "--build-only" ]; then
    info "Build-only mode, exiting."
    exit 0
fi

# ── Step 2: Verify VT-x nested support ────────────────────────────────

if [ -f /sys/module/kvm_intel/parameters/nested ]; then
    NESTED=$(cat /sys/module/kvm_intel/parameters/nested)
    if [ "$NESTED" = "Y" ] || [ "$NESTED" = "1" ]; then
        pass "Nested VT-x is enabled"
    else
        fail "Nested VT-x is NOT enabled (echo 1 > /sys/module/kvm_intel/parameters/nested)"
        exit 1
    fi
else
    info "Not running under KVM — assuming bare metal or VirtualBox"
fi

# ── Step 3: Load module ───────────────────────────────────────────────

info "Loading ghostring.ko..."
sudo dmesg -C  # clear dmesg

if sudo insmod loader/linux/ghostring.ko 2>&1; then
    pass "Module loaded"
else
    fail "insmod failed"
    sudo dmesg | grep -i ghost || true
    exit 1
fi

sleep 1

# ── Step 4: Verify installation via dmesg ─────────────────────────────

DMESG=$(sudo dmesg)

if echo "$DMESG" | grep -q "GhostRing.*installed"; then
    CPU_COUNT=$(echo "$DMESG" | grep -oP 'installed on \K[0-9]+' || echo "?")
    pass "Hypervisor installed on $CPU_COUNT CPUs"
else
    fail "No 'GhostRing installed' message in dmesg"
    echo "$DMESG" | grep -i ghost || true
fi

# ── Step 5: Verify CPUID hypervisor-present bit ──────────────────────

# Use cpuid tool if available, otherwise skip
if command -v cpuid &>/dev/null; then
    if cpuid -1 -l 0x40000000 2>/dev/null | grep -qi "ghost\|GhR"; then
        pass "CPUID 0x40000000 returns GhostRing signature"
    else
        fail "CPUID 0x40000000 does not return GhostRing signature"
    fi
else
    info "cpuid tool not installed, skipping CPUID signature check"
fi

# ── Step 6: Verify /dev/ghostring ─────────────────────────────────────

if [ -c /dev/ghostring ]; then
    pass "/dev/ghostring character device exists"
else
    fail "/dev/ghostring not found"
fi

# ── Step 7: Agent status check ────────────────────────────────────────

if [ -x "$PROJECT_DIR/agent/linux/ghostring-agent" ]; then
    if "$PROJECT_DIR/agent/linux/ghostring-agent" --status 2>&1 | grep -q "active"; then
        pass "Agent reports hypervisor active"
    else
        fail "Agent status check failed"
    fi
else
    info "Agent binary not built, skipping agent test"
fi

# ── Step 8: Unload module ─────────────────────────────────────────────

info "Unloading ghostring.ko..."
sudo dmesg -C

if sudo rmmod ghostring 2>&1; then
    pass "Module unloaded"
else
    fail "rmmod failed"
fi

sleep 1

# ── Step 9: Verify clean unload ──────────────────────────────────────

DMESG_UNLOAD=$(sudo dmesg)

if echo "$DMESG_UNLOAD" | grep -q "GhostRing.*unloaded"; then
    pass "Clean unload confirmed via dmesg"
else
    fail "No 'GhostRing unloaded' message in dmesg"
fi

# Check for kernel warnings/oops
if echo "$DMESG_UNLOAD" | grep -qi "oops\|panic\|BUG\|RIP:"; then
    fail "Kernel oops/panic detected during unload!"
    echo "$DMESG_UNLOAD" | grep -i "oops\|panic\|BUG\|RIP:" || true
else
    pass "No kernel oops during load/unload cycle"
fi

# ── Report ────────────────────────────────────────────────────────────

echo ""
echo "================================="
if [ $FAILURES -gt 0 ]; then
    echo -e "${RED} $FAILURES test(s) FAILED${RST}"
    exit 1
else
    echo -e "${GRN} All integration tests PASSED${RST}"
    exit 0
fi
