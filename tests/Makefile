# GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# tests/Makefile — Build and run userspace unit tests.
#
# Usage:
#   make            Build all tests
#   make run        Build and run all tests
#   make clean      Remove test binaries

CC      := gcc
CFLAGS  := -Wall -Wextra -Werror -std=c99 -O2 -g
CFLAGS  += -I../src/common -DTEST_USERSPACE

TESTS   := test_allocator test_integrity test_dkom test_vmcs_segment test_hypercall_ids test_alert_ring test_msr_bitmap test_ept_indices test_crc32c_polynomial test_platform_abi test_vmcs_encodings test_allocator_stress test_rflags test_mtrr_types test_exit_reasons test_selector_encoding test_dkom_generation test_adjust_controls

.PHONY: all run clean

all: $(TESTS)

run: $(TESTS)
	@echo "==============================="
	@echo " GhostRing Unit Tests"
	@echo "==============================="
	@failed=0; \
	for t in $(TESTS); do \
		echo ""; \
		./$$t || failed=$$((failed + 1)); \
	done; \
	echo ""; \
	echo "===============================" ; \
	if [ $$failed -gt 0 ]; then \
		echo " $$failed test suite(s) FAILED"; \
		exit 1; \
	else \
		echo " All test suites PASSED"; \
	fi

test_allocator: test_allocator.c ../src/common/mem.c
	$(CC) $(CFLAGS) -o $@ $^

test_integrity: test_integrity.c
	$(CC) $(CFLAGS) -msse4.2 -o $@ $<

test_dkom: test_dkom.c
	$(CC) $(CFLAGS) -o $@ $<

test_vmcs_segment: test_vmcs_segment.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TESTS)
