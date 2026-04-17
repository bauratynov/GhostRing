# GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License
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

TESTS   := test_allocator test_integrity test_dkom

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

clean:
	rm -f $(TESTS)
