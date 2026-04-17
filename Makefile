# GhostRing — Hypervisor-based endpoint security
# Author: Baurzhan Atynov <bauratynov@gmail.com>
# License: MIT

KDIR       ?= /lib/modules/$(shell uname -r)/build
MODULE_DIR  = loader/linux
CC          = gcc
CFLAGS_BASE = -std=c99 -Wall -Wextra -Werror -ffreestanding -nostdlib \
              -mno-red-zone -mcmodel=kernel -fno-stack-protector

# ─── CPU detection ───────────────────────────────────────────────────
VENDOR := $(shell grep -m1 vendor_id /proc/cpuinfo 2>/dev/null | awk '{print $$NF}')

ifeq ($(VENDOR),GenuineIntel)
  DEFAULT_TARGET = vmx
else ifeq ($(VENDOR),AuthenticAMD)
  DEFAULT_TARGET = svm
else
  DEFAULT_TARGET = vmx
endif

# ─── Targets ─────────────────────────────────────────────────────────
.PHONY: all vmx svm module clean test

all: $(DEFAULT_TARGET)
	@echo "[GhostRing] Built for $(DEFAULT_TARGET) (detected: $(VENDOR))"

vmx: CFLAGS = $(CFLAGS_BASE) -DGHOSTRI_NG_VTX
vmx: module
	@echo "[GhostRing] Intel VT-x build complete"

svm: CFLAGS = $(CFLAGS_BASE) -DGHOSTRI_NG_SVM
svm: module
	@echo "[GhostRing] AMD-V build complete"

module:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/$(MODULE_DIR) \
		EXTRA_CFLAGS="$(CFLAGS)" modules

# ─── Clean ───────────────────────────────────────────────────────────
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/$(MODULE_DIR) clean
	find . -name '*.o' -o -name '*.ko' -o -name '*.mod*' \
		-o -name '.*.cmd' -o -name 'modules.order' \
		-o -name 'Module.symvers' | xargs rm -f
	rm -rf .tmp_versions
	@echo "[GhostRing] Clean complete"

# ─── Test ────────────────────────────────────────────────────────────
test:
	@echo "[GhostRing] Running unit tests..."
	$(MAKE) -C tests run
	@echo "[GhostRing] All tests passed"
