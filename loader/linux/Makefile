# GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com>
# SPDX-License-Identifier: GPL-2.0-only
#
# Out-of-tree kernel module build for GhostRing hypervisor loader.
#
# Usage:
#   make                 — build against running kernel
#   make KDIR=/path/to   — build against specific kernel source
#   make clean           — remove build artifacts

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

obj-m := ghostring.o

#
# Relative paths for kbuild.  Kbuild parses obj-m entries relative
# to the directory containing this Makefile (what we pass as M=).
# So we use ../../src/... paths — kbuild resolves them internally.
#
ghostring-objs := ghostring_kmod.o \
                  ghostring_chardev.o \
                  ../../src/common/globals.o \
                  ../../src/common/serial.o \
                  ../../src/common/mem.o \
                  ../../src/common/glue.o \
                  ../../src/vmx/vmx_vmcs.o \
                  ../../src/vmx/vmx_ept.o \
                  ../../src/vmx/vmx_exit.o \
                  ../../src/vmx/vmx_asm.o \
                  ../../src/monitor/monitor.o \
                  ../../src/monitor/integrity.o \
                  ../../src/monitor/msr_guard.o \
                  ../../src/monitor/dkom.o \
                  ../../src/monitor/hooks.o \
                  ../../src/monitor/ssdt.o \
                  ../../src/monitor/driver_obj.o \
                  ../../src/monitor/code_inject.o \
                  ../../src/monitor/ransomware.o \
                  ../../src/monitor/cr_guard.o \
                  ../../src/monitor/shadow_stack.o \
                  ../../src/hypercall/hypercall.o

ccflags-y := -I$(src)/../../src \
             -I$(src)/../../src/common \
             -I$(src)/../../src/vmx \
             -I$(src)/../../src/svm \
             -I$(src)/../../src/monitor \
             -I$(src)/../../src/hypercall \
             -DGHOSTRING_VTX=1 \
             -DGHOSTRING_SVM=0 \
             -Wno-declaration-after-statement \
             -Wno-unused-function

AFLAGS_vmx_asm.o := -D__ASSEMBLY__

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	find ../../src -name '*.o' -delete 2>/dev/null || true

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

.PHONY: all clean install
