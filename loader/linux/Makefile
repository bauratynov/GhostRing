# GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License
#
# Out-of-tree kernel module build for GhostRing hypervisor loader.
#
# Usage:
#   make                 — build against running kernel
#   make KDIR=/path/to   — build against specific kernel source
#   make clean           — remove build artifacts

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
SRC  := $(src)/../../src

obj-m := ghostring.o

# Object files — must match actual source file names
ghostring-objs := ghostring_kmod.o \
                  ghostring_chardev.o \
                  $(SRC)/common/globals.o \
                  $(SRC)/common/serial.o \
                  $(SRC)/common/mem.o \
                  $(SRC)/common/glue.o \
                  $(SRC)/vmx/vmx_vmcs.o \
                  $(SRC)/vmx/vmx_ept.o \
                  $(SRC)/vmx/vmx_exit.o \
                  $(SRC)/vmx/vmx_asm.o \
                  $(SRC)/monitor/monitor.o \
                  $(SRC)/monitor/integrity.o \
                  $(SRC)/monitor/msr_guard.o \
                  $(SRC)/monitor/dkom.o \
                  $(SRC)/monitor/hooks.o \
                  $(SRC)/monitor/ssdt.o \
                  $(SRC)/monitor/driver_obj.o \
                  $(SRC)/monitor/code_inject.o \
                  $(SRC)/monitor/ransomware.o \
                  $(SRC)/monitor/cr_guard.o \
                  $(SRC)/monitor/shadow_stack.o \
                  $(SRC)/hypercall/hypercall.o

# Include paths for all subsystem headers
ccflags-y := -I$(src)/../../src \
             -I$(src)/../../src/common \
             -I$(src)/../../src/vmx \
             -I$(src)/../../src/svm \
             -I$(src)/../../src/monitor \
             -I$(src)/../../src/hypercall \
             -DGHOSTRING_VTX=1 \
             -DGHOSTRING_SVM=0 \
             -std=gnu99 \
             -Wno-declaration-after-statement

# Assembly files need gas syntax flag
AFLAGS_vmx_asm.o := -D__ASSEMBLY__

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	find $(SRC) -name '*.o' -delete

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

.PHONY: all clean install
