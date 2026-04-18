# GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# agent/linux/Makefile — Build the Linux userspace agent.
#
# Usage:
#   make              Build ghostring-agent
#   make install      Install to /usr/local/bin (requires root)
#   make clean

CC      := gcc
CFLAGS  := -Wall -Wextra -Werror -std=c99 -O2 -g
LDFLAGS :=

BIN   := ghostring-agent
SRC   := ghostring_agent.c

.PHONY: all install clean

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)/usr/local/bin/$(BIN)

clean:
	rm -f $(BIN)
