# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.

PREFIX  ?= /usr/local
VERSION := $(shell cat pkgIndex.tcl | grep -F 'package ifneeded tconfig ' | awk '{print $$4}')
INSTALL_DIR = $(PREFIX)/lib/tconfig$(VERSION)
WORKING_DIR_ABSOLUTE = $(shell pwd)

override TESTFLAGS += -verbose "body error start"

TCLSH ?= tclsh
TCLSH_EXE = TCLLIBPATH="$(WORKING_DIR_ABSOLUTE)" $(TCLSH)

.PHONY: all
all: install

.PHONY: install
install:
	mkdir -vp "$(INSTALL_DIR)"
	cp -vf LICENSE pkgIndex.tcl "$(INSTALL_DIR)"
	mkdir -vp "$(INSTALL_DIR)"/tcl
	cp -vfr tcl/* "$(INSTALL_DIR)"/tcl

.PHONY: test
test:
	$(TCLSH_EXE) tests/all.tcl $(TESTFLAGS)

.PHONY: example
example:
	$(TCLSH_EXE) examples/example1.tcl