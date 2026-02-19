C_COMPILER     ?= gcc
BUILD_TYPE     ?= Release
INSTALL_PREFIX ?= /usr/local
CFLAGS         ?= -Wextra -Wall -Wpedantic
TARGET_ARCH    ?=
EXTRA_CFLAGS   ?=
HCC_BIN        ?= ./hcc

default: all

.PHONY: all aarch64-sweep aarch64-sweep-assemble aarch64-op-audit aarch64-verify

# To add sqlite3 support add -DHCC_LINK_SQLITE3=1 to the below like so:
#```
#all:
#	cmake -S ./src -B ./build -G 'Unix Makefiles' \
#		-DCMAKE_C_COMPILER=$(_C_COMPILER) \
#		-DCMAKE_BUILD_TYPE=$(_BUILD_TYPE) \
#		-DHCC_LINK_SQLITE3=1 \
#		&& $(MAKE) -C ./build -j2
#```

# Cross-compile for aarch64 (requires aarch64-linux-gnu-gcc):
#   make C_COMPILER=aarch64-linux-gnu-gcc TARGET_ARCH=aarch64 clean all
all:
	cmake -S ./src \
		-B ./build \
		-G 'Unix Makefiles' \
		-DCMAKE_C_COMPILER=$(C_COMPILER) \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DCMAKE_INSTALL_PREFIX=$(INSTALL_PREFIX) \
		-DCMAKE_C_FLAGS="$(CFLAGS) $(EXTRA_CFLAGS)" \
		&& $(MAKE) -C ./build -j2

install:
	$(MAKE) -C ./build install

unit-test:
	$(MAKE) -C ./build unit-test

aarch64-sweep:
	HCC_BIN=$(HCC_BIN) ./scripts/aarch64-sweep.sh

aarch64-sweep-assemble:
	HCC_BIN=$(HCC_BIN) HCC_AARCH64_ASSEMBLE=1 ./scripts/aarch64-sweep.sh

aarch64-op-audit:
	HCC_BIN=$(HCC_BIN) ./scripts/aarch64-opcode-audit.sh

aarch64-verify:
	HCC_BIN=$(HCC_BIN) HCC_AARCH64_ASSEMBLE=1 ./scripts/aarch64-sweep.sh
	HCC_BIN=$(HCC_BIN) HCC_AARCH64_ASSEMBLE=1 HCC_ENABLE_SQLITE_TEST=1 ./scripts/aarch64-sweep.sh
	HCC_BIN=$(HCC_BIN) ./scripts/aarch64-opcode-audit.sh
	HCC_BIN=$(HCC_BIN) HCC_ENABLE_SQLITE_TEST=1 ./scripts/aarch64-opcode-audit.sh

clean:
	rm -rf ./build ./hcc
