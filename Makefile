C_COMPILER     ?= gcc
BUILD_TYPE     ?= Release
INSTALL_PREFIX ?= /usr/local
CFLAGS         ?= -Wextra -Wall -Wpedantic
TARGET_ARCH    ?=
EXTRA_CFLAGS   ?=

default: all

.PHONY: all aarch64-sweep

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
	./scripts/aarch64-sweep.sh

clean:
	rm -rf ./build ./hcc
