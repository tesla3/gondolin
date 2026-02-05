.PHONY: build build-bins build-inner test clean run assets qemu lint typecheck format

RUN_PARALLEL ?= ../scripts/run-parallel

ZIG ?= zig
OPTIMIZE ?= ReleaseSmall
TSX ?= ../host/node_modules/.bin/tsx
GONDOLIN ?= $(TSX) ../host/bin/gondolin.ts
GONDOLIN_BUILD_CONFIG ?=
GONDOLIN_BUILD_EXTRA_ARGS ?=

ZIG_SOURCES := $(shell find src -name '*.zig') build.zig
ZIG_BUILD_DEPS := $(ZIG_SOURCES) build.zig.zon
IMAGE_BUILD_DEPS := image/build.sh image/init image/initramfs-init
HOST_BUILD_DEPS := $(shell find ../host/src ../host/bin -name '*.ts') ../host/package.json ../host/tsconfig.json
GONDOLIN_CONFIG_DEP := $(if $(strip $(GONDOLIN_BUILD_CONFIG)),$(GONDOLIN_BUILD_CONFIG))
BUILD_DEPS := $(ZIG_BUILD_DEPS) $(IMAGE_BUILD_DEPS) $(HOST_BUILD_DEPS) $(GONDOLIN_CONFIG_DEP)

IMAGE_OUT ?= ./image/out
IMAGE_INITRAMFS ?= $(IMAGE_OUT)/initramfs.cpio.lz4
IMAGE_ROOTFS ?= $(IMAGE_OUT)/rootfs.ext4
KERNEL ?= $(IMAGE_OUT)/vmlinuz-virt

HOST_ARCH := $(shell uname -m)
HOST_OS := $(shell uname -s)
ifeq ($(HOST_OS),Darwin)
  ifeq ($(HOST_ARCH),x86_64)
    ifeq ($(shell sysctl -n hw.optional.arm64 2>/dev/null),1)
      HOST_ARCH := arm64
    endif
  endif
endif

ifeq ($(HOST_ARCH),arm64)
DEFAULT_ARCH := aarch64
DEFAULT_QEMU := qemu-system-aarch64
else ifeq ($(HOST_ARCH),aarch64)
DEFAULT_ARCH := aarch64
DEFAULT_QEMU := qemu-system-aarch64
else
DEFAULT_ARCH := x86_64
DEFAULT_QEMU := qemu-system-x86_64
endif

ALPINE_ARCH ?= $(DEFAULT_ARCH)
ifeq ($(ALPINE_ARCH),arm64)
ALPINE_ARCH := aarch64
endif
QEMU ?= $(DEFAULT_QEMU)
QEMU_MACHINE :=
ifeq ($(ALPINE_ARCH),aarch64)
QEMU_MACHINE := -machine virt
endif

GONDOLIN_BUILD_ARGS = --output $(IMAGE_OUT) --arch $(ALPINE_ARCH)
GONDOLIN_BUILD_ARGS += $(if $(strip $(GONDOLIN_BUILD_CONFIG)),--config $(GONDOLIN_BUILD_CONFIG),)
GONDOLIN_BUILD_ARGS += $(GONDOLIN_BUILD_EXTRA_ARGS)

QEMU_MEMORY ?= 256M
ifeq ($(ALPINE_ARCH),aarch64)
QEMU_MEMORY ?= 512M
endif
QEMU_SMP ?= 2
QEMU_SERIAL ?= stdio
QEMU_WAIT ?= on
VIRTIO_SOCK ?= $(IMAGE_OUT)/virtio.sock

build:
	@$(RUN_PARALLEL) -j 1 \
		"guest:build" "$(MAKE) assets"

build-bins:
	@$(RUN_PARALLEL) -j 1 \
		"guest:build" "$(MAKE) build-inner"

build-inner:
	$(ZIG) build -Doptimize=$(OPTIMIZE)

run: build-bins
	./zig-out/bin/sandboxd

assets: $(IMAGE_INITRAMFS) $(IMAGE_ROOTFS) $(KERNEL)

$(IMAGE_INITRAMFS) $(IMAGE_ROOTFS) $(KERNEL): $(BUILD_DEPS)
	$(GONDOLIN) build $(GONDOLIN_BUILD_ARGS)

qemu: assets
	@rm -f $(VIRTIO_SOCK)
	$(QEMU) $(QEMU_MACHINE) \
		-nodefaults -no-reboot -m $(QEMU_MEMORY) -smp $(QEMU_SMP) \
		-kernel $(KERNEL) \
		-initrd $(IMAGE_INITRAMFS) \
		-drive file=$(IMAGE_ROOTFS),format=raw,if=none,id=drive0,snapshot=on \
		-device virtio-blk-pci,drive=drive0 \
		-append "console=ttyS0 initramfs_async=1" \
		-nographic \
		-serial $(QEMU_SERIAL) \
		-object rng-random,filename=/dev/urandom,id=rng0 \
		-device virtio-rng-pci,rng=rng0 \
		-chardev socket,id=virtiocon0,path=$(VIRTIO_SOCK),server=on,wait=$(QEMU_WAIT) \
		-device virtio-serial-pci \
		-device virtserialport,chardev=virtiocon0,name=virtio-port

format:
	$(ZIG) fmt $(ZIG_SOURCES)

lint:
	$(ZIG) fmt --check $(ZIG_SOURCES)

typecheck: build-bins


test: assets
	$(ZIG) build test-bins -Doptimize=$(OPTIMIZE)
	$(TSX) ../host/bin/guest-tests.ts

clean:
	@rm -rf zig-cache zig-out $(IMAGE_OUT)
