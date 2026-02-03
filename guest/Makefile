.PHONY: build build-inner test clean run image image-inner kernel kernel-inner qemu lint typecheck format

RUN_PARALLEL ?= ../scripts/run-parallel

ZIG ?= zig
OPTIMIZE ?= ReleaseSmall
TSX ?= ../host/node_modules/.bin/tsx

ZIG_SOURCES := $(shell find src -name '*.zig') build.zig
ZIG_BUILD_DEPS := $(ZIG_SOURCES) build.zig.zon

IMAGE_SCRIPT ?= ./image/build.sh
IMAGE_OUT ?= ./image/out
IMAGE_INITRAMFS ?= $(IMAGE_OUT)/initramfs.cpio.gz
IMAGE_INIT ?= ./image/init
SANDBOXD_BIN ?= $(CURDIR)/zig-out/bin/sandboxd

ALPINE_BRANCH ?= v3.20
ALPINE_MIRROR ?= https://dl-cdn.alpinelinux.org/alpine
KERNEL_PKG ?= linux-virt
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
QEMU ?= $(DEFAULT_QEMU)
QEMU_MACHINE ?=
MITM_CA_CERT ?= $(abspath $(CURDIR)/../host/var/mitm/ca.crt)
MITM_CA_CERT_PATH := $(wildcard $(MITM_CA_CERT))
ifeq ($(ALPINE_ARCH),aarch64)
QEMU_MACHINE ?= -machine virt
endif

QEMU_MEMORY ?= 256M
ifeq ($(ALPINE_ARCH),aarch64)
QEMU_MEMORY ?= 512M
endif
QEMU_SMP ?= 1
QEMU_SERIAL ?= stdio
QEMU_WAIT ?= on
VIRTIO_SOCK ?= $(IMAGE_OUT)/virtio.sock

build:
	@$(RUN_PARALLEL) -j 1 \
		"guest:build" "$(MAKE) build-inner"

build-inner:
	$(ZIG) build -Doptimize=$(OPTIMIZE)

run: build
	./zig-out/bin/sandboxd

$(SANDBOXD_BIN): $(ZIG_BUILD_DEPS)
	$(ZIG) build -Doptimize=$(OPTIMIZE)

$(IMAGE_INITRAMFS): $(SANDBOXD_BIN) $(SANDBOXFS_BIN) $(IMAGE_SCRIPT) $(IMAGE_INIT) $(MITM_CA_CERT_PATH)
	ARCH=$(ALPINE_ARCH) MITM_CA_CERT=$(MITM_CA_CERT) $(IMAGE_SCRIPT)

image:
	@$(RUN_PARALLEL) -j 1 \
		"guest:image" "$(MAKE) image-inner"

image-inner: $(IMAGE_INITRAMFS)

kernel:
	@$(RUN_PARALLEL) -j 1 \
		"guest:kernel" "$(MAKE) kernel-inner"

kernel-inner:
	@set -e; \
		mkdir -p $(IMAGE_OUT); \
		if [ -f "$(KERNEL)" ]; then \
			echo "Kernel already present at $(KERNEL)"; \
			exit 0; \
		fi; \
		echo "Fetching $(KERNEL_PKG) from Alpine $(ALPINE_BRANCH) ($(ALPINE_ARCH))"; \
		index_url=$(ALPINE_MIRROR)/$(ALPINE_BRANCH)/main/$(ALPINE_ARCH)/APKINDEX.tar.gz; \
		if [ ! -f "$(IMAGE_OUT)/APKINDEX.tar.gz" ]; then \
			echo "Downloading $$index_url"; \
			curl -L -o "$(IMAGE_OUT)/APKINDEX.tar.gz" "$$index_url"; \
		fi; \
		tar -xzf "$(IMAGE_OUT)/APKINDEX.tar.gz" -C "$(IMAGE_OUT)" APKINDEX; \
		ver=$$(awk '/^P:$(KERNEL_PKG)$$/{p=1} p&&/^V:/{print substr($$0,3); exit}' "$(IMAGE_OUT)/APKINDEX"); \
		rm -f "$(IMAGE_OUT)/APKINDEX"; \
		if [ -z "$$ver" ]; then \
			echo "failed to determine $(KERNEL_PKG) version" >&2; \
			exit 1; \
		fi; \
		apk_url="$(ALPINE_MIRROR)/$(ALPINE_BRANCH)/main/$(ALPINE_ARCH)/$(KERNEL_PKG)-$$ver.apk"; \
		echo "Downloading $$apk_url"; \
		curl -L -o "$(IMAGE_OUT)/$(KERNEL_PKG).apk" "$$apk_url"; \
		tar -xzf "$(IMAGE_OUT)/$(KERNEL_PKG).apk" -C "$(IMAGE_OUT)" boot/vmlinuz-virt; \
		mv "$(IMAGE_OUT)/boot/vmlinuz-virt" "$(KERNEL)"; \
		rm -rf "$(IMAGE_OUT)/boot"

qemu: image kernel
	@rm -f $(VIRTIO_SOCK)
	$(QEMU) $(QEMU_MACHINE) \
		-nodefaults -no-reboot -m $(QEMU_MEMORY) -smp $(QEMU_SMP) \
		-kernel $(KERNEL) \
		-initrd $(IMAGE_INITRAMFS) \
		-append "console=ttyS0" \
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

typecheck: build


test: image kernel
	$(ZIG) build test-bins -Doptimize=$(OPTIMIZE)
	$(TSX) ../host/bin/guest-tests.ts

clean:
	rm -rf zig-cache zig-out
