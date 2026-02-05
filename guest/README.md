# Gondolin Guest Sandbox

This directory contains the guest-side components for the Gondolin sandbox: the
Zig `sandboxd` supervisor, the Alpine initramfs image builder, and helper
tooling to boot the micro-VM under QEMU.

## What it does

- Builds `sandboxd`, a tiny supervisor that listens on a virtio-serial port for
  exec requests, spawns processes inside the guest, and streams
  stdout/stderr/stdin over the wire.
- Assembles a minimal Alpine initramfs with `sandboxd`, an init script, and
  optional packages for networking and certificates.

## Layout

- `src/sandboxd/` — Zig sources for `sandboxd` and exec RPC handling.
- `src/sandboxfs/` — Zig sources for the FUSE filesystem daemon.
- `src/shared/` — Shared CBOR/protocol/RPC helpers.
- `image/` — initramfs build scripts and the minimal `/init`.
- `build.zig` — Zig build definition for `sandboxd`.
- `Makefile` — helpers to build, create images, and run QEMU.

## Requirements

| macOS | Linux (Debian/Ubuntu) |
|-------|----------------------|
| `brew install zig lz4 e2fsprogs` | `sudo apt install zig lz4 cpio curl e2fsprogs` |

The `make build` target invokes the shared `gondolin build` pipeline through
the host CLI. Make sure host Node dependencies are installed (e.g., `pnpm install`
at the repo root or `pnpm -C host install`).

## Common tasks

Mandatory build command (builds kernel, initramfs, and rootfs without booting):

```sh
make build
```

Build `sandboxd` only:

```sh
make build-bins
```

Build guest assets using a custom build config:

```sh
make build GONDOLIN_BUILD_CONFIG=../build-config.json
```

`make build` invokes the shared `gondolin build` pipeline and will produce all
assets in `image/out/`.

Boot the guest under QEMU (builds assets if needed):

```sh
make qemu
```

The QEMU target creates a virtio-serial socket at `image/out/virtio.sock` for
the host controller to connect.
