# Gondolin VM Analysis

*Date: 2026-02-17*

## Machine Overview

This is a lightweight microVM — a sandboxed virtual machine created by the Gondolin project. We are running *inside* the VM it builds.

### OS & Kernel

| Property | Value |
|---|---|
| **OS** | Alpine Linux v3.23 |
| **Kernel** | Linux 6.18.9-0-virt (x86_64, SMP PREEMPT_DYNAMIC) |
| **Built** | 2026-02-09, GCC 15.2.0 |
| **Machine type** | QEMU Q35 + ICH9 (virtual) |
| **Init** | Custom `/init` shell script → launches `sandboxd` (PID 1) |

### CPU

| Property | Value |
|---|---|
| **vCPUs** | 2 cores (Intel family 6 model 126, ~1.1 GHz) |
| **Features** | SSE4.2, AVX2, AVX-512 (F/BW/VL/DQ/CD/IFMA/VBMI), SHA-NI, AES-NI |
| **Hypervisor** | Yes — running under a hypervisor (likely macOS HVF/QEMU from the host) |

### Memory

| Property | Value |
|---|---|
| **Total RAM** | ~972 MB |
| **Used** | ~72 MB |
| **Available** | ~824 MB |
| **Swap** | None |

### Storage & Filesystems

| Mount | Type | Size | Used | Notes |
|---|---|---|---|---|
| `/` | ext4 (`/dev/vda`) | 269 MB | 184 MB (70%) | Root ramdisk (initramfs-based) |
| `/data` | **sandboxfs** (FUSE) | 234 GB | 111 GB | Host filesystem passthrough |
| `/workspace` | **sandboxfs** (FUSE) | 234 GB | 111 GB | Gondolin repo, bind-mounted from host |
| `/etc/gondolin` | **sandboxfs** (FUSE) | 64 GB | 0 | VM config (contains `listeners`) |
| `/etc/ssl/certs` | **sandboxfs** (FUSE) | 64 GB | 0 | SSL certs from host |
| `/tmp`, `/root`, `/var/*` | tmpfs | ~486 MB each | ~0 | Ephemeral in-memory |

### Networking

| Interface | Address |
|---|---|
| `lo` | 127.0.0.1/8 |
| `eth0` | 192.168.127.3/24 (MAC: 02:00:00:00:00:01) |

### Key Processes

| PID | Process | Role |
|---|---|---|
| 1 | `/usr/bin/sandboxd` | Init/supervisor daemon (Zig binary, 114 KB) |
| 568 | `/usr/bin/sandboxfs` | FUSE filesystem — bridges host FS via virtio-ports |
| 580 | `/usr/bin/sandboxssh` | SSH server for host↔guest communication |
| 581 | `/usr/bin/sandboxingress` | Ingress/networking handler |
| 533 | `rngd` | Hardware RNG daemon (`/dev/hwrng` → `/dev/random`) |

All four `sandbox*` binaries are small static Zig executables (50–114 KB).

### Installed Software

| Tool | Version |
|---|---|
| **Node.js** | v24.13.0 |
| **npm** | 11.6.3 |
| **Python** | 3.12.12 |
| **BusyBox** | 1.37.0 (provides most UNIX utilities) |

No `zig`, `gcc`, `make`, `git`, or `pnpm` installed inside the VM.

### Architecture Diagram

```
┌─────────────────────────────────────────────┐
│  macOS Host (Intel, /Users/hua)             │
│  ├── Ghostty terminal → tmux → pi agent    │
│  ├── QEMU/HVF hypervisor                   │
│  └── Gondolin host controller (TypeScript)  │
│       │ virtio-ports                        │
│       ▼                                     │
│  ┌──────────────────────────────────────┐   │
│  │  Gondolin microVM (this machine)     │   │
│  │  Alpine Linux 3.23, 2 vCPU, 1GB RAM │   │
│  │  PID 1: sandboxd (Zig)              │   │
│  │  sandboxfs (FUSE) ←→ host filesystem │   │
│  │  sandboxssh ← host SSH access       │   │
│  │  /workspace = host repo mount        │   │
│  └──────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

---

## How the Host Environment Was Deduced

Everything outside the VM was inferred from evidence found *inside* it.

### 1. macOS Host

Environment variables leaked from the host into the VM:
- `HOME=/Users/hua` — `/Users` is the macOS home directory convention (Linux uses `/home`)
- `TMPDIR=/var/folders/vk/...` — macOS's per-user temp directory structure
- `SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.*` — `com.apple.launchd` is an Apple service
- `__CFBundleIdentifier=com.mitchellh.ghostty` — Core Foundation is a macOS framework
- `XPC_SERVICE_NAME`, `XPC_FLAGS` — XPC is a macOS IPC mechanism

### 2. Ghostty Terminal

Environment variables injected by Ghostty survived into the VM:
- `GHOSTTY_BIN_DIR=/Applications/Ghostty.app/Contents/MacOS`
- `GHOSTTY_RESOURCES_DIR=...`
- `GHOSTTY_SHELL_FEATURES=cursor,path,title`
- `__CFBundleIdentifier=com.mitchellh.ghostty`

### 3. tmux

- `TMUX=/private/tmp/tmux-501/default,42322,0` — tmux session info
- `TMUX_PANE=%2`
- `TERM_PROGRAM=tmux`, `TERM_PROGRAM_VERSION=3.6a`
- `TERM=tmux-256color`

### 4. QEMU/HVF Hypervisor

- `dmesg` output: `DMI: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.17.0-...` — directly identifies QEMU with Q35 chipset
- CPU flags include `hypervisor` — the CPU advertises it's virtualized
- HVF (Hypervisor.framework) inferred: macOS host + QEMU = HVF for hardware acceleration (KVM is Linux-only; AGENTS.md also mentions "macOS HVF")

### 5. Gondolin Host Controller (TypeScript)

From project context (AGENTS.md and the repo in `/workspace`):
- `host/` directory contains "TypeScript host controller, networking stack, VFS, and CLI"
- Running processes (`sandboxd`, `sandboxfs`, `sandboxssh`, `sandboxingress`) are the Zig guest binaries from `guest/`
- `sandboxfs` args (`--rpc-path /dev/virtio-ports/virtio-fs`) confirm virtio communication with the host controller

### 6. Intel CPU

- `vendor_id: GenuineIntel`, `cpu family: 6, model: 126` from `/proc/cpuinfo`
- Host Mac has an Intel CPU (not Apple Silicon — if M-series, the VM would be aarch64, not x86_64)

---

**Summary:** The VM didn't sanitize its environment variables, so the host's macOS/Ghostty/tmux context leaked through. QEMU identified itself in DMI/BIOS strings via `dmesg`. The Gondolin architecture came from the project's documentation plus running processes.
