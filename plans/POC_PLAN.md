# POC Plan (Option B)

Goal: Prove a minimal QEMU micro‑VM can boot and execute commands via a structured RPC, using a tiny guest daemon (C/Zig).

## Scope (POC)
- Boot Alpine guest with custom init.
- Start a minimal `sandboxd` (C or Zig) as PID 1 (or from init).
- Host controller launches QEMU and communicates over virtio‑serial.
- Support a single RPC method: `exec` (cmd, argv, env, cwd).
- Stream stdout/stderr and return exit code to host.
- Add host‑controlled networking via a transparent proxy that re‑encrypts SSL.
- No FUSE, no persistence.

## Deliverables
- Guest image build script (Alpine base) with `sandboxd`.
- Host controller CLI that:
  - starts VM
  - sends exec RPC
  - prints outputs
- Simple protocol spec document (length‑prefixed frames).
- Latency measurements (boot time + exec time).

## Steps
1) **Define RPC framing**
   - Length‑prefixed frames over virtio‑serial.
   - Minimal message types: `exec_request`, `exec_output`, `exec_response` (stream output + completion).
   - Include: request id, command string, argv array, env array (`KEY=VALUE`), cwd.
   - **POC constraint:** only one in‑flight exec; `id` is used to assert this and reject concurrent requests.

2) **Guest: `sandboxd`**
   - Implement in C or Zig.
   - Reads frames from `/dev/vport0p0` (virtio‑serial).
   - Spawns process via `fork/exec`.
   - Captures stdout/stderr (pipes).
   - Sends `exec_output` frames for stdout/stderr as they happen, then `exec_response` with exit code.

3) **Guest image build**
   - Alpine rootfs.
   - Init launches `sandboxd`.
   - Install minimal busybox tools for testing.

4) **Host controller**
   - Spawn QEMU with:
     - virtio‑serial device
     - minimal rootfs
     - console output to stdio/log
   - Connect to virtio‑serial and send one exec.

5) **POC verification**
   - Run `echo hello` and `ls /`.
   - Validate outputs and exit codes.

6) **Measure**
   - Log VM boot time and exec latency.

7) **Host controller (WebSocket API + lifecycle)**
   - Manage QEMU sandbox lifecycle (spawn, monitor, restart, shutdown).
   - Detect host OS and prefer `microvm` machine type when supported; fall back to `q35`/`virt`.
   - Define optimal QEMU flags for Linux vs macOS (accel, CPU, RNG, virtio‑serial, console).
   - Expose a WebSocket server for exec streaming (stdin/out + status).
   - Define message schema (JSON control + binary output frames).
   - Support multiple concurrent execs via request ids.
   - Add auth/ACL hook (token header) for elwing integration.
   - Add tests: open WS, run `echo hello`, stream stdout, receive exit status.

8) **Networking via transparent proxy (host‑controlled)**
   - Add a host‑side transparent HTTP(S) proxy that intercepts guest egress.
   - Configure QEMU user‑mode networking or tap/bridge to route guest traffic through the proxy.
   - Ensure the proxy terminates TLS and re‑encrypts to the destination.
   - Provide a guest trust chain (custom CA) so HTTPS validation succeeds.
   - Define policy knobs (allowed hosts, logging, optional mTLS).
   - Add a test: guest can `curl https://example.com` and traffic is visible in proxy logs.

## Success Criteria
- Host CLI can boot VM and run at least 2 commands.
- RPC round‑trip works reliably.
- Binary size of guest daemon is minimal.
