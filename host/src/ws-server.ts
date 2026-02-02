import fs from "fs";
import net from "net";
import path from "path";

import { WebSocketServer, WebSocket } from "ws";

import {
  FrameReader,
  IncomingMessage,
  buildExecRequest,
  buildStdinData,
  decodeMessage,
  encodeFrame,
} from "./virtio-protocol";
import {
  ClientMessage,
  ErrorMessage,
  ExecCommandMessage,
  StdinCommandMessage,
  encodeOutputFrame,
  ServerMessage,
} from "./ws-protocol";
import { SandboxController, SandboxConfig } from "./sandbox-controller";

type Args = {
  host: string;
  port: number;
  qemuPath: string;
  kernelPath: string;
  initrdPath: string;
  memory: string;
  cpus: number;
  virtioSocketPath: string;
  machineType?: string;
  accel?: string;
  cpu?: string;
  console?: "stdio" | "none";
  token?: string;
  autoRestart: boolean;
};

function parseArgs(argv: string[]): Args {
  const repoRoot = path.resolve(__dirname, "../..");
  const defaultKernel = path.resolve(repoRoot, "guest/image/out/vmlinuz-virt");
  const defaultInitrd = path.resolve(repoRoot, "guest/image/out/initramfs.cpio.gz");
  const defaultVirtio = path.resolve(repoRoot, "tmp/virtio.sock");

  const args: Args = {
    host: "127.0.0.1",
    port: 8080,
    qemuPath: "qemu-system-x86_64",
    kernelPath: defaultKernel,
    initrdPath: defaultInitrd,
    memory: "256M",
    cpus: 1,
    virtioSocketPath: defaultVirtio,
    autoRestart: true,
  };

  const fail = (message: string): never => {
    console.error(message);
    usage();
    process.exit(1);
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case "--host":
        args.host = argv[++i] ?? args.host;
        break;
      case "--port":
        args.port = Number(argv[++i]);
        if (!Number.isFinite(args.port)) fail("--port must be a number");
        break;
      case "--qemu":
        args.qemuPath = argv[++i];
        break;
      case "--kernel":
        args.kernelPath = argv[++i];
        break;
      case "--initrd":
        args.initrdPath = argv[++i];
        break;
      case "--memory":
        args.memory = argv[++i];
        break;
      case "--cpus":
        args.cpus = Number(argv[++i]);
        if (!Number.isFinite(args.cpus)) fail("--cpus must be a number");
        break;
      case "--virtio-sock":
        args.virtioSocketPath = argv[++i];
        break;
      case "--machine":
        args.machineType = argv[++i];
        break;
      case "--accel":
        args.accel = argv[++i];
        break;
      case "--cpu":
        args.cpu = argv[++i];
        break;
      case "--console":
        args.console = argv[++i] === "none" ? "none" : "stdio";
        break;
      case "--token":
        args.token = argv[++i];
        break;
      case "--no-restart":
        args.autoRestart = false;
        break;
      case "--help":
      case "-h":
        usage();
        process.exit(0);
      default:
        fail(`Unknown argument: ${arg}`);
    }
  }

  return args;
}

function usage() {
  console.log("Usage: node dist/ws-server.js [options]");
  console.log("Options:");
  console.log("  --host HOST          Host to bind (default 127.0.0.1)");
  console.log("  --port PORT          Port to bind (default 8080)");
  console.log("  --qemu PATH          QEMU binary (default qemu-system-x86_64)");
  console.log("  --kernel PATH        Kernel path");
  console.log("  --initrd PATH        Initrd path");
  console.log("  --memory SIZE        Memory size (default 256M)");
  console.log("  --cpus N             vCPU count (default 1)");
  console.log("  --virtio-sock PATH   Virtio serial socket path");
  console.log("  --machine TYPE       Override QEMU machine type");
  console.log("  --accel TYPE         Override QEMU accel (kvm/hvf/tcg)");
  console.log("  --cpu TYPE           Override QEMU CPU type");
  console.log("  --console stdio|none Console output");
  console.log("  --token TOKEN        Require token in Authorization header");
  console.log("  --no-restart          Disable auto restart on exit");
}

class VirtioBridge {
  private socket: net.Socket | null = null;
  private readonly reader = new FrameReader();
  private reconnectTimer: NodeJS.Timeout | null = null;
  private pending: Buffer[] = [];
  private pendingBytes = 0;
  private waitingDrain = false;

  constructor(
    private readonly socketPath: string,
    private readonly maxPendingBytes: number = 8 * 1024 * 1024
  ) {}

  connect() {
    if (this.socket) return;
    if (!fs.existsSync(path.dirname(this.socketPath))) {
      fs.mkdirSync(path.dirname(this.socketPath), { recursive: true });
    }

    const socket = net.createConnection({ path: this.socketPath });
    this.socket = socket;
    this.waitingDrain = false;

    socket.on("connect", () => {
      this.flushPending();
    });

    socket.on("data", (chunk) => {
      this.reader.push(chunk, (frame) => {
        try {
          const message = decodeMessage(frame) as IncomingMessage;
          this.onMessage?.(message);
        } catch (err) {
          this.onError?.(err);
          this.handleDisconnect();
        }
      });
    });

    socket.on("error", () => {
      this.handleDisconnect();
    });

    socket.on("end", () => {
      this.handleDisconnect();
    });
  }

  disconnect() {
    if (this.socket) {
      this.socket.end();
      this.socket = null;
    }
    this.waitingDrain = false;
  }

  send(message: object): boolean {
    const frame = encodeFrame(message);
    if (this.pending.length === 0 && !this.waitingDrain) {
      return this.writeFrame(frame);
    }
    const queued = this.queueFrame(frame);
    if (queued && this.socket && this.socket.writable && !this.waitingDrain) {
      this.flushPending();
    }
    return queued;
  }

  onMessage?: (message: IncomingMessage) => void;
  onError?: (error: unknown) => void;

  private writeFrame(frame: Buffer): boolean {
    if (!this.socket || !this.socket.writable) {
      return this.queueFrame(frame);
    }
    const ok = this.socket.write(frame);
    if (!ok) {
      this.waitingDrain = true;
      this.socket.once("drain", () => {
        this.waitingDrain = false;
        this.flushPending();
      });
    }
    return true;
  }

  private queueFrame(frame: Buffer): boolean {
    if (this.pendingBytes + frame.length > this.maxPendingBytes) {
      return false;
    }
    this.pending.push(frame);
    this.pendingBytes += frame.length;
    return true;
  }

  private flushPending() {
    if (!this.socket || this.waitingDrain || !this.socket.writable) return;
    while (this.pending.length > 0) {
      const frame = this.pending.shift()!;
      this.pendingBytes -= frame.length;
      const ok = this.writeFrame(frame);
      if (!ok || this.waitingDrain) return;
    }
  }

  private handleDisconnect() {
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }
    this.waitingDrain = false;
    if (this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, 500);
  }
}

const MAX_REQUEST_ID = 0xffffffff;
const MAX_JSON_BYTES = 256 * 1024;
const MAX_STDIN_BYTES = 64 * 1024;

function isValidRequestId(value: unknown): value is number {
  return Number.isInteger(value) && value >= 0 && value <= MAX_REQUEST_ID;
}

function estimateBase64Bytes(value: string) {
  const len = value.length;
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  return Math.floor((len * 3) / 4) - padding;
}

function validateToken(headers: Record<string, string | string[] | undefined>, token?: string) {
  if (!token) return true;
  const headerToken = headers["x-elwing-token"] ?? headers["x-sandbox-token"];
  if (typeof headerToken === "string" && headerToken === token) return true;
  if (Array.isArray(headerToken) && headerToken.includes(token)) return true;
  const auth = headers.authorization;
  if (typeof auth === "string" && auth.startsWith("Bearer ")) {
    return auth.slice("Bearer ".length) === token;
  }
  return false;
}

function safeSend(
  ws: WebSocket,
  data: string | Buffer,
  options?: { binary?: boolean }
): boolean {
  if (ws.readyState !== WebSocket.OPEN) return false;
  try {
    ws.send(data, options);
    return true;
  } catch {
    return false;
  }
}

function sendJson(ws: WebSocket, message: ServerMessage): boolean {
  return safeSend(ws, JSON.stringify(message));
}

function sendBinary(ws: WebSocket, data: Buffer): boolean {
  return safeSend(ws, data, { binary: true });
}

function sendError(ws: WebSocket, error: ErrorMessage): boolean {
  return sendJson(ws, error);
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const token = args.token ?? process.env.ELWING_TOKEN ?? process.env.SANDBOX_WS_TOKEN;

  const sandboxConfig: SandboxConfig = {
    qemuPath: args.qemuPath,
    kernelPath: args.kernelPath,
    initrdPath: args.initrdPath,
    memory: args.memory,
    cpus: args.cpus,
    virtioSocketPath: args.virtioSocketPath,
    append: "console=ttyS0",
    machineType: args.machineType,
    accel: args.accel,
    cpu: args.cpu,
    console: args.console,
    autoRestart: args.autoRestart,
  };

  const controller = new SandboxController(sandboxConfig);
  const bridge = new VirtioBridge(args.virtioSocketPath);
  const inflight = new Map<number, WebSocket>();
  const stdinAllowed = new Set<number>();

  let wss: WebSocketServer | null = null;

  const failInflight = (code: string, message: string) => {
    for (const [id, client] of inflight.entries()) {
      sendError(client, {
        type: "error",
        id,
        code,
        message,
      });
    }
    inflight.clear();
    stdinAllowed.clear();
  };

  controller.on("state", (state) => {
    if (state === "stopped") {
      failInflight("sandbox_stopped", "sandbox is not running");
    }

    if (!wss) return;
    for (const client of wss.clients) {
      sendJson(client, { type: "status", state });
    }
  });

  controller.on("exit", () => {
    failInflight("sandbox_stopped", "sandbox exited");
  });

  controller.on("log", (line: string) => {
    process.stdout.write(`[qemu] ${line}`);
  });

  bridge.onMessage = (message) => {
    if (!isValidRequestId(message.id)) {
      return;
    }

    if (message.t === "exec_output") {
      const client = inflight.get(message.id);
      if (!client) return;
      const data = message.p.data;
      try {
        if (!sendBinary(client, encodeOutputFrame(message.id, message.p.stream, data))) {
          inflight.delete(message.id);
          stdinAllowed.delete(message.id);
        }
      } catch {
        inflight.delete(message.id);
        stdinAllowed.delete(message.id);
      }
    } else if (message.t === "exec_response") {
      const client = inflight.get(message.id);
      if (client) {
        sendJson(client, {
          type: "exec_response",
          id: message.id,
          exit_code: message.p.exit_code,
          signal: message.p.signal,
        });
      }
      inflight.delete(message.id);
      stdinAllowed.delete(message.id);
    } else if (message.t === "error") {
      const client = inflight.get(message.id);
      if (client) {
        sendError(client, {
          type: "error",
          id: message.id,
          code: message.p.code,
          message: message.p.message,
        });
      }
      inflight.delete(message.id);
      stdinAllowed.delete(message.id);
    }
  };

  bridge.onError = (err) => {
    const message = err instanceof Error ? err.message : "unknown error";
    console.error(`[virtio] decode error: ${message}`);
    failInflight("protocol_error", "virtio decode error");
  };

  wss = new WebSocketServer({
    host: args.host,
    port: args.port,
    maxPayload: MAX_JSON_BYTES,
    verifyClient: (info, done) => {
      if (!validateToken(info.req.headers, token)) {
        done(false, 401, "Unauthorized");
        return;
      }
      done(true);
    },
  });

  wss.on("connection", (ws) => {
    if (!sendJson(ws, { type: "status", state: controller.getState() })) {
      ws.close();
      return;
    }

    ws.on("message", (data, isBinary) => {
      if (isBinary) {
        sendError(ws, {
          type: "error",
          code: "invalid_message",
          message: "binary input frames are not supported",
        });
        return;
      }

      const size = typeof data === "string" ? Buffer.byteLength(data) : data.length;
      if (size > MAX_JSON_BYTES) {
        sendError(ws, {
          type: "error",
          code: "payload_too_large",
          message: "message exceeds size limit",
        });
        return;
      }

      let message: ClientMessage;
      try {
        message = JSON.parse(data.toString()) as ClientMessage;
      } catch {
        sendError(ws, {
          type: "error",
          code: "invalid_json",
          message: "failed to parse JSON",
        });
        return;
      }

      if (message.type === "exec") {
        handleExec(ws, message, inflight, stdinAllowed, bridge);
      } else if (message.type === "stdin") {
        handleStdin(ws, message, inflight, stdinAllowed, bridge);
      } else if (message.type === "lifecycle") {
        if (message.action === "restart") {
          void controller.restart();
        } else if (message.action === "shutdown") {
          void controller.stop();
        }
      } else {
        sendError(ws, {
          type: "error",
          code: "unknown_type",
          message: "unsupported message type",
        });
      }
    });

    ws.on("close", () => {
      for (const [id, client] of inflight.entries()) {
        if (client === ws) {
          inflight.delete(id);
          stdinAllowed.delete(id);
        }
      }
    });
  });

  void controller.start();
  bridge.connect();

  console.log(`WebSocket server listening on ws://${args.host}:${args.port}`);

  const shutdown = async () => {
    await controller.stop();
    wss?.close();
    bridge.disconnect();
    process.exit(0);
  };

  process.on("SIGINT", () => {
    void shutdown();
  });

  process.on("SIGTERM", () => {
    void shutdown();
  });
}

function handleExec(
  ws: WebSocket,
  message: ExecCommandMessage,
  inflight: Map<number, WebSocket>,
  stdinAllowed: Set<number>,
  bridge: VirtioBridge
) {
  if (!isValidRequestId(message.id) || !message.cmd) {
    sendError(ws, {
      type: "error",
      code: "invalid_request",
      message: "exec requires uint32 id and cmd",
    });
    return;
  }

  if (inflight.has(message.id)) {
    sendError(ws, {
      type: "error",
      id: message.id,
      code: "duplicate_id",
      message: "request id already in use",
    });
    return;
  }

  inflight.set(message.id, ws);
  if (message.stdin) stdinAllowed.add(message.id);

  const payload = {
    cmd: message.cmd,
    argv: message.argv ?? [],
    env: message.env ?? [],
    cwd: message.cwd,
    stdin: message.stdin ?? false,
  };

  if (!bridge.send(buildExecRequest(message.id, payload))) {
    inflight.delete(message.id);
    stdinAllowed.delete(message.id);
    sendError(ws, {
      type: "error",
      id: message.id,
      code: "queue_full",
      message: "virtio bridge queue exceeded",
    });
  }
}

function handleStdin(
  ws: WebSocket,
  message: StdinCommandMessage,
  inflight: Map<number, WebSocket>,
  stdinAllowed: Set<number>,
  bridge: VirtioBridge
) {
  if (!isValidRequestId(message.id)) {
    sendError(ws, {
      type: "error",
      code: "invalid_request",
      message: "stdin requires a uint32 id",
    });
    return;
  }

  if (!inflight.has(message.id)) {
    sendError(ws, {
      type: "error",
      id: message.id,
      code: "unknown_id",
      message: "request id not found",
    });
    return;
  }

  if (!stdinAllowed.has(message.id)) {
    sendError(ws, {
      type: "error",
      id: message.id,
      code: "stdin_disabled",
      message: "stdin was not enabled for this request",
    });
    return;
  }

  const base64 = message.data ?? "";
  if (base64 && estimateBase64Bytes(base64) > MAX_STDIN_BYTES) {
    sendError(ws, {
      type: "error",
      id: message.id,
      code: "payload_too_large",
      message: "stdin chunk exceeds size limit",
    });
    return;
  }

  const data = base64 ? Buffer.from(base64, "base64") : Buffer.alloc(0);
  if (data.length > MAX_STDIN_BYTES) {
    sendError(ws, {
      type: "error",
      id: message.id,
      code: "payload_too_large",
      message: "stdin chunk exceeds size limit",
    });
    return;
  }

  if (!bridge.send(buildStdinData(message.id, data, message.eof))) {
    sendError(ws, {
      type: "error",
      id: message.id,
      code: "queue_full",
      message: "virtio bridge queue exceeded",
    });
  }
}

main();
