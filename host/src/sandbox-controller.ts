import { EventEmitter } from "events";
import { spawn, ChildProcess } from "child_process";
import fs from "fs";

export type SandboxConfig = {
  qemuPath: string;
  kernelPath: string;
  initrdPath: string;
  memory: string;
  cpus: number;
  virtioSocketPath: string;
  append: string;
  machineType?: string;
  accel?: string;
  cpu?: string;
  console?: "stdio" | "none";
  netSocketPath?: string;
  netMac?: string;
  autoRestart: boolean;
};

export type SandboxState = "starting" | "running" | "stopped";

export class SandboxController extends EventEmitter {
  private child: ChildProcess | null = null;
  private state: SandboxState = "stopped";
  private restartTimer: NodeJS.Timeout | null = null;
  private manualStop = false;

  constructor(private readonly config: SandboxConfig) {
    super();
  }

  getState() {
    return this.state;
  }

  async start() {
    if (this.child) return;

    this.manualStop = false;
    this.setState("starting");

    const args = buildQemuArgs(this.config);
    this.child = spawn(this.config.qemuPath, args, {
      stdio: ["ignore", "pipe", "pipe"],
    });

    this.child.stdout?.on("data", (chunk) => {
      this.emit("log", chunk.toString());
    });

    this.child.stderr?.on("data", (chunk) => {
      this.emit("log", chunk.toString());
    });

    this.child.on("spawn", () => {
      this.setState("running");
    });

    this.child.on("exit", (code, signal) => {
      this.child = null;
      this.setState("stopped");
      this.emit("exit", { code, signal });
      if (this.manualStop) {
        this.manualStop = false;
        return;
      }
      if (this.config.autoRestart) {
        this.scheduleRestart();
      }
    });
  }

  async stop() {
    if (!this.child) return;
    const child = this.child;
    this.child = null;
    this.manualStop = true;

    if (this.restartTimer) {
      clearTimeout(this.restartTimer);
      this.restartTimer = null;
    }

    child.kill("SIGTERM");
    await new Promise<void>((resolve) => {
      const timeout = setTimeout(() => {
        child.kill("SIGKILL");
      }, 3000);
      child.once("exit", () => {
        clearTimeout(timeout);
        resolve();
      });
    });

    this.setState("stopped");
  }

  async restart() {
    await this.stop();
    await this.start();
  }

  private scheduleRestart() {
    if (this.restartTimer) return;
    this.restartTimer = setTimeout(() => {
      this.restartTimer = null;
      void this.start();
    }, 1000);
  }

  private setState(state: SandboxState) {
    if (this.state === state) return;
    this.state = state;
    this.emit("state", state);
  }
}

function buildQemuArgs(config: SandboxConfig) {
  const args: string[] = [
    "-nodefaults",
    "-no-reboot",
    "-m",
    config.memory,
    "-smp",
    String(config.cpus),
    "-kernel",
    config.kernelPath,
    "-initrd",
    config.initrdPath,
    "-append",
    config.append,
    "-nographic",
  ];

  const targetArch = detectTargetArch(config);
  const machineType = config.machineType ?? selectMachineType(targetArch);
  args.push("-machine", machineType);

  const accel = config.accel ?? selectAccel();
  if (accel) args.push("-accel", accel);

  const cpu = config.cpu ?? selectCpu();
  if (cpu) args.push("-cpu", cpu);

  if (config.console === "none") {
    args.push("-serial", "none");
  } else {
    args.push("-serial", "stdio");
  }

  args.push("-object", "rng-random,filename=/dev/urandom,id=rng0");
  args.push("-device", "virtio-rng-pci,rng=rng0");
  args.push(
    "-chardev",
    `socket,id=virtiocon0,path=${config.virtioSocketPath},server=off`
  );

  args.push("-device", "virtio-serial-pci,id=virtio-serial0");
  args.push(
    "-device",
    "virtserialport,chardev=virtiocon0,name=virtio-port,bus=virtio-serial0.0"
  );

  if (config.netSocketPath) {
    args.push(
      "-netdev",
      `stream,id=net0,server=off,addr.type=unix,addr.path=${config.netSocketPath}`
    );
    const mac = config.netMac ?? "02:00:00:00:00:01";
    args.push("-device", `virtio-net-pci,netdev=net0,mac=${mac}`);
  }

  return args;
}

function detectTargetArch(config: SandboxConfig): string {
  const qemuPath = config.qemuPath.toLowerCase();
  if (qemuPath.includes("aarch64") || qemuPath.includes("arm64")) {
    return "arm64";
  }
  if (qemuPath.includes("x86_64") || qemuPath.includes("x64")) {
    return "x64";
  }
  return process.arch;
}

function selectMachineType(targetArch: string) {
  if (process.platform === "linux" && targetArch === "x64") {
    return "microvm";
  }
  if (targetArch === "arm64") {
    return "virt";
  }
  return "q35";
}

function selectAccel() {
  if (process.platform === "linux") return "kvm";
  if (process.platform === "darwin") return "hvf";
  return "tcg";
}

function selectCpu() {
  if (process.platform === "linux" || process.platform === "darwin") {
    return "host";
  }
  return "max";
}
