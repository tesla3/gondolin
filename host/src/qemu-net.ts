import { EventEmitter } from "events";
import net from "net";
import fs from "fs";
import path from "path";
import dgram from "dgram";

import {
  NetworkStack,
  TcpCloseMessage,
  TcpConnectMessage,
  TcpPauseMessage,
  TcpResumeMessage,
  TcpSendMessage,
  UdpSendMessage,
} from "./network-stack";

type UdpSession = {
  socket: dgram.Socket;
  srcIP: string;
  srcPort: number;
  dstIP: string;
  dstPort: number;
};

type TcpSession = {
  socket: net.Socket;
  srcIP: string;
  srcPort: number;
  dstIP: string;
  dstPort: number;
  flowControlPaused: boolean;
};

export type QemuNetworkOptions = {
  socketPath: string;
  gatewayIP?: string;
  vmIP?: string;
  gatewayMac?: Buffer;
  vmMac?: Buffer;
  debug?: boolean;
};

export class QemuNetworkBackend extends EventEmitter {
  private server: net.Server | null = null;
  private socket: net.Socket | null = null;
  private waitingDrain = false;
  private stack: NetworkStack | null = null;
  private readonly udpSessions = new Map<string, UdpSession>();
  private readonly tcpSessions = new Map<string, TcpSession>();

  constructor(private readonly options: QemuNetworkOptions) {
    super();
  }

  start() {
    if (this.server) return;

    if (!fs.existsSync(path.dirname(this.options.socketPath))) {
      fs.mkdirSync(path.dirname(this.options.socketPath), { recursive: true });
    }
    fs.rmSync(this.options.socketPath, { force: true });

    this.server = net.createServer((socket) => this.attachSocket(socket));
    this.server.on("error", (err) => this.emit("error", err));
    this.server.listen(this.options.socketPath);
  }

  stop() {
    this.detachSocket();
    if (this.server) {
      this.server.close();
      this.server = null;
    }
  }

  private attachSocket(socket: net.Socket) {
    if (this.socket) this.socket.destroy();
    this.socket = socket;
    this.waitingDrain = false;

    this.resetStack();

    socket.on("data", (chunk) => {
      this.stack?.writeToNetwork(chunk);
      this.flush();
    });

    socket.on("drain", () => {
      this.waitingDrain = false;
      this.flush();
    });

    socket.on("error", (err) => {
      this.emit("error", err);
      this.detachSocket();
    });

    socket.on("close", () => {
      this.detachSocket();
    });
  }

  private detachSocket() {
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }
    this.waitingDrain = false;
    this.cleanupSessions();
    this.stack?.reset();
  }

  private resetStack() {
    this.cleanupSessions();

    this.stack = new NetworkStack({
      gatewayIP: this.options.gatewayIP,
      vmIP: this.options.vmIP,
      gatewayMac: this.options.gatewayMac,
      vmMac: this.options.vmMac,
      callbacks: {
        onUdpSend: (message) => this.handleUdpSend(message),
        onTcpConnect: (message) => this.handleTcpConnect(message),
        onTcpSend: (message) => this.handleTcpSend(message),
        onTcpClose: (message) => this.handleTcpClose(message),
        onTcpPause: (message) => this.handleTcpPause(message),
        onTcpResume: (message) => this.handleTcpResume(message),
      },
    });

    this.stack.on("network-activity", () => this.flush());
    this.stack.on("error", (err) => this.emit("error", err));
    if (this.options.debug) {
      this.stack.on("dhcp", (state, ip) => {
        this.emit("log", `[net] dhcp ${state} ${ip}`);
      });
    }
  }

  private flush() {
    if (!this.socket || this.waitingDrain || !this.stack) return;
    while (this.stack.hasPendingData()) {
      const chunk = this.stack.readFromNetwork(64 * 1024);
      if (!chunk || chunk.length === 0) break;
      if (this.options.debug) {
        this.emit("log", `[net] tx ${chunk.length} bytes to qemu`);
      }
      const ok = this.socket.write(chunk);
      if (!ok) {
        this.waitingDrain = true;
        return;
      }
    }
  }

  private cleanupSessions() {
    for (const session of this.udpSessions.values()) {
      try {
        session.socket.close();
      } catch {
        // ignore
      }
    }
    this.udpSessions.clear();

    for (const session of this.tcpSessions.values()) {
      try {
        session.socket.destroy();
      } catch {
        // ignore
      }
    }
    this.tcpSessions.clear();
  }

  private handleUdpSend(message: UdpSendMessage) {
    let session = this.udpSessions.get(message.key);
    if (!session) {
      const socket = dgram.createSocket("udp4");
      session = {
        socket,
        srcIP: message.srcIP,
        srcPort: message.srcPort,
        dstIP: message.dstIP,
        dstPort: message.dstPort,
      };
      this.udpSessions.set(message.key, session);

      socket.on("message", (data, rinfo) => {
        if (this.options.debug && session!.dstPort === 53) {
          this.emit("log", `[net] udp recv ${rinfo.address}:${rinfo.port} -> ${session!.srcIP}:${session!.srcPort} (${data.length} bytes)`);
        }
        this.stack?.handleUdpResponse({
          data: Buffer.from(data),
          srcIP: session!.srcIP,
          srcPort: session!.srcPort,
          dstIP: session!.dstIP,
          dstPort: session!.dstPort,
        });
        this.flush();
      });

      socket.on("error", (err) => {
        this.emit("error", err);
      });
    }

    if (this.options.debug && message.dstPort === 53) {
      this.emit("log", `[net] udp send ${message.srcIP}:${message.srcPort} -> ${message.dstIP}:${message.dstPort} (${message.payload.length} bytes)`);
    }
    session.socket.send(message.payload, message.dstPort, message.dstIP);
  }

  private handleTcpConnect(message: TcpConnectMessage) {
    const connectIP =
      message.dstIP === (this.options.gatewayIP ?? "192.168.127.1") ? "127.0.0.1" : message.dstIP;

    const socket = new net.Socket();
    const session: TcpSession = {
      socket,
      srcIP: message.srcIP,
      srcPort: message.srcPort,
      dstIP: message.dstIP,
      dstPort: message.dstPort,
      flowControlPaused: false,
    };
    this.tcpSessions.set(message.key, session);

    socket.connect(message.dstPort, connectIP, () => {
      this.stack?.handleTcpConnected({ key: message.key });
      this.flush();
    });

    socket.on("data", (data) => {
      this.stack?.handleTcpData({ key: message.key, data: Buffer.from(data) });
      this.flush();
    });

    socket.on("end", () => {
      this.stack?.handleTcpEnd({ key: message.key });
      this.flush();
    });

    socket.on("close", () => {
      this.stack?.handleTcpClosed({ key: message.key });
      this.tcpSessions.delete(message.key);
    });

    socket.on("error", () => {
      this.stack?.handleTcpError({ key: message.key });
      this.tcpSessions.delete(message.key);
    });
  }

  private handleTcpSend(message: TcpSendMessage) {
    const session = this.tcpSessions.get(message.key);
    if (session && session.socket.writable) {
      session.socket.write(message.data);
    }
  }

  private handleTcpClose(message: TcpCloseMessage) {
    const session = this.tcpSessions.get(message.key);
    if (session) {
      if (message.destroy) {
        session.socket.destroy();
      } else {
        session.socket.end();
      }
    }
  }

  private handleTcpPause(message: TcpPauseMessage) {
    const session = this.tcpSessions.get(message.key);
    if (session) {
      session.flowControlPaused = true;
      session.socket.pause();
    }
  }

  private handleTcpResume(message: TcpResumeMessage) {
    const session = this.tcpSessions.get(message.key);
    if (session) {
      session.flowControlPaused = false;
      session.socket.resume();
    }
  }
}
