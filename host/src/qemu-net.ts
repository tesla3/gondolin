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
  TcpFlowProtocol,
  UdpSendMessage,
} from "./network-stack";

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-connection",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
]);

type UdpSession = {
  socket: dgram.Socket;
  srcIP: string;
  srcPort: number;
  dstIP: string;
  dstPort: number;
};

type HttpRequestData = {
  method: string;
  target: string;
  version: string;
  headers: Record<string, string>;
  body: Buffer;
};

type HttpSession = {
  buffer: Buffer;
  processing: boolean;
  closed: boolean;
};

type TcpSession = {
  socket: net.Socket | null;
  srcIP: string;
  srcPort: number;
  dstIP: string;
  dstPort: number;
  connectIP: string;
  flowControlPaused: boolean;
  protocol: TcpFlowProtocol | null;
  connected: boolean;
  pendingWrites: Buffer[];
  http?: HttpSession;
};

export type HttpHookRequest = {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: Buffer | null;
};

export type HttpHookResponse = {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: Buffer;
};

export type HttpHooks = {
  onRequest?: (request: HttpHookRequest) => Promise<HttpHookRequest | void> | HttpHookRequest | void;
  onResponse?: (
    response: HttpHookResponse,
    request: HttpHookRequest
  ) => Promise<HttpHookResponse | void> | HttpHookResponse | void;
};

export type QemuNetworkOptions = {
  socketPath: string;
  gatewayIP?: string;
  vmIP?: string;
  gatewayMac?: Buffer;
  vmMac?: Buffer;
  debug?: boolean;
  httpHooks?: HttpHooks;
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
      allowTcpFlow: (info) => {
        const session = this.tcpSessions.get(info.key);
        if (session) {
          session.protocol = info.protocol;
          if (info.protocol === "http") {
            session.http = session.http ?? {
              buffer: Buffer.alloc(0),
              processing: false,
              closed: false,
            };
          }
        }
        return true;
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
        session.socket?.destroy();
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

    const session: TcpSession = {
      socket: null,
      srcIP: message.srcIP,
      srcPort: message.srcPort,
      dstIP: message.dstIP,
      dstPort: message.dstPort,
      connectIP,
      flowControlPaused: false,
      protocol: null,
      connected: false,
      pendingWrites: [],
    };
    this.tcpSessions.set(message.key, session);

    this.stack?.handleTcpConnected({ key: message.key });
    this.flush();
  }

  private handleTcpSend(message: TcpSendMessage) {
    const session = this.tcpSessions.get(message.key);
    if (!session) return;

    if (session.protocol === "http") {
      this.handleHttpData(message.key, session, message.data);
      return;
    }

    this.ensureTcpSocket(message.key, session);
    if (session.socket && session.connected && session.socket.writable) {
      session.socket.write(message.data);
    } else {
      session.pendingWrites.push(message.data);
    }
  }

  private handleTcpClose(message: TcpCloseMessage) {
    const session = this.tcpSessions.get(message.key);
    if (session) {
      session.http = undefined;
      if (session.socket) {
        if (message.destroy) {
          session.socket.destroy();
        } else {
          session.socket.end();
        }
      } else {
        this.tcpSessions.delete(message.key);
      }
    }
  }

  private handleTcpPause(message: TcpPauseMessage) {
    const session = this.tcpSessions.get(message.key);
    if (session && session.socket) {
      session.flowControlPaused = true;
      session.socket.pause();
    }
  }

  private handleTcpResume(message: TcpResumeMessage) {
    const session = this.tcpSessions.get(message.key);
    if (session && session.socket) {
      session.flowControlPaused = false;
      session.socket.resume();
    }
  }

  private ensureTcpSocket(key: string, session: TcpSession) {
    if (session.socket) return;

    const socket = new net.Socket();
    session.socket = socket;

    socket.connect(session.dstPort, session.connectIP, () => {
      session.connected = true;
      for (const pending of session.pendingWrites) {
        socket.write(pending);
      }
      session.pendingWrites = [];
    });

    socket.on("data", (data) => {
      this.stack?.handleTcpData({ key, data: Buffer.from(data) });
      this.flush();
    });

    socket.on("end", () => {
      this.stack?.handleTcpEnd({ key });
      this.flush();
    });

    socket.on("close", () => {
      this.stack?.handleTcpClosed({ key });
      this.tcpSessions.delete(key);
    });

    socket.on("error", () => {
      this.stack?.handleTcpError({ key });
      this.tcpSessions.delete(key);
    });
  }

  private async handleHttpData(key: string, session: TcpSession, data: Buffer) {
    const httpSession = session.http ?? {
      buffer: Buffer.alloc(0),
      processing: false,
      closed: false,
    };
    session.http = httpSession;

    if (httpSession.closed) return;

    httpSession.buffer = Buffer.concat([httpSession.buffer, data]);
    if (httpSession.processing) return;

    const parsed = this.parseHttpRequest(httpSession.buffer);
    if (!parsed) return;

    httpSession.processing = true;
    httpSession.buffer = parsed.remaining;

    try {
      await this.fetchAndRespond(key, parsed.request);
    } catch (err) {
      this.emit("error", err instanceof Error ? err : new Error(String(err)));
      this.respondWithError(key, 502, "Bad Gateway");
    } finally {
      httpSession.closed = true;
      this.stack?.handleTcpEnd({ key });
      this.flush();
    }
  }

  private parseHttpRequest(buffer: Buffer): { request: HttpRequestData; remaining: Buffer } | null {
    const headerEnd = buffer.indexOf("\r\n\r\n");
    if (headerEnd === -1) return null;

    const headerBlock = buffer.subarray(0, headerEnd).toString("utf8");
    const lines = headerBlock.split("\r\n");
    if (lines.length === 0) return null;

    const [method, target, version] = lines[0].split(" ");
    if (!method || !target || !version) return null;

    const headers: Record<string, string> = {};
    for (let i = 1; i < lines.length; i += 1) {
      const line = lines[i];
      const idx = line.indexOf(":");
      if (idx === -1) continue;
      const key = line.slice(0, idx).trim().toLowerCase();
      const value = line.slice(idx + 1).trim();
      if (!key) continue;
      if (headers[key]) {
        headers[key] = `${headers[key]}, ${value}`;
      } else {
        headers[key] = value;
      }
    }

    const bodyOffset = headerEnd + 4;
    const bodyBuffer = buffer.subarray(bodyOffset);

    const transferEncoding = headers["transfer-encoding"]?.toLowerCase();
    if (transferEncoding === "chunked") {
      const chunked = this.decodeChunkedBody(bodyBuffer);
      if (!chunked.complete) return null;
      return {
        request: {
          method,
          target,
          version,
          headers,
          body: chunked.body,
        },
        remaining: bodyBuffer.subarray(chunked.bytesConsumed),
      };
    }

    const contentLength = headers["content-length"] ? Number(headers["content-length"]) : 0;
    if (!Number.isFinite(contentLength) || contentLength < 0) return null;

    if (bodyBuffer.length < contentLength) return null;

    return {
      request: {
        method,
        target,
        version,
        headers,
        body: bodyBuffer.subarray(0, contentLength),
      },
      remaining: bodyBuffer.subarray(contentLength),
    };
  }

  private decodeChunkedBody(buffer: Buffer): { complete: boolean; body: Buffer; bytesConsumed: number } {
    let offset = 0;
    const chunks: Buffer[] = [];

    while (true) {
      const lineEnd = buffer.indexOf("\r\n", offset);
      if (lineEnd === -1) return { complete: false, body: Buffer.alloc(0), bytesConsumed: 0 };

      const sizeLine = buffer.subarray(offset, lineEnd).toString("ascii").split(";")[0].trim();
      const size = parseInt(sizeLine, 16);
      if (!Number.isFinite(size)) return { complete: false, body: Buffer.alloc(0), bytesConsumed: 0 };

      const chunkStart = lineEnd + 2;
      const chunkEnd = chunkStart + size;
      if (buffer.length < chunkEnd + 2) return { complete: false, body: Buffer.alloc(0), bytesConsumed: 0 };

      if (size > 0) {
        chunks.push(buffer.subarray(chunkStart, chunkEnd));
      }

      if (buffer[chunkEnd] !== 0x0d || buffer[chunkEnd + 1] !== 0x0a) {
        return { complete: false, body: Buffer.alloc(0), bytesConsumed: 0 };
      }

      offset = chunkEnd + 2;
      if (size === 0) {
        return { complete: true, body: Buffer.concat(chunks), bytesConsumed: offset };
      }
    }
  }

  private async fetchAndRespond(key: string, request: HttpRequestData) {
    const url = this.buildFetchUrl(request);
    if (!url) {
      this.respondWithError(key, 400, "Bad Request");
      return;
    }

    if (this.options.debug) {
      this.emit("log", `[net] http bridge ${request.method} ${url}`);
    }

    let hookRequest: HttpHookRequest = {
      method: request.method,
      url,
      headers: this.stripHopByHopHeaders(request.headers),
      body: request.body.length > 0 ? request.body : null,
    };

    if (this.options.httpHooks?.onRequest) {
      const updated = await this.options.httpHooks.onRequest(hookRequest);
      if (updated) hookRequest = updated;
    }

    const response = await fetch(hookRequest.url, {
      method: hookRequest.method,
      headers: hookRequest.headers,
      body: hookRequest.body ?? undefined,
    });

    if (this.options.debug) {
      this.emit("log", `[net] http bridge response ${response.status} ${response.statusText}`);
    }

    const responseBody = Buffer.from(await response.arrayBuffer());
    let responseHeaders = this.stripHopByHopHeaders(this.headersToRecord(response.headers));
    responseHeaders["content-length"] = responseBody.length.toString();
    responseHeaders["connection"] = "close";

    let hookResponse: HttpHookResponse = {
      status: response.status,
      statusText: response.statusText || "OK",
      headers: responseHeaders,
      body: responseBody,
    };

    if (this.options.httpHooks?.onResponse) {
      const updated = await this.options.httpHooks.onResponse(hookResponse, hookRequest);
      if (updated) hookResponse = updated;
    }

    this.sendHttpResponse(key, hookResponse);
  }

  private sendHttpResponse(key: string, response: HttpHookResponse) {
    const statusLine = `HTTP/1.1 ${response.status} ${response.statusText}\r\n`;
    const headers = Object.entries(response.headers)
      .map(([name, value]) => `${name}: ${value}`)
      .join("\r\n");
    const headerBlock = `${statusLine}${headers}\r\n\r\n`;

    this.stack?.handleTcpData({ key, data: Buffer.from(headerBlock) });
    if (response.body.length > 0) {
      this.stack?.handleTcpData({ key, data: response.body });
    }
    this.flush();
  }

  private respondWithError(key: string, status: number, statusText: string) {
    const body = Buffer.from(`${status} ${statusText}\n`);
    this.sendHttpResponse(key, {
      status,
      statusText,
      headers: {
        "content-length": body.length.toString(),
        "content-type": "text/plain",
        connection: "close",
      },
      body,
    });
  }

  private buildFetchUrl(request: HttpRequestData) {
    if (request.target.startsWith("http://") || request.target.startsWith("https://")) {
      return request.target;
    }
    const host = request.headers["host"];
    if (!host) return null;
    return `http://${host}${request.target}`;
  }

  private stripHopByHopHeaders(headers: Record<string, string>) {
    const output: Record<string, string> = {};
    for (const [name, value] of Object.entries(headers)) {
      if (!HOP_BY_HOP_HEADERS.has(name.toLowerCase())) {
        output[name.toLowerCase()] = value;
      }
    }
    return output;
  }

  private headersToRecord(headers: Headers) {
    const record: Record<string, string> = {};
    headers.forEach((value, key) => {
      record[key.toLowerCase()] = value;
    });
    return record;
  }
}
