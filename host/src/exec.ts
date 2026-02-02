import net from "net";

import {
  FrameReader,
  buildExecRequest,
  decodeMessage,
  encodeFrame,
  IncomingMessage,
} from "./virtio-protocol";

type Command = {
  cmd: string;
  argv: string[];
  env: string[];
  cwd?: string;
  id: number;
};

type Args = {
  sock?: string;
  commands: Command[];
};

function parseArgs(argv: string[]): Args {
  const args: Args = { commands: [] };
  let current: Command | null = null;
  let nextId = 1;

  const fail = (message: string): never => {
    console.error(message);
    usage();
    process.exit(1);
  };

  const parseId = (value: string) => {
    const id = Number(value);
    if (!Number.isFinite(id)) fail("--id must be a number");
    if (id >= nextId) nextId = id + 1;
    return id;
  };

  const separatorIndex = argv.indexOf("--");
  if (separatorIndex !== -1) {
    const optionArgs = argv.slice(0, separatorIndex);
    const commandArgs = argv.slice(separatorIndex + 1);
    if (commandArgs.length === 0) fail("missing command after --");

    current = {
      cmd: commandArgs[0],
      argv: commandArgs.slice(1),
      env: [],
      id: nextId++,
    };
    args.commands.push(current);

    for (let i = 0; i < optionArgs.length; i += 1) {
      const arg = optionArgs[i];
      switch (arg) {
        case "--sock":
          args.sock = optionArgs[++i];
          break;
        case "--env":
          current.env.push(optionArgs[++i]);
          break;
        case "--cwd":
          current.cwd = optionArgs[++i];
          break;
        case "--id":
          current.id = parseId(optionArgs[++i]);
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

  const requireCurrent = (flag: string): Command => {
    if (!current) fail(`${flag} requires --cmd`);
    return current!;
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case "--sock":
        args.sock = argv[++i];
        break;
      case "--cmd":
        current = { cmd: argv[++i], argv: [], env: [], id: nextId++ };
        args.commands.push(current);
        break;
      case "--arg": {
        const command = requireCurrent("--arg");
        command.argv.push(argv[++i]);
        break;
      }
      case "--env": {
        const command = requireCurrent("--env");
        command.env.push(argv[++i]);
        break;
      }
      case "--cwd": {
        const command = requireCurrent("--cwd");
        command.cwd = argv[++i];
        break;
      }
      case "--id": {
        const command = requireCurrent("--id");
        command.id = parseId(argv[++i]);
        break;
      }
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
  console.log("Usage:");
  console.log("  node dist/exec.js --sock PATH -- CMD [ARGS...]");
  console.log(
    "  node dist/exec.js --sock PATH --cmd CMD [--arg ARG] [--env KEY=VALUE] [--cwd PATH] [--cmd CMD ...]"
  );
  console.log("Use -- to pass a command and its arguments directly.");
  console.log("Arguments apply to the most recent --cmd.");
}


function buildCommandPayload(command: Command) {
  const payload: { cmd: string; argv?: string[]; env?: string[]; cwd?: string } = {
    cmd: command.cmd,
  };

  if (command.argv.length > 0) payload.argv = command.argv;
  if (command.env.length > 0) payload.env = command.env;
  if (command.cwd) payload.cwd = command.cwd;

  return payload;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.sock || args.commands.length === 0) {
    usage();
    process.exit(1);
  }

  const socket = net.createConnection({ path: args.sock });
  const reader = new FrameReader();
  let currentIndex = 0;
  let inflightId: number | null = null;
  let exitCode = 0;
  let closing = false;

  const sendNext = () => {
    const command = args.commands[currentIndex];
    inflightId = command.id;
    const payload = buildCommandPayload(command);
    const message = buildExecRequest(command.id, payload);
    socket.write(encodeFrame(message));
  };

  const finish = (code?: number) => {
    if (code !== undefined && exitCode === 0) exitCode = code;
    if (closing) return;
    closing = true;
    socket.end();
  };

  socket.on("connect", () => {
    console.log(`connected to ${args.sock}`);
    sendNext();
  });

  socket.on("data", (chunk) => {
    reader.push(chunk, (frame) => {
      const message = decodeMessage(frame) as IncomingMessage;
      if (message.t === "exec_output") {
        const data = message.p.data;
        if (message.p.stream === "stdout") {
          process.stdout.write(data);
        } else {
          process.stderr.write(data);
        }
      } else if (message.t === "exec_response") {
        if (inflightId !== null && message.id !== inflightId) {
          console.error(`unexpected response id ${message.id} (expected ${inflightId})`);
          finish(1);
          return;
        }
        const code = message.p.exit_code ?? 1;
        const signal = message.p.signal;
        if (signal !== undefined) {
          console.error(`process exited due to signal ${signal}`);
        }
        if (code !== 0 && exitCode === 0) exitCode = code;
        currentIndex += 1;
        if (currentIndex < args.commands.length) {
          sendNext();
        } else {
          finish();
        }
      } else if (message.t === "error") {
        console.error(`error ${message.p.code}: ${message.p.message}`);
        finish(1);
      }
    });
  });

  socket.on("error", (err) => {
    console.error(`socket error: ${err.message}`);
    finish(1);
  });

  socket.on("end", () => {
    if (!closing && exitCode === 0) exitCode = 1;
  });

  socket.on("close", () => {
    process.exit(exitCode);
  });
}

main();
