import { WebSocket } from "ws";

import { decodeOutputFrame } from "./ws-protocol";

const url = process.env.WS_URL ?? "ws://127.0.0.1:8080";
const timeoutMs = Number(process.env.WS_TIMEOUT ?? 5000);

async function run() {
  const ws = new WebSocket(url);
  let output = "";

  const done = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error("timeout waiting for response"));
    }, timeoutMs);

    ws.on("open", () => {
      ws.send(
        JSON.stringify({
          type: "exec",
          id: 1,
          cmd: "echo",
          argv: ["hello"],
        })
      );
    });

    ws.on("message", (data, isBinary) => {
      if (isBinary) {
        const frame = decodeOutputFrame(Buffer.from(data as Buffer));
        if (frame.stream === "stdout") {
          output += frame.data.toString();
        }
        return;
      }

      const message = JSON.parse(data.toString()) as { type: string; exit_code?: number };
      if (message.type === "exec_response") {
        clearTimeout(timer);
        if (output.trim() !== "hello") {
          reject(new Error(`unexpected output: ${output.trim()}`));
          return;
        }
        if (message.exit_code !== 0) {
          reject(new Error(`unexpected exit code: ${message.exit_code}`));
          return;
        }
        resolve();
      }
    });

    ws.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });

  await done;
  ws.close();
  console.log("WS test passed");
}

run().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
