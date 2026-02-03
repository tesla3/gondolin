import { WebSocket } from "ws";

import { decodeOutputFrame } from "./ws-protocol";

const url = process.env.WS_URL ?? "ws://127.0.0.1:8080";
const timeoutMs = Number(process.env.WS_TIMEOUT ?? 15000);
const httpUrl = process.env.WS_HTTP_URL ?? "http://icanhazip.com";
const httpsUrl = process.env.WS_HTTPS_URL ?? "https://icanhazip.com";

async function run() {
  const ws = new WebSocket(url);
  let output = "";
  let stderr = "";

  const done = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error("timeout waiting for response"));
    }, timeoutMs);

    ws.on("open", () => {
      ws.send(
        JSON.stringify({
          type: "exec",
          id: 1,
          cmd: "python3",
          argv: [
            "-c",
            `import sys,urllib.request;\n` +
              `print('HTTP');\n` +
              `print(urllib.request.urlopen('${httpUrl}', timeout=10).read().decode().strip());\n` +
              `print('HTTPS');\n` +
              `print(urllib.request.urlopen('${httpsUrl}', timeout=10).read().decode().strip());\n`,
          ],
        })
      );
    });

    ws.on("message", (data, isBinary) => {
      if (isBinary) {
        const frame = decodeOutputFrame(Buffer.from(data as Buffer));
        if (frame.stream === "stdout") {
          output += frame.data.toString();
        } else if (frame.stream === "stderr") {
          stderr += frame.data.toString();
        }
        return;
      }

      const message = JSON.parse(data.toString()) as { type: string; exit_code?: number };
      if (message.type === "exec_response") {
        clearTimeout(timer);
        if (message.exit_code !== 0) {
          const detail = stderr.trim() ? `\n${stderr.trim()}` : "";
          reject(new Error(`unexpected exit code: ${message.exit_code}${detail}`));
          return;
        }
        const lines = output.trim().split("\n");
        const httpIndex = lines.findIndex((line) => line.trim() === "HTTP");
        const httpsIndex = lines.findIndex((line) => line.trim() === "HTTPS");
        if (httpIndex === -1 || httpsIndex === -1) {
          const detail = stderr.trim() ? `\n${stderr.trim()}` : "";
          reject(new Error(`missing http/https output: ${output.trim()}${detail}`));
          return;
        }
        const httpValue = lines[httpIndex + 1]?.trim();
        const httpsValue = lines[httpsIndex + 1]?.trim();
        if (!httpValue || !httpsValue) {
          const detail = stderr.trim() ? `\n${stderr.trim()}` : "";
          reject(new Error(`empty http/https response: ${output.trim()}${detail}`));
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
  console.log(output);
}

run().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
