import assert from "node:assert/strict";
import os from "node:os";
import test from "node:test";

import { VM } from "../src/vm";
import { MemoryProvider } from "../src/vfs";
import { createErrnoError } from "../src/vfs/errors";

const url = process.env.WS_URL;
const timeoutMs = Number(process.env.WS_TIMEOUT ?? 15000);
const { errno: ERRNO } = os.constants;

async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | null = null;
  const timeout = new Promise<T>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error("timeout waiting for response"));
    }, ms);
  });

  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function waitForDataMount(vm: VM) {
  const result = await withTimeout(
    vm.exec([
      "sh",
      "-c",
      "for i in $(seq 1 50); do grep -q ' /data fuse.sandboxfs ' /proc/mounts && exit 0; sleep 0.1; done; exit 1",
    ]),
    timeoutMs
  );
  if (result.exitCode !== 0) {
    throw new Error(
      `sandboxfs mount not ready (exit ${result.exitCode}): ${result.stderr.toString().trim()}`
    );
  }
}

async function waitForBindMount(vm: VM, mountPoint: string) {
  const result = await withTimeout(
    vm.exec([
      "sh",
      "-c",
      `for i in $(seq 1 50); do grep -q ' ${mountPoint} ' /proc/mounts && exit 0; sleep 0.1; done; exit 1`,
    ]),
    timeoutMs
  );
  if (result.exitCode !== 0) {
    throw new Error(
      `bind mount ${mountPoint} not ready (exit ${result.exitCode}): ${result.stderr.toString().trim()}`
    );
  }
}

test("vfs roundtrip between host and guest", { timeout: timeoutMs, skip: Boolean(url) }, async () => {
  const provider = new MemoryProvider();
  const handle = await provider.open("/host.txt", "w+");
  await handle.writeFile("host-data");
  await handle.close();

  const vm = new VM({
    server: { console: "none" },
    vfs: { mounts: { "/": provider } },
  });

  try {
    await waitForDataMount(vm);

    const read = await withTimeout(vm.exec(["sh", "-c", "cat /data/host.txt"]), timeoutMs);
    if (read.exitCode !== 0) {
      throw new Error(
        `cat failed (exit ${read.exitCode}): ${read.stderr.toString().trim()}`
      );
    }
    assert.equal(read.stdout.toString().trim(), "host-data");

    const write = await withTimeout(
      vm.exec(["sh", "-c", "echo -n guest-data > /data/guest.txt"]),
      timeoutMs
    );
    if (write.exitCode !== 0) {
      throw new Error(
        `write failed (exit ${write.exitCode}): ${write.stderr.toString().trim()}`
      );
    }

    const append = await withTimeout(
      vm.exec(["sh", "-c", "printf foo > /data/append.txt; printf bar >> /data/append.txt; cat /data/append.txt"]),
      timeoutMs
    );
    if (append.exitCode !== 0) {
      throw new Error(
        `append failed (exit ${append.exitCode}): ${append.stderr.toString().trim()}`
      );
    }
    assert.equal(append.stdout.toString(), "foobar");
  } finally {
    await vm.stop();
  }

  const guestHandle = await provider.open("/guest.txt", "r");
  const data = await guestHandle.readFile({ encoding: "utf-8" });
  await guestHandle.close();
  assert.equal(data, "guest-data");
});

test("vfs hooks can block writes", { timeout: timeoutMs, skip: Boolean(url) }, async () => {
  const provider = new MemoryProvider();
  const blocked: string[] = [];

  const vm = new VM({
    server: { console: "none" },
    vfs: {
      mounts: { "/": provider },
      hooks: {
        before: (ctx) => {
          if (ctx.op === "open" && ctx.path === "/blocked.txt" && typeof ctx.flags === "string") {
            blocked.push(`${ctx.path}:${ctx.flags}`);
            if (ctx.flags.includes("w") || ctx.flags.includes("a")) {
              throw createErrnoError(ERRNO.EACCES, "open", ctx.path);
            }
          }
        },
      },
    },
  });

  try {
    await waitForDataMount(vm);

    const result = await withTimeout(
      vm.exec(["sh", "-c", "echo nope > /data/blocked.txt"]),
      timeoutMs
    );
    assert.notEqual(result.exitCode, 0);
  } finally {
    await vm.stop();
  }

  assert.ok(blocked.length > 0);
  assert.ok(blocked.some((entry) => entry.startsWith("/blocked.txt:")));
});

test("vfs supports read-only email mounts with dynamic content", { timeout: timeoutMs, skip: Boolean(url) }, async () => {
  const rootProvider = new MemoryProvider();
  const rootHandle = await rootProvider.open("/root.txt", "w+");
  await rootHandle.writeFile("root-data");
  await rootHandle.close();

  const emailProvider = new MemoryProvider();
  const emailId = "12345";
  const emailBody = "Subject: Hello\nFrom: test@example.com\n\nHi there!";
  const apiCalls: string[] = [];
  const mockApi = {
    fetchEmail(id: string) {
      apiCalls.push(id);
      return id === emailId ? emailBody : "";
    },
  };

  await emailProvider.mkdir("/email", { recursive: true });
  const emailPath = `/email/${emailId}.eml`;
  const emailHandle = await emailProvider.open(emailPath, "w+");
  await emailHandle.writeFile(emailBody);
  await emailHandle.close();

  const emailEntry = (emailProvider as unknown as {
    _getEntry: (path: string, syscall: string) => { content: Buffer; contentProvider?: () => string };
  })._getEntry(emailPath, "vfs-test");
  emailEntry.contentProvider = () => {
    const payload = mockApi.fetchEmail(emailId);
    emailEntry.content = Buffer.from(payload);
    return payload;
  };

  emailProvider.setReadOnly();

  const vm = new VM({
    server: { console: "none" },
    vfs: {
      mounts: {
        "/": rootProvider,
        "/app": emailProvider,
      },
    },
  });

  try {
    await waitForDataMount(vm);
    await waitForBindMount(vm, "/app");

    const rootRead = await withTimeout(vm.exec(["sh", "-c", "cat /data/root.txt"]), timeoutMs);
    if (rootRead.exitCode !== 0) {
      throw new Error(`cat root failed (exit ${rootRead.exitCode}): ${rootRead.stderr.toString().trim()}`);
    }
    assert.equal(rootRead.stdout.toString().trim(), "root-data");

    const emailRead = await withTimeout(
      vm.exec(["sh", "-c", `cat /app/email/${emailId}.eml`]),
      timeoutMs
    );
    if (emailRead.exitCode !== 0) {
      throw new Error(`cat email failed (exit ${emailRead.exitCode}): ${emailRead.stderr.toString().trim()}`);
    }
    assert.equal(emailRead.stdout.toString().trim(), emailBody);

    const writeAttempt = await withTimeout(
      vm.exec(["sh", "-c", `echo nope > /app/email/${emailId}-new.eml`]),
      timeoutMs
    );
    assert.notEqual(writeAttempt.exitCode, 0);
  } finally {
    await vm.stop();
  }

  assert.ok(apiCalls.includes(emailId));
});
