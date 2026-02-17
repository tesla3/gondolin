import assert from "node:assert/strict";
import test from "node:test";

import { createHttpHooks } from "../src/http-hooks";
import {
  closeVm,
  withVm,
  shouldSkipVmTests,
  scheduleForceExit,
} from "./helpers/vm-fixture";

const skipVmTests = shouldSkipVmTests();
const timeoutMs = Number(process.env.WS_TIMEOUT ?? 120_000);

// ---------------------------------------------------------------------------
// Shared VM: allowedHosts = ["httpbin.org"], one secret bound to httpbin.org
// ---------------------------------------------------------------------------

const REAL_SECRET = "gondolin-test-secret-value-" + Date.now();

const { httpHooks, env: secretEnv } = createHttpHooks({
  allowedHosts: ["httpbin.org"],
  secrets: {
    TEST_SECRET: {
      hosts: ["httpbin.org"],
      value: REAL_SECRET,
    },
  },
});

const secVmKey = "sec-httpbin";
const secVmOptions = {
  sandbox: { console: "none" as const },
  httpHooks,
  env: secretEnv,
};

test.after(async () => {
  await closeVm(secVmKey);
  scheduleForceExit();
});

// ---------------------------------------------------------------------------
// 1. TLS MITM E2E
// ---------------------------------------------------------------------------

test(
  "security: TLS MITM — curl https through the MITM chain succeeds",
  { skip: skipVmTests, timeout: timeoutMs },
  async () => {
    await withVm(secVmKey, secVmOptions, async (vm) => {
      await vm.start();

      // Basic HTTPS request through the full MITM pipeline
      const result = await vm.exec(
        'curl -sS -f https://httpbin.org/get 2>&1',
      );
      assert.equal(result.exitCode, 0, `curl failed: ${result.stderr}`);

      // Response should be valid JSON from httpbin
      const body = JSON.parse(result.stdout);
      assert.equal(body.url, "https://httpbin.org/get");
    });
  },
);

test(
  "security: TLS MITM — guest sees MITM CA, not the real certificate",
  { skip: skipVmTests, timeout: timeoutMs },
  async () => {
    await withVm(secVmKey, secVmOptions, async (vm) => {
      await vm.start();

      // curl -v prints certificate info to stderr
      const result = await vm.exec(
        'curl -vsS https://httpbin.org/get 2>&1 >/dev/null',
      );

      // The issuer should be gondolin's MITM CA, not a real CA
      assert.match(
        result.stdout + result.stderr,
        /gondolin-mitm-ca/i,
        "expected MITM CA issuer in curl verbose output",
      );
    });
  },
);

// ---------------------------------------------------------------------------
// 2. Secret non-exposure inside the VM
// ---------------------------------------------------------------------------

test(
  "security: secrets — guest env var contains placeholder, not real value",
  { skip: skipVmTests, timeout: timeoutMs },
  async () => {
    await withVm(secVmKey, secVmOptions, async (vm) => {
      await vm.start();

      const result = await vm.exec('echo "$TEST_SECRET"');
      const value = result.stdout.trim();

      // Must be a placeholder
      assert.match(
        value,
        /^GONDOLIN_SECRET_/,
        "env var should be a GONDOLIN_SECRET_ placeholder",
      );

      // Must NOT be the real secret
      assert.ok(
        !value.includes(REAL_SECRET),
        "real secret value must not appear in guest env",
      );
    });
  },
);

test(
  "security: secrets — real value never appears in guest environment",
  { skip: skipVmTests, timeout: timeoutMs },
  async () => {
    await withVm(secVmKey, secVmOptions, async (vm) => {
      await vm.start();

      // Scan the entire environment for the real secret
      const result = await vm.exec("env");
      assert.ok(
        !result.stdout.includes(REAL_SECRET),
        "real secret must not appear anywhere in `env` output",
      );
    });
  },
);

// ---------------------------------------------------------------------------
// 3. Secret reflection via echo service (proves substitution + documents
//    the known limitation that allowed hosts can reflect secrets)
// ---------------------------------------------------------------------------

test(
  "security: secrets — host substitutes real value on allowed host (httpbin echo)",
  { skip: skipVmTests, timeout: timeoutMs },
  async () => {
    await withVm(secVmKey, secVmOptions, async (vm) => {
      await vm.start();

      // httpbin.org/headers echoes request headers back in JSON
      const result = await vm.exec(
        'curl -sS -f https://httpbin.org/headers -H "Authorization: Bearer $TEST_SECRET"',
      );
      assert.equal(result.exitCode, 0, `curl failed: ${result.stderr}`);

      const body = JSON.parse(result.stdout);
      const authHeader: string = body.headers?.Authorization ?? "";

      // The host should have substituted the placeholder with the real value
      assert.ok(
        authHeader.includes(REAL_SECRET),
        "httpbin should echo back the real secret (host substitution worked)",
      );

      // The placeholder should NOT appear in the echoed header
      assert.ok(
        !authHeader.includes("GONDOLIN_SECRET_"),
        "placeholder must not leak to upstream — substitution should have replaced it",
      );
    });
  },
);

// ---------------------------------------------------------------------------
// 4. Secret blocked on disallowed host
// ---------------------------------------------------------------------------

test(
  "security: secrets — request with secret placeholder to disallowed host is blocked",
  { skip: skipVmTests, timeout: timeoutMs },
  async () => {
    await withVm(secVmKey, secVmOptions, async (vm) => {
      await vm.start();

      // example.com is not in allowedHosts — the host should block it.
      // The host returns an HTTP error (e.g. 403) since the policy check
      // happens after the TCP/TLS handshake is bridged.
      const result = await vm.exec([
        "/bin/sh",
        "-c",
        'curl -sS -o /dev/null -w "%{http_code}" https://example.com/test -H "Authorization: Bearer $TEST_SECRET" 2>&1',
      ]);

      const output = result.stdout + result.stderr;

      // The real secret must never appear in any output
      assert.ok(
        !output.includes(REAL_SECRET),
        "real secret must not appear in error output",
      );

      // Host should reject with a 4xx/5xx or curl should fail outright
      const httpCode = Number(result.stdout.trim()) || 0;
      const blocked =
        result.exitCode !== 0 || httpCode === 0 || httpCode >= 400;
      assert.ok(
        blocked,
        `request to disallowed host should be blocked (exit=${result.exitCode}, http=${httpCode})`,
      );
    });
  },
);
