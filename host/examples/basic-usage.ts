/**
 * Basic usage examples for the Gondolin VM API.
 * 
 * Run with: npx tsx examples/basic-usage.ts
 */

import { VM } from "../src/vm";

async function main() {
  const vm = new VM();

  try {
    // ═══════════════════════════════════════════════════════════════════════
    // Example 1: Simple command execution
    // ═══════════════════════════════════════════════════════════════════════
    console.log("=== Simple command ===");
    const result = await vm.exec(["echo", "Hello, World!"]);
    console.log("stdout:", result.stdout);        // "Hello, World!\n"
    console.log("exit code:", result.exitCode);   // 0
    console.log("ok:", result.ok);                // true

    // ═══════════════════════════════════════════════════════════════════════
    // Example 2: Using shell string syntax
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n=== Shell string syntax ===");
    const shellResult = await vm.exec("echo 'Hello from shell'", { argv: [] });
    console.log("stdout:", shellResult.stdout);

    // ═══════════════════════════════════════════════════════════════════════
    // Example 3: Result helpers
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n=== Result helpers ===");
    
    // .lines() - split output into lines
    const lsResult = await vm.exec(["ls", "-la", "/tmp"]);
    const files = lsResult.lines();
    console.log("Files in /tmp:", files.length, "lines");

    // .json() - parse JSON output
    const jsonResult = await vm.exec(["sh", "-c", 'echo \'{"name": "gondolin", "version": 1}\''']);
    const data = jsonResult.json<{ name: string; version: number }>();
    console.log("Parsed JSON:", data);

    // ═══════════════════════════════════════════════════════════════════════
    // Example 4: Streaming output with async iteration
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n=== Streaming output ===");
    const streamProc = vm.exec(["sh", "-c", "for i in 1 2 3; do echo Line $i; sleep 0.1; done"]);
    
    // Iterate over stdout chunks as they arrive
    for await (const chunk of streamProc) {
      process.stdout.write(`[stream] ${chunk}`);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Example 5: Labeled output (stdout + stderr)
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n=== Labeled output ===");
    const mixedProc = vm.exec(["sh", "-c", "echo stdout; echo stderr >&2; echo stdout2"]);
    
    for await (const { stream, text } of mixedProc.output()) {
      console.log(`[${stream}] ${text.trim()}`);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Example 6: Line-by-line iteration
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n=== Line iteration ===");
    const lineProc = vm.exec(["sh", "-c", "echo one; echo two; echo three"]);
    
    let lineNum = 1;
    for await (const line of lineProc.lines()) {
      console.log(`Line ${lineNum++}: ${line}`);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Example 7: Stdin input
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n=== Stdin input ===");
    
    // Pass string as stdin
    const catResult = await vm.exec(["cat"], { stdin: "Hello from stdin!\n" });
    console.log("cat output:", catResult.stdout);

    // ═══════════════════════════════════════════════════════════════════════
    // Example 8: Manual stdin with write/end
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n=== Manual stdin ===");
    const proc = vm.exec(["cat"], { stdin: true });
    proc.write("First line\n");
    proc.write("Second line\n");
    proc.end();
    
    const manualResult = await proc;
    console.log("Manual stdin output:", manualResult.stdout);

    // ═══════════════════════════════════════════════════════════════════════
    // Example 9: Error handling
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n=== Error handling ===");
    const failResult = await vm.exec(["sh", "-c", "exit 42"]);
    console.log("Exit code:", failResult.exitCode);  // 42
    console.log("ok:", failResult.ok);               // false

    // ═══════════════════════════════════════════════════════════════════════
    // Example 10: Interactive shell (non-blocking demo)
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n=== Shell helper (non-interactive demo) ===");
    const shell = vm.shell({ attach: false, command: ["sh"] });
    shell.write("echo Hello from shell helper\n");
    shell.write("exit\n");
    
    for await (const chunk of shell) {
      process.stdout.write(chunk);
    }

    console.log("\n=== All examples completed! ===");
  } finally {
    await vm.close();
  }
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
