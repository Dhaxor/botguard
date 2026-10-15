// BotGuard Claude Code hook (generated bundle, do not edit). Source: packages/cli/src/hook.ts
// Blocks installs of known-malicious, typosquatted or impersonating npm/PyPI packages.
import { createRequire as __bgCreateRequire } from "node:module"; const require = __bgCreateRequire(import.meta.url);
import {
  commandToCheck
} from "./botguard-chunk-H66DWGCU.mjs";

// packages/cli/src/hook-entry.ts
var raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => raw += chunk);
process.stdin.on("end", async () => {
  if (!commandToCheck(raw)) process.exit(0);
  const { runClaudeCodeHook } = await import("./botguard-hook-KD6QAMWV.mjs");
  const out = await runClaudeCodeHook(raw);
  if (out.stdout) process.stdout.write(out.stdout);
  process.exit(out.exitCode);
});
