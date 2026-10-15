// Standalone entry for the Claude Code plugin: `node botguard-hook.mjs` reads the hook JSON on stdin.
// The scanner is only loaded (dynamic import) when the command might install something.
import { commandToCheck } from "./prefilter";

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (raw += chunk));
process.stdin.on("end", async () => {
  if (!commandToCheck(raw)) process.exit(0);
  const { runClaudeCodeHook } = await import("./hook");
  const out = await runClaudeCodeHook(raw);
  if (out.stdout) process.stdout.write(out.stdout);
  process.exit(out.exitCode);
});
