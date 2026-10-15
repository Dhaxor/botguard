import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import pc from "picocolors";
import { describeTarget, parseTarget, scanTarget, type Target } from "@botguard/core";
import { checkInstallCommand } from "@botguard/core/install";
import { formatCheck, formatReport } from "./format";
import { runClaudeCodeHook } from "./hook";
import { initClaude } from "./init";

const VERSION = "0.1.0";

const HELP = `
${pc.bold("botguard")} ${pc.dim(VERSION)}: check crypto trading bots before they check out your wallet.

${pc.bold("Usage")}
  botguard scan <target> [--json] [--verbose] [--no-sandbox]
      <target>  GitHub repo     github.com/owner/repo, owner/repo
                npm package     npm:name[@version], https://www.npmjs.com/package/name
                PyPI package    pypi:name[==version], https://pypi.org/project/name
                Solidity        path/to/Contract.sol (compiled and run in a sandbox EVM)
                Local folder    ./path/to/bot
  botguard check "<shell command>"     what the Claude Code hook would decide
  botguard init claude [--user] [--dry-run]
                                      add the install guard to .claude/settings.json
                                      (or ~/.claude/settings.json with --user)
  botguard hook claude-code           PreToolUse hook handler (reads JSON on stdin)

${pc.bold("Exit codes")}  0 no red flags/caution · 1 suspicious · 2 dangerous · 3 error
${pc.bold("Env")}         GITHUB_TOKEN (higher GitHub limits), BOTGUARD_ALLOW=pkg1,pkg2 (hook allow list)
`;

function readStdin(): Promise<string> {
  return new Promise((res) => {
    let raw = "";
    if (process.stdin.isTTY) return res("");
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (raw += c));
    process.stdin.on("end", () => res(raw));
  });
}

function localTarget(arg: string): Target | null {
  const p = resolve(arg);
  if (!existsSync(p)) return null;
  if (p.endsWith(".sol")) return { kind: "solidity", raw: arg, source: readFileSync(p, "utf8"), path: p };
  return { kind: "directory", raw: arg, path: p };
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  const flags = new Set(rest.filter((a) => a.startsWith("--")));
  const args = rest.filter((a) => !a.startsWith("--"));

  if (!cmd || cmd === "--help" || cmd === "-h" || cmd === "help") {
    console.log(HELP);
    return 0;
  }
  if (cmd === "--version" || cmd === "-v") {
    console.log(VERSION);
    return 0;
  }

  if (cmd === "hook") {
    if (args[0] !== "claude-code") {
      console.error("Usage: botguard hook claude-code");
      return 3;
    }
    const out = await runClaudeCodeHook(await readStdin());
    if (out.stdout) process.stdout.write(out.stdout);
    return out.exitCode;
  }

  if (cmd === "check") {
    const command = args.join(" ");
    if (!command) {
      console.error('Usage: botguard check "npm install some-package"');
      return 3;
    }
    const allow = (process.env.BOTGUARD_ALLOW ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    const result = await checkInstallCommand(command, { allow });
    if (flags.has("--json")) console.log(JSON.stringify(result, null, 2));
    else console.log(formatCheck(command, result));
    return result.decision === "deny" ? 2 : result.decision === "ask" ? 1 : 0;
  }

  if (cmd === "init") {
    if (args[0] !== "claude") {
      console.error("Usage: botguard init claude [--user] [--dry-run]");
      return 3;
    }
    const res = initClaude({ scope: flags.has("--user") ? "user" : "project", cwd: process.cwd(), dryRun: flags.has("--dry-run") });
    if (!res.changed) console.log(pc.green(`BotGuard is already set up in ${res.settingsPath}`));
    else if (flags.has("--dry-run")) console.log(`Would add to ${res.settingsPath}:\n${JSON.stringify(res.entry, null, 2)}`);
    else {
      console.log(pc.green(`Added the BotGuard install guard to ${res.settingsPath}`));
      if (res.backup) console.log(pc.dim(`Previous settings backed up to ${res.backup}`));
      console.log(pc.dim("Restart Claude Code (or run /hooks) for it to take effect."));
    }
    return 0;
  }

  if (cmd === "scan") {
    const input = args.join(" ");
    if (!input) {
      console.error("Usage: botguard scan <github repo | npm:name | pypi:name | file.sol | folder>");
      return 3;
    }
    let target: Target;
    try {
      target = localTarget(input) ?? parseTarget(input);
    } catch (err) {
      console.error(pc.red((err as Error).message));
      return 3;
    }
    const json = flags.has("--json");
    const progress = json || !process.stderr.isTTY ? undefined : (m: string) => process.stderr.write(pc.dim(`\r  ${m}…`.padEnd(70)));
    if (!json) process.stderr.write(pc.dim(`Scanning ${describeTarget(target)}\n`));
    const report = await scanTarget(target, { detonate: !flags.has("--no-sandbox"), onProgress: progress });
    if (progress) process.stderr.write("\r".padEnd(72) + "\r");
    if (json) console.log(JSON.stringify(report, null, 2));
    else console.log(formatReport(report, flags.has("--verbose")));
    return { dangerous: 2, suspicious: 1, caution: 0, "no-red-flags": 0, error: 3 }[report.verdict];
  }

  console.error(`Unknown command "${cmd}". Run botguard --help.`);
  return 3;
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => {
    console.error(pc.red(`botguard: ${(err as Error).stack ?? err}`));
    process.exit(3);
  },
);
