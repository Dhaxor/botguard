import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export interface InitResult {
  settingsPath: string;
  changed: boolean;
  backup?: string;
  entry: unknown;
}

/**
 * The hook entry Claude Code should run: this CLI's own bundle via node. Shell form on purpose:
 * exec-form `args` only exists from Claude Code 2.1.139, and older versions silently drop it.
 */
export function hookEntry(cliPath = fileURLToPath(import.meta.url)): Record<string, unknown> {
  // Forward slashes work in Git Bash, sh and PowerShell alike.
  const script = resolve(cliPath).replace(/\\/g, "/");
  return {
    matcher: "Bash|PowerShell",
    hooks: [{ type: "command", command: `node "${script}" hook claude-code`, timeout: 30 }],
  };
}

/**
 * Add the BotGuard PreToolUse hook to Claude Code settings (project .claude/settings.json by default).
 * Idempotent; keeps a backup of the previous file.
 */
export function initClaude(opts: { scope: "project" | "user"; cwd: string; dryRun?: boolean; cliPath?: string }): InitResult {
  const settingsPath = opts.scope === "user" ? join(homedir(), ".claude", "settings.json") : join(opts.cwd, ".claude", "settings.json");
  let settings: Record<string, unknown> = {};
  if (existsSync(settingsPath)) {
    const text = readFileSync(settingsPath, "utf8");
    try {
      settings = text.trim() ? (JSON.parse(text) as Record<string, unknown>) : {};
    } catch {
      throw new Error(`${settingsPath} is not valid JSON; fix it first so BotGuard doesn't overwrite your settings.`);
    }
  }
  const entry = hookEntry(opts.cliPath);
  const hooks = (settings.hooks ??= {}) as Record<string, unknown[]>;
  const pre = (hooks.PreToolUse ??= []) as Record<string, unknown>[];
  // Matches this entry and the args-form entry older BotGuard versions wrote.
  const already = pre.some((e) => /botguard|hook claude-code|"hook","claude-code"/.test(JSON.stringify(e)));
  if (already) return { settingsPath, changed: false, entry };
  pre.push(entry);
  if (opts.dryRun) return { settingsPath, changed: true, entry };
  mkdirSync(dirname(settingsPath), { recursive: true });
  let backup: string | undefined;
  if (existsSync(settingsPath)) {
    backup = `${settingsPath}.bak-botguard`;
    copyFileSync(settingsPath, backup);
  }
  writeFileSync(settingsPath, `${JSON.stringify(settings, null, 2)}\n`);
  return { settingsPath, changed: true, backup, entry };
}
