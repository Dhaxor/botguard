import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { checkInstallCommand, type CheckResult } from "@botguard/core/install";
import { GUARDED_TOOLS, MAYBE_INSTALL } from "./prefilter";

export interface HookInput {
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: { command?: unknown };
  cwd?: string;
}

export interface HookOutput {
  stdout?: string;
  exitCode: number;
}

function allowList(cwd: string): string[] {
  const fromEnv = (process.env.BOTGUARD_ALLOW ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const file = join(cwd, ".botguard.json");
  if (!existsSync(file)) return fromEnv;
  try {
    const cfg = JSON.parse(readFileSync(file, "utf8")) as { allow?: string[] };
    return [...fromEnv, ...(cfg.allow ?? [])];
  } catch {
    return fromEnv;
  }
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | "timeout"> {
  return Promise.race([p, new Promise<"timeout">((r) => setTimeout(() => r("timeout"), ms).unref())]);
}

function decisionJson(result: CheckResult): string {
  const decision = result.decision === "deny" ? "deny" : "ask";
  const flagged = result.verdicts.filter((v) => v.decision !== "allow").map((v) => v.label);
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: decision,
      permissionDecisionReason: result.reason,
    },
    systemMessage: `BotGuard ${decision === "deny" ? "blocked" : "flagged"}: ${flagged.join(", ")}`,
  });
}

/**
 * Claude Code PreToolUse handler. Allowed installs produce no output, so Claude Code's normal
 * permission flow still applies: BotGuard can only ever tighten permissions, never grant them.
 */
export async function runClaudeCodeHook(raw: string): Promise<HookOutput> {
  let input: HookInput;
  try {
    input = JSON.parse(raw) as HookInput;
  } catch {
    return { exitCode: 0 };
  }
  if (!input.tool_name || !GUARDED_TOOLS.has(input.tool_name)) return { exitCode: 0 };
  const command = typeof input.tool_input?.command === "string" ? input.tool_input.command : "";
  if (!command || !MAYBE_INSTALL.test(command)) return { exitCode: 0 };

  const cwd = input.cwd ?? process.cwd();
  const failClosed = process.env.BOTGUARD_FAIL_CLOSED === "1";
  try {
    const result = await withTimeout(checkInstallCommand(command, { cwd, allow: allowList(cwd) }), Number(process.env.BOTGUARD_TIMEOUT_MS ?? 20_000));
    if (result === "timeout") {
      if (failClosed) {
        return {
          exitCode: 0,
          stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: "BotGuard couldn't finish checking this install in time." } }),
        };
      }
      return { exitCode: 0, stdout: JSON.stringify({ systemMessage: "BotGuard: install check timed out, so this install was not verified." }) };
    }
    if (result.decision === "allow") return { exitCode: 0 };
    return { exitCode: 0, stdout: decisionJson(result) };
  } catch (err) {
    if (failClosed) {
      return {
        exitCode: 0,
        stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: `BotGuard check failed: ${(err as Error).message}` } }),
      };
    }
    return { exitCode: 0 };
  }
}
