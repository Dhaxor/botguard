import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { hookEntry, initClaude } from "../src/init";

type Entry = { matcher: string; hooks: { type: string; command: string; args?: unknown }[] };

function projectWithSettings(settings: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), "botguard-init-"));
  mkdirSync(join(dir, ".claude"));
  writeFileSync(join(dir, ".claude", "settings.json"), JSON.stringify(settings));
  return dir;
}

describe("hookEntry", () => {
  it("uses shell form, which every Claude Code version runs (exec-form args needs 2.1.139+)", () => {
    const cli = join(tmpdir(), "Some One", "botguard", "cli.mjs");
    const entry = hookEntry(cli) as Entry;
    expect(entry.matcher).toBe("Bash|PowerShell");
    expect(entry.hooks[0]!.args).toBeUndefined();
    expect(entry.hooks[0]!.command).toBe(`node "${resolve(cli).replace(/\\/g, "/")}" hook claude-code`);
    expect(entry.hooks[0]!.command).not.toContain("\\");
  });
});

describe("initClaude", () => {
  it("adds the hook once and keeps the other settings", () => {
    const dir = projectWithSettings({ model: "x", hooks: { PreToolUse: [] } });
    const cliPath = join(dir, "cli.mjs");
    const first = initClaude({ scope: "project", cwd: dir, cliPath });
    expect(first.changed).toBe(true);
    const settings = JSON.parse(readFileSync(first.settingsPath, "utf8")) as { model: string; hooks: { PreToolUse: Entry[] } };
    expect(settings.model).toBe("x");
    expect(settings.hooks.PreToolUse).toHaveLength(1);
    expect(initClaude({ scope: "project", cwd: dir, cliPath }).changed).toBe(false);
  });

  it("recognises an entry written in the older args form", () => {
    const old = { matcher: "Bash|PowerShell", hooks: [{ type: "command", command: "node", args: ["/x/cli.mjs", "hook", "claude-code"] }] };
    const dir = projectWithSettings({ hooks: { PreToolUse: [old] } });
    expect(initClaude({ scope: "project", cwd: dir, cliPath: "/x/cli.mjs" }).changed).toBe(false);
  });
});
