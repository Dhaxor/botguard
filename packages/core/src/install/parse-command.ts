import { parseGithubRef } from "../registry/github";
import type { Ecosystem } from "../types";

export type InstallIntent =
  | { kind: "package"; ecosystem: Ecosystem; name: string; spec?: string; executes: boolean; raw: string }
  | { kind: "manifest"; ecosystem: Ecosystem; file?: string; raw: string }
  | { kind: "repo"; owner: string; repo: string; ref?: string; url: string; raw: string }
  | { kind: "remote-archive"; url: string; ecosystem: Ecosystem; raw: string }
  | { kind: "pipe-to-shell"; url?: string; raw: string }
  | { kind: "custom-registry"; registry: string; ecosystem: Ecosystem; raw: string };

/** Split a shell line into simple commands on ; && || | & and newlines, honouring quotes. */
export function splitCommands(line: string): { words: string[]; pipedTo?: string[] }[] {
  const commands: string[][] = [];
  const pipes: boolean[] = [];
  let words: string[] = [];
  let cur = "";
  let quote: string | null = null;
  let hasWord = false;
  const pushWord = () => {
    if (hasWord) words.push(cur);
    cur = "";
    hasWord = false;
  };
  const pushCmd = (piped: boolean) => {
    pushWord();
    if (words.length) {
      commands.push(words);
      pipes.push(piped);
    }
    words = [];
  };
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (quote) {
      if (c === quote) quote = null;
      else if (c === "\\" && quote === '"' && i + 1 < line.length) cur += line[++i];
      else cur += c;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      hasWord = true;
    } else if (c === "\\" && i + 1 < line.length) {
      if (line[i + 1] === "\n") i++;
      else {
        cur += line[++i];
        hasWord = true;
      }
    } else if (c === " " || c === "\t") pushWord();
    else if (c === "\n" || c === "\r" || c === ";") pushCmd(false);
    else if (c === "&" || c === "|") {
      const doubled = line[i + 1] === c;
      if (doubled) i++;
      pushCmd(c === "|" && !doubled);
    } else if (c === "(" || c === ")" || c === "{" || c === "}") pushWord();
    else {
      cur += c;
      hasWord = true;
    }
  }
  pushCmd(false);
  return commands.map((w, i) => ({ words: w, pipedTo: pipes[i] ? commands[i + 1] : undefined }));
}

const WRAPPERS = new Set(["sudo", "doas", "time", "nohup", "exec", "command", "env", "nice", "call", "start", "cmd", "/c"]);
const NPM_INSTALL = new Set(["install", "i", "add", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "ci", "update", "up", "upgrade"]);
const NPM_FLAGS_WITH_VALUE = new Set(["--registry", "--prefix", "-C", "--cache", "--tag", "--workspace", "-w", "--filter", "--dir", "--userconfig", "--global-dir", "--cwd"]);
const PIP_FLAGS_WITH_VALUE = new Set(["-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url", "-t", "--target", "--prefix", "--root", "--python", "-f", "--find-links", "--platform", "--python-version", "--implementation", "--abi", "--src", "--upgrade-strategy", "--cache-dir", "--trusted-host", "--progress-bar", "--log", "--proxy", "--timeout", "--retries", "--group", "--with", "--from", "-p"]);

function stripWrappers(words: string[]): string[] {
  let i = 0;
  while (i < words.length && (WRAPPERS.has(words[i]!) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i]!))) i++;
  return words.slice(i);
}

function base(cmd: string): string {
  return cmd.replace(/\\/g, "/").split("/").pop()!.replace(/\.(exe|cmd|bat|ps1)$/i, "").toLowerCase();
}

/** "pkg@1.2", "@scope/pkg@^1", "alias@npm:real@2", github/url forms. */
function npmSpecIntent(arg: string, executes: boolean, raw: string): InstallIntent | null {
  if (/^(?:\.{1,2}\/|\/|~\/|[A-Za-z]:[\\/]|file:|link:|workspace:)/.test(arg) || arg === ".") return null;
  if (/^https?:\/\/.+\.(?:tgz|tar\.gz)(?:[?#].*)?$/i.test(arg)) return { kind: "remote-archive", url: arg, ecosystem: "npm", raw };
  if (/^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:\/\/(?:www\.)?github\.com)/i.test(arg) || /^[\w.-]+\/[\w.-]+(?:#.+)?$/.test(arg)) {
    const ref = parseGithubRef(arg);
    if (ref) return { kind: "repo", owner: ref.owner, repo: ref.repo, ref: ref.ref, url: `https://github.com/${ref.owner}/${ref.repo}`, raw };
    return null;
  }
  const alias = /^(?:@[^/@]+\/)?[^@]+@npm:((?:@[^/@]+\/)?[^@]+)(?:@(.+))?$/.exec(arg);
  if (alias) return { kind: "package", ecosystem: "npm", name: alias[1]!, spec: alias[2], executes, raw };
  const m = /^((?:@[a-z0-9][\w.-]*\/)?[a-z0-9~][\w.-]*)(?:@(.+))?$/i.exec(arg);
  if (!m) return null;
  return { kind: "package", ecosystem: "npm", name: m[1]!, spec: m[2], executes, raw };
}

function pipSpecIntent(arg: string, executes: boolean, raw: string): InstallIntent | null {
  if (/^(?:\.{1,2}[\\/]|\/|~\/|[A-Za-z]:[\\/])/.test(arg) || arg === ".") return null;
  const gitUrl = /^git\+(https?:\/\/[^@#\s]+?)(?:\.git)?(?:@([^#\s]+))?(?:#.*)?$/.exec(arg);
  if (gitUrl) {
    const ref = parseGithubRef(gitUrl[1]!);
    if (ref) return { kind: "repo", owner: ref.owner, repo: ref.repo, ref: gitUrl[2], url: `https://github.com/${ref.owner}/${ref.repo}`, raw };
    return { kind: "remote-archive", url: gitUrl[1]!, ecosystem: "pypi", raw };
  }
  if (/^https?:\/\//i.test(arg)) return { kind: "remote-archive", url: arg, ecosystem: "pypi", raw };
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*((?:===?|~=|>=|<=|!=|>|<)[^;\s]*(?:,(?:===?|~=|>=|<=|!=|>|<)[^;\s]*)*)?/.exec(arg);
  if (!m) return null;
  return { kind: "package", ecosystem: "pypi", name: m[1]!, spec: m[2] || undefined, executes, raw };
}

function parseNpmFamily(tool: string, args: string[], raw: string, out: InstallIntent[]): void {
  // npx / pnpm dlx / bunx / yarn dlx / npm exec: first positional is a package that will be executed.
  const execLike = tool === "npx" || tool === "pnpx" || tool === "bunx";
  let sub = execLike ? "exec" : args[0]?.toLowerCase();
  let rest = execLike ? args : args.slice(1);
  if (tool === "yarn" && (sub === undefined || sub.startsWith("-"))) {
    out.push({ kind: "manifest", ecosystem: "npm", raw });
    return;
  }
  if (tool === "npm" && (sub === "exec" || sub === "x")) sub = "exec";
  if ((tool === "pnpm" || tool === "yarn") && sub === "dlx") sub = "exec";
  if (tool === "bun" && sub === "x") sub = "exec";
  if ((tool === "npm" || tool === "pnpm" || tool === "yarn" || tool === "bun") && (sub === "create" || sub === "init")) {
    const initializer = rest.find((a) => !a.startsWith("-"));
    if (!initializer) return;
    const name = initializer.startsWith("@") ? initializer.replace(/^(@[^/]+)(?:\/(.+))?$/, (_m, s, n) => `${s}/create${n ? `-${n}` : ""}`) : `create-${initializer.replace(/@.*$/, "")}`;
    out.push({ kind: "package", ecosystem: "npm", name, executes: true, raw });
    return;
  }
  const isInstall = sub !== undefined && (NPM_INSTALL.has(sub) || (tool === "bun" && sub === "a") || (tool === "pnpm" && sub === "i"));
  if (!isInstall && sub !== "exec") return;
  const positional: string[] = [];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a === "--") {
      if (sub === "exec") break;
      continue;
    }
    if (a.startsWith("--registry=")) out.push({ kind: "custom-registry", registry: a.slice(11), ecosystem: "npm", raw });
    else if (a === "--registry" && rest[i + 1]) out.push({ kind: "custom-registry", registry: rest[i + 1]!, ecosystem: "npm", raw });
    if (a === "-p" || a === "--package") {
      if (rest[i + 1]) positional.push(rest[++i]!);
      continue;
    }
    if (a.startsWith("--package=")) {
      positional.push(a.slice(10));
      continue;
    }
    if (a.startsWith("-")) {
      if (NPM_FLAGS_WITH_VALUE.has(a) && !a.includes("=")) i++;
      continue;
    }
    positional.push(a);
    if (sub === "exec") break; // the rest are arguments to the executed binary
  }
  if (sub === "exec") {
    const pkg = positional[0];
    if (pkg) {
      const intent = npmSpecIntent(pkg, true, raw);
      if (intent) out.push(intent);
    }
    return;
  }
  if (!positional.length) {
    if (sub === "install" || sub === "i" || sub === "ci" || tool === "bun" || tool === "pnpm") out.push({ kind: "manifest", ecosystem: "npm", raw });
    return;
  }
  for (const p of positional) {
    const intent = npmSpecIntent(p, false, raw);
    if (intent) out.push(intent);
  }
}

function parsePipArgs(args: string[], raw: string, out: InstallIntent[], executes = false): void {
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "-r" || a === "--requirement") {
      if (args[i + 1]) out.push({ kind: "manifest", ecosystem: "pypi", file: args[++i], raw });
      continue;
    }
    if (a.startsWith("--requirement=") || /^-r\S/.test(a)) {
      out.push({ kind: "manifest", ecosystem: "pypi", file: a.replace(/^--requirement=|^-r/, ""), raw });
      continue;
    }
    if (a === "-i" || a === "--index-url" || a === "--extra-index-url") {
      const v = args[i + 1];
      if (v && !/pypi\.org\/simple/.test(v)) out.push({ kind: "custom-registry", registry: v, ecosystem: "pypi", raw });
      i++;
      continue;
    }
    if (/^--(?:extra-)?index-url=/.test(a)) {
      const v = a.split("=").slice(1).join("=");
      if (!/pypi\.org\/simple/.test(v)) out.push({ kind: "custom-registry", registry: v, ecosystem: "pypi", raw });
      continue;
    }
    if (a.startsWith("-")) {
      if (PIP_FLAGS_WITH_VALUE.has(a)) i++;
      continue;
    }
    const intent = pipSpecIntent(a, executes, raw);
    if (intent) out.push(intent);
  }
}

function parsePythonFamily(tool: string, args: string[], raw: string, out: InstallIntent[]): void {
  if (tool === "pip" || /^pip\d/.test(tool)) {
    if (args[0] === "install" || args[0] === "download") parsePipArgs(args.slice(1), raw, out);
    return;
  }
  if (/^(?:python|py)\d?(?:\.\d+)?$/.test(tool)) {
    const m = args.indexOf("-m");
    if (m >= 0 && args[m + 1] === "pip" && args[m + 2] === "install") parsePipArgs(args.slice(m + 3), raw, out);
    return;
  }
  if (tool === "uv") {
    if (args[0] === "pip" && args[1] === "install") parsePipArgs(args.slice(2), raw, out);
    else if (args[0] === "add") parsePipArgs(args.slice(1), raw, out);
    else if (args[0] === "tool" && (args[1] === "install" || args[1] === "run")) parsePipArgs(args.slice(2, 3), raw, out, args[1] === "run");
    else if (args[0] === "run" && args.includes("--with")) parsePipArgs([args[args.indexOf("--with") + 1] ?? ""], raw, out);
    else if (args[0] === "sync") out.push({ kind: "manifest", ecosystem: "pypi", raw });
    return;
  }
  if (tool === "uvx") {
    const first = args.find((a) => !a.startsWith("-"));
    if (first) parsePipArgs([first], raw, out, true);
    return;
  }
  if (tool === "pipx" && (args[0] === "install" || args[0] === "run")) {
    const first = args.slice(1).find((a) => !a.startsWith("-"));
    if (first) parsePipArgs([first], raw, out, args[0] === "run");
    return;
  }
  if ((tool === "poetry" || tool === "pdm" || tool === "rye" || tool === "hatch") && args[0] === "add") parsePipArgs(args.slice(1), raw, out);
  else if ((tool === "poetry" || tool === "pdm") && args[0] === "install") out.push({ kind: "manifest", ecosystem: "pypi", raw });
}

/** Everything in a shell command that would fetch and run third-party code. */
export function parseInstallCommand(command: string): InstallIntent[] {
  const out: InstallIntent[] = [];
  for (const { words, pipedTo } of splitCommands(command)) {
    const w = stripWrappers(words);
    if (!w.length) continue;
    const tool = base(w[0]!);
    const args = w.slice(1);
    const raw = w.join(" ").slice(0, 300);

    if (["npm", "pnpm", "yarn", "bun", "npx", "pnpx", "bunx"].includes(tool)) parseNpmFamily(tool, args, raw, out);
    else if (/^(?:pip\d?(?:\.\d+)?|python\d?(?:\.\d+)?|py|uv|uvx|pipx|poetry|pdm|rye|hatch)$/.test(tool)) parsePythonFamily(tool, args, raw, out);
    else if (tool === "git" && args[0] === "clone") {
      const url = args.slice(1).find((a) => !a.startsWith("-") && /github\.com|^git@/.test(a));
      const ref = url ? parseGithubRef(url) : null;
      if (ref) out.push({ kind: "repo", owner: ref.owner, repo: ref.repo, ref: ref.ref, url: `https://github.com/${ref.owner}/${ref.repo}`, raw });
    } else if (tool === "gh" && args[0] === "repo" && args[1] === "clone" && args[2]) {
      const ref = parseGithubRef(args[2]);
      if (ref) out.push({ kind: "repo", owner: ref.owner, repo: ref.repo, url: `https://github.com/${ref.owner}/${ref.repo}`, raw });
    } else if (["curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod"].includes(tool) && pipedTo) {
      const sink = base(stripWrappers(pipedTo)[0] ?? "");
      if (/^(?:ba|z|da|k)?sh$|^iex$|^invoke-expression$|^python\d?$|^node$|^pwsh$|^powershell$/.test(sink)) {
        out.push({ kind: "pipe-to-shell", url: args.find((a) => /^https?:\/\//i.test(a)), raw: `${raw} | ${sink}` });
      }
    }
  }
  return out;
}
