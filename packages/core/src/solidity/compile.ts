import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import semver from "semver";
import { fetchBytes, fetchJson } from "../net/http";

const require = createRequire(import.meta.url);
const BINARIES = "https://binaries.soliditylang.org/bin";

export interface AbiParam {
  name: string;
  type: string;
  components?: AbiParam[];
}

export interface AbiItem {
  type: "function" | "constructor" | "receive" | "fallback" | "event" | "error";
  name?: string;
  inputs?: AbiParam[];
  stateMutability?: "pure" | "view" | "nonpayable" | "payable";
}

export interface CompiledContract {
  file: string;
  name: string;
  abi: AbiItem[];
  bytecode: string;
  /** "start()" -> "be9a6555" */
  methodIdentifiers: Record<string, string>;
}

export interface CompileResult {
  ok: boolean;
  compilerVersion?: string;
  contracts: CompiledContract[];
  errors: string[];
}

interface SolcCompiler {
  version(): string;
  compile(input: string): string;
}

interface BuildInfo {
  path: string;
  version: string;
  longVersion: string;
  sha256: string;
  prerelease?: string;
}

const compilerCache = new Map<string, Promise<SolcCompiler>>();

function defaultCacheDir(): string {
  const base = process.env.BOTGUARD_CACHE ?? (process.env.VERCEL ? join(tmpdir(), "botguard") : join(homedir(), ".botguard"));
  return join(base, "solc");
}

/** "^0.6.6", ">=0.6.0 <0.8.0", "0.8.19" -> semver range. Multiple pragmas are intersected. */
export function pragmaRange(sources: Record<string, string>): string | undefined {
  const ranges: string[] = [];
  for (const src of Object.values(sources)) {
    for (const m of src.matchAll(/pragma\s+solidity\s+([^;]+);/g)) ranges.push(m[1]!.trim().replace(/\s+/g, " "));
  }
  return ranges.length ? ranges.join(" ") : undefined;
}

function bundled(): SolcCompiler {
  return require("solc") as SolcCompiler;
}

async function remoteCompiler(build: BuildInfo, cacheDir: string): Promise<SolcCompiler> {
  mkdirSync(cacheDir, { recursive: true });
  const file = join(cacheDir, build.path);
  if (!existsSync(file)) {
    const bytes = await fetchBytes(`${BINARIES}/${build.path}`, { timeoutMs: 120_000, maxBytes: 40 * 1024 * 1024 });
    const digest = `0x${createHash("sha256").update(bytes).digest("hex")}`;
    if (digest !== build.sha256) throw new Error(`Checksum mismatch for ${build.path}`);
    writeFileSync(file, bytes);
  } else {
    const digest = `0x${createHash("sha256").update(readFileSync(file)).digest("hex")}`;
    if (digest !== build.sha256) throw new Error(`Cached compiler ${build.path} is corrupted; delete ${file}`);
  }
  const wrapper = require("solc/wrapper") as (soljson: unknown) => SolcCompiler;
  return wrapper(requireDownloaded(file));
}

/**
 * Node's own require for a compiler downloaded at runtime. Reached through process.getBuiltinModule so
 * bundlers (Next's Turbopack) leave it alone: a bundled require can't load a file that only exists at runtime.
 */
function requireDownloaded(file: string): unknown {
  const getBuiltin = (process as { getBuiltinModule?: (id: string) => unknown }).getBuiltinModule;
  const nodeModule = getBuiltin?.("node:module") as typeof import("node:module") | undefined;
  return (nodeModule ?? { createRequire }).createRequire(file)(file);
}

async function pickCompiler(range: string | undefined, cacheDir: string): Promise<SolcCompiler> {
  const local = bundled();
  const localVersion = semver.coerce(local.version())?.version;
  if (!range || (localVersion && semver.satisfies(localVersion, range))) return local;
  const list = await fetchJson<{ builds: BuildInfo[] }>(`${BINARIES}/list.json`, { timeoutMs: 20_000 });
  const releases = (list?.builds ?? []).filter((b) => !b.prerelease);
  const best = semver.maxSatisfying(releases.map((b) => b.version), range);
  if (!best) throw new Error(`No Solidity compiler satisfies "${range}"`);
  const build = releases.find((b) => b.version === best)!;
  let p = compilerCache.get(build.longVersion);
  if (!p) {
    p = remoteCompiler(build, cacheDir);
    compilerCache.set(build.longVersion, p);
    p.catch(() => compilerCache.delete(build.longVersion));
  }
  return p;
}

const IMPORT_HOSTS = /^https:\/\/(?:raw\.githubusercontent\.com|gist\.githubusercontent\.com|cdn\.jsdelivr\.net|unpkg\.com|ipfs\.io|dweb\.link)\//;

function githubBlobToRaw(url: string): string {
  return url.replace(/^https:\/\/github\.com\/([^/]+)\/([^/]+)\/(?:blob|raw)\/(.+)$/, "https://raw.githubusercontent.com/$1/$2/$3");
}

/** Where to fetch an import from, or undefined if we won't fetch it (local path we don't have). */
function importUrl(path: string, from: string, ozVersion: string): string | undefined {
  if (/^https?:\/\//.test(path)) return githubBlobToRaw(path.replace(/^http:/, "https:"));
  if (path.startsWith("ipfs://")) return `https://ipfs.io/ipfs/${path.slice(7)}`;
  if (path.startsWith("./") || path.startsWith("../")) {
    if (/^https:\/\//.test(from)) return new URL(path, from).toString();
    return undefined;
  }
  const npm = /^(@[^/]+\/[^/]+|[^@/][^/]*)\/(.+)$/.exec(path);
  if (!npm) return undefined;
  const pkg = npm[1] === "@openzeppelin/contracts" ? `${npm[1]}@${ozVersion}` : npm[1];
  return `https://cdn.jsdelivr.net/npm/${pkg}/${npm[2]}`;
}

/** Fetch remote and npm-style imports up front: solc-js import callbacks must be synchronous. */
async function resolveImports(sources: Record<string, string>, range: string | undefined, notes: string[]): Promise<Record<string, { content: string }>> {
  const out: Record<string, { content: string }> = {};
  for (const [k, v] of Object.entries(sources)) out[k] = { content: v };
  const ozVersion = range && semver.intersects(range, "<0.8.0") ? "3.4.2" : "4.9.6";
  const queue = Object.keys(sources).map((k) => ({ key: k, base: k }));
  let fetched = 0;
  while (queue.length) {
    const { key, base } = queue.shift()!;
    const content = out[key]!.content;
    for (const m of content.matchAll(/^\s*import\s+(?:[^"'\n]*from\s+)?["']([^"']+)["']/gm)) {
      const path = m[1]!;
      if (out[path]) continue;
      const url = importUrl(path, base, ozVersion);
      if (!url) continue;
      if (!IMPORT_HOSTS.test(url)) {
        notes.push(`Skipped import from untrusted host: ${path}`);
        continue;
      }
      if (++fetched > 40) {
        notes.push("Stopped resolving imports after 40 files.");
        return out;
      }
      try {
        const text = new TextDecoder().decode(await fetchBytes(url, { timeoutMs: 12_000, maxBytes: 1024 * 1024 }));
        out[path] = { content: text };
        queue.push({ key: path, base: url });
      } catch (err) {
        notes.push(`Could not fetch import ${path}: ${(err as Error).message}`);
      }
    }
  }
  return out;
}

export async function compileSolidity(
  sources: Record<string, string>,
  opts: { cacheDir?: string; notes: string[] },
): Promise<CompileResult> {
  const range = pragmaRange(sources);
  let compiler: SolcCompiler;
  try {
    compiler = await pickCompiler(range && semver.validRange(range) ? range : undefined, opts.cacheDir ?? defaultCacheDir());
  } catch (err) {
    return { ok: false, contracts: [], errors: [`Compiler unavailable: ${(err as Error).message}`] };
  }
  const input = {
    language: "Solidity",
    sources: await resolveImports(sources, range, opts.notes),
    settings: {
      optimizer: { enabled: false, runs: 200 },
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.methodIdentifiers"] } },
    },
  };
  const output = JSON.parse(compiler.compile(JSON.stringify(input))) as {
    errors?: { severity: string; formattedMessage?: string; message: string }[];
    contracts?: Record<string, Record<string, { abi: AbiItem[]; evm: { bytecode: { object: string }; methodIdentifiers?: Record<string, string> } }>>;
  };
  const errors = (output.errors ?? []).filter((e) => e.severity === "error").map((e) => (e.formattedMessage ?? e.message).trim());
  const contracts: CompiledContract[] = [];
  for (const [file, byName] of Object.entries(output.contracts ?? {})) {
    if (!(file in sources)) continue; // only the user's contracts, not fetched dependencies
    for (const [name, c] of Object.entries(byName)) {
      contracts.push({ file, name, abi: c.abi, bytecode: c.evm.bytecode.object, methodIdentifiers: c.evm.methodIdentifiers ?? {} });
    }
  }
  return { ok: errors.length === 0 && contracts.length > 0, compilerVersion: compiler.version(), contracts, errors };
}
