import type { Ecosystem, Finding, SourceFile } from "../types";
import { LineIndex } from "./text";

export interface Dependency {
  ecosystem: Ecosystem;
  name: string;
  /** Range/specifier as written, if any. */
  spec?: string;
  /** Exact version when pinned (lockfile or ==). */
  version?: string;
  /** Manifest the dependency came from. */
  source: string;
  direct: boolean;
}

export interface ManifestResult {
  findings: Finding[];
  dependencies: Dependency[];
  /** Paths (relative to the scan root) that execute automatically during install. */
  installTime: Set<string>;
}

const INSTALL_HOOKS = ["preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare"];
const BENIGN_SCRIPT =
  /^(?:husky(?: install)?|is-ci \|\| husky(?: install)?|patch-package|node-gyp rebuild|prebuild-install(?: \|\| node-gyp rebuild)?|node-gyp-build|ngcc|lerna bootstrap|npm run build|pnpm build|yarn build|tsc(?: -p \S+)?|prisma generate|svelte-kit sync|nuxt prepare|electron-builder install-app-deps|simple-git-hooks|lefthook install|opencollective-postinstall(?: \|\| true)?|node scripts\/postinstall\.js|exit 0|echo .*)$/;
const DANGEROUS_SCRIPT =
  /\bcurl\b|\bwget\b|powershell|Invoke-WebRequest|\biwr\b|certutil|bitsadmin|node\s+-e\b|node\s+--eval|python[0-9.]*\s+-c\b|base64\s+(?:-d|--decode)|\beval\b|\|\s*(?:ba)?sh\b|https?:\/\//i;

function dirOf(path: string): string {
  const i = path.lastIndexOf("/");
  return i < 0 ? "" : path.slice(0, i + 1);
}

function normalize(path: string): string {
  const out: string[] = [];
  for (const part of path.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") out.pop();
    else out.push(part);
  }
  return out.join("/");
}

/** Files a script line runs: "node scripts/x.js", "python setup_hook.py", "sh ./install.sh". */
function scriptTargets(script: string, base: string): string[] {
  const out: string[] = [];
  for (const m of script.matchAll(/\b(?:node|nodejs|bun|deno run|tsx|ts-node|python[0-9.]*|sh|bash|zsh|pwsh|powershell(?:\.exe)?(?:\s+-File)?)\s+(?:-\S+\s+)*["']?([\w./\\-]+\.(?:[cm]?js|ts|py|sh|ps1))/g)) {
    out.push(normalize(base + m[1]!.replace(/\\/g, "/")));
  }
  return out;
}

function urlOrGitSpec(spec: string): boolean {
  return /^(?:https?:|git\+|git:|github:|gitlab:|bitbucket:|[\w.-]+\/[\w.-]+(?:#.*)?$)/.test(spec) && !spec.startsWith("npm:");
}

function analyzePackageJson(file: SourceFile, isRoot: boolean, result: ManifestResult): void {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(file.text) as Record<string, unknown>;
  } catch {
    return;
  }
  const base = dirOf(file.path);
  const lines = new LineIndex(file.text);
  const scripts = (pkg.scripts ?? {}) as Record<string, string>;
  for (const hook of INSTALL_HOOKS) {
    const script = scripts[hook];
    if (typeof script !== "string" || !script.trim()) continue;
    // "prepare" only runs for git/local installs; still relevant when you clone and npm install a repo.
    for (const t of scriptTargets(script, base)) result.installTime.add(t);
    const at = file.text.indexOf(`"${hook}"`);
    const evidence = [at >= 0 ? lines.evidence(file.path, at, hook.length) : { file: file.path, snippet: `${hook}: ${script}` }];
    if (DANGEROUS_SCRIPT.test(script)) {
      result.findings.push({
        id: "manifest.install-script-download",
        severity: "high",
        category: "install-script",
        title: `"${hook}" script downloads or evaluates code during install`,
        detail: `npm runs this automatically: \`${script.slice(0, 160)}\`. Fetching or evaluating code at install time is how most npm malware triggers.`,
        evidence,
      });
    } else if (!BENIGN_SCRIPT.test(script.trim())) {
      result.findings.push({
        id: "manifest.install-script",
        severity: isRoot ? "low" : "info",
        category: "install-script",
        title: `Runs a "${hook}" script automatically`,
        detail: `npm executes \`${script.slice(0, 160)}\` on install. The files it runs were scanned with extra suspicion.`,
        evidence,
      });
    }
  }

  for (const field of ["dependencies", "optionalDependencies", "devDependencies", "peerDependencies"] as const) {
    const deps = (pkg[field] ?? {}) as Record<string, string>;
    for (const [name, spec] of Object.entries(deps)) {
      if (typeof spec !== "string") continue;
      if (spec.startsWith("workspace:") || spec.startsWith("file:") || spec.startsWith("link:")) continue;
      if (urlOrGitSpec(spec) && field !== "devDependencies") {
        const at = file.text.indexOf(`"${name}"`);
        result.findings.push({
          id: "manifest.url-dependency",
          severity: "medium",
          category: "install-script",
          title: "Depends on code fetched from a URL or git repo",
          detail: `"${name}": "${spec}" bypasses the npm registry, where packages are at least scanned and can be taken down.`,
          evidence: at >= 0 ? [lines.evidence(file.path, at, name.length)] : undefined,
        });
        continue;
      }
      const alias = /^npm:(@?[^@]+)@?(.*)$/.exec(spec);
      result.dependencies.push({
        ecosystem: "npm",
        name: alias ? alias[1]! : name,
        spec: alias ? alias[2] || undefined : spec,
        source: file.path,
        direct: true,
      });
    }
  }
}

function analyzeSetupPy(file: SourceFile, result: ManifestResult): void {
  result.installTime.add(file.path);
  const lines = new LineIndex(file.text);
  const cmd = /cmdclass\s*=|class\s+\w+\s*\(\s*(?:install|develop|egg_info|build_py|sdist|bdist_egg)\s*\)/.exec(file.text);
  if (cmd) {
    result.findings.push({
      id: "manifest.setup-cmdclass",
      severity: "low",
      category: "install-script",
      title: "setup.py overrides install commands",
      detail: "Custom install/develop/egg_info commands run arbitrary Python during `pip install`. setup.py was scanned with extra suspicion.",
      evidence: [lines.evidence(file.path, cmd.index, cmd[0].length)],
    });
  }
  for (const m of file.text.matchAll(/install_requires\s*=\s*\[([^\]]*)\]/g)) {
    for (const req of quotedStrings(m[1]!)) pushRequirement(req, file.path, result);
  }
}

/** String literals in a Python/TOML list, keeping "x; marker == 'y'" intact. */
function quotedStrings(list: string): string[] {
  return [...list.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g)].map((m) => (m[1] ?? m[2] ?? "").replace(/\\"/g, '"'));
}

function pushRequirement(line: string, source: string, result: ManifestResult): void {
  const clean = line.replace(/\s+#.*$/, "").trim();
  if (!clean || clean.startsWith("#") || clean.startsWith("-")) return;
  if (/^(?:git\+|https?:)/.test(clean) || clean.includes(" @ ")) {
    result.findings.push({
      id: "manifest.url-requirement",
      severity: "low",
      category: "install-script",
      title: "Installs a Python dependency from a URL",
      detail: `\`${clean.slice(0, 160)}\` skips PyPI, so nothing vets what gets downloaded.`,
      evidence: [{ file: source, snippet: clean.slice(0, 160) }],
    });
    return;
  }
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*((?:[<>=!~]=?|===)\s*[^;\s]+(?:\s*,\s*(?:[<>=!~]=?|===)\s*[^;\s]+)*)?/.exec(clean);
  if (!m) return;
  const spec = m[2]?.replace(/\s+/g, "");
  const exact = spec && /^===?([^,*]+)$/.exec(spec);
  result.dependencies.push({ ecosystem: "pypi", name: m[1]!, spec, version: exact ? exact[1] : undefined, source, direct: true });
}

function analyzeRequirements(file: SourceFile, result: ManifestResult): void {
  const lines = new LineIndex(file.text);
  for (const m of file.text.matchAll(/^\s*(?:--(?:extra-)?index-url|-i)\s+(\S+)/gm)) {
    if (/pypi\.org\/simple/.test(m[1]!)) continue;
    result.findings.push({
      id: "manifest.custom-index",
      severity: "medium",
      category: "install-script",
      title: "Pulls packages from a non-PyPI index",
      detail: `pip will consult ${m[1]} as well as or instead of PyPI. Attackers use extra indexes for dependency-confusion attacks.`,
      evidence: [lines.evidence(file.path, m.index, m[0].length)],
    });
  }
  for (const line of file.text.split(/\r?\n/)) pushRequirement(line, file.path, result);
}

function analyzePyproject(file: SourceFile, result: ManifestResult): void {
  // Either `dependencies = ["a", "b[x]>=1"]` on one line, or a multi-line array closed by a "]" line.
  const deps = /^\s*dependencies\s*=\s*\[(.*)\]\s*$/m.exec(file.text) ?? /^\s*dependencies\s*=\s*\[\s*$([\s\S]*?)^\s*\]/m.exec(file.text);
  if (deps) for (const req of quotedStrings(deps[1]!)) pushRequirement(req, file.path, result);
  const poetry = /\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\n\[|$)/.exec(file.text);
  if (poetry) {
    for (const m of poetry[1]!.matchAll(/^\s*([A-Za-z0-9][\w.-]*)\s*=/gm)) {
      if (m[1]!.toLowerCase() !== "python") result.dependencies.push({ ecosystem: "pypi", name: m[1]!, source: file.path, direct: true });
    }
  }
}

function analyzePth(file: SourceFile, result: ManifestResult): void {
  const m = /^\s*import\s.+$/m.exec(file.text);
  if (!m) return;
  result.findings.push({
    id: "manifest.pth-autorun",
    severity: "high",
    category: "persistence",
    title: "Ships a .pth file that runs code on every Python start",
    detail: "Lines starting with `import` in a .pth file execute whenever any Python program starts, a known way for malicious packages to stay active.",
    evidence: [new LineIndex(file.text).evidence(file.path, m.index, m[0].length)],
  });
}

function analyzePackageLock(file: SourceFile, result: ManifestResult): void {
  let lock: { packages?: Record<string, { version?: string; resolved?: string }>; dependencies?: Record<string, unknown> };
  try {
    lock = JSON.parse(file.text);
  } catch {
    return;
  }
  if (lock.packages) {
    for (const [key, info] of Object.entries(lock.packages)) {
      const i = key.lastIndexOf("node_modules/");
      if (i < 0 || !info?.version) continue;
      result.dependencies.push({ ecosystem: "npm", name: key.slice(i + 13), version: info.version, source: file.path, direct: false });
    }
    return;
  }
  const walk = (deps: Record<string, unknown> | undefined) => {
    for (const [name, raw] of Object.entries(deps ?? {})) {
      const info = raw as { version?: string; dependencies?: Record<string, unknown> };
      if (info?.version && !/^(?:file|link|git)/.test(info.version)) {
        result.dependencies.push({ ecosystem: "npm", name, version: info.version, source: file.path, direct: false });
      }
      walk(info?.dependencies);
    }
  };
  walk(lock.dependencies);
}

function analyzeYarnLock(file: SourceFile, result: ManifestResult): void {
  for (const m of file.text.matchAll(/^"?(@?[^@\s"]+)@[^\n]*:\n\s+version:?\s+"?([^"\s]+)"?/gm)) {
    result.dependencies.push({ ecosystem: "npm", name: m[1]!, version: m[2]!, source: file.path, direct: false });
  }
}

function analyzePnpmLock(file: SourceFile, result: ManifestResult): void {
  for (const m of file.text.matchAll(/^\s{2}'?\/?(@?[^@\s'/][^@\s']*(?:\/[^@\s']+)?)@(\d[^:'\s(]*)/gm)) {
    result.dependencies.push({ ecosystem: "npm", name: m[1]!, version: m[2]!, source: file.path, direct: false });
  }
}

function analyzePoetryLock(file: SourceFile, result: ManifestResult): void {
  for (const m of file.text.matchAll(/\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g)) {
    result.dependencies.push({ ecosystem: "pypi", name: m[1]!, version: m[2]!, source: file.path, direct: false });
  }
}

/** Manifests, lockfiles and install hooks. `rootDepth` limits which package.json counts as the project root. */
export function analyzeManifests(files: SourceFile[]): ManifestResult {
  const result: ManifestResult = { findings: [], dependencies: [], installTime: new Set() };
  for (const file of files) {
    const name = file.path.split("/").pop()!.toLowerCase();
    if (name === "package.json") analyzePackageJson(file, !file.path.includes("/"), result);
    else if (name === "setup.py") analyzeSetupPy(file, result);
    else if (/^requirements[^/]*\.(txt|in)$/.test(name)) analyzeRequirements(file, result);
    else if (name === "pyproject.toml") analyzePyproject(file, result);
    else if (name.endsWith(".pth")) analyzePth(file, result);
    else if (name === "package-lock.json" || name === "npm-shrinkwrap.json") analyzePackageLock(file, result);
    else if (name === "yarn.lock") analyzeYarnLock(file, result);
    else if (name === "pnpm-lock.yaml") analyzePnpmLock(file, result);
    else if (name === "poetry.lock") analyzePoetryLock(file, result);
  }
  return result;
}
