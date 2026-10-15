import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { analyzeManifests } from "../analyzers/manifest";
import { daysSince, repoSignals } from "../analyzers/repo";
import { TRUSTED_INSTALL_HOSTS } from "../analyzers/rules";
import { scanScamText } from "../analyzers/scam-text";
import { isOfficialPublisher, matchBrands } from "../intel/brands";
import { checkDependencies } from "../intel/deps";
import { osvQuery } from "../intel/osv";
import { canonicalPypi, findTyposquat, isPopular } from "../intel/popular";
import { fetchGithubRaw, getGithubOwner, getGithubRepo } from "../registry/github";
import { getNpmPackument, getNpmVersion, getNpmWeeklyDownloads, isDirectSpec, npmScope, repoUrlOf, resolveNpmSpec } from "../registry/npm";
import { getPypiProject, pypiCreated, pypiRepoUrl, resolvePypiSpec } from "../registry/pypi";
import type { Finding, SourceFile } from "../types";
import { severityRank, sortFindings } from "../verdict";
import { parseInstallCommand, type InstallIntent } from "./parse-command";

export type Decision = "allow" | "ask" | "deny";

export interface IntentVerdict {
  label: string;
  decision: Decision;
  findings: Finding[];
}

export interface CheckResult {
  decision: Decision;
  /** Explanation for Claude (deny) or the user (ask). Empty when everything is allowed. */
  reason: string;
  verdicts: IntentVerdict[];
  notes: string[];
}

export interface CheckOptions {
  cwd?: string;
  /** Package names or owner/repo the user explicitly trusts. */
  allow?: string[];
  /** Cache file path; false disables caching. */
  cachePath?: string | false;
}

const INSTALL_HOOK_DANGER = /\bcurl\b|\bwget\b|powershell|Invoke-WebRequest|\biwr\b|node\s+-e\b|python[0-9.]*\s+-c\b|base64|\beval\b|https?:\/\//i;
const CACHE_TTL: Record<Decision, number> = { allow: 12 * 3600_000, ask: 24 * 3600_000, deny: 7 * 24 * 3600_000 };

type CacheEntry = { at: number; verdict: IntentVerdict };

function loadCache(path: string): Record<string, CacheEntry> {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as Record<string, CacheEntry>;
  } catch {
    return {};
  }
}

function saveCache(path: string, cache: Record<string, CacheEntry>): void {
  try {
    mkdirSync(dirname(path), { recursive: true });
    const now = Date.now();
    const kept = Object.entries(cache).filter(([, e]) => now - e.at < CACHE_TTL.deny).slice(-2000);
    writeFileSync(path, JSON.stringify(Object.fromEntries(kept)));
  } catch {
    /* best effort */
  }
}

/** critical -> deny; high -> deny (strict) or ask; medium -> ask; low/info -> allow. */
export function decide(findings: Finding[], strict = true): Decision {
  const worst = sortFindings(findings)[0]?.severity;
  if (!worst) return "allow";
  if (worst === "critical") return "deny";
  if (worst === "high") return strict ? "deny" : "ask";
  if (worst === "medium") return "ask";
  return "allow";
}

function mergeDecision(a: Decision, b: Decision): Decision {
  const rank: Record<Decision, number> = { deny: 0, ask: 1, allow: 2 };
  return rank[a] <= rank[b] ? a : b;
}

function squatF(name: string, target: string, severity: Finding["severity"], detail: string): Finding {
  return { id: "pkg.typosquat", severity, category: "typosquat", title: `"${name}" looks like a typosquat of "${target}"`, detail, advice: `did you mean "${target}"?` };
}

// ------------------------------------------------------------------------------------ packages

async function checkNpmPackage(name: string, spec: string | undefined, executes: boolean): Promise<IntentVerdict> {
  const label = `${name}${spec ? `@${spec}` : ""} (npm${executes ? ", runs immediately" : ""})`;
  const findings: Finding[] = [];
  const popular = isPopular(name, "npm");
  let created: string | undefined;
  let doc = null;
  if (popular && isDirectSpec(spec)) doc = await getNpmVersion(name, spec || "latest");
  else {
    const p = await getNpmPackument(name);
    if (p) {
      const v = resolveNpmSpec(p, spec);
      doc = v ? p.versions[v] ?? null : null;
      created = p.time?.created;
    }
  }
  if (!doc) {
    // Not on npm: the install will fail. Still worth flagging hallucinated names that squat popular ones.
    const squat = findTyposquat(name, "npm");
    if (squat) findings.push(squatF(name, squat.target, "medium", "npm has no such package right now, so this install fails, but the name is a near-miss of a popular package. Don't retry with a similar-looking name."));
    return { label, decision: decide(findings), findings };
  }
  const resolved = `${name}@${doc.version} (npm${executes ? ", runs immediately" : ""})`;
  const [advisories, weekly] = await Promise.all([osvQuery({ ecosystem: "npm", name, version: doc.version }).catch(() => []), getNpmWeeklyDownloads(name)]);
  const mal = advisories.filter((a) => a.malicious);
  if (mal.length) {
    findings.push({
      id: "intel.osv-malicious",
      severity: "critical",
      category: "intel",
      title: `known malware (${mal.map((m) => m.id).join(", ")})`,
      detail: mal[0]!.summary ?? "Listed in the OSV / OpenSSF malicious-packages database.",
      evidence: mal.map((m) => ({ url: m.url })),
    });
  }
  if (doc.version.endsWith("-security")) {
    findings.push({ id: "intel.npm-security-placeholder", severity: "critical", category: "intel", title: "taken down by npm for being malicious", detail: "Only a 0.0.1-security placeholder remains." });
  }
  if (!popular) {
    const squat = findTyposquat(name, "npm");
    if (squat && (weekly === null || weekly < 5000)) {
      findings.push(squatF(name, squat.target, weekly === null || weekly < 1000 ? "high" : "medium", `${weekly ?? "unknown"} weekly downloads, versus one of npm's most-used packages.`));
    }
    const ageDays = daysSince(created);
    for (const brand of matchBrands(name)) {
      const emails = [doc._npmUser?.email, ...(doc.maintainers ?? []).map((m) => m.email)].filter((e): e is string => Boolean(e));
      if (isOfficialPublisher(brand, { scope: npmScope(name), emails })) continue;
      const claims = isOfficialPublisher(brand, { repositoryUrl: repoUrlOf(doc.repository), homepage: doc.homepage });
      const fresh = (ageDays !== undefined && ageDays < 120) || (weekly !== null && weekly < 500);
      findings.push({
        id: "pkg.brand",
        severity: claims || fresh ? "high" : "medium",
        category: "typosquat",
        title: `uses the ${brand.label} name but isn't published by ${brand.label}`,
        detail: `${ageDays !== undefined ? `First published ${ageDays} days ago, ` : ""}${weekly ?? "unknown"} downloads last week.`,
        advice: brand.npmScopes[0] ? `official packages live under ${brand.npmScopes[0]}/` : undefined,
      });
      break;
    }
    if (ageDays !== undefined && ageDays < 7) {
      findings.push({ id: "pkg.new", severity: "medium", category: "metadata", title: `first published ${ageDays} day(s) ago`, detail: "Brand-new packages are where most npm malware lives." });
    }
    const hooks = Object.entries(doc.scripts ?? {}).filter(([k]) => k === "preinstall" || k === "install" || k === "postinstall");
    for (const [hook, script] of hooks) {
      if (INSTALL_HOOK_DANGER.test(script)) {
        findings.push({ id: "pkg.install-hook-danger", severity: "high", category: "install-script", title: `runs a risky "${hook}" script: ${script.slice(0, 80)}`, detail: "It runs automatically during install." });
      } else if ((weekly ?? 0) < 1000) {
        findings.push({ id: "pkg.install-hook", severity: "low", category: "install-script", title: `runs a "${hook}" script on install`, detail: script.slice(0, 120) });
      }
    }
  }
  return { label: resolved, decision: decide(findings), findings };
}

async function checkPypiPackage(name: string, spec: string | undefined, executes: boolean): Promise<IntentVerdict> {
  const label = `${name}${spec ?? ""} (PyPI${executes ? ", runs immediately" : ""})`;
  const findings: Finding[] = [];
  const project = await getPypiProject(name);
  if (!project) {
    const squat = findTyposquat(name, "pypi");
    if (squat) findings.push(squatF(name, squat.target, "medium", "PyPI has no such project right now, so this install fails, but the name is a near-miss of a popular one."));
    return { label, decision: decide(findings), findings };
  }
  const version = resolvePypiSpec(project, spec);
  const resolved = `${project.info.name}==${version ?? "?"} (PyPI${executes ? ", runs immediately" : ""})`;
  if (version) {
    const advisories = await osvQuery({ ecosystem: "pypi", name: canonicalPypi(name), version }).catch(() => []);
    const mal = advisories.filter((a) => a.malicious);
    if (mal.length) {
      findings.push({ id: "intel.osv-malicious", severity: "critical", category: "intel", title: `known malware (${mal.map((m) => m.id).join(", ")})`, detail: mal[0]!.summary ?? "Listed in the OSV / OpenSSF malicious-packages database.", evidence: mal.map((m) => ({ url: m.url })) });
    }
  }
  if (!isPopular(name, "pypi")) {
    const ageDays = daysSince(pypiCreated(project));
    const squat = findTyposquat(name, "pypi");
    if (squat) findings.push(squatF(name, squat.target, ageDays !== undefined && ageDays < 365 ? "high" : "medium", `"${squat.target}" is one of PyPI's most downloaded projects; this one is not.`));
    const emails = `${project.info.author_email ?? ""},${project.info.maintainer_email ?? ""}`.match(/[\w.+-]+@[\w.-]+/g) ?? [];
    for (const brand of matchBrands(name)) {
      const official = isOfficialPublisher(brand, { repositoryUrl: pypiRepoUrl(project.info), homepage: project.info.home_page, emails }) && (ageDays ?? 0) > 60;
      if (official) continue;
      findings.push({
        id: "pkg.brand",
        severity: ageDays !== undefined && ageDays < 120 ? "high" : "medium",
        category: "typosquat",
        title: `uses the ${brand.label} name but isn't published by ${brand.label}`,
        detail: ageDays !== undefined ? `First uploaded ${ageDays} days ago.` : "Check who publishes it.",
      });
      break;
    }
    if (ageDays !== undefined && ageDays < 7) {
      findings.push({ id: "pkg.new", severity: "medium", category: "metadata", title: `first uploaded ${ageDays} day(s) ago`, detail: "Brand-new packages are where most PyPI malware lives." });
    }
  }
  return { label: resolved, decision: decide(findings), findings };
}

// ------------------------------------------------------------------------------- manifests/repos

function readLocal(cwd: string, file: string): SourceFile | null {
  const path = isAbsolute(file) ? file : join(cwd, file);
  if (!existsSync(path)) return null;
  try {
    const text = readFileSync(path, "utf8");
    return { path: file.replace(/\\/g, "/"), text, size: text.length };
  } catch {
    return null;
  }
}

async function checkManifest(intent: Extract<InstallIntent, { kind: "manifest" }>, cwd: string, notes: string[]): Promise<IntentVerdict> {
  const names =
    intent.ecosystem === "npm"
      ? ["package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"]
      : intent.file
        ? [intent.file]
        : ["requirements.txt", "pyproject.toml", "poetry.lock"];
  const files = names.map((n) => readLocal(cwd, n)).filter((f): f is SourceFile => f !== null);
  const label = intent.ecosystem === "npm" ? "the project's npm dependencies" : `requirements in ${intent.file ?? "the project"}`;
  if (!files.length) return { label, decision: "allow", findings: [] };
  const manifest = analyzeManifests(files);
  const findings = await checkDependencies(manifest.dependencies, { notes, skipDownloads: true });
  findings.push(...manifest.findings.filter((f) => f.id === "manifest.install-script-download" || f.id === "manifest.custom-index"));
  // Dependencies the user already chose: a typosquat signal is worth a question, not a block. Malware still blocks.
  return { label, decision: decide(findings, false), findings };
}

async function checkRepo(intent: Extract<InstallIntent, { kind: "repo" }>, notes: string[]): Promise<IntentVerdict> {
  const ref = { owner: intent.owner, repo: intent.repo, ref: intent.ref };
  const label = `github.com/${intent.owner}/${intent.repo}`;
  const findings: Finding[] = [];
  const repo = await getGithubRepo(ref).catch(() => null);
  if (repo) {
    const owner = await getGithubOwner(repo.owner.login).catch(() => null);
    findings.push(...repoSignals({ repo, owner }));
  }
  const [readme, pkg, reqs] = await Promise.all([fetchGithubRaw(ref, "README.md"), fetchGithubRaw(ref, "package.json"), fetchGithubRaw(ref, "requirements.txt")]);
  if (readme) findings.push(...scanScamText([{ path: "README.md", text: readme, size: readme.length }]));
  const manifestFiles: SourceFile[] = [];
  if (pkg) manifestFiles.push({ path: "package.json", text: pkg, size: pkg.length });
  if (reqs) manifestFiles.push({ path: "requirements.txt", text: reqs, size: reqs.length });
  if (manifestFiles.length) {
    const manifest = analyzeManifests(manifestFiles);
    findings.push(...manifest.findings.filter((f) => severityRank(f.severity) <= severityRank("medium")));
    findings.push(...(await checkDependencies(manifest.dependencies, { notes, skipDownloads: true })));
  }
  return { label, decision: decide(findings, false), findings };
}

async function checkIntent(intent: InstallIntent, cwd: string, notes: string[]): Promise<IntentVerdict> {
  switch (intent.kind) {
    case "package":
      return intent.ecosystem === "npm" ? checkNpmPackage(intent.name, intent.spec, intent.executes) : checkPypiPackage(intent.name, intent.spec, intent.executes);
    case "manifest":
      return checkManifest(intent, cwd, notes);
    case "repo":
      return checkRepo(intent, notes);
    case "remote-archive":
      return {
        label: intent.url,
        decision: "ask",
        findings: [{ id: "install.remote-archive", severity: "medium", category: "install-script", title: "installs code straight from a URL", detail: "It bypasses the package registry, so it can't be checked against malware intel." }],
      };
    case "pipe-to-shell":
      if (intent.url && TRUSTED_INSTALL_HOSTS.test(intent.url)) return { label: intent.url, decision: "allow", findings: [] };
      return {
        label: intent.url ?? "remote script",
        decision: "ask",
        findings: [{ id: "install.pipe-to-shell", severity: "medium", category: "execution", title: "pipes a downloaded script straight into a shell", detail: "It runs with your permissions without being reviewed." }],
      };
    case "custom-registry":
      return {
        label: intent.registry,
        decision: "ask",
        findings: [{ id: "install.custom-registry", severity: "medium", category: "install-script", title: "uses a non-default package registry", detail: "Unknown registries can serve anything under familiar names." }],
      };
  }
}

function cacheKey(i: InstallIntent): string | undefined {
  return i.kind === "package" ? `${i.ecosystem}:${i.ecosystem === "pypi" ? canonicalPypi(i.name) : i.name}@${i.spec ?? ""}:${i.executes ? "x" : ""}` : undefined;
}

function allowName(i: InstallIntent): string | undefined {
  if (i.kind === "package") return i.name.toLowerCase();
  if (i.kind === "repo") return `${i.owner}/${i.repo}`.toLowerCase();
  return undefined;
}

/** Check a shell command for risky installs. Lookup failures fail open (allow) and are noted. */
export async function checkInstallCommand(command: string, opts: CheckOptions = {}): Promise<CheckResult> {
  const intents = parseInstallCommand(command);
  const notes: string[] = [];
  if (!intents.length) return { decision: "allow", reason: "", verdicts: [], notes };
  const allow = new Set((opts.allow ?? []).map((a) => a.toLowerCase()));
  const cachePath = opts.cachePath === false ? undefined : (opts.cachePath ?? join(homedir(), ".botguard", "hook-cache.json"));
  const cache = cachePath ? loadCache(cachePath) : {};
  const cwd = opts.cwd ?? process.cwd();

  const verdicts = await Promise.all(
    intents.slice(0, 20).map(async (intent): Promise<IntentVerdict> => {
      const name = allowName(intent);
      if (name && allow.has(name)) return { label: name, decision: "allow", findings: [] };
      const key = cacheKey(intent);
      const hit = key ? cache[key] : undefined;
      if (hit && Date.now() - hit.at < CACHE_TTL[hit.verdict.decision]) return hit.verdict;
      try {
        const v = await checkIntent(intent, cwd, notes);
        if (key) cache[key] = { at: Date.now(), verdict: v };
        return v;
      } catch (err) {
        notes.push(`Couldn't check ${name ?? intent.kind}: ${(err as Error).message}`);
        return { label: name ?? intent.kind, decision: "allow", findings: [] };
      }
    }),
  );
  if (cachePath) saveCache(cachePath, cache);
  const decision = verdicts.reduce<Decision>((d, v) => mergeDecision(d, v.decision), "allow");
  return { decision, reason: formatReason(decision, verdicts), verdicts, notes };
}

export function formatReason(decision: Decision, verdicts: IntentVerdict[]): string {
  if (decision === "allow") return "";
  const flagged = verdicts.filter((v) => v.decision !== "allow");
  const lines = flagged.flatMap((v) => {
    const top = sortFindings(v.findings).filter((f) => f.severity !== "info" && f.severity !== "low").slice(0, 3);
    return [`- ${v.label}: ${top.map((f) => f.title + (f.advice ? ` (${f.advice})` : "")).join("; ")}`];
  });
  if (decision === "deny") {
    return [
      "BotGuard blocked this install: it matches known malware or a strong typosquat/impersonation signal.",
      ...lines,
      "Do not retry with a similar-looking name. Use the official package, or ask the user which exact package they want (they can allow it with BOTGUARD_ALLOW=<name>).",
    ].join("\n");
  }
  return ["BotGuard flagged this for a second look:", ...lines, "Approve only if you recognise the package and its publisher."].join("\n");
}
