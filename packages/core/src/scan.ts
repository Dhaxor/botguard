import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { decodeText, extractTarGz, extractZip, isBinaryPath, isScannablePath, toSourceFiles, type ArchiveEntry } from "./archive/extract";
import type { Dependency } from "./analyzers/manifest";
import { daysSince, repoSignals } from "./analyzers/repo";
import { isOfficialPublisher, matchBrands } from "./intel/brands";
import { osvQuery } from "./intel/osv";
import { canonicalPypi, findTyposquat, isPopular, popularityRank, pypiMonthlyDownloads } from "./intel/popular";
import { HttpError } from "./net/http";
import { analyzeFiles } from "./pipeline";
import { fetchGithubTarball, getGithubOwner, getGithubRepo, getLatestReleaseAssets, getStarTimes } from "./registry/github";
import {
  fetchNpmTarball,
  getNpmPackument,
  getNpmVersion,
  getNpmWeeklyDownloads,
  isDirectSpec,
  npmScope,
  repoUrlOf,
  resolveNpmSpec,
  type NpmVersionDoc,
} from "./registry/npm";
import { fetchPypiFile, getPypiProject, pickPypiFiles, pypiCreated, pypiRepoUrl, resolvePypiSpec } from "./registry/pypi";
import { describeTarget, parseTarget, type TargetHint } from "./targets";
import type { Finding, ReportTarget, ScanOptions, ScanReport, SourceFile, Target } from "./types";
import { computeVerdict, dedupeFindings, summarize } from "./verdict";

export const ENGINE = "botguard-core 0.1.0";

interface Partial {
  target: ReportTarget;
  findings: Finding[];
  facts: { label: string; value: string }[];
  files: number;
  bytes: number;
  notes: string[];
  detonation?: ScanReport["detonation"];
}

function fmtDate(d: Date | string | undefined): string {
  if (!d) return "unknown";
  const date = typeof d === "string" ? new Date(d) : d;
  const days = daysSince(date);
  return `${date.toISOString().slice(0, 10)}${days !== undefined ? ` (${days} day${days === 1 ? "" : "s"} ago)` : ""}`;
}

function fmtNumber(n: number): string {
  return n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}k` : `${n}`;
}

function squatFinding(name: string, target: string, kind: string, severity: Finding["severity"], detail: string): Finding {
  return {
    id: "pkg.typosquat",
    severity,
    category: "typosquat",
    title: `Name looks like a typosquat of "${target}"`,
    detail,
    advice: `If you meant the popular package, install "${target}" instead.`,
    evidence: [{ snippet: `${name}  vs  ${target} (${kind})` }],
  };
}

// ---------------------------------------------------------------------------------------------- npm

async function scanNpm(name: string, spec: string | undefined, opts: ScanOptions, notes: string[]): Promise<Partial> {
  opts.onProgress?.(`Looking up ${name} on npm`);
  const popular = isPopular(name, "npm");
  let doc: NpmVersionDoc | null;
  let created: string | undefined;
  let versionCount: number | undefined;
  if (popular && isDirectSpec(spec)) {
    doc = await getNpmVersion(name, spec || "latest");
  } else {
    const p = await getNpmPackument(name);
    if (!p) doc = null;
    else {
      const v = resolveNpmSpec(p, spec);
      doc = v ? p.versions[v] ?? null : null;
      created = p.time?.created;
      versionCount = Object.keys(p.versions).length;
      if (!v) throw new Error(`No version of ${name} matches "${spec}"`);
    }
  }
  const target: ReportTarget = { kind: "npm", display: `npm ${name}`, url: `https://www.npmjs.com/package/${name}` };
  const findings: Finding[] = [];
  const facts: Partial["facts"] = [];
  if (!doc) {
    const squat = findTyposquat(name, "npm");
    throw new Error(`${name} isn't on npm${squat ? ` (did you mean "${squat.target}"?)` : ""}.`);
  }
  target.version = doc.version;
  target.display = `npm ${name}@${doc.version}`;
  target.url = `https://www.npmjs.com/package/${name}/v/${doc.version}`;

  const [advisories, weekly] = await Promise.all([
    osvQuery({ ecosystem: "npm", name, version: doc.version }).catch((err: Error) => {
      notes.push(`OSV lookup failed: ${err.message}`);
      return [];
    }),
    getNpmWeeklyDownloads(name),
  ]);
  const malicious = advisories.filter((a) => a.malicious);
  if (malicious.length) {
    findings.push({
      id: "intel.osv-malicious",
      severity: "critical",
      category: "intel",
      title: `Listed as malware: ${malicious.map((m) => m.id).join(", ")}`,
      detail: `${malicious[0]!.summary ?? "Malicious code"}. This version is in the OSV / OpenSSF malicious-packages database.`,
      advice: "Don't install it. If it already ran on a machine, assume every key and secret on that machine is stolen and rotate them from a clean device.",
      evidence: malicious.map((m) => ({ url: m.url, snippet: m.id })),
    });
  } else {
    const others = await osvQuery({ ecosystem: "npm", name }).catch(() => []);
    const past = others.filter((a) => a.malicious);
    if (past.length) {
      findings.push({
        id: "intel.past-hijack",
        severity: "info",
        category: "intel",
        title: `Other versions of ${name} were hijacked (${past.map((p) => p.id).join(", ")})`,
        detail: `${doc.version} isn't affected. Make sure your lockfile doesn't pin a bad version.`,
        evidence: past.map((m) => ({ url: m.url, snippet: m.id })),
      });
    }
  }
  if (doc.version.endsWith("-security") || /security holding package/i.test(doc.description ?? "")) {
    findings.push({
      id: "intel.npm-security-placeholder",
      severity: "critical",
      category: "intel",
      title: "npm took this package down for being malicious",
      detail: "npm replaces removed malware with a 0.0.1-security placeholder. Earlier copies, forks and mirrors of it are still dangerous.",
    });
  }
  if (doc.deprecated && /malware|malicious|compromis|security/i.test(doc.deprecated)) {
    findings.push({
      id: "intel.deprecated-security",
      severity: "high",
      category: "intel",
      title: "Deprecated for security reasons",
      detail: `The maintainer's deprecation notice says: "${doc.deprecated.slice(0, 200)}"`,
    });
  }

  const squat = popular ? null : findTyposquat(name, "npm");
  if (squat && (weekly === null || weekly < 5000)) {
    findings.push(
      squatFinding(
        name,
        squat.target,
        squat.kind,
        weekly === null || weekly < 1000 ? "high" : "medium",
        `${name} has ${weekly === null ? "unknown" : fmtNumber(weekly)} weekly downloads; "${squat.target}" is one of npm's most used packages. Names this close are registered to catch typos and AI-hallucinated imports.`,
      ),
    );
  }
  const repoUrl = repoUrlOf(doc.repository);
  const ageDays = daysSince(created);
  for (const brand of matchBrands(name)) {
    if (popular) break;
    // Trust only what npm verifies: the scope, and the publisher's/maintainers' account emails.
    const emails = [doc._npmUser?.email, ...(doc.maintainers ?? []).map((m) => m.email)].filter((e): e is string => Boolean(e));
    const official = isOfficialPublisher(brand, { scope: npmScope(name), emails });
    if (official) continue;
    const claimsOfficial = isOfficialPublisher(brand, { repositoryUrl: repoUrl, homepage: doc.homepage });
    const young = ageDays !== undefined && ageDays < 120;
    const fresh = weekly !== null && weekly < 500;
    findings.push({
      id: "pkg.brand",
      severity: claimsOfficial || (young && fresh) ? "high" : "medium",
      category: "typosquat",
      title: claimsOfficial
        ? `Claims to be ${brand.label}'s code but isn't published by ${brand.label}`
        : `Uses the ${brand.label} name but isn't an official ${brand.label} package`,
      detail: claimsOfficial
        ? `Its repository link points at ${brand.label}'s GitHub, but official ${brand.label} npm packages live under ${brand.npmScopes.join(", ") || "their own scope"}. Anyone can type any URL into package.json.`
        : `In 2026 attackers published packages like polymarket-bot and polymarket-claude-code that stole wallet keys. ${brand.label}'s own packages are published under ${brand.npmScopes.join(", ") || "their own accounts"}.`,
      advice: brand.npmScopes.length ? `Prefer the official ${brand.npmScopes[0]}/* packages.` : undefined,
    });
  }
  if (ageDays !== undefined && ageDays < 30) {
    findings.push({
      id: "pkg.new",
      severity: ageDays < 7 ? "medium" : "low",
      category: "metadata",
      title: `First published ${ageDays} day${ageDays === 1 ? "" : "s"} ago`,
      detail: "Most malicious packages are removed within days, so brand-new packages carry the most risk.",
    });
  }
  if (weekly !== null && weekly < 50 && !popular) {
    findings.push({ id: "pkg.low-downloads", severity: "low", category: "metadata", title: `Only ${weekly} downloads last week`, detail: "Very few people use this package, so nobody else has vetted it." });
  }
  if (!repoUrl && !popular) {
    findings.push({ id: "pkg.no-repo", severity: "low", category: "metadata", title: "No source repository linked", detail: "You can't compare the published code with any public source." });
  }

  facts.push({ label: "Version", value: doc.version });
  if (created) facts.push({ label: "First published", value: fmtDate(created) });
  if (weekly !== null) facts.push({ label: "Weekly downloads", value: fmtNumber(weekly) });
  if (versionCount !== undefined) facts.push({ label: "Versions", value: String(versionCount) });
  const rank = popularityRank(name, "npm");
  if (rank !== undefined) facts.push({ label: "Popularity", value: `top ${fmtNumber(Math.ceil((rank + 1) / 100) * 100)} on npm` });
  const publisher = doc._npmUser?.name ?? doc.maintainers?.[0]?.name;
  if (publisher) facts.push({ label: "Published by", value: publisher });
  if (repoUrl) facts.push({ label: "Repository", value: repoUrl });

  opts.onProgress?.("Downloading and unpacking the package");
  let entries: ArchiveEntry[] = [];
  try {
    entries = extractTarGz(await fetchNpmTarball(doc.dist.tarball));
  } catch (err) {
    notes.push(`Couldn't download the package contents: ${(err as Error).message}`);
  }
  const files = toSourceFiles(entries);
  const analysis = await analyzeFiles(files, entries, {
    ...opts,
    notes,
    checkDeps: true,
    detonate: false, // packages ship contract libraries, not a bot contract you deploy
    trusted: popular,
  });
  findings.push(...analysis.findings);
  return { target, findings, facts, files: files.length, bytes: files.reduce((s, f) => s + f.size, 0), notes, detonation: analysis.detonation };
}

// --------------------------------------------------------------------------------------------- PyPI

function requiresDist(reqs: string[] | null | undefined, source: string): Dependency[] {
  const deps: Dependency[] = [];
  for (const r of reqs ?? []) {
    if (/;\s*.*extra\s*==/.test(r)) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*\(?\s*([^;)]*)\)?/.exec(r);
    if (m) deps.push({ ecosystem: "pypi", name: m[1]!, spec: m[2]?.replace(/\s+/g, "") || undefined, source, direct: true });
  }
  return deps;
}

async function scanPypi(name: string, spec: string | undefined, opts: ScanOptions, notes: string[]): Promise<Partial> {
  opts.onProgress?.(`Looking up ${name} on PyPI`);
  const project = await getPypiProject(name);
  if (!project) {
    const squat = findTyposquat(name, "pypi");
    throw new Error(`${name} isn't on PyPI${squat ? ` (did you mean "${squat.target}"?)` : ""}.`);
  }
  const version = resolvePypiSpec(project, spec);
  if (!version) throw new Error(`No release of ${name} matches "${spec}"`);
  const info = project.info;
  const canonical = canonicalPypi(project.info.name);
  const target: ReportTarget = { kind: "pypi", display: `PyPI ${info.name}==${version}`, url: `https://pypi.org/project/${info.name}/${version}/`, version };
  const findings: Finding[] = [];
  const facts: Partial["facts"] = [];

  const advisories = await osvQuery({ ecosystem: "pypi", name: canonical, version }).catch((err: Error) => {
    notes.push(`OSV lookup failed: ${err.message}`);
    return [];
  });
  const malicious = advisories.filter((a) => a.malicious);
  if (malicious.length) {
    findings.push({
      id: "intel.osv-malicious",
      severity: "critical",
      category: "intel",
      title: `Listed as malware: ${malicious.map((m) => m.id).join(", ")}`,
      detail: `${malicious[0]!.summary ?? "Malicious code"}. This release is in the OSV / OpenSSF malicious-packages database.`,
      advice: "Don't install it. If it already ran, rotate every key and secret on that machine from a clean device.",
      evidence: malicious.map((m) => ({ url: m.url, snippet: m.id })),
    });
  }
  const files = project.releases[version] ?? [];
  const yankedBad = files.find((f) => f.yanked && /malware|malicious|compromis/i.test(f.yanked_reason ?? ""));
  if (yankedBad) {
    findings.push({
      id: "intel.yanked-malware",
      severity: "critical",
      category: "intel",
      title: "Yanked from PyPI as malicious",
      detail: `Yank reason: "${yankedBad.yanked_reason}"`,
    });
  }

  const popular = isPopular(name, "pypi");
  const monthly = pypiMonthlyDownloads(name);
  const created = pypiCreated(project);
  const ageDays = daysSince(created);
  const squat = popular ? null : findTyposquat(name, "pypi");
  if (squat) {
    findings.push(
      squatFinding(
        info.name,
        squat.target,
        squat.kind,
        ageDays !== undefined && ageDays < 365 ? "high" : "medium",
        `"${squat.target}" is one of PyPI's most downloaded projects and ${info.name} is not. Names this close are registered to catch typos and AI-hallucinated imports.`,
      ),
    );
  }
  const repoUrl = pypiRepoUrl(info);
  const emails = [info.author_email, info.maintainer_email].filter(Boolean).join(",").match(/[\w.+-]+@[\w.-]+/g) ?? [];
  for (const brand of matchBrands(name)) {
    if (popular) break;
    const official = isOfficialPublisher(brand, { repositoryUrl: repoUrl, homepage: info.home_page, emails }) && (ageDays ?? 0) > 60;
    if (official) continue;
    findings.push({
      id: "pkg.brand",
      severity: ageDays !== undefined && ageDays < 120 ? "high" : "medium",
      category: "typosquat",
      title: `Uses the ${brand.label} name but isn't published by ${brand.label}`,
      detail: `Fake ${brand.label} SDKs and bots are a common way to steal trading keys. Check the publisher before trusting it.`,
    });
  }
  if (ageDays !== undefined && ageDays < 30) {
    findings.push({
      id: "pkg.new",
      severity: ageDays < 7 ? "medium" : "low",
      category: "metadata",
      title: `First uploaded ${ageDays} day${ageDays === 1 ? "" : "s"} ago`,
      detail: "Most malicious packages are removed within days, so brand-new projects carry the most risk.",
    });
  }
  if (!repoUrl && !popular) {
    findings.push({ id: "pkg.no-repo", severity: "low", category: "metadata", title: "No source repository linked", detail: "You can't compare the published code with any public source." });
  }

  facts.push({ label: "Version", value: version });
  if (created) facts.push({ label: "First uploaded", value: fmtDate(created) });
  if (monthly !== undefined && popular) facts.push({ label: "Monthly downloads", value: fmtNumber(monthly) });
  facts.push({ label: "Releases", value: String(Object.keys(project.releases).length) });
  if (info.author || info.author_email) facts.push({ label: "Author", value: (info.author || info.author_email || "").slice(0, 80) });
  if (repoUrl) facts.push({ label: "Repository", value: repoUrl });

  opts.onProgress?.("Downloading and unpacking the release");
  const entries: ArchiveEntry[] = [];
  for (const f of pickPypiFiles(files)) {
    try {
      const bytes = await fetchPypiFile(f.url);
      const extracted = f.filename.endsWith(".whl") || f.filename.endsWith(".zip") ? extractZip(bytes) : extractTarGz(bytes);
      entries.push(...extracted.map((e) => ({ ...e, path: `${f.packagetype === "sdist" ? "sdist" : "wheel"}/${e.path}` })));
    } catch (err) {
      notes.push(`Couldn't unpack ${f.filename}: ${(err as Error).message}`);
    }
  }
  const sourceFiles = toSourceFiles(entries);
  const analysis = await analyzeFiles(sourceFiles, entries, {
    ...opts,
    notes,
    extraDependencies: requiresDist(info.requires_dist, "requires_dist"),
    detonate: false,
    trusted: popular,
  });
  findings.push(...analysis.findings);
  return { target, findings, facts, files: sourceFiles.length, bytes: sourceFiles.reduce((s, f) => s + f.size, 0), notes, detonation: analysis.detonation };
}

// ------------------------------------------------------------------------------------------- GitHub

async function scanGithub(owner: string, repoName: string, ref: string | undefined, opts: ScanOptions, notes: string[]): Promise<Partial> {
  opts.onProgress?.(`Fetching github.com/${owner}/${repoName}`);
  const gref = { owner, repo: repoName, ref };
  const findings: Finding[] = [];
  const facts: Partial["facts"] = [];
  const target: ReportTarget = { kind: "github", display: `github.com/${owner}/${repoName}`, url: `https://github.com/${owner}/${repoName}` };

  let repo = null;
  try {
    repo = await getGithubRepo(gref, opts.githubToken);
  } catch (err) {
    if (err instanceof HttpError && (err.status === 403 || err.status === 429)) notes.push("GitHub API rate limit hit: repository metadata (age, stars, owner) was skipped.");
    else notes.push(`GitHub API error: ${(err as Error).message}`);
  }
  if (repo) {
    const [ownerInfo, starTimes, assets] = await Promise.all([
      getGithubOwner(repo.owner.login, opts.githubToken).catch(() => null),
      repo.stargazers_count >= 20 && repo.stargazers_count <= 40_000 ? getStarTimes(gref, opts.githubToken).catch(() => undefined) : Promise.resolve(undefined),
      getLatestReleaseAssets(gref, opts.githubToken),
    ]);
    findings.push(...repoSignals({ repo, owner: ownerInfo, starTimes, assets }));
    facts.push({ label: "Stars", value: fmtNumber(repo.stargazers_count) });
    facts.push({ label: "Forks", value: fmtNumber(repo.forks_count) });
    facts.push({ label: "Created", value: fmtDate(repo.created_at) });
    facts.push({ label: "Last push", value: fmtDate(repo.pushed_at) });
    if (ownerInfo) facts.push({ label: `Owner (${ownerInfo.type === "Organization" ? "org" : "user"})`, value: `${ownerInfo.login}, joined ${fmtDate(ownerInfo.created_at)}` });
    if (repo.archived) facts.push({ label: "Status", value: "archived" });
  }

  opts.onProgress?.("Downloading repository snapshot");
  const entries = extractTarGz(await fetchGithubTarball(gref, repo?.default_branch ?? "HEAD"));
  if (entries.length >= 8000) notes.push("Very large repository: only the first 8,000 files were scanned.");
  const files = toSourceFiles(entries);
  opts.onProgress?.(`Scanning ${files.length} files`);
  const analysis = await analyzeFiles(files, entries, { ...opts, notes });
  findings.push(...analysis.findings);
  return { target, findings, facts, files: files.length, bytes: files.reduce((s, f) => s + f.size, 0), notes, detonation: analysis.detonation };
}

// ------------------------------------------------------------------------------------ Solidity text

async function scanSoliditySource(source: string, opts: ScanOptions, notes: string[]): Promise<Partial> {
  const name = /\bcontract\s+([A-Za-z_]\w*)/.exec(source)?.[1] ?? "Contract";
  const files: SourceFile[] = [{ path: `${name}.sol`, text: source, size: source.length }];
  opts.onProgress?.("Analyzing and sandboxing the contract");
  const analysis = await analyzeFiles(files, [], { ...opts, notes, checkDeps: false });
  const facts: Partial["facts"] = [{ label: "Lines", value: String(source.split("\n").length) }];
  if (analysis.detonation?.compilerVersion) facts.push({ label: "Compiler", value: analysis.detonation.compilerVersion.split("+")[0]! });
  return {
    target: { kind: "solidity", display: `Solidity: ${name}` },
    findings: analysis.findings,
    facts,
    files: 1,
    bytes: source.length,
    notes,
    detonation: analysis.detonation,
  };
}

// --------------------------------------------------------------------------------------- directory

function readDirectory(root: string, limit = 8000): { files: SourceFile[]; entries: ArchiveEntry[] } {
  const files: SourceFile[] = [];
  const entries: ArchiveEntry[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      if (entries.length >= limit) return;
      const full = join(dir, name);
      const rel = relative(root, full).split(sep).join("/");
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (/^(\.git|node_modules|__pycache__|\.venv|venv|\.next|dist-newstyle|target)$/.test(name)) continue;
        walk(full);
      } else if (st.isFile()) {
        const entry: ArchiveEntry = { path: rel, size: st.size };
        if (isBinaryPath(rel)) entry.binary = true;
        else if (isScannablePath(rel) && st.size <= 3 * 1024 * 1024) {
          entry.text = decodeText(readFileSync(full));
          if (entry.text !== undefined) files.push({ path: rel, text: entry.text, size: st.size });
        }
        entries.push(entry);
      }
    }
  };
  walk(root);
  return { files, entries };
}

async function scanDirectory(path: string, opts: ScanOptions, notes: string[]): Promise<Partial> {
  const st = statSync(path);
  if (st.isFile()) {
    const text = readFileSync(path, "utf8");
    if (path.endsWith(".sol")) return scanSoliditySource(text, opts, notes);
    const file: SourceFile = { path: path.split(/[\\/]/).pop()!, text, size: text.length };
    const analysis = await analyzeFiles([file], [{ path: file.path, size: file.size, text }], { ...opts, notes });
    return { target: { kind: "directory", display: path }, findings: analysis.findings, facts: [], files: 1, bytes: text.length, notes, detonation: analysis.detonation };
  }
  opts.onProgress?.(`Reading ${path}`);
  const { files, entries } = readDirectory(path);
  const analysis = await analyzeFiles(files, entries, { ...opts, notes });
  return {
    target: { kind: "directory", display: path },
    findings: analysis.findings,
    facts: [{ label: "Files scanned", value: String(files.length) }],
    files: files.length,
    bytes: files.reduce((s, f) => s + f.size, 0),
    notes,
    detonation: analysis.detonation,
  };
}

// ------------------------------------------------------------------------------------------- entry

export async function scanTarget(target: Target, opts: ScanOptions = {}): Promise<ScanReport> {
  const started = Date.now();
  const notes: string[] = [];
  let partial: Partial;
  try {
    switch (target.kind) {
      case "npm":
        partial = await scanNpm(target.name!, target.spec, opts, notes);
        break;
      case "pypi":
        partial = await scanPypi(target.name!, target.spec, opts, notes);
        break;
      case "github":
        partial = await scanGithub(target.owner!, target.repo!, target.spec, opts, notes);
        break;
      case "solidity":
        partial = await scanSoliditySource(target.source!, opts, notes);
        break;
      case "directory":
        partial = await scanDirectory(target.path!, opts, notes);
        break;
    }
  } catch (err) {
    return {
      target: { kind: target.kind, display: describeTarget(target) },
      verdict: "error",
      score: 0,
      summary: (err as Error).message,
      findings: [],
      facts: [],
      stats: { filesScanned: 0, bytesScanned: 0, durationMs: Date.now() - started },
      notes,
      scannedAt: new Date().toISOString(),
      engine: ENGINE,
    };
  }
  const findings = dedupeFindings(partial.findings);
  const { verdict, score } = computeVerdict(findings);
  return {
    target: partial.target,
    verdict,
    score,
    summary: summarize(verdict, findings),
    findings,
    facts: partial.facts,
    stats: { filesScanned: partial.files, bytesScanned: partial.bytes, durationMs: Date.now() - started },
    notes: [...new Set(partial.notes)],
    scannedAt: new Date().toISOString(),
    engine: ENGINE,
    detonation: partial.detonation,
  };
}

/** Parse free-form input and scan it. Bare names fall back from npm to PyPI when npm has no such package. */
export async function scan(input: string, opts: ScanOptions & { hint?: TargetHint } = {}): Promise<ScanReport> {
  let target: Target;
  try {
    target = parseTarget(input, opts.hint ?? "auto");
  } catch (err) {
    return {
      target: { kind: "npm", display: input.slice(0, 80) },
      verdict: "error",
      score: 0,
      summary: (err as Error).message,
      findings: [],
      facts: [],
      stats: { filesScanned: 0, bytesScanned: 0, durationMs: 0 },
      notes: [],
      scannedAt: new Date().toISOString(),
      engine: ENGINE,
    };
  }
  const report = await scanTarget(target, opts);
  const bare = (opts.hint ?? "auto") === "auto" && target.kind === "npm" && !/^npm:/i.test(input.trim()) && !target.name!.startsWith("@");
  if (report.verdict === "error" && bare && /isn't on npm/.test(report.summary)) {
    const py = await scanTarget({ kind: "pypi", raw: input, name: target.name, spec: target.spec ? `==${target.spec}` : undefined }, opts);
    if (py.verdict !== "error") return py;
  }
  return report;
}
