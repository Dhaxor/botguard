import type { ArchiveEntry } from "./archive/extract";
import { scanCode } from "./analyzers/code";
import { analyzeManifests, type Dependency } from "./analyzers/manifest";
import { scanScamText } from "./analyzers/scam-text";
import { checkDependencies } from "./intel/deps";
import { scanSoliditySources } from "./solidity";
import type { DetonationSummary, Finding, ScanOptions, SourceFile } from "./types";

export interface FileAnalysis {
  findings: Finding[];
  dependencies: Dependency[];
  detonation?: DetonationSummary;
}

/**
 * Everything we can learn from a set of files: install hooks, code rules, scam text, Solidity,
 * and malware intel on declared dependencies. Shared by repo, package and folder scans.
 */
export async function analyzeFiles(
  files: SourceFile[],
  entries: ArchiveEntry[],
  opts: ScanOptions & {
    notes: string[];
    extraDependencies?: Dependency[];
    checkDeps?: boolean;
    /** Widely used package: install hooks are expected (esbuild, sharp...), so only real code red flags count. */
    trusted?: boolean;
  },
): Promise<FileAnalysis> {
  const manifest = analyzeManifests(files);
  const findings: Finding[] = [...manifest.findings];
  findings.push(...scanCode(files, { installTime: manifest.installTime }));
  findings.push(...scanScamText(files));
  if (opts.trusted) {
    for (let i = findings.length - 1; i >= 0; i--) {
      const f = findings[i]!;
      if (f.id === "code.install-time-activity") findings.splice(i, 1);
      else if (f.id === "manifest.install-script") f.severity = "info";
    }
  }

  const binaries = entries.filter((e) => e.binary && !/(^|\/)(node_modules|vendor|third_party)\//.test(e.path));
  const exe = binaries.filter((e) => /\.(exe|scr|msi|com|bat|jar|apk|dmg|pkg)$/i.test(e.path));
  if (exe.length) {
    findings.push({
      id: "files.executables",
      severity: "medium",
      category: "execution",
      title: `Ships ${exe.length} executable file${exe.length === 1 ? "" : "s"}`,
      detail: "Prebuilt executables can't be reviewed. Trading-bot malware is very often distributed as an .exe alongside harmless-looking source.",
      evidence: exe.slice(0, 5).map((e) => ({ file: e.path, snippet: `${(e.size / 1024).toFixed(0)} KB` })),
    });
  }

  let detonation: DetonationSummary | undefined;
  const solCount = files.filter((f) => f.path.endsWith(".sol")).length;
  if (solCount) {
    opts.onProgress?.("Checking Solidity contracts");
    // Sandbox runs are for "deploy this bot contract" repos, not contract libraries with dozens of files.
    const runSandbox = opts.detonate !== false && solCount <= 10;
    if (opts.detonate !== false && !runSandbox) opts.notes.push(`${solCount} Solidity files: ran static checks only (the sandbox is for small bot-contract repos).`);
    const sol = await scanSoliditySources(files, { detonate: runSandbox, cacheDir: opts.cacheDir, notes: opts.notes });
    findings.push(...sol.findings);
    detonation = sol.detonation;
  }

  const dependencies = [...manifest.dependencies, ...(opts.extraDependencies ?? [])];
  if (opts.checkDeps !== false && dependencies.length) {
    opts.onProgress?.(`Checking ${dependencies.length} dependencies against malware intel`);
    findings.push(...(await checkDependencies(dependencies, { notes: opts.notes })));
  }
  return { findings, dependencies, detonation };
}
