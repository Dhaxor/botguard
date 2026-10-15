import semver from "semver";
import type { Dependency } from "../analyzers/manifest";
import { getNpmVersionList, getNpmWeeklyDownloads } from "../registry/npm";
import { satisfiesPep440 } from "../registry/pep440";
import { getPypiProject, pypiCreated } from "../registry/pypi";
import type { Ecosystem, Finding } from "../types";
import { matchBrands } from "./brands";
import { getOsvAffected, osvQueryBatch, type OsvAdvisory } from "./osv";
import { canonicalPypi, findTyposquat, isPopular } from "./popular";

export interface DependencyCheckOptions {
  notes: string[];
  /** Skip the per-package download lookups used to confirm typosquats (offline/fast mode). */
  skipDownloads?: boolean;
}

function key(d: Dependency): string {
  const name = d.ecosystem === "pypi" ? canonicalPypi(d.name) : d.name;
  return `${d.ecosystem}:${name}@${d.version ?? d.spec ?? ""}`;
}

function rangeAllows(eco: Ecosystem, spec: string | undefined, version: string): boolean {
  if (!spec || spec === "*" || spec === "latest") return false; // resolves to latest, which registries keep clean
  if (eco === "npm") {
    try {
      return semver.satisfies(version, spec, { includePrerelease: false });
    } catch {
      return false;
    }
  }
  return satisfiesPep440(version, spec);
}

async function publishedSubset(eco: Ecosystem, name: string, versions: string[]): Promise<string[]> {
  try {
    if (eco === "npm") {
      const list = await getNpmVersionList(name);
      return list ? versions.filter((v) => list.includes(v)) : versions;
    }
    const project = await getPypiProject(name);
    if (!project) return versions;
    return versions.filter((v) => (project.releases[v] ?? []).some((f) => !f.yanked));
  } catch {
    return versions; // can't tell: assume the worst
  }
}

/** Malware intel for a dependency set: known-malicious packages, hijacked versions, typosquats, brand-jacking. */
export async function checkDependencies(deps: Dependency[], opts: DependencyCheckOptions): Promise<Finding[]> {
  const unique = new Map<string, Dependency>();
  for (const d of deps) if (!unique.has(key(d))) unique.set(key(d), d);
  const list = [...unique.values()].slice(0, 4000);
  if (unique.size > list.length) opts.notes.push(`Checked the first ${list.length} of ${unique.size} dependencies against OSV.`);
  const findings: Finding[] = [];

  let osv: OsvAdvisory[][] = [];
  try {
    osv = await osvQueryBatch(list.map((d) => ({ ecosystem: d.ecosystem, name: d.ecosystem === "pypi" ? canonicalPypi(d.name) : d.name, version: d.version })));
  } catch (err) {
    opts.notes.push(`OSV malware lookup failed: ${(err as Error).message}`);
  }

  await Promise.all(
    list.map(async (dep, i) => {
      const mal = (osv[i] ?? []).filter((a) => a.malicious);
      if (!mal.length) return;
      const label = `${dep.name}${dep.version ? `@${dep.version}` : dep.spec ? ` (${dep.spec})` : ""}`;
      const evidence = [{ file: dep.source, snippet: label, url: mal[0]!.url }];
      if (dep.version) {
        findings.push({
          id: `dep.malicious:${dep.ecosystem}:${dep.name}`,
          severity: "critical",
          category: "intel",
          title: `Depends on known malware: ${label}`,
          detail: `${mal.map((m) => m.id).join(", ")}: this exact version is listed as malicious in the OSV / OpenSSF malicious-packages database.`,
          advice: "Remove it. If it was ever installed on a machine, rotate every key and secret that machine could reach.",
          evidence,
        });
        return;
      }
      const affected = await Promise.all(mal.map((m) => getOsvAffected(m.id, dep.name)));
      if (affected.some((a) => a?.allVersions)) {
        findings.push({
          id: `dep.malicious:${dep.ecosystem}:${dep.name}`,
          severity: "critical",
          category: "intel",
          title: `Depends on a known malicious package: ${dep.name}`,
          detail: `${mal.map((m) => m.id).join(", ")}: every version of this package is listed as malware.`,
          advice: "Remove it. If it was ever installed, treat that machine's keys and secrets as stolen.",
          evidence,
        });
        return;
      }
      const bad = [...new Set(affected.flatMap((a) => a?.versions ?? []))];
      const allowed = bad.filter((v) => rangeAllows(dep.ecosystem, dep.spec, v));
      // Registries pull hijacked releases quickly; once gone, only an old lockfile or cache can still carry them.
      const stillPublished = allowed.length ? await publishedSubset(dep.ecosystem, dep.name, allowed) : [];
      findings.push(
        allowed.length
          ? {
              id: `dep.hijacked-range:${dep.ecosystem}:${dep.name}`,
              severity: stillPublished.length ? "high" : "low",
              category: "intel",
              title: stillPublished.length
                ? `Version range for ${dep.name} can install a hijacked release (${stillPublished.join(", ")})`
                : `Version range for ${dep.name} covers a hijacked release that has since been removed (${allowed.join(", ")})`,
              detail: stillPublished.length
                ? `${mal.map((m) => m.id).join(", ")}: those releases were published by attackers and are still downloadable. "${dep.spec}" can resolve to one.`
                : `${mal.map((m) => m.id).join(", ")}: fresh installs can't get it any more, but check that no lockfile pins it.`,
              advice: "Pin to a known-good version and check your lockfile.",
              evidence,
            }
          : {
              id: `dep.hijacked-history:${dep.ecosystem}:${dep.name}`,
              severity: "info",
              category: "intel",
              title: `${dep.name} once had hijacked releases (${bad.join(", ") || "see advisory"})`,
              detail: "Your declared range excludes them, so this is informational.",
              evidence,
            },
      );
    }),
  );

  // Typosquats and brand-jacking among direct dependencies.
  const direct = list.filter((d) => d.direct);
  await Promise.all(
    direct.map(async (dep) => {
      const squat = findTyposquat(dep.name, dep.ecosystem);
      if (squat) {
        // Confirm before accusing: established packages with real usage aren't typosquats.
        if (!opts.skipDownloads) {
          if (dep.ecosystem === "npm") {
            const weekly = await getNpmWeeklyDownloads(dep.name);
            if (weekly !== null && weekly >= 1000) return;
          } else {
            const project = await getPypiProject(dep.name).catch(() => null);
            if (!project) return; // not a real project (often a parsing artefact); pip would fail anyway
            const first = pypiCreated(project);
            if (first && Date.now() - first.getTime() > 2 * 365 * 86_400_000) return;
          }
        }
        findings.push({
          id: `dep.typosquat:${dep.ecosystem}:${dep.name}`,
          severity: "high",
          category: "typosquat",
          title: `"${dep.name}" looks like a typosquat of "${squat.target}"`,
          detail: `It differs from the popular package "${squat.target}" only by ${squat.kind === "lookalike" ? `${squat.distance} character${squat.distance === 1 ? "" : "s"}` : squat.kind === "scope" ? "its npm scope" : squat.kind === "separator" ? "punctuation" : squat.kind === "affix" ? "a prefix/suffix" : "look-alike characters"}. Attackers register these names to catch typos and AI-hallucinated imports.`,
          advice: `Use "${squat.target}" unless you're sure this is the package you meant.`,
          evidence: [{ file: dep.source, snippet: `${dep.name}${dep.spec ? ` ${dep.spec}` : ""}` }],
        });
      }
      const brands = matchBrands(dep.name).filter((b) => !(dep.ecosystem === "npm" && b.npmScopes.some((s) => dep.name.toLowerCase().startsWith(`${s}/`))));
      if (brands.length && !isPopular(dep.name, dep.ecosystem)) {
        findings.push({
          id: `dep.brand:${dep.ecosystem}:${dep.name}`,
          severity: "low",
          category: "typosquat",
          title: `"${dep.name}" uses the ${brands[0]!.label} name but isn't an official package`,
          detail: `Fake "${brands[0]!.label}" packages are a favourite way to target bot builders. Check who publishes it before trusting it with keys.`,
          evidence: [{ file: dep.source, snippet: dep.name }],
        });
      }
    }),
  );
  return findings;
}
