import { fetchBytes, fetchJson } from "../net/http";
import { canonicalPypi } from "../intel/popular";
import { maxSatisfyingPep440 } from "./pep440";

export interface PypiFile {
  filename: string;
  url: string;
  packagetype: "sdist" | "bdist_wheel" | string;
  size: number;
  upload_time_iso_8601?: string;
  yanked?: boolean;
  yanked_reason?: string | null;
}

export interface PypiInfo {
  name: string;
  version: string;
  summary?: string;
  author?: string;
  author_email?: string;
  maintainer_email?: string;
  home_page?: string;
  project_urls?: Record<string, string> | null;
  requires_dist?: string[] | null;
  yanked?: boolean;
  yanked_reason?: string | null;
  description?: string;
}

export interface PypiProject {
  info: PypiInfo;
  releases: Record<string, PypiFile[]>;
  urls: PypiFile[];
}

export async function getPypiProject(name: string, timeoutMs = 10_000): Promise<PypiProject | null> {
  return fetchJson<PypiProject>(`https://pypi.org/pypi/${encodeURIComponent(canonicalPypi(name))}/json`, {
    timeoutMs,
    maxBytes: 30 * 1024 * 1024,
  });
}

export async function getPypiRelease(name: string, version: string, timeoutMs = 8000): Promise<PypiProject | null> {
  return fetchJson<PypiProject>(
    `https://pypi.org/pypi/${encodeURIComponent(canonicalPypi(name))}/${encodeURIComponent(version)}/json`,
    { timeoutMs },
  );
}

/** What pip would pick for this specifier, ignoring fully-yanked releases. */
export function resolvePypiSpec(p: PypiProject, spec?: string): string | null {
  const live = Object.entries(p.releases)
    .filter(([, files]) => files.length > 0 && !files.every((f) => f.yanked))
    .map(([v]) => v);
  if (!spec) return live.includes(p.info.version) ? p.info.version : maxSatisfyingPep440(live);
  return maxSatisfyingPep440(live, spec);
}

/** First upload time across all releases. */
export function pypiCreated(p: PypiProject): Date | undefined {
  let first: number | undefined;
  for (const files of Object.values(p.releases)) {
    for (const f of files) {
      const t = f.upload_time_iso_8601 ? Date.parse(f.upload_time_iso_8601) : NaN;
      if (!Number.isNaN(t) && (first === undefined || t < first)) first = t;
    }
  }
  return first === undefined ? undefined : new Date(first);
}

/** Prefer the sdist: it carries setup.py, which is where install-time code lives. */
export function pickPypiFiles(files: PypiFile[]): PypiFile[] {
  const sdist = files.find((f) => f.packagetype === "sdist");
  const wheel = files.find((f) => f.packagetype === "bdist_wheel" && /none-any\.whl$/.test(f.filename)) ??
    files.find((f) => f.packagetype === "bdist_wheel");
  return [sdist, wheel].filter((f): f is PypiFile => Boolean(f));
}

export async function fetchPypiFile(url: string, maxBytes = 30 * 1024 * 1024): Promise<Uint8Array> {
  if (!/^https:\/\/files\.pythonhosted\.org\//.test(url)) throw new Error(`Refusing download outside PyPI: ${url}`);
  return fetchBytes(url, { timeoutMs: 30_000, maxBytes });
}

export function pypiRepoUrl(info: PypiInfo): string | undefined {
  const urls = Object.values(info.project_urls ?? {});
  return [...urls, info.home_page ?? ""].find((u) => /github\.com|gitlab\.com/i.test(u));
}
