import semver from "semver";
import { fetchBytes, fetchJson } from "../net/http";

const REGISTRY = "https://registry.npmjs.org";

export interface NpmVersionDoc {
  name: string;
  version: string;
  description?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  bin?: string | Record<string, string>;
  repository?: string | { type?: string; url?: string };
  homepage?: string;
  deprecated?: string;
  maintainers?: { name?: string; email?: string }[];
  _npmUser?: { name?: string; email?: string };
  dist: { tarball: string; integrity?: string; fileCount?: number; unpackedSize?: number; attestations?: unknown };
  hasInstallScript?: boolean;
}

export interface NpmPackument {
  name: string;
  "dist-tags": Record<string, string>;
  versions: Record<string, NpmVersionDoc>;
  time?: Record<string, string>;
  maintainers?: { name?: string; email?: string }[];
  repository?: string | { url?: string };
  readme?: string;
}

export function encodeNpmName(name: string): string {
  return name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

export function npmScope(name: string): string | undefined {
  return name.startsWith("@") ? name.split("/")[0] : undefined;
}

export function repoUrlOf(repo: NpmVersionDoc["repository"]): string | undefined {
  const raw = typeof repo === "string" ? repo : repo?.url;
  if (!raw) return undefined;
  return raw
    .replace(/^git\+/, "")
    .replace(/^git:\/\//, "https://")
    .replace(/^ssh:\/\/git@/, "https://")
    .replace(/^github:/, "https://github.com/")
    .replace(/\.git$/, "");
}

/** Full packument. Large for very popular packages, so callers should prefer `getNpmVersion` when they can. */
export async function getNpmPackument(name: string, timeoutMs = 10_000): Promise<NpmPackument | null> {
  return fetchJson<NpmPackument>(`${REGISTRY}/${encodeNpmName(name)}`, { timeoutMs, maxBytes: 40 * 1024 * 1024 });
}

/** Published version numbers only (abbreviated "corgi" document, much smaller than the packument). */
export async function getNpmVersionList(name: string, timeoutMs = 10_000): Promise<string[] | null> {
  const doc = await fetchJson<{ versions?: Record<string, unknown> }>(`${REGISTRY}/${encodeNpmName(name)}`, {
    timeoutMs,
    headers: { accept: "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8" },
    maxBytes: 40 * 1024 * 1024,
  });
  return doc ? Object.keys(doc.versions ?? {}) : null;
}

/** One version document; `spec` may be an exact version or a dist-tag. */
export async function getNpmVersion(name: string, spec = "latest", timeoutMs = 8000): Promise<NpmVersionDoc | null> {
  return fetchJson<NpmVersionDoc>(`${REGISTRY}/${encodeNpmName(name)}/${encodeURIComponent(spec)}`, { timeoutMs });
}

/** Resolve a user spec (tag, exact version or semver range) against a packument. */
export function resolveNpmSpec(p: NpmPackument, spec?: string): string | null {
  const tags = p["dist-tags"] ?? {};
  if (!spec || spec === "*" || spec === "") return tags.latest ?? null;
  if (tags[spec]) return tags[spec]!;
  if (p.versions[spec]) return spec;
  const versions = Object.keys(p.versions);
  try {
    // npm prefers the latest tag when it satisfies the range.
    if (tags.latest && semver.satisfies(tags.latest, spec)) return tags.latest;
    return semver.maxSatisfying(versions, spec);
  } catch {
    return null;
  }
}

/** Is `spec` something the version endpoint can answer directly (tag or exact version)? */
export function isDirectSpec(spec?: string): boolean {
  return !spec || /^[a-z][\w.-]*$/i.test(spec) || semver.valid(spec) !== null;
}

export async function getNpmWeeklyDownloads(name: string, timeoutMs = 6000): Promise<number | null> {
  const res = await fetchJson<{ downloads?: number }>(
    `https://api.npmjs.org/downloads/point/last-week/${name}`,
    { timeoutMs },
  ).catch(() => null);
  return typeof res?.downloads === "number" ? res.downloads : null;
}

export async function fetchNpmTarball(url: string, maxBytes = 30 * 1024 * 1024): Promise<Uint8Array> {
  if (!/^https:\/\/registry\.npmjs\.org\//.test(url)) throw new Error(`Refusing tarball outside the npm registry: ${url}`);
  return fetchBytes(url, { timeoutMs: 30_000, maxBytes });
}
