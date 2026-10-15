import { fetchJson } from "../net/http";
import type { Ecosystem } from "../types";

const OSV = "https://api.osv.dev/v1";

export interface OsvAdvisory {
  id: string;
  /** OpenSSF malicious-packages entries are published under MAL- ids. */
  malicious: boolean;
  summary?: string;
  url: string;
}

export interface OsvQuery {
  ecosystem: Ecosystem;
  name: string;
  /** Exact version. Without it OSV returns advisories for any version. */
  version?: string;
}

interface OsvVuln {
  id: string;
  summary?: string;
  aliases?: string[];
}

export function osvEcosystem(eco: Ecosystem): string {
  return eco === "npm" ? "npm" : "PyPI";
}

export function advisoryUrl(id: string): string {
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

function toAdvisory(v: OsvVuln): OsvAdvisory {
  const text = `${v.summary ?? ""}`.toLowerCase();
  return {
    id: v.id,
    malicious: v.id.startsWith("MAL-") || /\b(malware|malicious code)\b/.test(text),
    summary: v.summary,
    url: advisoryUrl(v.id),
  };
}

function queryBody(q: OsvQuery) {
  return {
    package: { name: q.name, ecosystem: osvEcosystem(q.ecosystem) },
    ...(q.version ? { version: q.version } : {}),
  };
}

/** Full advisories (with summaries) for one package. */
export async function osvQuery(q: OsvQuery, timeoutMs = 8000): Promise<OsvAdvisory[]> {
  const res = await fetchJson<{ vulns?: OsvVuln[] }>(`${OSV}/query`, {
    method: "POST",
    body: JSON.stringify(queryBody(q)),
    timeoutMs,
  });
  return (res?.vulns ?? []).map(toAdvisory);
}

export interface OsvAffected {
  /** Every version is malicious (typical for packages created by attackers). */
  allVersions: boolean;
  /** Explicitly listed bad versions (typical for hijacked releases of real packages). */
  versions: string[];
  summary?: string;
}

interface OsvVulnFull extends OsvVuln {
  affected?: {
    package?: { name?: string; ecosystem?: string };
    versions?: string[];
    ranges?: { type: string; events: { introduced?: string; fixed?: string; last_affected?: string }[] }[];
  }[];
}

const affectedCache = new Map<string, Promise<OsvAffected | null>>();

/** Which versions an advisory covers, for deciding whether a version range can pull in the bad release. */
export function getOsvAffected(id: string, name: string): Promise<OsvAffected | null> {
  const key = `${id}|${name}`;
  let p = affectedCache.get(key);
  if (!p) {
    p = fetchJson<OsvVulnFull>(`${OSV}/vulns/${encodeURIComponent(id)}`, { timeoutMs: 8000 })
      .then((v) => {
        if (!v) return null;
        const entries = (v.affected ?? []).filter((a) => !a.package?.name || a.package.name.toLowerCase() === name.toLowerCase());
        const versions = entries.flatMap((a) => a.versions ?? []);
        // Attacker-made packages get an open "introduced: 0" range (often alongside a version list);
        // hijacked releases of real packages list only the bad versions.
        const allVersions = entries.some((a) =>
          (a.ranges ?? []).some(
            (r) => r.events.some((e) => e.introduced === "0") && !r.events.some((e) => e.fixed || e.last_affected),
          ),
        );
        return { allVersions, versions, summary: v.summary };
      })
      .catch(() => null);
    affectedCache.set(key, p);
  }
  return p;
}

/**
 * Advisory ids for many packages in one round trip (chunked at 1000, OSV's limit).
 * Batch results carry ids only, which is enough to tell MAL- entries apart.
 */
export async function osvQueryBatch(queries: OsvQuery[], timeoutMs = 10_000): Promise<OsvAdvisory[][]> {
  const out: OsvAdvisory[][] = [];
  for (let i = 0; i < queries.length; i += 1000) {
    const chunk = queries.slice(i, i + 1000);
    const res = await fetchJson<{ results: { vulns?: { id: string }[] }[] }>(`${OSV}/querybatch`, {
      method: "POST",
      body: JSON.stringify({ queries: chunk.map(queryBody) }),
      timeoutMs,
    });
    for (let j = 0; j < chunk.length; j++) {
      out.push((res?.results[j]?.vulns ?? []).map((v) => toAdvisory({ id: v.id })));
    }
  }
  return out;
}
