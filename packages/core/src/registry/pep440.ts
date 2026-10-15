/** Minimal PEP 440 parsing, ordering and specifier matching - enough to resolve what pip would install. */

export interface Pep440 {
  epoch: number;
  release: number[];
  pre?: [number, number]; // [0=a,1=b,2=rc, n]
  post?: number;
  dev?: number;
  raw: string;
}

const RE =
  /^\s*v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d+)?)?(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d+)?))?(?:[-_.]?(dev)[-_.]?(\d+)?)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?\s*$/i;

export function parsePep440(v: string): Pep440 | null {
  const m = RE.exec(v);
  if (!m) return null;
  const preTag = m[3]?.toLowerCase();
  const preKind = preTag === undefined ? undefined : preTag.startsWith("a") ? 0 : preTag === "b" || preTag === "beta" ? 1 : 2;
  return {
    epoch: m[1] ? Number(m[1]) : 0,
    release: m[2]!.split(".").map(Number),
    pre: preKind === undefined ? undefined : [preKind, m[4] ? Number(m[4]) : 0],
    post: m[5] ? Number(m[5]) : m[6] ? (m[7] ? Number(m[7]) : 0) : undefined,
    dev: m[8] ? (m[9] ? Number(m[9]) : 0) : undefined,
    raw: v,
  };
}

export function isPrerelease(v: Pep440): boolean {
  return v.pre !== undefined || v.dev !== undefined;
}

function cmpRelease(a: number[], b: number[]): number {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export function comparePep440(a: Pep440, b: Pep440): number {
  if (a.epoch !== b.epoch) return a.epoch - b.epoch;
  const r = cmpRelease(a.release, b.release);
  if (r !== 0) return r;
  // dev-only releases sort before pre-releases, which sort before finals.
  const preKey = (v: Pep440) => (v.pre ? v.pre[0] * 1e6 + v.pre[1] : v.dev !== undefined && v.post === undefined ? -1 : 9e9);
  const p = preKey(a) - preKey(b);
  if (p !== 0) return p;
  const post = (a.post ?? -1) - (b.post ?? -1);
  if (post !== 0) return post;
  return (a.dev ?? Infinity) - (b.dev ?? Infinity);
}

function matchOne(v: Pep440, op: string, target: string): boolean {
  if (op === "===") return v.raw === target;
  if (target.endsWith(".*") && (op === "==" || op === "!=")) {
    const prefix = parsePep440(target.slice(0, -2));
    if (!prefix) return false;
    const eq = prefix.release.every((n, i) => (v.release[i] ?? 0) === n) && v.epoch === prefix.epoch;
    return op === "==" ? eq : !eq;
  }
  const t = parsePep440(target);
  if (!t) return false;
  const c = comparePep440(v, t);
  switch (op) {
    case "==":
      return c === 0;
    case "!=":
      return c !== 0;
    case ">=":
      return c >= 0;
    case "<=":
      return c <= 0;
    case ">":
      return c > 0;
    case "<":
      return c < 0;
    case "~=": {
      if (c < 0 || t.release.length < 2) return false;
      const upper = t.release.slice(0, -1);
      return upper.every((n, i) => (v.release[i] ?? 0) === n);
    }
    default:
      return false;
  }
}

export function satisfiesPep440(version: string, specifier: string): boolean {
  const v = parsePep440(version);
  if (!v) return false;
  const parts = specifier.split(",").map((s) => s.trim()).filter(Boolean);
  return parts.every((part) => {
    const m = /^(===|==|!=|~=|>=|<=|>|<)\s*(.+)$/.exec(part);
    return m ? matchOne(v, m[1]!, m[2]!.trim()) : false;
  });
}

/** Highest version satisfying the specifier, skipping pre-releases unless nothing else matches. */
export function maxSatisfyingPep440(versions: string[], specifier?: string): string | null {
  const parsed = versions.map((raw) => parsePep440(raw)).filter((v): v is Pep440 => v !== null);
  const ok = parsed.filter((v) => !specifier || satisfiesPep440(v.raw, specifier));
  const finals = ok.filter((v) => !isPrerelease(v));
  const pool = finals.length ? finals : ok;
  pool.sort(comparePep440);
  return pool.at(-1)?.raw ?? null;
}
