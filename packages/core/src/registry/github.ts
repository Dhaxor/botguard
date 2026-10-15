import { fetchBytes, fetchJson, HttpError } from "../net/http";

export interface GithubRef {
  owner: string;
  repo: string;
  ref?: string;
}

export interface GithubRepo {
  full_name: string;
  html_url: string;
  description: string | null;
  created_at: string;
  pushed_at: string;
  stargazers_count: number;
  forks_count: number;
  open_issues_count: number;
  has_issues: boolean;
  archived: boolean;
  fork: boolean;
  default_branch: string;
  topics?: string[];
  owner: { login: string; type: "User" | "Organization" | string };
}

export interface GithubOwner {
  login: string;
  type: string;
  created_at: string;
  public_repos: number;
  followers: number;
}

/** Accepts https URLs, "github.com/o/r", "o/r", "github:o/r", git+https and tree/blob URLs. */
export function parseGithubRef(input: string): GithubRef | null {
  const s = input.trim().replace(/^git\+/, "").replace(/\.git(?=$|[#/])/, "");
  const short = /^(?:github:)?([A-Za-z0-9][A-Za-z0-9-]{0,38})\/([A-Za-z0-9._-]+?)(?:#(.+))?$/.exec(s);
  if (short && !s.includes("://") && !s.startsWith("@")) return { owner: short[1]!, repo: short[2]!, ref: short[3] };
  const m = /^(?:https?:\/\/|ssh:\/\/git@|git@)?(?:www\.)?github\.com[/:]([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+?)(?:\/(?:tree|blob|commit)\/([^/?#]+))?(?:[/?#].*)?$/i.exec(s);
  if (!m) return null;
  const hashRef = /#([^#]+)$/.exec(s)?.[1];
  return { owner: m[1]!, repo: m[2]!, ref: m[3] ?? hashRef };
}

function headers(token?: string): Record<string, string> {
  const t = token ?? process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  return {
    accept: "application/vnd.github+json",
    "x-github-api-version": "2022-11-28",
    ...(t ? { authorization: `Bearer ${t}` } : {}),
  };
}

export async function getGithubRepo(ref: GithubRef, token?: string): Promise<GithubRepo | null> {
  return fetchJson<GithubRepo>(`https://api.github.com/repos/${ref.owner}/${ref.repo}`, { headers: headers(token), timeoutMs: 10_000 });
}

export async function getGithubOwner(login: string, token?: string): Promise<GithubOwner | null> {
  return fetchJson<GithubOwner>(`https://api.github.com/users/${encodeURIComponent(login)}`, { headers: headers(token), timeoutMs: 8000 });
}

/** Earliest stars with timestamps (first page = the first 100 stargazers). */
export async function getStarTimes(ref: GithubRef, token?: string): Promise<Date[]> {
  const res = await fetchJson<{ starred_at: string }[]>(
    `https://api.github.com/repos/${ref.owner}/${ref.repo}/stargazers?per_page=100`,
    { headers: { ...headers(token), accept: "application/vnd.github.star+json" }, timeoutMs: 8000 },
  );
  return (res ?? []).map((s) => new Date(s.starred_at)).filter((d) => !Number.isNaN(d.getTime()));
}

export interface GithubReleaseAsset {
  name: string;
  size: number;
  download_count: number;
}

export async function getLatestReleaseAssets(ref: GithubRef, token?: string): Promise<GithubReleaseAsset[]> {
  const res = await fetchJson<{ assets?: GithubReleaseAsset[] }[]>(
    `https://api.github.com/repos/${ref.owner}/${ref.repo}/releases?per_page=5`,
    { headers: headers(token), timeoutMs: 8000 },
  ).catch(() => null);
  return (res ?? []).flatMap((r) => r.assets ?? []);
}

/** Repo snapshot as a gzipped tarball. codeload does not count against the REST rate limit. */
export async function fetchGithubTarball(ref: GithubRef, branch: string, maxBytes = 60 * 1024 * 1024): Promise<Uint8Array> {
  const url = `https://codeload.github.com/${ref.owner}/${ref.repo}/tar.gz/${encodeURIComponent(ref.ref ?? branch)}`;
  try {
    return await fetchBytes(url, { timeoutMs: 45_000, maxBytes });
  } catch (err) {
    if (err instanceof HttpError && err.status === 404) throw new Error(`GitHub repo or ref not found: ${ref.owner}/${ref.repo}`);
    throw err;
  }
}

export async function fetchGithubRaw(ref: GithubRef, path: string, timeoutMs = 6000): Promise<string | null> {
  const url = `https://raw.githubusercontent.com/${ref.owner}/${ref.repo}/${encodeURIComponent(ref.ref ?? "HEAD")}/${path}`;
  try {
    return new TextDecoder().decode(await fetchBytes(url, { timeoutMs, maxBytes: 2 * 1024 * 1024 }));
  } catch {
    return null;
  }
}
