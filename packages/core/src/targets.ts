import { parseGithubRef } from "./registry/github";
import type { Target, TargetKind } from "./types";

export type TargetHint = "auto" | TargetKind;

function looksLikeSolidity(s: string): boolean {
  return /\bpragma\s+solidity\b/.test(s) || /\bcontract\s+[A-Za-z_]\w*\s*(?:is\s+[\w\s,]+)?\{/.test(s);
}

/** Turn whatever the user pasted into a scan target. Throws a readable error when it can't. */
export function parseTarget(raw: string, hint: TargetHint = "auto"): Target {
  const input = raw.trim();
  if (!input) throw new Error("Nothing to scan: paste a GitHub repo, a package name or Solidity code.");

  if (hint === "solidity" || (hint === "auto" && looksLikeSolidity(input))) {
    return { kind: "solidity", raw, source: input };
  }

  let s = input;
  let kind: TargetKind | undefined = hint === "auto" ? undefined : hint;
  const prefixed = /^(npm|pypi|pip|gh|github):(.+)$/i.exec(s);
  if (prefixed) {
    const p = prefixed[1]!.toLowerCase();
    kind = p === "npm" ? "npm" : p === "pypi" || p === "pip" ? "pypi" : "github";
    s = prefixed[2]!.trim();
  }

  const npmUrl = /^(?:https?:\/\/)?(?:www\.)?npmjs\.com\/package\/((?:@[^/]+\/)?[^/?#]+)(?:\/v\/([^/?#]+))?/i.exec(s);
  if (npmUrl) return { kind: "npm", raw, name: decodeURIComponent(npmUrl[1]!), spec: npmUrl[2] };
  const pypiUrl = /^(?:https?:\/\/)?pypi\.org\/project\/([^/?#]+)(?:\/([^/?#]+))?/i.exec(s);
  if (pypiUrl) return { kind: "pypi", raw, name: pypiUrl[1]!, spec: pypiUrl[2] ? `==${pypiUrl[2]}` : undefined };

  if (kind === "github" || (kind === undefined && /github\.com|^github:/i.test(s))) {
    const ref = parseGithubRef(s);
    if (!ref) throw new Error(`Not a GitHub repository: ${input}`);
    return { kind: "github", raw, owner: ref.owner, repo: ref.repo, spec: ref.ref };
  }

  if (kind === "pypi" || (kind === undefined && /^[A-Za-z0-9][A-Za-z0-9._-]*\s*(?:\[[^\]]*\])?\s*(?:===?|~=|>=|<=|!=)/.test(s))) {
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(s);
    if (!m) throw new Error(`Not a PyPI package: ${input}`);
    return { kind: "pypi", raw, name: m[1]!, spec: m[2]?.replace(/\s+/g, "") || undefined };
  }

  // owner/repo shorthand (no scope "@", exactly one slash) is a GitHub repo unless the user said npm.
  if (kind === undefined && /^[A-Za-z0-9][A-Za-z0-9-]*\/[A-Za-z0-9._-]+$/.test(s)) {
    const ref = parseGithubRef(s)!;
    return { kind: "github", raw, owner: ref.owner, repo: ref.repo };
  }

  const npm = /^((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)(?:@(.+))?$/i.exec(s);
  if (npm && (kind === undefined || kind === "npm")) return { kind: "npm", raw, name: npm[1]!, spec: npm[2] };
  throw new Error(`Couldn't tell what "${input}" is. Try a GitHub URL, npm:<name>, pypi:<name> or paste Solidity source.`);
}

export function describeTarget(t: Target): string {
  switch (t.kind) {
    case "npm":
      return `npm ${t.name}${t.spec ? `@${t.spec}` : ""}`;
    case "pypi":
      return `PyPI ${t.name}${t.spec ?? ""}`;
    case "github":
      return `github.com/${t.owner}/${t.repo}${t.spec ? `#${t.spec}` : ""}`;
    case "solidity":
      return "Solidity source";
    case "directory":
      return t.path ?? "folder";
  }
}
