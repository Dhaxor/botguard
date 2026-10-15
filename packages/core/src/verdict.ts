import type { Finding, Severity, Verdict } from "./types";

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 100,
  high: 40,
  medium: 15,
  low: 4,
  info: 0,
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/** Bump a severity up one level (used when code runs at install time). */
export function escalate(s: Severity): Severity {
  const i = severityRank(s);
  return SEVERITY_ORDER[Math.max(0, i - 1)]!;
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}

export function computeVerdict(findings: Finding[]): { verdict: Verdict; score: number } {
  const raw = findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
  const score = Math.min(100, raw);
  const has = (s: Severity) => findings.some((f) => f.severity === s);
  if (has("critical")) return { verdict: "dangerous", score };
  if (has("high") || raw >= 60) return { verdict: "suspicious", score };
  if (has("medium") || raw >= 15) return { verdict: "caution", score };
  return { verdict: "no-red-flags", score };
}

export const VERDICT_LABEL: Record<Verdict, string> = {
  dangerous: "Dangerous",
  suspicious: "Suspicious",
  caution: "Caution",
  "no-red-flags": "No red flags found",
  error: "Scan failed",
};

export function summarize(verdict: Verdict, findings: Finding[]): string {
  const top = sortFindings(findings)[0];
  switch (verdict) {
    case "dangerous":
      return `Do not run or install this. ${top?.title ?? ""}`.trim();
    case "suspicious":
      return `Strong warning signs. ${top?.title ?? ""}`.trim();
    case "caution":
      return `Some risk factors worth checking. ${top?.title ?? ""}`.trim();
    case "no-red-flags":
      return "No known malware or common red flags found. This is not a guarantee: still use a fresh wallet and keys that cannot withdraw.";
    default:
      return "The scan could not finish.";
  }
}

/** Merge findings that share a rule id, keeping the worst severity and pooling evidence. */
export function dedupeFindings(findings: Finding[], maxEvidence = 5): Finding[] {
  const byId = new Map<string, Finding>();
  for (const f of findings) {
    const prev = byId.get(f.id);
    if (!prev) {
      byId.set(f.id, { ...f, evidence: f.evidence ? [...f.evidence] : undefined });
      continue;
    }
    if (severityRank(f.severity) < severityRank(prev.severity)) {
      prev.severity = f.severity;
      prev.title = f.title;
      prev.detail = f.detail;
    }
    if (f.evidence?.length) {
      prev.evidence = [...(prev.evidence ?? []), ...f.evidence];
    }
  }
  for (const f of byId.values()) {
    if (f.evidence) {
      const seen = new Set<string>();
      f.evidence = f.evidence.filter((e) => {
        const k = `${e.file ?? ""}:${e.line ?? ""}:${e.snippet ?? ""}:${e.url ?? ""}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });
    }
    if (f.evidence && f.evidence.length > maxEvidence) {
      const extra = f.evidence.length - maxEvidence;
      f.evidence = f.evidence.slice(0, maxEvidence);
      f.detail = `${f.detail} (${extra} more location${extra === 1 ? "" : "s"} not shown)`;
    }
  }
  return sortFindings([...byId.values()]);
}
