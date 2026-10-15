import type { Evidence, Finding, Severity, SourceFile } from "../types";
import { escalate, severityRank } from "../verdict";
import { COMBOS, RULES, type Rule, type Tag } from "./rules";
import { callArgs, isMinified, isNonRuntimePath, langOf, LineIndex } from "./text";

export interface CodeScanOptions {
  /** Files that run automatically at install time (package.json scripts, setup.py). */
  installTime?: Set<string>;
}

interface Hit {
  rule: Rule;
  evidence: Evidence[];
  count: number;
}

function downgrade(s: Severity): Severity {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  return order[Math.min(order.length - 1, order.indexOf(s) + 1)]!;
}

function scanFile(file: SourceFile, lang: NonNullable<ReturnType<typeof langOf>>): Hit[] {
  const hits: Hit[] = [];
  let index: LineIndex | undefined;
  for (const rule of RULES) {
    if (!rule.langs.includes(lang)) continue;
    rule.re.lastIndex = 0;
    const evidence: Evidence[] = [];
    let count = 0;
    for (const m of file.text.matchAll(rule.re)) {
      if (rule.accept && !rule.accept(m[0])) continue;
      if (rule.argsTest) {
        const args = callArgs(file.text, m.index + m[0].length - 1);
        if (args === null || !rule.argsTest(args)) continue;
      }
      count++;
      if (evidence.length < 3) {
        index ??= new LineIndex(file.text);
        evidence.push(index.evidence(file.path, m.index, m[0].length));
      }
      if (count > 500) break;
    }
    if (count >= (rule.minCount ?? 1)) hits.push({ rule, evidence, count });
  }
  return hits;
}

/**
 * Apply the code rules to every file. Signals that are only meaningful together (read a secret + send
 * it somewhere) are combined per file, so ordinary bots that read PRIVATE_KEY and call an exchange
 * API do not light up.
 */
export function scanCode(files: SourceFile[], opts: CodeScanOptions = {}): Finding[] {
  const findings: Finding[] = [];
  for (const file of files) {
    const lang = langOf(file.path);
    if (!lang || lang === "sol" || lang === "text") continue;
    const hits = scanFile(file, lang);
    if (!hits.length) continue;

    const installTime = opts.installTime?.has(file.path) ?? false;
    const nonRuntime = isNonRuntimePath(file.path) && !installTime;
    const minified = lang === "js" && isMinified(file.text);
    const adjust = (s: Severity) => (installTime ? escalate(s) : nonRuntime ? downgrade(s) : s);

    const tags = new Set<Tag>();
    for (const h of hits) {
      for (const t of h.rule.tags) {
        // eval/new Function are routine in bundled/minified output; only obfuscation makes them interesting.
        if (minified && t === "eval" && !hits.some((x) => x.rule.tags.includes("obf"))) continue;
        tags.add(t);
      }
    }

    const consumed = new Set<string>();
    for (const combo of COMBOS) {
      if (!combo.all.every((group) => group.some((t) => tags.has(t)))) continue;
      // One rule that already covers every part of the combo reports itself with a more specific title.
      const selfContained = hits.some((h) => h.rule.alone && combo.all.every((g) => g.some((t) => h.rule.tags.includes(t))));
      if (selfContained) continue;
      const parts = hits.filter((h) => combo.all.some((g) => g.some((t) => h.rule.tags.includes(t))));
      const severity = adjust(combo.severity);
      for (const p of parts) if (p.rule.alone && severityRank(severity) <= severityRank(p.rule.alone.severity)) consumed.add(p.rule.id);
      findings.push({
        id: `code.${combo.id}`,
        severity,
        category: combo.category,
        title: combo.title + (installTime ? " (runs at install time)" : ""),
        detail: combo.detail,
        advice: combo.advice,
        evidence: parts.flatMap((p) => p.evidence.slice(0, 2)).slice(0, 5),
      });
    }

    for (const h of hits) {
      if (!h.rule.alone || consumed.has(h.rule.id)) continue;
      findings.push({
        id: `code.${h.rule.id}`,
        severity: adjust(h.rule.alone.severity),
        category: h.rule.alone.category,
        title: h.rule.alone.title + (installTime ? " (runs at install time)" : ""),
        detail: h.rule.alone.detail,
        advice: h.rule.alone.advice,
        evidence: h.evidence,
      });
    }

    // Install hooks that phone home or spawn processes are worth flagging even without other signals.
    if (installTime && (tags.has("net") || tags.has("exec"))) {
      const parts = hits.filter((h) => h.rule.tags.includes("net") || h.rule.tags.includes("exec"));
      findings.push({
        id: "code.install-time-activity",
        severity: "medium",
        category: "install-script",
        title: "Install-time code makes network calls or spawns processes",
        detail: "This file runs automatically during install. Network or process activity at that point happens before you have reviewed or run anything yourself.",
        evidence: parts.flatMap((p) => p.evidence.slice(0, 1)).slice(0, 4),
      });
    }
  }
  return findings;
}
