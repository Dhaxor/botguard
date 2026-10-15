import pc from "picocolors";
import type { CheckResult } from "@botguard/core/install";
import { VERDICT_LABEL, type Finding, type ScanReport, type Severity, type Verdict } from "@botguard/core";

const SEV_COLOR: Record<Severity, (s: string) => string> = {
  critical: (s) => pc.bgRed(pc.white(pc.bold(s))),
  high: (s) => pc.red(pc.bold(s)),
  medium: (s) => pc.yellow(s),
  low: (s) => pc.cyan(s),
  info: (s) => pc.dim(s),
};

const VERDICT_COLOR: Record<Verdict, (s: string) => string> = {
  dangerous: (s) => pc.bgRed(pc.white(pc.bold(s))),
  suspicious: (s) => pc.bgYellow(pc.black(pc.bold(s))),
  caution: (s) => pc.yellow(pc.bold(s)),
  "no-red-flags": (s) => pc.green(pc.bold(s)),
  error: (s) => pc.bgMagenta(pc.white(s)),
};

function wrap(text: string, indent: string, width = 92): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const w of words) {
    if ((line + " " + w).trim().length > width) {
      lines.push(line);
      line = w;
    } else line = `${line} ${w}`.trim();
  }
  if (line) lines.push(line);
  return lines.map((l) => indent + l).join("\n");
}

function finding(f: Finding): string {
  const out = [`  ${SEV_COLOR[f.severity](` ${f.severity.toUpperCase()} `)} ${pc.bold(f.title)}`, wrap(f.detail, "      ")];
  for (const e of f.evidence ?? []) {
    const where = e.file ? pc.dim(`${e.file}${e.line ? `:${e.line}` : ""}`) : "";
    const snippet = e.snippet ? pc.white(e.snippet.slice(0, 140)) : "";
    const url = e.url ? pc.underline(pc.blue(e.url)) : "";
    out.push(`      ${[where, snippet, url].filter(Boolean).join("  ")}`);
  }
  if (f.advice) out.push(pc.green(wrap(`→ ${f.advice}`, "      ")));
  return out.join("\n");
}

export function formatReport(r: ScanReport, verbose = false): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(`${VERDICT_COLOR[r.verdict](` ${VERDICT_LABEL[r.verdict].toUpperCase()} `)}  ${pc.bold(r.target.display)}${r.verdict !== "error" ? pc.dim(`  risk ${r.score}/100`) : ""}`);
  lines.push(wrap(r.summary, "  "));
  if (r.facts.length) {
    lines.push("");
    for (const f of r.facts) lines.push(`  ${pc.dim(f.label.padEnd(18))} ${f.value}`);
  }
  if (r.detonation) {
    lines.push("");
    if (r.detonation.compiled) {
      const runs = r.detonation.contracts.reduce((n, c) => n + c.calls.length, 0);
      lines.push(`  ${pc.dim("Sandbox".padEnd(18))} compiled with solc ${r.detonation.compilerVersion?.split("+")[0]}, ${runs} calls executed, ${r.detonation.outflows.length} outflow${r.detonation.outflows.length === 1 ? "" : "s"} to other addresses`);
    } else lines.push(`  ${pc.dim("Sandbox".padEnd(18))} not run (${r.detonation.error?.split("\n")[0] ?? "compile failed"})`);
  }
  const shown = r.findings.filter((f) => verbose || f.severity !== "info");
  if (shown.length) {
    lines.push("");
    for (const f of shown) lines.push(finding(f), "");
  }
  for (const n of r.notes) lines.push(pc.dim(`  note: ${n}`));
  lines.push(pc.dim(`  ${r.stats.filesScanned} file${r.stats.filesScanned === 1 ? "" : "s"}, ${(r.stats.bytesScanned / 1024).toFixed(0)} KB scanned in ${(r.stats.durationMs / 1000).toFixed(1)}s · ${r.engine}`));
  lines.push("");
  return lines.join("\n");
}

export function formatCheck(command: string, r: CheckResult): string {
  const badge = r.decision === "deny" ? pc.bgRed(pc.white(pc.bold(" BLOCK "))) : r.decision === "ask" ? pc.bgYellow(pc.black(pc.bold(" ASK "))) : pc.green(pc.bold(" ALLOW "));
  const lines = ["", `${badge}  ${pc.bold(command)}`];
  if (!r.verdicts.length) lines.push(pc.dim("  No installs detected in this command."));
  for (const v of r.verdicts) {
    const mark = v.decision === "deny" ? pc.red("✖") : v.decision === "ask" ? pc.yellow("?") : pc.green("✔");
    lines.push(`  ${mark} ${v.label}`);
    for (const f of v.findings.filter((x) => x.severity !== "info")) lines.push(`      ${SEV_COLOR[f.severity](f.severity)} ${f.title}`);
  }
  for (const n of r.notes) lines.push(pc.dim(`  note: ${n}`));
  lines.push("");
  return lines.join("\n");
}
