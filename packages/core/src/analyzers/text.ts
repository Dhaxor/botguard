import type { Evidence } from "../types";
import type { Lang } from "./rules";

export function langOf(path: string): Lang | undefined {
  const p = path.toLowerCase();
  if (p.endsWith(".d.ts")) return undefined;
  if (/\.(m?[jt]sx?|c[jt]s)$/.test(p)) return "js";
  if (/\.(py|pyw)$/.test(p) || /(^|\/)setup$/.test(p)) return "py";
  if (/\.(sh|bash|zsh|ps1|psm1|bat|cmd|vbs)$/.test(p) || /(^|\/)(makefile|install)$/.test(p)) return "shell";
  if (p.endsWith(".sol")) return "sol";
  if (/\.(md|markdown|txt|rst|html?)$/.test(p) || /(^|\/)readme$/.test(p)) return "text";
  return undefined;
}

/** Paths whose code never runs for an end user: tests, fixtures, examples, docs. */
export function isNonRuntimePath(path: string): boolean {
  return /(^|\/)(tests?|__tests__|spec|specs|fixtures?|__fixtures__|__mocks__|examples?|docs?|benchmarks?)\//i.test(path) ||
    /\.(test|spec)\.[cm]?[jt]sx?$/i.test(path) ||
    /(^|\/)test_[^/]+\.py$/i.test(path);
}

export function isMinified(text: string): boolean {
  if (text.length < 4000) return false;
  const lines = text.split("\n", 50);
  const longest = Math.max(...lines.map((l) => l.length));
  return longest > 3000;
}

export class LineIndex {
  private starts: number[] = [0];
  constructor(private text: string) {
    for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) this.starts.push(i + 1);
  }
  lineOf(index: number): number {
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.starts[mid]! <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  }
  /** The matched line, trimmed to a window around the match for very long (minified) lines. */
  snippet(index: number, length: number): string {
    const line = this.lineOf(index) - 1;
    const start = this.starts[line]!;
    const end = this.starts[line + 1] !== undefined ? this.starts[line + 1]! - 1 : this.text.length;
    let s = this.text.slice(start, end);
    let offset = index - start;
    if (s.length > 180) {
      const from = Math.max(0, offset - 60);
      s = (from > 0 ? "…" : "") + s.slice(from, from + 170) + (from + 170 < s.length ? "…" : "");
      offset = 0;
    }
    void length;
    return s.replace(/\t/g, "  ").trim();
  }
  evidence(file: string, index: number, length: number): Evidence {
    return { file, line: this.lineOf(index), snippet: this.snippet(index, length) };
  }
}

/** Arguments of a call whose "(" sits at `open`, with naive string/paren balancing. */
export function callArgs(text: string, open: number, maxLen = 2000): string | null {
  let depth = 0;
  let quote: string | null = null;
  const end = Math.min(text.length, open + maxLen);
  for (let i = open; i < end; i++) {
    const c = text[i]!;
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") quote = c;
    else if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return text.slice(open + 1, i);
    }
  }
  return null;
}
