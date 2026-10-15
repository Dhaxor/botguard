"use client";

import { useEffect, useRef, useState } from "react";
import type { ScanReport } from "@botguard/core";
import { EXAMPLES, type Mode } from "@/lib/samples";
import { Report } from "./Report";

const MODES: { id: Mode; label: string }[] = [
  { id: "auto", label: "Auto" },
  { id: "github", label: "GitHub" },
  { id: "npm", label: "npm" },
  { id: "pypi", label: "PyPI" },
  { id: "solidity", label: "Solidity" },
];

const PLACEHOLDER: Record<Mode, string> = {
  auto: "github.com/owner/repo · npm:package · pypi:package · or paste a Solidity contract",
  github: "github.com/owner/polymarket-bot",
  npm: "package-name or package@version",
  pypi: "package-name or package==version",
  solidity: "Paste the contract source the video told you to deploy…",
};

const STEPS: Record<"github" | "package" | "solidity", string[]> = {
  github: ["Reading repository metadata", "Downloading the code", "Running 40+ malware rules", "Checking dependencies against OSV", "Looking for scam instructions"],
  package: ["Resolving the version", "Checking the OSV malware database", "Unpacking the package", "Running 40+ malware rules", "Checking its dependencies"],
  solidity: ["Compiling with solc", "Deploying to a sandbox EVM", "Funding it with 10 test ETH", "Pressing every button", "Tracing where the money goes"],
};

function looksLikeSolidity(s: string) {
  return /\bpragma\s+solidity\b|\bcontract\s+\w+\s*(?:is\s+[\w\s,]+)?\{/.test(s);
}

export function Scanner() {
  const [input, setInput] = useState("");
  const [mode, setMode] = useState<Mode>("auto");
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);
  const textRef = useRef<HTMLTextAreaElement>(null);

  const isSol = mode === "solidity" || (mode === "auto" && looksLikeSolidity(input));
  const kind: keyof typeof STEPS = isSol ? "solidity" : mode === "github" || /github\.com|^[\w-]+\/[\w.-]+$/.test(input.trim()) ? "github" : "package";

  useEffect(() => {
    if (!loading) return;
    setStep(0);
    const t = setInterval(() => setStep((s) => Math.min(s + 1, STEPS[kind].length - 1)), 1300);
    return () => clearInterval(t);
  }, [loading, kind]);

  useEffect(() => {
    const el = textRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(isSol ? 360 : 140, el.scrollHeight)}px`;
  }, [input, isSol]);

  async function run(value = input, m = mode) {
    if (!value.trim() || loading) return;
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const res = await fetch("/api/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ input: value, kind: m }) });
      const data = (await res.json()) as ScanReport & { error?: string };
      if (!res.ok || data.error) setError(data.error ?? `Scan failed (HTTP ${res.status})`);
      else setReport(data);
    } catch {
      setError("Couldn't reach the scanner. Check your connection and try again.");
    } finally {
      setLoading(false);
      requestAnimationFrame(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
    }
  }

  return (
    <div>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          run();
        }}
        className="glow-accent rounded-2xl border border-line-2 bg-panel/90 p-2 backdrop-blur"
      >
        <div className="flex flex-wrap items-center gap-1 px-1 pb-2 pt-1" role="radiogroup" aria-label="What are you scanning?">
          {MODES.map((m) => (
            <button
              key={m.id}
              type="button"
              role="radio"
              aria-checked={mode === m.id}
              onClick={() => setMode(m.id)}
              className={`rounded-lg px-2.5 py-1 text-xs font-medium transition ${
                mode === m.id ? "bg-accent text-bg" : "text-muted hover:bg-panel-2 hover:text-text"
              }`}
            >
              {m.label}
            </button>
          ))}
          {mode === "auto" && input.trim() && (
            <span className="ml-auto pr-1 font-mono text-[11px] text-dim">detected: {isSol ? "solidity" : kind === "github" ? "github" : "package"}</span>
          )}
        </div>
        <div className="flex items-end gap-2 rounded-xl border border-line bg-bg p-2 focus-within:border-accent/50">
          <label htmlFor="scan-input" className="sr-only">
            Repo, package or contract to scan
          </label>
          <textarea
            id="scan-input"
            ref={textRef}
            rows={1}
            value={input}
            spellCheck={false}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey && (!isSol || e.metaKey || e.ctrlKey)) {
                e.preventDefault();
                run();
              }
            }}
            placeholder={PLACEHOLDER[mode]}
            className={`min-h-[44px] flex-1 resize-none bg-transparent px-2 py-2.5 text-[15px] text-text outline-none placeholder:text-dim ${isSol ? "font-mono text-[13px] leading-relaxed" : ""}`}
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="h-11 shrink-0 rounded-lg bg-accent px-5 font-display text-[15px] font-semibold text-bg transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {loading ? "Scanning…" : "Scan"}
          </button>
        </div>
        {loading && (
          <div className="px-2 pb-1 pt-3" aria-live="polite">
            <div className="scan-bar relative h-1 overflow-hidden rounded-full bg-panel-2" />
            <div className="mt-2 font-mono text-xs text-muted">{STEPS[kind][step]}…</div>
          </div>
        )}
      </form>

      <div className="mt-4 flex flex-wrap items-center gap-2 text-sm">
        <span className="text-dim">Try:</span>
        {EXAMPLES.map((ex) => (
          <button
            key={ex.label}
            type="button"
            disabled={loading}
            onClick={() => {
              setInput(ex.input);
              setMode(ex.mode);
              run(ex.input, ex.mode);
            }}
            className="group inline-flex items-center gap-2 rounded-full border border-line bg-panel px-3 py-1.5 text-left transition hover:border-accent/50 disabled:opacity-50"
          >
            <span className="font-mono text-[13px] text-text">{ex.label}</span>
            <span className="text-xs text-dim group-hover:text-muted">{ex.hint}</span>
          </button>
        ))}
      </div>

      <div ref={resultRef} className="scroll-mt-6">
        {error && <div className="mt-6 rounded-xl border border-critical/40 bg-critical/10 px-4 py-3 text-sm text-text">{error}</div>}
        {report && (
          <div className="mt-8">
            <Report report={report} />
          </div>
        )}
      </div>
    </div>
  );
}
