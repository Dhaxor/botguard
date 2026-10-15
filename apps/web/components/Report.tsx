"use client";

import type { DetonationSummary, Finding, ScanReport, Severity, Verdict } from "@botguard/core";

const VERDICT: Record<Verdict, { label: string; tone: string; ring: string; blurb: string }> = {
  dangerous: { label: "Dangerous", tone: "text-critical", ring: "border-critical/50 bg-critical/[0.07]", blurb: "Do not run, install or fund this." },
  suspicious: { label: "Suspicious", tone: "text-high", ring: "border-high/50 bg-high/[0.07]", blurb: "Strong warning signs. Treat as hostile until proven otherwise." },
  caution: { label: "Caution", tone: "text-medium", ring: "border-medium/40 bg-medium/[0.06]", blurb: "Some risk factors worth checking before you trust it." },
  "no-red-flags": { label: "No red flags", tone: "text-ok", ring: "border-ok/40 bg-ok/[0.06]", blurb: "Nothing known-bad found. Still use a fresh wallet and keys that can't withdraw." },
  error: { label: "Couldn't scan", tone: "text-muted", ring: "border-line-2 bg-panel", blurb: "" },
};

const SEV: Record<Severity, { label: string; pill: string; bar: string }> = {
  critical: { label: "Critical", pill: "bg-critical text-white", bar: "bg-critical" },
  high: { label: "High", pill: "bg-high/15 text-high ring-1 ring-high/40", bar: "bg-high" },
  medium: { label: "Medium", pill: "bg-medium/12 text-medium ring-1 ring-medium/35", bar: "bg-medium" },
  low: { label: "Low", pill: "bg-low/12 text-low ring-1 ring-low/30", bar: "bg-low" },
  info: { label: "Info", pill: "bg-panel-2 text-muted ring-1 ring-line-2", bar: "bg-dim" },
};

function VerdictIcon({ verdict }: { verdict: Verdict }) {
  const common = "h-10 w-10 shrink-0";
  if (verdict === "no-red-flags") {
    return (
      <svg viewBox="0 0 40 40" className={`${common} text-ok`} aria-hidden="true">
        <path d="M20 4l13 5v9.5c0 8.2-5.5 14.2-13 16.8C12.5 32.7 7 26.7 7 18.5V9z" fill="currentColor" fillOpacity="0.12" stroke="currentColor" strokeWidth="2.2" strokeLinejoin="round" />
        <path d="M14 20l4.2 4.2L26.5 16" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  const color = verdict === "dangerous" ? "text-critical" : verdict === "suspicious" ? "text-high" : verdict === "caution" ? "text-medium" : "text-muted";
  return (
    <svg viewBox="0 0 40 40" className={`${common} ${color}`} aria-hidden="true">
      {verdict === "dangerous" ? (
        <path d="M13.4 4h13.2L36 13.4v13.2L26.6 36H13.4L4 26.6V13.4z" fill="currentColor" fillOpacity="0.14" stroke="currentColor" strokeWidth="2.2" strokeLinejoin="round" />
      ) : (
        <path d="M20 5L36 33H4z" fill="currentColor" fillOpacity="0.12" stroke="currentColor" strokeWidth="2.2" strokeLinejoin="round" />
      )}
      <path d={verdict === "dangerous" ? "M20 12v10" : "M20 15v8"} stroke="currentColor" strokeWidth="2.8" strokeLinecap="round" />
      <circle cx="20" cy={verdict === "dangerous" ? 27.5 : 28} r="1.8" fill="currentColor" />
    </svg>
  );
}

function RiskMeter({ score, verdict }: { score: number; verdict: Verdict }) {
  const color = verdict === "dangerous" ? "bg-critical" : verdict === "suspicious" ? "bg-high" : verdict === "caution" ? "bg-medium" : "bg-ok";
  return (
    <div className="w-full max-w-[220px]">
      <div className="mb-1.5 flex items-baseline justify-between text-xs text-dim">
        <span>Risk</span>
        <span className="font-mono text-sm text-text">{score}<span className="text-dim">/100</span></span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-panel-2 ring-1 ring-line">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${Math.max(4, score)}%` }} />
      </div>
    </div>
  );
}

function short(addr: string) {
  return addr.length > 14 ? `${addr.slice(0, 8)}…${addr.slice(-4)}` : addr;
}

function eth(wei: string) {
  const v = Number(BigInt(wei) / 10n ** 14n) / 10_000;
  return `${v.toLocaleString(undefined, { maximumFractionDigits: 4 })} ETH`;
}

function SandboxPanel({ d }: { d: DetonationSummary }) {
  if (!d.compiled) {
    return (
      <section className="rounded-2xl border border-line bg-panel p-5">
        <h3 className="font-display text-base font-semibold">Sandbox run</h3>
        <p className="mt-1 text-sm text-muted">The contract couldn&apos;t be compiled here, so only static checks ran. {d.error ? <span className="font-mono text-xs text-dim">{d.error.split("\n")[0]}</span> : null}</p>
      </section>
    );
  }
  const drained = d.outflows.filter((o) => !o.label);
  const total = drained.reduce((s, o) => s + BigInt(o.valueWei), 0n);
  const recipient = drained[0]?.to;
  const contract = d.contracts.find((c) => c.deployed)?.name ?? d.contracts[0]?.name ?? "Contract";
  const bad = drained.length > 0;
  return (
    <section className={`rounded-2xl border p-5 ${bad ? "border-critical/40 bg-critical/[0.05]" : "border-line bg-panel"}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-display text-base font-semibold">Sandbox run</h3>
        <span className="font-mono text-xs text-dim">solc {d.compilerVersion?.split("+")[0]} · in-memory EVM · test ETH only</span>
      </div>
      <p className="mt-1 text-sm text-muted">We deployed it from a test wallet, funded it with test ETH, then pressed every button the way a victim would.</p>

      <div className="mt-5 grid grid-cols-1 items-center gap-1 text-center sm:grid-cols-[1fr_auto_1fr_auto_1fr] sm:gap-3">
        <div className="rounded-xl border border-line-2 bg-bg px-2 py-3">
          <div className="text-[11px] uppercase tracking-wider text-dim">You</div>
          <div className="mt-0.5 font-mono text-xs text-text sm:text-sm">test wallet</div>
        </div>
        <FlowArrow label={d.depositedWei ? eth(d.depositedWei) : "test ETH"} tone="text-muted" />
        <div className="rounded-xl border border-line-2 bg-bg px-2 py-3">
          <div className="text-[11px] uppercase tracking-wider text-dim">Contract</div>
          <div className="mt-0.5 truncate font-mono text-xs text-text sm:text-sm">{contract}</div>
        </div>
        <FlowArrow label={bad ? eth(total.toString()) : "0 ETH"} tone={bad ? "text-critical" : "text-dim"} active={bad} />
        <div className={`rounded-xl border px-2 py-3 ${bad ? "border-critical/60 bg-critical/10" : "border-line-2 bg-bg"}`}>
          <div className={`text-[11px] uppercase tracking-wider ${bad ? "text-critical" : "text-dim"}`}>{bad ? "Unknown address" : "Others"}</div>
          <div className="mt-0.5 truncate font-mono text-xs text-text sm:text-sm" title={recipient}>{recipient ? short(recipient) : "nothing sent"}</div>
        </div>
      </div>

      <div className="mt-5 flex flex-wrap gap-2">
        {d.contracts.flatMap((c) =>
          c.calls.map((call, i) => {
            const out = d.outflows.filter((o) => o.contract === c.name && o.fn === call.fn && !o.label);
            return (
              <span
                key={`${c.name}-${call.fn}-${i}`}
                className={`inline-flex items-center gap-1.5 rounded-md px-2 py-1 font-mono text-xs ring-1 ${
                  out.length ? "bg-critical/10 text-critical ring-critical/40" : call.ok ? "bg-panel-2 text-muted ring-line-2" : "bg-panel-2 text-dim ring-line"
                }`}
              >
                {call.fn}
                <span className="opacity-80">{out.length ? `→ ${eth(out.reduce((s, o) => s + BigInt(o.valueWei), 0n).toString())} out` : call.ok ? "✓" : "reverted"}</span>
              </span>
            );
          }),
        )}
      </div>
    </section>
  );
}

function FlowArrow({ label, tone, active = false }: { label: string; tone: string; active?: boolean }) {
  return (
    <div className={tone}>
      {/* Phones: arrow points down between stacked boxes. */}
      <div className="flex items-center justify-center gap-2 py-0.5 sm:hidden">
        <svg viewBox="0 0 12 28" className="h-6 w-3" aria-hidden="true">
          <line x1="6" y1="0" x2="6" y2="22" stroke="currentColor" strokeWidth="2" className={active ? "flow-line" : undefined} />
          <path d="M1 20l5 7 5-7" fill="none" stroke="currentColor" strokeWidth="2" />
        </svg>
        <span className="font-mono text-xs">{label}</span>
      </div>
      <div className="hidden min-w-[56px] flex-col items-center sm:flex">
        <span className="whitespace-nowrap font-mono text-xs">{label}</span>
        <svg viewBox="0 0 80 12" className="h-3 w-full" aria-hidden="true" preserveAspectRatio="none">
          <line x1="0" y1="6" x2="72" y2="6" stroke="currentColor" strokeWidth="2" className={active ? "flow-line" : undefined} />
          <path d="M70 1l8 5-8 5" fill="none" stroke="currentColor" strokeWidth="2" />
        </svg>
      </div>
    </div>
  );
}

function FindingCard({ f }: { f: Finding }) {
  const sev = SEV[f.severity];
  return (
    <li className="rounded-xl border border-line bg-panel">
      <details className="group" open={f.severity === "critical" || f.severity === "high"}>
        <summary className="flex cursor-pointer items-start gap-3 p-4">
          <span className={`mt-0.5 shrink-0 rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${sev.pill}`}>{sev.label}</span>
          <span className="min-w-0 flex-1">
            <span className="block font-medium leading-snug text-text">{f.title}</span>
            <span className="mt-1 block text-sm leading-relaxed text-muted">{f.detail}</span>
          </span>
          <svg viewBox="0 0 20 20" className="mt-1 h-4 w-4 shrink-0 text-dim transition group-open:rotate-180" aria-hidden="true">
            <path d="M5 8l5 5 5-5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </summary>
        {(f.evidence?.length || f.advice) && (
          <div className="space-y-2 border-t border-line px-4 pb-4 pt-3">
            {f.evidence?.map((e, i) => (
              <div key={i} className="overflow-hidden rounded-lg border border-line bg-bg">
                {(e.file || e.url) && (
                  <div className="flex items-center justify-between gap-2 border-b border-line px-3 py-1.5 font-mono text-[11px] text-dim">
                    <span className="truncate">{e.file ? `${e.file}${e.line ? `:${e.line}` : ""}` : ""}</span>
                    {e.url && (
                      <a href={e.url} target="_blank" rel="noreferrer" className="shrink-0 text-accent hover:underline">
                        source ↗
                      </a>
                    )}
                  </div>
                )}
                {e.snippet && <pre className="overflow-x-auto px-3 py-2 font-mono text-[12.5px] leading-relaxed text-text">{e.snippet}</pre>}
              </div>
            ))}
            {f.advice && <p className="text-sm text-ok">→ {f.advice}</p>}
          </div>
        )}
      </details>
    </li>
  );
}

export function Report({ report }: { report: ScanReport }) {
  const v = VERDICT[report.verdict];
  const findings = report.findings.filter((f) => f.severity !== "info");
  const info = report.findings.filter((f) => f.severity === "info");
  return (
    <div className="space-y-4">
      <section className={`rounded-2xl border p-5 sm:p-6 ${v.ring}`}>
        <div className="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex items-start gap-4">
            <VerdictIcon verdict={report.verdict} />
            <div className="min-w-0">
              <div className={`font-display text-3xl font-bold tracking-tight ${v.tone}`}>{v.label}</div>
              <div className="mt-1 break-all font-mono text-sm text-muted">
                {report.target.url ? (
                  <a href={report.target.url} target="_blank" rel="noreferrer" className="hover:text-text hover:underline">
                    {report.target.display}
                  </a>
                ) : (
                  report.target.display
                )}
              </div>
            </div>
          </div>
          {report.verdict !== "error" && <RiskMeter score={report.score} verdict={report.verdict} />}
        </div>
        <p className="mt-4 text-[15px] leading-relaxed text-text">{report.verdict === "error" ? report.summary : v.blurb}</p>
        {report.verdict !== "error" && report.verdict !== "no-red-flags" && findings[0] && (
          <p className="mt-1 text-sm text-muted">Top issue: {findings[0].title}</p>
        )}
        {report.facts.length > 0 && (
          <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-3 border-t border-line pt-4 sm:grid-cols-3">
            {report.facts.map((f) => (
              <div key={f.label} className="min-w-0">
                <dt className="text-[11px] uppercase tracking-wider text-dim">{f.label}</dt>
                <dd className="mt-0.5 truncate font-mono text-[13px] text-text" title={f.value}>
                  {f.value}
                </dd>
              </div>
            ))}
          </dl>
        )}
      </section>

      {report.detonation && <SandboxPanel d={report.detonation} />}

      {findings.length > 0 && (
        <section>
          <h3 className="mb-2 mt-6 font-display text-base font-semibold">
            {findings.length} finding{findings.length === 1 ? "" : "s"}
          </h3>
          <ul className="space-y-2">
            {findings.map((f) => (
              <FindingCard key={f.id} f={f} />
            ))}
          </ul>
        </section>
      )}

      {info.length > 0 && (
        <details className="rounded-xl border border-line bg-panel px-4 py-3 text-sm text-muted">
          <summary className="cursor-pointer text-dim">{info.length} informational note{info.length === 1 ? "" : "s"}</summary>
          <ul className="mt-2 space-y-1.5">
            {info.map((f) => (
              <li key={f.id}>
                <span className="text-text">{f.title}.</span> {f.detail}
              </li>
            ))}
          </ul>
        </details>
      )}

      {report.notes.length > 0 && (
        <ul className="space-y-1 text-xs text-dim">
          {report.notes.map((n) => (
            <li key={n}>Note: {n}</li>
          ))}
        </ul>
      )}
      {report.verdict !== "error" && (
        <p className="font-mono text-[11px] text-dim">
          {report.stats.filesScanned} file{report.stats.filesScanned === 1 ? "" : "s"} · {(report.stats.bytesScanned / 1024).toFixed(0)} KB · {(report.stats.durationMs / 1000).toFixed(1)}s · {report.engine}
        </p>
      )}
    </div>
  );
}
