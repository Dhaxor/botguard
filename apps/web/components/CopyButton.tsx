"use client";

import { useState } from "react";

export function CopyLine({ text, prompt = "$" }: { text: string; prompt?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="group flex items-center gap-3 rounded-lg border border-line bg-bg px-3.5 py-2.5 font-mono text-[13px]">
      <span className="select-none text-dim">{prompt}</span>
      <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap text-text [scrollbar-width:none]">{text}</code>
      <button
        type="button"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 1400);
          } catch {
            /* clipboard unavailable */
          }
        }}
        className="shrink-0 rounded-md border border-line-2 px-2 py-1 font-sans text-xs text-muted transition hover:border-accent/60 hover:text-accent"
        aria-label={`Copy: ${text}`}
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}
