export function ShieldMark({ className = "h-7 w-7" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden="true">
      <path d="M16 4.5l9.5 3.6v7.2c0 6-4 10.4-9.5 12.2C10.5 25.7 6.5 21.3 6.5 15.3V8.1z" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinejoin="round" />
      <path d="M11.5 16.2l3.2 3.2 6-6.4" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Logo() {
  return (
    <span className="inline-flex items-center gap-2 text-accent">
      <ShieldMark />
      <span className="font-display text-lg font-bold tracking-tight text-text">BotGuard</span>
    </span>
  );
}
