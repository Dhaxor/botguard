import { CopyLine } from "@/components/CopyButton";
import { Logo, ShieldMark } from "@/components/Logo";
import { Scanner } from "@/components/Scanner";
import { SITE } from "@/lib/site";

const INCIDENTS = [
  {
    stat: "$517k",
    text: "drained from 224 people who followed YouTube tutorials for a “Claude-built arbitrage bot” and funded the contract themselves.",
    source: "TRM Labs, Feb–Aug 2026",
    href: "https://www.trmlabs.com/resources/blog/fake-ai-trading-bots-are-getting-victims-to-build-their-own-drainers",
  },
  {
    stat: "20+",
    text: "fake “Polymarket copy-trading bot” repos with typosquatted npm dependencies that stole .env files and wallet keys, boosted with fake stars.",
    source: "StepSecurity, Feb 2026",
    href: "https://github.com/dev-protocol/protocol/issues/1334",
  },
  {
    stat: "9",
    text: "npm packages like polymarket-claude-code and polymarket-ai-agent, named to land in AI coding sessions and exfiltrate private keys.",
    source: "OSV MAL-2026-4209…4215",
    href: "https://osv.dev/vulnerability/MAL-2026-4212",
  },
];

const CHECKS = [
  {
    title: "Known malware",
    body: "Every package and pinned dependency is checked against the OSV / OpenSSF malicious-packages database, including hijacked releases of real packages like axios 1.14.1.",
  },
  {
    title: "Typosquats & fake brands",
    body: "“axois”, “polymarket-clob-client”, unofficial “hyperliquid-sdk-pro”: names one keystroke away from the real thing, or borrowing a brand they don't own.",
  },
  {
    title: "Key-stealing code",
    body: "40+ rules for env dumps, wallet-extension and browser-profile theft, keys sent in requests, SSH backdoors, clipboard hijackers and obfuscated payloads.",
  },
  {
    title: "Install-time traps",
    body: "postinstall scripts, setup.py hooks and .pth files that run before you've read a line, scanned with extra suspicion.",
  },
  {
    title: "Drainer contracts",
    body: "Solidity is compiled and deployed into a private in-memory chain, funded with test ETH and every button pressed. You see exactly where the money goes.",
  },
  {
    title: "Fake-trust repos",
    body: "Star bursts, throwaway owner accounts, disabled issues, release .exe files and README scripts like “deploy in Remix, send ETH, press start”.",
  },
];

const FAQ = [
  {
    q: "Does BotGuard run the code I scan?",
    a: "Never the JavaScript or Python. Repos and packages are only read as text. Solidity contracts are executed, but only inside an isolated in-memory EVM with test ETH. Nothing touches a real network or wallet.",
  },
  {
    q: "What does “No red flags” mean?",
    a: "That nothing matched known malware, typosquats or the patterns we look for. It isn't a guarantee: new attacks appear daily. Run bots from a fresh wallet with keys that can't withdraw.",
  },
  {
    q: "Is my input stored?",
    a: "No. Scans run in memory and the result is returned to your browser. Public repos and packages are downloaded from GitHub, npm and PyPI only to read them.",
  },
  {
    q: "Is it free?",
    a: "Yes. The web scanner, the CLI and the Claude Code guard are free, and the code is open source (MIT) on GitHub.",
  },
];

export default function Home() {
  return (
    <div className="relative overflow-x-clip">
      <div className="lab-grid pointer-events-none absolute inset-x-0 top-0 h-[720px]" aria-hidden="true" />

      <header className="relative mx-auto flex max-w-6xl items-center justify-between px-4 py-5 sm:px-6">
        <Logo />
        <nav className="flex items-center gap-5 text-sm text-muted">
          <a href="#claude-code" className="hidden hover:text-text sm:inline">
            Claude Code guard
          </a>
          <a href="#checks" className="hidden hover:text-text sm:inline">
            What we check
          </a>
          <a href={`https://github.com/${SITE.repo}`} className="rounded-lg border border-line-2 px-3 py-1.5 hover:border-accent/50 hover:text-text">
            GitHub
          </a>
        </nav>
      </header>

      <main className="relative">
        <section className="mx-auto max-w-3xl px-4 pb-16 pt-10 sm:px-6 sm:pt-16">
          <p className="mb-4 inline-flex items-center gap-2 rounded-full border border-line-2 bg-panel/80 px-3 py-1 text-xs text-muted">
            <span className="h-1.5 w-1.5 rounded-full bg-accent" /> Free scanner for crypto trading bots
          </p>
          <h1 className="font-display text-[40px] font-bold leading-[1.02] tracking-tight sm:text-6xl">
            Check the bot before it checks out <span className="text-accent">your wallet.</span>
          </h1>
          <p className="mt-5 max-w-2xl text-[17px] leading-relaxed text-muted">
            Paste a GitHub repo, npm or PyPI package, or the Solidity contract a video told you to deploy. BotGuard hunts for key stealers, typosquats and fake-star repos, and runs contracts in a sandbox to show where your money would go.
          </p>
          <div className="mt-8">
            <Scanner />
          </div>
        </section>

        <section className="border-y border-line bg-panel/60">
          <div className="mx-auto grid max-w-6xl gap-px px-4 sm:grid-cols-3 sm:px-6">
            {INCIDENTS.map((i) => (
              <a key={i.stat} href={i.href} target="_blank" rel="noreferrer" className="group block px-1 py-8 sm:px-6">
                <div className="font-display text-4xl font-bold tracking-tight text-critical">{i.stat}</div>
                <p className="mt-2 text-sm leading-relaxed text-muted">{i.text}</p>
                <p className="mt-3 font-mono text-[11px] text-dim group-hover:text-accent">{i.source} ↗</p>
              </a>
            ))}
          </div>
        </section>

        <section id="claude-code" className="mx-auto max-w-6xl scroll-mt-8 px-4 py-20 sm:px-6">
          <div className="grid items-center gap-10 lg:grid-cols-2">
            <div className="min-w-0">
              <p className="font-mono text-xs uppercase tracking-[0.2em] text-accent">Claude Code guard</p>
              <h2 className="mt-3 font-display text-3xl font-bold tracking-tight sm:text-4xl">Your AI agent installs packages faster than you can read them.</h2>
              <p className="mt-4 leading-relaxed text-muted">
                Attackers now name packages for AI coding sessions. The BotGuard plugin checks every <span className="font-mono text-text">npm</span>, <span className="font-mono text-text">pip</span>, <span className="font-mono text-text">npx</span>, <span className="font-mono text-text">uv</span> and <span className="font-mono text-text">git clone</span> Claude is about to run. It blocks known malware and lookalikes before anything executes, and asks you about the borderline ones. Allowed installs stay silent.
              </p>
              <div className="mt-6 space-y-2">
                <CopyLine prompt=">" text={`/plugin marketplace add ${SITE.repo}`} />
                <CopyLine prompt=">" text="/plugin install botguard@botguard" />
              </div>
              <p className="mt-4 text-sm text-dim">
                Rather use a settings hook than a plugin?{" "}
                <a href={`https://github.com/${SITE.repo}#claude-code-guard`} className="text-muted underline decoration-line-2 underline-offset-4 hover:text-accent">
                  Install the CLI
                </a>{" "}
                and add the hook:
              </p>
              <div className="mt-2">
                <CopyLine text="npm i -g botguard && botguard init claude" />
              </div>
            </div>
            <div className="min-w-0 overflow-hidden rounded-2xl border border-line-2 bg-[#07080a] shadow-2xl shadow-black/40">
              <div className="flex items-center gap-1.5 border-b border-line px-4 py-2.5">
                <span className="h-2.5 w-2.5 rounded-full bg-line-2" />
                <span className="h-2.5 w-2.5 rounded-full bg-line-2" />
                <span className="h-2.5 w-2.5 rounded-full bg-line-2" />
                <span className="ml-2 font-mono text-[11px] text-dim">claude: polymarket-bot</span>
              </div>
              <div className="space-y-3 p-4 font-mono text-[12.5px] leading-relaxed">
                <p className="text-muted">
                  <span className="text-accent">●</span> Installing the Polymarket client and a copy-trading helper.
                </p>
                <p className="text-text">
                  <span className="text-dim">Bash(</span>npm install polymarket-claude-code @polymarket/clob-client<span className="text-dim">)</span>
                </p>
                <div className="rounded-lg border border-critical/40 bg-critical/10 p-3">
                  <p className="font-semibold text-critical">⛔ BotGuard blocked this install</p>
                  <p className="mt-1 text-muted">polymarket-claude-code@0.0.1-security: known malware (MAL-2026-4212); taken down by npm; uses the Polymarket name but isn&apos;t published by Polymarket</p>
                </div>
                <p className="text-muted">
                  <span className="text-accent">●</span> That package is a known key stealer. I&apos;ll use only the official <span className="text-text">@polymarket/clob-client</span>.
                </p>
              </div>
            </div>
          </div>
        </section>

        <section id="checks" className="mx-auto max-w-6xl scroll-mt-8 px-4 pb-20 sm:px-6">
          <h2 className="font-display text-3xl font-bold tracking-tight">What BotGuard checks</h2>
          <div className="mt-8 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {CHECKS.map((c) => (
              <div key={c.title} className="rounded-2xl border border-line bg-panel p-5">
                <div className="flex items-center gap-2 text-accent">
                  <ShieldMark className="h-5 w-5" />
                  <h3 className="font-display text-lg font-semibold text-text">{c.title}</h3>
                </div>
                <p className="mt-2 text-sm leading-relaxed text-muted">{c.body}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="mx-auto max-w-3xl px-4 pb-24 sm:px-6">
          <h2 className="font-display text-3xl font-bold tracking-tight">Questions</h2>
          <div className="mt-6 divide-y divide-line rounded-2xl border border-line bg-panel">
            {FAQ.map((f) => (
              <details key={f.q} className="group px-5 py-4">
                <summary className="flex cursor-pointer items-center justify-between gap-4 font-medium">
                  {f.q}
                  <span className="text-dim transition group-open:rotate-45">+</span>
                </summary>
                <p className="mt-2 text-sm leading-relaxed text-muted">{f.a}</p>
              </details>
            ))}
          </div>
          <div className="mt-8">
            <p className="text-sm text-muted">Prefer the terminal? The CLI is on npm (Node 20+):</p>
            <div className="mt-2 space-y-2">
              <CopyLine text="npx botguard scan github.com/owner/some-bot" />
              <CopyLine text="npx botguard scan npm:some-package" />
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-6xl flex-col gap-2 px-4 py-8 text-xs text-dim sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <span>BotGuard flags risk; it can&apos;t prove anything is safe. Not financial advice.</span>
          <span>Malware intel: OSV.dev / OpenSSF malicious-packages.</span>
        </div>
      </footer>
    </div>
  );
}
