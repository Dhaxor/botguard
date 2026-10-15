# BotGuard

**Check the bot before it checks out your wallet.**

BotGuard scans crypto trading-bot repos, npm/PyPI packages and Solidity contracts for the things that actually drain people in 2026: known malware, typosquats, brand impersonation, key-stealing code, install-time traps, fake-star repos and "deploy this MEV bot in Remix" drainer contracts. Solidity is compiled and **executed in a sandbox EVM** so you can see where the money goes.

It ships three ways:

| | What it does |
|---|---|
| **Web scanner** (`apps/web`) | Live at **https://botguard-scanner.vercel.app**. Paste a GitHub URL, `npm:name`, `pypi:name` or Solidity source and get a verdict, evidence and a sandbox money-flow diagram. |
| **CLI** (`packages/cli`) | `botguard scan <target>` for terminals/CI, `botguard check "<command>"` to test the install guard. |
| **Claude Code guard** (`plugin/`) | A PreToolUse hook that checks every `npm`/`pnpm`/`yarn`/`bun`/`npx`/`pip`/`uv`/`pipx`/`poetry`, `git clone` and `curl \| sh` Claude is about to run. Known malware and strong impostors are blocked; borderline cases ask you; everything else stays silent. Plus a `safe-trading-bots` skill. |

## Why

The searches behind this (Google Trends, Oct 2026): "polymarket trading bot" +2,500% YoY, "claude trading bot" +900%, "claude polymarket bot" Breakout, "trading bot github" +150%. The people searching are being hunted:

- Fake "Claude-built arbitrage bot" YouTube tutorials drained ~$517k from 224 victims; wallet warnings never fire because victims deploy the drainer themselves ([TRM Labs](https://www.trmlabs.com/resources/blog/fake-ai-trading-bots-are-getting-victims-to-build-their-own-drainers)).
- 20+ fake Polymarket bot repos with typosquatted npm deps (`ts-bign`, `big-nunber`) that stole `.env` files and keys ([StepSecurity](https://github.com/dev-protocol/protocol/issues/1334)).
- npm packages named to land in AI coding sessions: `polymarket-claude-code`, `polymarket-ai-agent`, `polymarket-bot`... ([OSV MAL-2026-4209…4215](https://osv.dev/vulnerability/MAL-2026-4212)).
- A DPRK-attributed package stealing Polymarket CLOB credentials ([Panther](https://panther.com/blog/polymarket-trader-funds-at-risk-dprk-npm-package-steals-wallet-keys)).

## Quick start (development)

```bash
npm install            # workspaces: packages/core, packages/cli, apps/web
npm test               # 45 offline tests
npm run test:live      # +10 tests against npm, PyPI, OSV and GitHub
npm run build          # packages/cli/dist/cli.mjs + plugin/hooks/botguard-hook*.mjs
npm run web            # http://localhost:3230
```

Node 20+. `GITHUB_TOKEN` raises GitHub API limits (60/h unauthenticated).

## CLI

The CLI isn't on npm yet, so run it from a checkout (Node 20+):

```bash
git clone https://github.com/Dhaxor/botguard.git && cd botguard
npm install && npm run build
node packages/cli/dist/cli.mjs scan github.com/someone/polymarket-bot
cd packages/cli && npm link     # optional: puts `botguard` on your PATH
```

Then:

```bash
botguard scan github.com/someone/polymarket-bot
botguard scan npm:polymarket-claude-code
botguard scan pypi:polymarket-client==0.13.0
botguard scan ./contracts/FrontRunBot.sol      # compiled + run in the sandbox EVM
botguard scan ./my-bot                         # local folder
botguard check "npm i axois && pip install polymarket-client"
botguard init claude [--user] [--dry-run]      # add the hook to Claude Code settings
```

Exit codes: `0` no red flags / caution, `1` suspicious, `2` dangerous, `3` error. `--json` prints the full report.

## Claude Code guard

As a plugin:

```
/plugin marketplace add Dhaxor/botguard
/plugin install botguard@botguard
```

Without the plugin: install the CLI from source (see [CLI](#cli)) and run `botguard init claude`, which adds the hook to `.claude/settings.json` (`--user` for `~/.claude/settings.json`). Local plugin testing: `claude --plugin-dir ./plugin`. Either way the hook needs Node 20+ on your PATH.

How it decides:

| Finding | Decision |
|---|---|
| Listed malware (OSV `MAL-*`), npm security placeholder | **deny**: the reason goes to Claude, which is told not to retry lookalikes |
| Strong typosquat / impersonation of a crypto brand on a fresh, low-download package | **deny** |
| Brand-new package, risky install script, custom registry, `curl \| sh` from an unknown host | **ask** you |
| Everything else | no output, so Claude Code's normal permissions apply |

BotGuard can only tighten permissions; it never auto-approves. Lookups fail open (with a note) unless `BOTGUARD_FAIL_CLOSED=1`. Commands that install nothing exit before the scanner loads (~40 ms over Node startup). Allow-list with `BOTGUARD_ALLOW=pkg1,pkg2` or a `.botguard.json` `{ "allow": [...] }` in the project.

## What it checks

- **Malware intel**: OSV / OpenSSF malicious-packages, version-exact (hijacked releases such as `axios@1.14.1` or `chalk@5.6.1` are flagged only when your version or lockfile can resolve to them, and downgraded once the registry has pulled them).
- **Typosquats**: edit distance / scope / separator / homoglyph checks against ~6.7k top npm and ~8k top PyPI names plus crypto SDKs, confirmed with download counts and age.
- **Brand impersonation**: names using Polymarket, Kalshi, Hyperliquid, MetaMask, Binance, Claude... that aren't published from the brand's npm scope, verified publisher email domain or GitHub org.
- **Code rules** (`packages/core/src/analyzers/rules.ts`): 40+ signals combined per file, so "reads PRIVATE_KEY + calls an exchange" stays quiet while "dumps env + posts to webhook.site" is critical. Covers wallet-extension / browser-profile / Telegram-session theft, keys in request bodies, env dumps, SSH backdoors, autostart persistence, clipboard hijackers, balance sweeps to hard-coded addresses, decode-and-eval payloads, obfuscators and PyArmor.
- **Install-time traps**: `preinstall`/`postinstall` scripts (and the files they run), `setup.py` cmdclass, `.pth` autorun files, URL/git dependencies, extra package indexes, lockfiles (npm, yarn, pnpm, poetry).
- **Scam text**: README instructions like "deploy in Remix, send ETH, press start", seed-phrase requests, activation fees, "disable your antivirus", profit promises, file-host binaries.
- **Repo signals**: star bursts (bought stars), throwaway owners, disabled issues, release executables.
- **Solidity**: hidden-recipient balance sweeps, string-to-address parsers, hex fragments, scam template naming, remote imports, then the **sandbox**: compile with solc (any 0.4–0.8 version, downloaded from binaries.soliditylang.org and SHA-256 verified), deploy from a test wallet in an in-memory EVM (EthereumJS), fund it, call every state-changing function and trace ETH that leaves for any address other than the caller.

## Accuracy notes (Oct 2026 run)

Known-bad caught: every `polymarket-*` package from the 2026 campaign, `ts-bign`, `axois`, the sample drainer (both 0.8 and 0.6 compilers), a lockfile pinning `axios@1.14.1`. No red flags on: axios, ethers, viem, @solana/web3.js, esbuild, sharp, hardhat, ccxt (npm and PyPI), web3, requests, cryptography, freqtrade, solana, python-binance, hyperliquid-python-sdk, polymarket-client, @polymarket/client, and the Polymarket / Hyperliquid / freqtrade GitHub repos. `npx tsx scripts/eval.ts [targets...]` reruns this.

## Limitations

- Static rules are pattern-based; determined attackers can evade them. "No red flags" is not a guarantee.
- The hook checks direct packages, manifests and lockfiles against intel; it doesn't download and scan every transitive tarball.
- The sandbox traces ETH only (not ERC-20 approvals or transfers) and calls functions with default arguments.
- Official-publisher checks trust npm scopes and verified publisher emails; PyPI checks rely on project URLs, email domains and age.

## Deploying the web scanner

The live site runs on Vercel with Root Directory `apps/web`. Vercel installs only that workspace, so every package its build needs (including `typescript`) is declared in `apps/web/package.json` or `packages/core`. Optional environment variable: `GITHUB_TOKEN` (a fine-grained token with read-only access to public repositories) lifts GitHub's 60 requests/hour limit for repo metadata; without it, scans still run but may skip stars, age and owner checks.

## Layout

```
packages/core     scanning engine (intel, registries, archives, analyzers, Solidity, install checks)
packages/cli      CLI + Claude Code hook source
plugin/           Claude Code plugin (hooks.json, bundled hook, safe-trading-bots skill)
.claude-plugin/   marketplace manifest
apps/web          Next.js 16 web scanner
scripts/          build, popular-name snapshot, accuracy eval
```

`npm run popular:update` refreshes the popular-package snapshots.

## License

MIT, see [LICENSE](LICENSE).
