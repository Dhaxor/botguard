# botguard

**Check the bot before it checks out your wallet.**

BotGuard scans crypto trading-bot repos, npm/PyPI packages and Solidity contracts for known malware, typosquats, brand impersonation, key-stealing code, install-time traps and "deploy this MEV bot in Remix" drainer contracts. Solidity is compiled and run in a sandbox EVM so you can see where the money goes.

- Web scanner: https://botguard-scanner.vercel.app
- Source, Claude Code plugin and docs: https://github.com/Dhaxor/botguard

Needs Node 20+.

```bash
npx botguard scan github.com/someone/polymarket-bot
npm i -g botguard        # or install it once
```

## scan

```bash
botguard scan github.com/someone/polymarket-bot   # GitHub repo (or owner/repo)
botguard scan npm:polymarket-claude-code          # npm package, npm:name[@version]
botguard scan pypi:polymarket-client==0.13.0      # PyPI package
botguard scan ./contracts/FrontRunBot.sol         # compiled + run in the sandbox EVM
botguard scan ./my-bot                            # local folder
```

`--json` prints the full report, `--verbose` adds info-level findings, `--no-sandbox` skips the EVM run.

## check

```bash
botguard check "npm i axois && pip install polymarket-client"
```

Shows what the Claude Code install guard would decide for a shell command: allow, ask or deny.

## init

```bash
npm i -g botguard
botguard init claude               # add the guard to .claude/settings.json
botguard init claude --user        # or to ~/.claude/settings.json
botguard init claude --dry-run     # print the hook entry without writing it
```

Adds a PreToolUse hook that checks every `npm`/`pnpm`/`yarn`/`bun`/`npx`/`pip`/`uv`/`pipx`/`poetry` install, `git clone` and `curl | sh` Claude Code is about to run. Known malware and strong impostors are blocked, borderline cases ask you, everything else stays silent. The hook runs this package's own files, so install it globally instead of running `init` through npx. Prefer a plugin? `/plugin marketplace add Dhaxor/botguard`, then `/plugin install botguard@botguard`.

## Exit codes and environment

Exit codes: `0` no red flags / caution, `1` suspicious, `2` dangerous, `3` error.

- `GITHUB_TOKEN` raises GitHub API limits (60 requests/hour without it).
- `BOTGUARD_ALLOW=pkg1,pkg2` allow-lists packages for the guard and `check`; the hook also reads `{ "allow": [...] }` from a `.botguard.json` in the project.
- `BOTGUARD_FAIL_CLOSED=1` makes the hook ask instead of allowing when a lookup fails.

BotGuard flags risk; it can't prove anything is safe.

## License

MIT
