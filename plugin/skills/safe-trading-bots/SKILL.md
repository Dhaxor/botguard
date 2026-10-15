---
name: safe-trading-bots
description: Use when building, modifying or running a crypto trading bot, prediction-market bot (Polymarket, Kalshi), Hyperliquid bot, sniper/MEV/arbitrage bot, or anything that holds a private key, seed phrase or exchange API key. Covers which official SDKs to use, how to handle keys, and which "bot" patterns are scams.
---

# Building trading bots without getting drained

Bot builders are a prime target in 2026: fake "Polymarket bot" repos with key-stealing npm packages, packages named to land in AI coding sessions (`polymarket-claude-code`), and YouTube "deploy this MEV bot in Remix" contracts that forward every deposit to the scammer. Follow these rules whenever the task touches a bot or a wallet.

## Packages: use the official SDKs, by exact name

| Need | Use | Never |
|---|---|---|
| Polymarket (TS) | `@polymarket/client` (unified SDK), `@polymarket/clob-client-v2` | `polymarket-bot`, `polymarket-trade`, `polymarket-claude-code`, other unscoped `polymarket-*` names |
| Polymarket (Python) | `polymarket-client` (unified SDK), `py-clob-client-v2` | `py-clob-client` (archived, no longer works), look-alikes, forks from random GitHub orgs |
| Polymarket US | `polymarket-us` (npm and PyPI, published by Polymarket) | |
| Kalshi | `kalshi-python` / `kalshi_python_sync` (published by Kalshi) | unofficial "kalshi bot" packages |
| Hyperliquid | `hyperliquid-python-sdk` (hyperliquid-dex) | packages that ask for your seed phrase |
| EVM | `ethers`, `viem`, `web3` | `ethres`, `etherjs`, `web3-js-pro`... |
| Solana | `@solana/web3.js` / `@solana/kit`, `solana`, `solders` | |
| Exchanges | `ccxt` | |

- Copy package names from the provider's own docs. Never "fix" a failed install by trying a similar-looking name.
- If BotGuard blocks an install, do not work around it. Tell the user what was blocked and why.
- Before running a cloned bot repo, scan it with BotGuard: paste the URL into the web scanner linked from https://github.com/Dhaxor/botguard, or run `node packages/cli/dist/cli.mjs scan <github-url>` from a BotGuard checkout. Read `package.json` scripts and every dependency name first.

## Keys and wallets

- Use a **fresh wallet** that holds only what the bot may lose. Never the user's main wallet.
- Read keys from environment variables or a local `.env` (in `.gitignore`). Never hard-code them, log them, or send them over the network.
- Never ask for, store or handle a **seed phrase**. A bot needs at most one private key for one wallet.
- Prefer keys that **cannot withdraw**: exchange API keys with withdrawals disabled and IP allow-listing; Hyperliquid API ("agent") wallets, which can trade but not withdraw.
- Signing happens locally. If code sends a private key, mnemonic or API secret in an HTTP request, it is malware.

## Scam patterns to refuse

- "Deploy this contract in Remix, send it ETH/BNB, then call `start()`." The contract forwards the deposit to an address hidden in string fragments (`callMempool`, `parseMemoryPool`, `checkLiquidity`...). Scan the contract with BotGuard (web scanner, or `node packages/cli/dist/cli.mjs scan Contract.sol`): it executes the contract in a sandbox EVM and shows where the money goes.
- Bots that require "activation fees", disabling antivirus, or downloading an `.exe`.
- Guaranteed or daily profit claims.

## Before going live

1. Backtest or paper-trade first, with realistic fees and slippage.
2. Start with a small, capped amount and a hard kill switch (max loss per day, max position).
3. Log every order; alert on errors.
