// Scan a list of targets and print one line per verdict: a quick false-positive / true-positive check.
// Usage: npx tsx scripts/eval.ts [target ...]   (defaults to a set of popular legit crypto packages and repos)
import { scan } from "../packages/core/src/index";

const DEFAULTS = [
  "npm:axios",
  "npm:ethers",
  "npm:@solana/web3.js",
  "npm:@polymarket/clob-client",
  "npm:viem",
  "npm:node-telegram-bot-api",
  "npm:dotenv",
  "npm:polymarket-bot",
  "npm:polymarket-claude-code",
  "pypi:py-clob-client",
  "pypi:requests",
  "pypi:web3",
  "pypi:hyperliquid-python-sdk",
  "github.com/Polymarket/py-clob-client",
  "github.com/Polymarket/clob-client",
  "github.com/hyperliquid-dex/hyperliquid-python-sdk",
];

const targets = process.argv.slice(2).length ? process.argv.slice(2) : DEFAULTS;
for (const t of targets) {
  const started = Date.now();
  const r = await scan(t);
  const top = r.findings
    .filter((f) => f.severity !== "info")
    .slice(0, 4)
    .map((f) => `[${f.severity}] ${f.id}: ${f.title}`)
    .join("\n      ");
  console.log(`${r.verdict.padEnd(13)} ${String(r.score).padStart(3)}  ${r.target.display}  (${r.stats.filesScanned} files, ${((Date.now() - started) / 1000).toFixed(1)}s)`);
  if (top) console.log(`      ${top}`);
  if (r.verdict === "error") console.log(`      ${r.summary}`);
  for (const n of r.notes) console.log(`      note: ${n}`);
}
