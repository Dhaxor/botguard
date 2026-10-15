import npmData from "../../data/popular-npm.json";
import pypiData from "../../data/popular-pypi.json";
import type { Ecosystem } from "../types";

/** Crypto / trading SDKs that bot builders reach for. Always treated as popular squat targets. */
const CRYPTO_NPM = [
  "ethers", "web3", "viem", "wagmi", "@solana/web3.js", "@solana/spl-token", "@solana/kit", "@coral-xyz/anchor",
  "@project-serum/anchor", "ccxt", "@polymarket/client", "@polymarket/clob-client", "@polymarket/clob-client-v2",
  "@polymarket/order-utils", "polymarket-us", "@uniswap/sdk-core",
  "@uniswap/v2-sdk", "@uniswap/v3-sdk", "@uniswap/universal-router-sdk", "bignumber.js", "bn.js", "big.js",
  "decimal.js", "@jup-ag/api", "@raydium-io/raydium-sdk-v2", "@pythnetwork/client", "@openzeppelin/contracts",
  "@chainlink/contracts", "hardhat", "@nomicfoundation/hardhat-toolbox", "dotenv", "axios", "node-fetch", "ws",
  "telegraf", "node-telegram-bot-api", "grammy", "discord.js", "@binance/connector", "binance-api-node",
  "node-binance-api", "@metamask/sdk", "@coinbase/coinbase-sdk", "@coinbase/cdp-sdk", "@nktkas/hyperliquid",
  "hyperliquid", "technicalindicators", "trading-signals", "@anthropic-ai/sdk", "@anthropic-ai/claude-agent-sdk",
  "openai", "bs58", "tweetnacl", "@noble/hashes", "@noble/curves", "@scure/bip39", "bip39", "ethereumjs-util",
];

const CRYPTO_PYPI = [
  "polymarket-client", "py-clob-client", "py-clob-client-v2", "polymarket-us", "web3", "eth-account", "ccxt", "python-binance", "binance-connector", "solana", "solders",
  "anchorpy", "hyperliquid-python-sdk", "freqtrade", "requests", "python-dotenv", "websockets", "aiohttp", "pandas",
  "numpy", "ta", "backtrader", "vectorbt", "python-telegram-bot", "anthropic", "openai", "eth-utils", "eth-abi",
  "coinbase-advanced-py", "kalshi-python", "py-order-utils", "pycryptodome", "base58", "mnemonic", "bip-utils",
];

export function canonicalPypi(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

const npmNames: string[] = [...new Set([...CRYPTO_NPM, ...(npmData as { names: string[] }).names])];
const pypiRows = (pypiData as unknown as { rows: [string, number][] }).rows;
const pypiDownloads = new Map<string, number>();
for (const [name, count] of pypiRows) pypiDownloads.set(canonicalPypi(name), count);
for (const name of CRYPTO_PYPI) {
  const key = canonicalPypi(name);
  if (!pypiDownloads.has(key)) pypiDownloads.set(key, 1_000_000);
}
const pypiNames = [...pypiDownloads.keys()];
const npmRank = new Map(npmNames.map((n, i) => [n, i] as const));

export function isPopular(name: string, eco: Ecosystem): boolean {
  return eco === "npm" ? npmRank.has(name) : pypiDownloads.has(canonicalPypi(name));
}

/** Rank in the snapshot (0 = most popular) or undefined. PyPI uses download counts instead. */
export function popularityRank(name: string, eco: Ecosystem): number | undefined {
  if (eco === "npm") return npmRank.get(name);
  const key = canonicalPypi(name);
  if (!pypiDownloads.has(key)) return undefined;
  return pypiNames.indexOf(key);
}

export function pypiMonthlyDownloads(name: string): number | undefined {
  return pypiDownloads.get(canonicalPypi(name));
}

/** Damerau-Levenshtein (optimal string alignment) with an early exit above `max`. */
export function editDistance(a: string, b: string, max = 3): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const rows = a.length + 1;
  const cols = b.length + 1;
  let prevPrev: number[] = [];
  let prev = Array.from({ length: cols }, (_, j) => j);
  for (let i = 1; i < rows; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j < cols; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        v = Math.min(v, prevPrev[j - 2]! + 1);
      }
      cur.push(v);
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    prevPrev = prev;
    prev = cur;
  }
  return prev[cols - 1]!;
}

// Visually confusable sequences. Single-character swaps are already caught by edit distance.
const HOMOGLYPHS: [RegExp, string][] = [
  [/rn/g, "m"],
  [/vv/g, "w"],
  [/0/g, "o"],
  [/1/g, "l"],
];

function squash(name: string): string {
  return name.toLowerCase().replace(/^@/, "").replace(/[-_./]+/g, "");
}

function deglyph(name: string): string {
  let s = squash(name);
  for (const [re, to] of HOMOGLYPHS) s = s.replace(re, to);
  return s;
}

export type SquatKind = "lookalike" | "separator" | "scope" | "homoglyph" | "affix";

export interface SquatMatch {
  target: string;
  kind: SquatKind;
  distance: number;
}

const squashIndex = new Map<string, Map<string, string>>();
const glyphIndex = new Map<string, Map<string, string>>();
function indexFor(eco: Ecosystem) {
  if (!squashIndex.has(eco)) {
    const names = eco === "npm" ? npmNames : pypiNames;
    const sq = new Map<string, string>();
    const gl = new Map<string, string>();
    for (const n of names) {
      if (!sq.has(squash(n))) sq.set(squash(n), n);
      if (!gl.has(deglyph(n))) gl.set(deglyph(n), n);
    }
    squashIndex.set(eco, sq);
    glyphIndex.set(eco, gl);
  }
  return { sq: squashIndex.get(eco)!, gl: glyphIndex.get(eco)! };
}

const AFFIXES = [/^python-?/, /^py-?/, /-?py$/, /-?python3?$/, /^node-?/, /-?js$/, /-?sdk$/, /-?api$/, /-?lib$/, /-?official$/, /-?v\d$/, /\d$/];
const CRYPTO_TARGETS = new Set([...CRYPTO_NPM, ...CRYPTO_PYPI].map((n) => squash(n)));

/**
 * Is `name` a likely typosquat of a popular package? Popular names themselves never match.
 * Kept conservative: short names and distance-2 matches on short targets are ignored.
 */
export function findTyposquat(name: string, eco: Ecosystem): SquatMatch | null {
  if (isPopular(name, eco)) return null;
  const key = eco === "pypi" ? canonicalPypi(name) : name.toLowerCase();
  const { sq, gl } = indexFor(eco);

  // Same letters, different separators or scope: "polymarket-clob-client" vs "@polymarket/clob-client".
  const squashed = squash(key);
  const sameLetters = sq.get(squashed);
  if (sameLetters && sameLetters !== name && eco === "npm") {
    return { target: sameLetters, kind: sameLetters.startsWith("@") || key.startsWith("@") ? "scope" : "separator", distance: 0 };
  }
  const glyph = gl.get(deglyph(key));
  if (glyph && squash(glyph) !== squashed) return { target: glyph, kind: "homoglyph", distance: 1 };

  if (squashed.length >= 5) {
    const names = eco === "npm" ? npmNames : pypiNames;
    let best: SquatMatch | null = null;
    for (const cand of names) {
      const target = eco === "pypi" ? cand : cand.toLowerCase();
      if (target === key) continue;
      const len = target.length;
      if (Math.abs(len - key.length) > 2) continue;
      const allowed = len >= 9 ? 2 : len >= 5 ? 1 : 0;
      if (allowed === 0) continue;
      const d = editDistance(key, target, allowed);
      if (d <= allowed && (!best || d < best.distance)) {
        best = { target: cand, kind: "lookalike", distance: d };
        if (d === 1) break; // names are ranked by popularity: first distance-1 hit is the likeliest target
      }
    }
    if (best) return best;
  }

  // "ethers-js", "web3-py", "ccxt-python": only for crypto SDKs, where the payoff for attackers is highest.
  for (const re of AFFIXES) {
    const stripped = squashed.replace(re, "");
    if (stripped !== squashed && stripped.length >= 3 && CRYPTO_TARGETS.has(stripped)) {
      const target = [...CRYPTO_NPM, ...CRYPTO_PYPI].find((n) => squash(n) === stripped)!;
      return { target, kind: "affix", distance: 0 };
    }
  }
  return null;
}
