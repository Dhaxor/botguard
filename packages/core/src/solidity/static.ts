import { LineIndex } from "../analyzers/text";
import type { Evidence, Finding, SourceFile } from "../types";

/** Blank out comments but keep offsets and newlines, so evidence line numbers stay right. */
export function stripSolidityComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'/g, (m) =>
    m.startsWith("/") ? m.replace(/[^\n]/g, " ") : m,
  );
}

const SWEEP =
  /([\w.()[\]\s]{1,120}?)\s*\.\s*(?:transfer|send)\s*\(\s*address\s*\(\s*this\s*\)\s*\.balance\s*\)|([\w.()[\]\s]{1,120}?)\s*\.\s*call\s*\{\s*value\s*:\s*address\s*\(\s*this\s*\)\s*\.balance\s*\}/g;
const NAMED_CONVERTER = /\b(?:parseAddr|parseAddress|parseMemoryPool|parseMempool|fromHexChar|hexToAddress|stringToAddress|strToAddr)\b/g;
const CHAR_ARITHMETIC = /-=?\s*(?:48|87|55)\s*;|>=\s*97\s*\)\s*&&\s*\(?\s*\w+\s*<=\s*102/g;
const TO_ADDRESS = /\buint160\s*\(|\biaddr\b/;

/** Hand-rolled hex-string -> address parsing (named helpers, or ASCII arithmetic feeding uint160). */
function findConverters(code: string): RegExpExecArray[] {
  const named = [...code.matchAll(NAMED_CONVERTER)];
  if (named.length) return named;
  const arith = [...code.matchAll(CHAR_ARITHMETIC)];
  return arith.length && TO_ADDRESS.test(code) ? arith : [];
}
const SCAM_NAMES =
  /\b(?:callMempool|parseMemoryPool|getMemPool\w*|mempool\w*|Mempool\w*|frontRun\w*|FrontRun\w*|checkLiquidity|startExploration|loadCurrentContract|findNewContracts|findContracts|getMempool\w*|_callFrontRunActionMempool|_callStartActionMempool)\b/g;
const HEX_LITERAL = /"(?:0x)?[0-9a-fA-F]{4,}"|'(?:0x)?[0-9a-fA-F]{4,}'/g;
const ADDRESS_LITERAL = /0x[0-9a-fA-F]{40}\b/g;

function recipientKind(expr: string, code: string): "caller" | "owner" | "hardcoded" | "computed" {
  const e = expr.replace(/\s+/g, "");
  if (/msg\.sender/.test(e)) return "caller";
  if (/0x[0-9a-fA-F]{40}/.test(e)) return "hardcoded";
  const ident = /(?:payable\()?\(?([A-Za-z_]\w*)(\(\))?\)?$/.exec(e)?.[1];
  if (ident && /^_?(?:owner|admin|deployer|creator)$/i.test(ident)) {
    // Owner is fine only if the constructor takes it from msg.sender.
    const assign = new RegExp(String.raw`\b${ident}\s*=\s*([^;]+);`).exec(code);
    if (assign && /0x[0-9a-fA-F]{40}/.test(assign[1]!)) return "hardcoded";
    return "owner";
  }
  return "computed";
}

export interface SolidityStaticResult {
  findings: Finding[];
  /** Address-looking strings worth comparing with runtime transfers. */
  addresses: string[];
}

/** Pattern checks for Solidity sources, tuned for the "MEV / front-running bot" drainer family. */
export function analyzeSolidity(files: SourceFile[]): SolidityStaticResult {
  const findings: Finding[] = [];
  const addresses = new Set<string>();
  for (const file of files.filter((f) => f.path.endsWith(".sol") || f.path === "contract.sol")) {
    const code = stripSolidityComments(file.text);
    const lines = new LineIndex(file.text);
    const ev = (i: number, len: number): Evidence => {
      // Matches may start with the whitespace/newline before the statement; point at the statement itself.
      let start = i;
      while (start < i + len && /\s/.test(file.text[start]!)) start++;
      return lines.evidence(file.path, start, len - (start - i));
    };

    const converters = findConverters(code);
    const scamNames = [...code.matchAll(SCAM_NAMES)];
    const hexLits = [...code.matchAll(HEX_LITERAL)];
    for (const m of code.matchAll(ADDRESS_LITERAL)) addresses.add(m[0]);

    for (const m of code.matchAll(SWEEP)) {
      const expr = (m[1] ?? m[2] ?? "").trim();
      const kind = recipientKind(expr, code);
      if (kind === "caller" || kind === "owner") continue;
      if (kind === "hardcoded") {
        findings.push({
          id: "sol.sweep-hardcoded",
          severity: "high",
          category: "solidity",
          title: "Sends the contract's whole balance to a hard-coded address",
          detail: "Every wei the contract holds goes to a fixed address written into the code, not to you.",
          advice: "Look the address up. If it isn't yours, deploying and funding this contract hands your money to its author.",
          evidence: [ev(m.index, m[0].length)],
        });
      } else {
        const hidden = converters.length > 0 || hexLits.length >= 4;
        findings.push({
          id: hidden ? "sol.sweep-hidden-recipient" : "sol.sweep-computed",
          severity: hidden ? "critical" : "medium",
          category: "solidity",
          title: hidden
            ? "Sends the whole balance to an address assembled from hidden strings"
            : "Sends the whole balance to an address computed at runtime",
          detail: hidden
            ? "The recipient is built at runtime from string or hex fragments, so you can't see who gets paid. This is the 'MEV bot' drainer pattern: the money goes to the scammer the moment you call start/withdraw."
            : `The contract sends its entire balance to \`${expr.slice(0, 80)}\`, which is not msg.sender or an owner set from msg.sender.`,
          evidence: [ev(m.index, m[0].length), ...converters.slice(0, 2).map((c) => ev(c.index, c[0].length))],
        });
      }
    }

    if (converters.length && !findings.some((f) => f.id === "sol.sweep-hidden-recipient")) {
      findings.push({
        id: "sol.string-to-address",
        severity: "high",
        category: "solidity",
        title: "Builds an address out of text at runtime",
        detail: "Converting strings or hex characters into an address is how drainer contracts hide where funds go. Trading contracts take addresses as parameters or constants.",
        evidence: converters.slice(0, 3).map((c) => ev(c.index, c[0].length)),
      });
    }
    if (scamNames.length >= 3) {
      findings.push({
        id: "sol.mev-scam-template",
        severity: "medium",
        category: "solidity",
        title: "Uses the naming of a known 'mempool front-running bot' scam template",
        detail: "Functions like callMempool / parseMemoryPool / checkLiquidity come from a contract template copied across hundreds of scam videos. Real MEV bots are not run by sending ETH to a contract you deploy from Remix.",
        evidence: scamNames.slice(0, 3).map((c) => ev(c.index, c[0].length)),
      });
    }
    if (hexLits.length >= 6) {
      findings.push({
        id: "sol.hex-fragments",
        severity: "medium",
        category: "solidity",
        title: "Hex strings scattered through the code",
        detail: `${hexLits.length} hex-looking string literals. Splitting an address into fragments is a common trick to keep it from being spotted.`,
        evidence: hexLits.slice(0, 3).map((c) => ev(c.index, c[0].length)),
      });
    }
    for (const m of code.matchAll(/^\s*import\s+(?:[^"'\n]*from\s+)?["']((?:https?|ipfs):\/\/[^"']+)["']/gm)) {
      findings.push({
        id: "sol.remote-import",
        severity: "medium",
        category: "solidity",
        title: "Imports code from a URL",
        detail: `The contract pulls ${m[1]} at compile time. Whatever that URL serves becomes part of the contract, and it can change.`,
        evidence: [ev(m.index, m[0].length)],
      });
    }
    for (const m of code.matchAll(/selfdestruct\s*\(\s*(?:payable\s*\()?\s*0x[0-9a-fA-F]{40}/g)) {
      findings.push({
        id: "sol.selfdestruct-hardcoded",
        severity: "high",
        category: "solidity",
        title: "Self-destructs and pays a hard-coded address",
        detail: "selfdestruct sends the contract's remaining balance to a fixed address.",
        evidence: [ev(m.index, m[0].length)],
      });
    }
    for (const m of code.matchAll(/payable\s*\(\s*0x[0-9a-fA-F]{40}\s*\)\s*\.\s*(?:transfer|send|call)/g)) {
      findings.push({
        id: "sol.pay-hardcoded",
        severity: "medium",
        category: "solidity",
        title: "Pays a hard-coded address",
        detail: "The contract sends ETH to a fixed address. Make sure you know whose it is.",
        evidence: [ev(m.index, m[0].length)],
      });
    }
    const origin = /\btx\.origin\b/.exec(code);
    if (origin) {
      findings.push({
        id: "sol.tx-origin",
        severity: "low",
        category: "solidity",
        title: "Uses tx.origin",
        detail: "tx.origin-based checks can be abused by other contracts; scam contracts also use it to fingerprint victims.",
        evidence: [ev(origin.index, origin[0].length)],
      });
    }
  }
  return { findings, addresses: [...addresses] };
}
