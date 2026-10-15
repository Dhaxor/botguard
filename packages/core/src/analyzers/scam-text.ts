import type { Evidence, Finding, SourceFile } from "../types";
import { langOf, LineIndex } from "./text";

const REMIX = /remix(?:\.ethereum\.org|\s+ide)?\b/i;
const FUND = /\b(?:fund|deposit|send|transfer)\b[^\n]{0,80}?\b(?:ETH|BNB|ether|MATIC|POL|AVAX|ARB)\b/i;
const START = /\bstart\s*\(\s*\)|\bclick\s+(?:on\s+)?["'“]?start|\b(?:call|press|hit)\s+["'“]?start\b|\bstart\s+(?:the\s+)?bot\b/i;

interface TextRule {
  id: string;
  re: RegExp;
  severity: Finding["severity"];
  title: string;
  detail: string;
  advice?: string;
}

const TEXT_RULES: TextRule[] = [
  {
    id: "seed-phrase-request",
    re: /\b(?:enter|paste|input|provide|type|submit|share|import|send)\s+(?:in\s+)?(?:your\s+)?(?:12|24|twelve|twenty[- ]four)?[- ]?(?:word\s+)?(?:seed\s*phrase|recovery\s*phrase|secret\s+recovery\s+phrase|mnemonic(?:\s+phrase)?)/gi,
    severity: "medium",
    title: "Asks for your seed phrase",
    detail: "A seed phrase controls every account in a wallet, forever. No legitimate bot needs it; use a fresh wallet with only the funds you're willing to lose if you ever must.",
  },
  {
    id: "activation-fee",
    re: /\b(?:send|pay|deposit|transfer)\b[^.\n]{0,50}\b(?:to\s+activate|activation\s+fee|to\s+unlock|unlock\s+fee|license\s+fee|whitelist\s+fee)/gi,
    severity: "high",
    title: "Asks you to pay or deposit to 'activate' the bot",
    detail: "Activation or unlock deposits are the payout of the scam itself.",
  },
  {
    id: "disable-antivirus",
    re: /\b(?:disable|turn\s+off|deactivate|pause)\s+(?:your\s+)?(?:anti-?virus|windows\s+defender|defender|real[- ]time\s+protection|smartscreen)|\badd\s+(?:an?\s+)?(?:exclusion|exception)\s+(?:in|to|for)\s+(?:windows\s+)?defender/gi,
    severity: "high",
    title: "Tells you to disable your antivirus",
    detail: "Real software does not need Defender turned off. Malware authors ask because otherwise it gets caught.",
  },
  {
    id: "profit-promise",
    re: /\b(?:guaranteed|risk[- ]free)\s+(?:profits?|returns?|income|gains)|\b\d{1,4}(?:\.\d+)?\s*%\s*(?:daily|per\s+day|a\s+day|every\s+day)\b|\bpassive\s+income\b|\bmake\s+\$\s?\d[\d,]*\s*(?:a|per)\s+day\b/gi,
    severity: "medium",
    title: "Promises guaranteed or daily profits",
    detail: "No trading strategy guarantees returns. Profit promises are the bait in most bot scams.",
  },
  {
    id: "binary-download",
    re: /https?:\/\/(?:mega\.nz|(?:www\.)?mediafire\.com|gofile\.io|pixeldrain\.com|anonfiles|catbox\.moe|transfer\.sh)[^\s)'"<>]*|https?:\/\/(?!(?:[\w-]+\.)*(?:aka\.ms|microsoft\.com|python\.org|nodejs\.org|git-scm\.com|visualstudio\.com|nvidia\.com|intel\.com|oracle\.com|docker\.com|rust-lang\.org|golang\.org|go\.dev|mozilla\.org|google\.com)\/)[^\s)'"<>]+\.(?:exe|scr|msi|rar|7z)\b/gi,
    severity: "medium",
    title: "Distributes the bot as a download from a file host",
    detail: "The bot is offered as an executable or archive from a file host instead of source you can read. That is how many trading-bot infostealers spread.",
  },
];

/** Depth below the archive wrapper ("sdist/", "wheel/") - scam instructions live in top-level docs. */
function docDepth(path: string): number {
  return path.replace(/^(?:sdist|wheel)\//, "").split("/").length - 1;
}

function isUserFacingDoc(path: string): boolean {
  if (langOf(path) !== "text" && !/(^|\/)readme/i.test(path)) return false;
  if (/(^|\/)(?:node_modules|vendor|third_party|tests?|docs?\/api)\//i.test(path)) return false;
  return /(^|\/)readme[^/]*$/i.test(path) ? docDepth(path) <= 1 : docDepth(path) === 0;
}

/** README/docs red flags, including the "deploy this contract in Remix, fund it, call start()" scam. */
export function scanScamText(files: SourceFile[]): Finding[] {
  const findings: Finding[] = [];
  const docs = files.filter((f) => isUserFacingDoc(f.path));
  for (const file of docs.slice(0, 60)) {
    const lines = new LineIndex(file.text);
    for (const rule of TEXT_RULES) {
      const evidence: Evidence[] = [];
      for (const m of file.text.matchAll(rule.re)) {
        evidence.push(lines.evidence(file.path, m.index, m[0].length));
        if (evidence.length >= 2) break;
      }
      if (evidence.length) {
        findings.push({ id: `text.${rule.id}`, severity: rule.severity, category: "scam-text", title: rule.title, detail: rule.detail, advice: rule.advice, evidence });
      }
    }
    const remix = REMIX.exec(file.text);
    const fund = FUND.exec(file.text);
    const start = START.exec(file.text);
    if (remix && fund && start) {
      findings.push({
        id: "text.remix-fund-start",
        severity: "critical",
        category: "scam-text",
        title: "Matches the 'deploy in Remix, fund it, press start' bot scam",
        detail:
          "The instructions have you deploy a contract yourself, send it ETH/BNB, then call start(). In this scam the contract forwards everything to the author. Wallet warnings never fire because you deploy it yourself.",
        advice: "Never fund a contract you cannot read line by line. Scan the contract source here first.",
        evidence: [remix, fund, start].map((m) => lines.evidence(file.path, m.index, m[0].length)),
      });
    }
  }
  return findings;
}
