export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Overall call. "no-red-flags" is deliberately not "safe": absence of evidence is not a guarantee. */
export type Verdict = "dangerous" | "suspicious" | "caution" | "no-red-flags" | "error";

export type Ecosystem = "npm" | "pypi";

export type FindingCategory =
  | "intel"
  | "typosquat"
  | "install-script"
  | "secrets"
  | "exfiltration"
  | "obfuscation"
  | "execution"
  | "persistence"
  | "wallet"
  | "repo"
  | "metadata"
  | "scam-text"
  | "solidity"
  | "detonation";

export interface Evidence {
  /** Path inside the scanned target (repo/package/contract file). */
  file?: string;
  line?: number;
  /** Short excerpt around the match, never the whole file. */
  snippet?: string;
  url?: string;
}

export interface Finding {
  /** Stable rule id, e.g. "intel.osv-malicious" or "code.secret-exfil". */
  id: string;
  severity: Severity;
  category: FindingCategory;
  title: string;
  detail: string;
  evidence?: Evidence[];
  advice?: string;
}

export type TargetKind = "npm" | "pypi" | "github" | "solidity" | "directory";

export interface Target {
  kind: TargetKind;
  /** What the user typed, untouched. */
  raw: string;
  /** Package name (npm/pypi). */
  name?: string;
  /** Version or range spec (npm/pypi), or git ref (github). */
  spec?: string;
  owner?: string;
  repo?: string;
  /** Local directory or file path. */
  path?: string;
  /** Inline Solidity source. */
  source?: string;
}

export interface ReportTarget {
  kind: TargetKind;
  display: string;
  url?: string;
  version?: string;
}

export interface ScanStats {
  filesScanned: number;
  bytesScanned: number;
  durationMs: number;
}

export interface ScanReport {
  target: ReportTarget;
  verdict: Verdict;
  /** 0-100, higher is riskier. */
  score: number;
  summary: string;
  findings: Finding[];
  /** Facts worth showing next to the verdict (age, downloads, stars...). */
  facts: { label: string; value: string }[];
  stats: ScanStats;
  /** Non-fatal problems: rate limits, files skipped, compile failures. */
  notes: string[];
  scannedAt: string;
  engine: string;
  /** Present when a Solidity contract was executed in the sandbox EVM. */
  detonation?: DetonationSummary;
}

export interface DetonationTransfer {
  contract: string;
  fn: string;
  to: string;
  valueWei: string;
  label?: string;
}

export interface DetonationSummary {
  compiled: boolean;
  compilerVersion?: string;
  contracts: { name: string; deployed: boolean; calls: { fn: string; ok: boolean; transfers: number }[] }[];
  /** Value that left a contract for an address that is not the caller. */
  outflows: DetonationTransfer[];
  /** Total test ETH (wei) the "victim" wallet sent in: plain deposits plus value attached to payable calls. */
  depositedWei?: string;
  error?: string;
}

export interface ScanOptions {
  /** GitHub token for higher API limits (falls back to GITHUB_TOKEN / GH_TOKEN). */
  githubToken?: string;
  /** Execute Solidity contracts in the in-memory EVM (default true). */
  detonate?: boolean;
  /** Directory for cached compilers. */
  cacheDir?: string;
  /** Overall budget for network work. */
  timeoutMs?: number;
  onProgress?: (message: string) => void;
}

/** A source file pulled out of a repo, package archive or local folder. */
export interface SourceFile {
  path: string;
  /** Decoded UTF-8 text; binary files are not represented. */
  text: string;
  size: number;
}
