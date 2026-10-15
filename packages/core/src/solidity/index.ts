import type { DetonationSummary, Finding, SourceFile } from "../types";
import { compileSolidity } from "./compile";
import { detonate } from "./detonate";
import { analyzeSolidity } from "./static";

export { analyzeSolidity, stripSolidityComments } from "./static";
export { compileSolidity, pragmaRange } from "./compile";
export { detonate } from "./detonate";

export interface SolidityScan {
  findings: Finding[];
  detonation?: DetonationSummary;
}

/** Static checks on all .sol files, then (optionally) compile + execute them in a sandbox EVM. */
export async function scanSoliditySources(
  files: SourceFile[],
  opts: { detonate?: boolean; cacheDir?: string; notes: string[] },
): Promise<SolidityScan> {
  const sol = files.filter((f) => f.path.endsWith(".sol"));
  if (!sol.length) return { findings: [] };
  const findings = analyzeSolidity(sol).findings;
  if (opts.detonate === false) return { findings };

  // Detonate at most a handful of top-level contracts; libraries/interfaces compile to empty bytecode.
  const sources = Object.fromEntries(sol.slice(0, 25).map((f) => [f.path, f.text]));
  let detonation: DetonationSummary | undefined;
  try {
    const compiled = await compileSolidity(sources, { cacheDir: opts.cacheDir, notes: opts.notes });
    if (!compiled.contracts.length) {
      opts.notes.push(`Could not compile the contract for sandbox execution${compiled.errors[0] ? `: ${compiled.errors[0].split("\n")[0]}` : "."} Static checks still ran.`);
      detonation = { compiled: false, compilerVersion: compiled.compilerVersion, contracts: [], outflows: [], error: compiled.errors[0] };
    } else {
      const result = await detonate(compiled.contracts, compiled.compilerVersion);
      findings.push(...result.findings);
      detonation = { compiled: true, compilerVersion: result.compilerVersion, contracts: result.contracts, outflows: result.outflows, depositedWei: result.depositedWei };
    }
  } catch (err) {
    opts.notes.push(`Sandbox execution failed: ${(err as Error).message}`);
    detonation = { compiled: false, contracts: [], outflows: [], error: (err as Error).message };
  }

  // A confirmed runtime drain supersedes the static "hidden recipient" guess; keep both but the runtime one leads.
  return { findings, detonation };
}
