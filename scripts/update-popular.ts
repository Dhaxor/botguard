// Regenerates the popular-package snapshots used for typosquat detection.
// npm: npm-high-impact (ranked by downloads + dependents). PyPI: hugovk/top-pypi-packages (30-day downloads).
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { npmTopDownloads, npmTopDependents } from "npm-high-impact";

const NPM_LIMIT = 6000;
const PYPI_LIMIT = 8000;
const dataDir = fileURLToPath(new URL("../packages/core/data/", import.meta.url));

const npm: string[] = [];
const seen = new Set<string>();
for (const name of [...npmTopDownloads.slice(0, NPM_LIMIT), ...npmTopDependents.slice(0, 1500)]) {
  if (!seen.has(name)) {
    seen.add(name);
    npm.push(name);
  }
}

const res = await fetch("https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json");
if (!res.ok) throw new Error(`top-pypi-packages: HTTP ${res.status}`);
const body = (await res.json()) as { last_update: string; rows: { project: string; download_count: number }[] };
const pypi = body.rows.slice(0, PYPI_LIMIT).map((r) => [r.project, r.download_count] as const);

writeFileSync(
  `${dataDir}popular-npm.json`,
  JSON.stringify({ source: "npm-high-impact", generated: new Date().toISOString().slice(0, 10), names: npm }),
);
writeFileSync(
  `${dataDir}popular-pypi.json`,
  JSON.stringify({ source: "hugovk/top-pypi-packages", generated: body.last_update.slice(0, 10), rows: pypi }),
);
console.log(`npm: ${npm.length} names, pypi: ${pypi.length} names`);
