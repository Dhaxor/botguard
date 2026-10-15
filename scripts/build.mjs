// Bundles the CLI (packages/cli/dist/cli.mjs) and the self-contained Claude Code hook (plugin/hooks/botguard-hook.mjs).
// Usage: node scripts/build.mjs [cli|hook]   (default: both)
import { build } from "esbuild";
import { chmodSync, readdirSync, rmSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const which = process.argv[2];
const requireShim = 'import { createRequire as __bgCreateRequire } from "node:module"; const require = __bgCreateRequire(import.meta.url);';

const common = {
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  absWorkingDir: root,
  logLevel: "warning",
  legalComments: "none",
};

if (!which || which === "cli") {
  const outfile = "packages/cli/dist/cli.mjs";
  await build({
    ...common,
    entryPoints: ["packages/cli/src/cli.ts"],
    outfile,
    // Heavy runtime deps stay external: they're regular dependencies of the published CLI.
    external: ["solc", "@ethereumjs/evm", "@ethereumjs/util"],
    banner: { js: `#!/usr/bin/env node\n${requireShim}` },
  });
  chmodSync(`${root}${outfile}`, 0o755);
  console.log(`built ${outfile} (${(statSync(`${root}${outfile}`).size / 1024).toFixed(0)} KB)`);
}

if (!which || which === "hook") {
  const outdir = "plugin/hooks";
  for (const f of readdirSync(`${root}${outdir}`)) if (/^botguard-.*\.mjs$/.test(f)) rmSync(`${root}${outdir}/${f}`);
  // Code-split so the tiny entry can exit before loading the scanner for commands that install nothing.
  await build({
    ...common,
    entryPoints: { "botguard-hook": "packages/cli/src/hook-entry.ts" },
    outdir,
    splitting: true,
    chunkNames: "botguard-[name]-[hash]",
    outExtension: { ".js": ".mjs" },
    banner: {
      js: `// BotGuard Claude Code hook (generated bundle, do not edit). Source: packages/cli/src/hook.ts\n// Blocks installs of known-malicious, typosquatted or impersonating npm/PyPI packages.\n${requireShim}`,
    },
  });
  for (const f of readdirSync(`${root}${outdir}`).filter((f) => f.endsWith(".mjs"))) {
    console.log(`built ${outdir}/${f} (${(statSync(`${root}${outdir}/${f}`).size / 1024).toFixed(0)} KB)`);
  }
}
