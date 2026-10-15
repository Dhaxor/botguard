// Network tests against npm, PyPI, OSV and GitHub. Run with: npm run test:live
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkInstallCommand } from "../src/install/check";
import { checkDependencies } from "../src/intel/deps";
import { scan } from "../src/scan";
import { scanSoliditySources } from "../src/solidity";

const live = process.env.BOTGUARD_LIVE === "1";
const opts = { cachePath: false as const };

describe.skipIf(!live)("install hook decisions (live)", () => {
  it("blocks the 2026 Polymarket malware packages", async () => {
    for (const cmd of ["npm i polymarket-claude-code", "npx -y polymarket-bot", "pnpm add polymarket-copy-trading"]) {
      const r = await checkInstallCommand(cmd, opts);
      expect(r.decision, cmd).toBe("deny");
      expect(r.reason).toMatch(/malware|taken down/i);
    }
  });

  it("blocks packages npm already replaced with a security placeholder", async () => {
    const r = await checkInstallCommand("npm install axois", opts);
    expect(r.decision).toBe("deny");
  });

  it("allows the real SDKs", async () => {
    for (const cmd of [
      "npm install ethers dotenv @polymarket/client @polymarket/clob-client-v2",
      "npm install polymarket-us",
      "pip install polymarket-client py-clob-client-v2 web3",
      "pip install polymarket-us hyperliquid-python-sdk",
    ]) {
      const r = await checkInstallCommand(cmd, opts);
      expect(r.decision, `${cmd}: ${r.reason}`).toBe("allow");
    }
  });

  it("checks package.json dependencies on a bare npm install", async () => {
    const dir = mkdtempSync(join(tmpdir(), "botguard-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "x", dependencies: { "ts-bign": "^1.0.0", ethers: "^6.0.0" } }));
    const r = await checkInstallCommand("npm install", { ...opts, cwd: dir });
    expect(r.decision).toBe("deny");
    expect(r.reason).toContain("ts-bign");
  });

  it("respects the allow list", async () => {
    const r = await checkInstallCommand("npm i polymarket-bot", { ...opts, allow: ["polymarket-bot"] });
    expect(r.decision).toBe("allow");
  });
});

describe.skipIf(!live)("dependency intel (live)", () => {
  it("flags a lockfile that pins a hijacked release", async () => {
    const findings = await checkDependencies([{ ecosystem: "npm", name: "axios", version: "1.14.1", source: "package-lock.json", direct: false }], { notes: [] });
    expect(findings[0]).toMatchObject({ severity: "critical" });
  });
});

describe.skipIf(!live)("full scans (live)", () => {
  it("rates a known-malicious package dangerous", async () => {
    const r = await scan("npm:polymarket-claude-code");
    expect(r.verdict).toBe("dangerous");
  });

  it("rates the official SDKs clean", async () => {
    for (const t of ["npm:@solana/web3.js", "pypi:py-clob-client", "github.com/Polymarket/py-clob-client"]) {
      const r = await scan(t);
      expect(r.verdict, `${t}: ${r.findings.map((f) => f.id).join(",")}`).toBe("no-red-flags");
    }
  });

  it("falls back from npm to PyPI for bare names", async () => {
    const r = await scan("py-clob-client");
    expect(r.target.kind).toBe("pypi");
  });
});

describe.skipIf(!live)("solidity 0.6 with a downloaded compiler (live)", () => {
  it("detonates the 0.6 drainer", async () => {
    const text = readFileSync(fileURLToPath(new URL("./fixtures/sol/FrontRunBot06.sol", import.meta.url)), "utf8");
    const res = await scanSoliditySources([{ path: "FrontRunBot06.sol", text, size: text.length }], { notes: [] });
    expect(res.detonation?.compilerVersion).toMatch(/^0\.6\./);
    expect(res.findings.find((f) => f.id === "detonation.drain")?.severity).toBe("critical");
    expect(res.detonation?.outflows[0]?.to).toBe("0xbad0bad0bad000000000000000000000b0700b07");
  }, 180_000);
});
