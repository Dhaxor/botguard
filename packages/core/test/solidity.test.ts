import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scanSoliditySources } from "../src/solidity";
import { analyzeSolidity } from "../src/solidity/static";
import type { SourceFile } from "../src/types";

const fixture = (name: string): SourceFile => {
  const text = readFileSync(fileURLToPath(new URL(`./fixtures/sol/${name}`, import.meta.url)), "utf8");
  return { path: name, text, size: text.length };
};

describe("solidity static analysis", () => {
  it("flags the hidden-recipient drainer template", () => {
    const ids = analyzeSolidity([fixture("FrontRunBot.sol")]).findings.map((f) => `${f.id}:${f.severity}`);
    expect(ids).toEqual(expect.arrayContaining(["sol.sweep-hidden-recipient:critical", "sol.mev-scam-template:medium"]));
  });

  it("does not flag an owner-only vault", () => {
    const findings = analyzeSolidity([fixture("OwnerVault.sol")]).findings;
    expect(findings.filter((f) => f.severity === "critical" || f.severity === "high")).toEqual([]);
  });
});

describe("solidity sandbox detonation (bundled compiler)", () => {
  it("watches the drainer send the victim's ETH to the hidden address", async () => {
    const notes: string[] = [];
    const res = await scanSoliditySources([fixture("FrontRunBot.sol")], { notes });
    expect(res.detonation?.compiled).toBe(true);
    const drain = res.findings.find((f) => f.id === "detonation.drain");
    expect(drain?.severity).toBe("critical");
    // 10 ETH deposited via receive() + 10 ETH sent along with the payable start() call.
    expect(res.detonation!.outflows[0]).toMatchObject({ fn: "start()", to: "0xbad0bad0bad000000000000000000000b0700b07", valueWei: (20n * 10n ** 18n).toString() });
  });

  it("sees no outflow from the owner vault", async () => {
    const res = await scanSoliditySources([fixture("OwnerVault.sol")], { notes: [] });
    expect(res.detonation?.compiled).toBe(true);
    expect(res.detonation?.contracts[0]?.deployed).toBe(true);
    expect(res.detonation?.outflows).toEqual([]);
  });
});
