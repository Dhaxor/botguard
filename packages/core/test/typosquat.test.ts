import { describe, expect, it } from "vitest";
import { editDistance, findTyposquat, isPopular } from "../src/intel/popular";
import { matchBrands, isOfficialPublisher, BRANDS } from "../src/intel/brands";

describe("editDistance", () => {
  it("counts substitutions, insertions and transpositions", () => {
    expect(editDistance("axios", "axois")).toBe(1);
    expect(editDistance("ethers", "ether")).toBe(1);
    expect(editDistance("requests", "reqeusts")).toBe(1);
    expect(editDistance("lodash", "lodahs")).toBe(1);
    expect(editDistance("react", "preact", 1)).toBe(1);
    expect(editDistance("abcdef", "uvwxyz", 2)).toBe(3);
  });
});

describe("findTyposquat", () => {
  it("ignores popular packages", () => {
    for (const n of ["lodash", "axios", "ethers", "@polymarket/clob-client", "react"]) expect(findTyposquat(n, "npm")).toBeNull();
    for (const n of ["requests", "py-clob-client", "web3", "numpy"]) expect(findTyposquat(n, "pypi")).toBeNull();
  });

  it("catches one-character lookalikes of popular npm packages", () => {
    expect(findTyposquat("axois", "npm")?.target).toBe("axios");
    expect(findTyposquat("ethres", "npm")?.target).toBe("ethers");
    expect(findTyposquat("expresss", "npm")?.target).toBe("express");
  });

  it("catches scope confusion", () => {
    const m = findTyposquat("polymarket-clob-client", "npm");
    expect(m).toMatchObject({ target: "@polymarket/clob-client", kind: "scope" });
  });

  it("catches PyPI lookalikes and crypto affixes", () => {
    expect(findTyposquat("reqeusts", "pypi")?.target).toBe("requests");
    expect(findTyposquat("web3-py", "pypi")).toMatchObject({ target: "web3", kind: "affix" });
    expect(findTyposquat("py_clob_client", "pypi")).toBeNull(); // same project on PyPI
  });

  it("leaves unrelated names alone", () => {
    expect(findTyposquat("my-weird-trading-bot-xyz", "npm")).toBeNull();
    expect(findTyposquat("botguard", "npm")).toBeNull();
  });

  it("knows the popular sets", () => {
    expect(isPopular("@solana/web3.js", "npm")).toBe(true);
    expect(isPopular("PY-CLOB_client", "pypi")).toBe(true);
  });
});

describe("brands", () => {
  it("matches brand names in package names", () => {
    expect(matchBrands("polymarket-claude-code").map((b) => b.key)).toEqual(expect.arrayContaining(["polymarket", "anthropic"]));
    expect(matchBrands("hyper-liquid-sniper").map((b) => b.key)).toContain("hyperliquid");
    expect(matchBrands("left-pad")).toEqual([]);
  });

  it("treats the npm scope as authoritative", () => {
    const pm = BRANDS.find((b) => b.key === "polymarket")!;
    expect(isOfficialPublisher(pm, { scope: "@polymarket" })).toBe(true);
    expect(isOfficialPublisher(pm, { scope: "@polymarket-dev" })).toBe(false);
    expect(isOfficialPublisher(pm, { repositoryUrl: "https://github.com/Polymarket/py-clob-client" })).toBe(true);
  });
});
