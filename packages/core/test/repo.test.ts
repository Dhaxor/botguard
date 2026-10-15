import { describe, expect, it } from "vitest";
import { repoSignals } from "../src/analyzers/repo";
import type { GithubOwner, GithubRepo } from "../src/registry/github";

const daysAgo = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString();

function repo(over: Partial<GithubRepo> = {}): GithubRepo {
  return {
    full_name: "someone/polymarket-bot",
    html_url: "https://github.com/someone/polymarket-bot",
    description: "Polymarket copy trading bot",
    created_at: daysAgo(400),
    pushed_at: daysAgo(1),
    stargazers_count: 12,
    forks_count: 3,
    open_issues_count: 0,
    has_issues: true,
    archived: false,
    fork: false,
    default_branch: "main",
    owner: { login: "someone", type: "User" },
    ...over,
  };
}

const owner = (type: string, ageDays: number): GithubOwner => ({ login: "x", type, created_at: daysAgo(ageDays), public_repos: 5, followers: 1 });
const releaseFinding = (assets: string[], o: GithubOwner) =>
  repoSignals({ repo: repo(), owner: o, assets: assets.map((name) => ({ name })) as never }).find((f) => f.id === "repo.release-binaries");

describe("release assets", () => {
  it("flags a bot program shipped from a personal account", () => {
    expect(releaseFinding(["PolymarketBot-setup.exe"], owner("User", 400))?.severity).toBe("medium");
    expect(releaseFinding(["bot-v2.rar"], owner("User", 400))?.severity).toBe("medium");
  });

  it("ignores docs and source bundles", () => {
    expect(releaseFinding(["polymarket-client-0.13.0-sphinx.zip", "docs.zip"], owner("User", 400))).toBeUndefined();
  });

  it("keeps long-established organizations at low", () => {
    expect(releaseFinding(["trader-windows.zip"], owner("Organization", 3000))?.severity).toBe("low");
  });
});
